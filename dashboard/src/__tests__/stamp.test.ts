import { describe, expect, it } from "vitest";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { hexToBytes } from "@noble/hashes/utils";
import {
  buildStamp,
  generateIdentity,
  SCHEME_P256,
  verifyStamp,
} from "@/lib/stamp";

function decodeBase64Url(value: string): string {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  return atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad);
}

describe("X-Stamp construction", () => {
  it("generates a compressed P-256 identity (33-byte pubkey, hex)", () => {
    const identity = generateIdentity();
    expect(identity.privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.publicKeyHex).toMatch(/^0[23][0-9a-f]{64}$/);
  });

  it("produces base64url (no +, /, or padding) of a JSON envelope", () => {
    const identity = generateIdentity();
    const stamp = buildStamp(identity, '{"hello":"world"}');
    expect(stamp).not.toMatch(/[+/=]/);

    const envelope = JSON.parse(decodeBase64Url(stamp)) as Record<string, string>;
    expect(Object.keys(envelope).sort()).toEqual(["publicKey", "scheme", "signature"]);
    expect(envelope.publicKey).toBe(identity.publicKeyHex);
    expect(envelope.scheme).toBe(SCHEME_P256);
    expect(envelope.signature).toMatch(/^[0-9a-f]+$/);
  });

  it("signature is DER ECDSA over SHA-256 of the exact body string (server-verify mirror)", () => {
    const identity = generateIdentity();
    const body = JSON.stringify({
      type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
      timestampMs: "1700000000000",
      organizationId: "org-1",
      parameters: { signWith: "pk-1", unsignedTransaction: "0x02...", type: "TRANSACTION_TYPE_ETHEREUM" },
    });
    const stamp = buildStamp(identity, body);

    // Mirror of tools/compat-harness/src/stamp.ts verifyStamp.
    const envelope = JSON.parse(decodeBase64Url(stamp)) as {
      publicKey: string;
      signature: string;
    };
    const digest = sha256(new TextEncoder().encode(body));
    const ok = p256.verify(hexToBytes(envelope.signature), digest, hexToBytes(envelope.publicKey));
    expect(ok).toBe(true);
  });

  it("verifyStamp accepts the exact body and rejects a tampered one", () => {
    const identity = generateIdentity();
    const body = '{"a":1}';
    const stamp = buildStamp(identity, body);
    expect(verifyStamp(stamp, body)).toBe(true);
    expect(verifyStamp(stamp, '{"a":2}')).toBe(false);
  });
});
