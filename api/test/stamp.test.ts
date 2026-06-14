import { describe, it, expect, beforeAll } from "vitest";
import { p256 } from "@noble/curves/p256";
import { ed25519 } from "@noble/curves/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
import { ApiKeyStamper } from "@turnkey/api-key-stamper";
import { decodeStamp, verifyStamp, SCHEME_P256, SCHEME_ED25519 } from "../src/stamp";

const P256_PRIV = "0101010101010101010101010101010101010101010101010101010101010101";
let p256Pub: string;
let stamper: ApiKeyStamper;

beforeAll(() => {
  p256Pub = bytesToHex(p256.getPublicKey(P256_PRIV, true));
  stamper = new ApiKeyStamper({ apiPublicKey: p256Pub, apiPrivateKey: P256_PRIV });
});

describe("X-Stamp verify", () => {
  const body = '{"type":"ACTIVITY_TYPE_SIGN_TRANSACTION_V2","timestampMs":"1780000000000"}';

  it("verifies a real P-256 ApiKeyStamper stamp; rejects tampering", async () => {
    const { stampHeaderValue } = await stamper.stamp(body);
    const stamp = decodeStamp(stampHeaderValue);
    expect(stamp.scheme).toBe(SCHEME_P256);
    expect(verifyStamp(stamp, body)).toBe(true);
    expect(verifyStamp(stamp, body + " ")).toBe(false);
  });

  it("verifies an Ed25519 stamp; rejects tampering", () => {
    const priv = new Uint8Array(32).fill(7);
    const pub = bytesToHex(ed25519.getPublicKey(priv));
    const sig = bytesToHex(ed25519.sign(new TextEncoder().encode(body), priv));
    const stamp = { publicKey: pub, scheme: SCHEME_ED25519, signature: sig };
    expect(verifyStamp(stamp, body)).toBe(true);
    expect(verifyStamp(stamp, body + " ")).toBe(false);
  });

  it("rejects unknown scheme and malformed envelope", () => {
    expect(verifyStamp({ publicKey: p256Pub, scheme: "NOPE", signature: "00" }, body)).toBe(false);
    const bad = Buffer.from(JSON.stringify({ publicKey: p256Pub }), "utf8").toString("base64url");
    expect(() => decodeStamp(bad)).toThrow();
  });
});
