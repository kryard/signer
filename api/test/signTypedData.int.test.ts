/**
 * Integration test: signMessage (EIP-191) & signTypedData (EIP-712) parity — AC-B4.
 *
 * Turnkey's `signMessage` / `signTypedData` (e.g. via @turnkey/viem's createAccount)
 * reduce to ECDSA over a 32-byte digest:
 *   - personal_sign (EIP-191): digest = keccak256("\x19Ethereum Signed Message:\n"+len+msg)
 *   - signTypedData (EIP-712): digest = keccak256(0x19 0x01 || domainSeparator || hashStruct)
 * Both are submitted to Turnkey as a pre-hashed payload with HASH_FUNCTION_NO_OP.
 *
 * Kryard exposes the SAME path (sign_raw_payload, NO_OP). Because secp256k1 ECDSA
 * is deterministic (RFC-6979), the SAME key over the SAME digest yields the SAME
 * (r,s) — so Kryard's signature over a viem-computed EIP-191/EIP-712 digest is
 * byte-equivalent to Turnkey's.
 *
 * We prove it WITHOUT a live Turnkey by computing the digests with viem's own
 * `hashMessage` / `hashTypedData`, signing through Kryard, assembling the
 * signature with viem's `serializeSignature`, and confirming viem's
 * `verifyMessage` / `verifyTypedData` ACCEPT it against the key's address. A
 * signer that signed a different digest (or with the wrong key) would fail viem's
 * verification — the check binds the exact EIP-191/EIP-712 preimage.
 *
 * Requires Docker (Postgres) + Go toolchain (signer). Skips if Go is absent.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  hashMessage,
  hashTypedData,
  verifyMessage,
  verifyTypedData,
  serializeSignature,
  type Hex,
  type TypedDataDomain,
} from "viem";
import { createApp } from "../src/app";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedStamper, stampedRequest } from "./helpers/stamp";
import { startTestSigner, type TestSigner } from "./helpers/signer";
import type { ApiKeyStamper } from "@turnkey/api-key-stamper";

let tdb: TestDb;
let signer: TestSigner | null = null;
let app: ReturnType<typeof createApp>;
let organizationId: string;
let stamper: ApiKeyStamper;
let goAvailable = true;

beforeAll(async () => {
  tdb = await startTestDb();
  ({ organizationId, stamper } = await seedStamper(tdb.db));
  signer = await startTestSigner(false);
  if (!signer) {
    goAvailable = false;
    app = createApp({ db: tdb.db, signerBaseUrl: "http://127.0.0.1:1", allowRawPayloadSigning: true, policyBypassAllowed: true });
    return;
  }
  app = createApp({ db: tdb.db, signerBaseUrl: signer.baseUrl, allowRawPayloadSigning: true, policyBypassAllowed: true });
});

afterAll(async () => {
  signer?.stop();
  await tdb.stop();
});

async function createKey() {
  const body = {
    type: "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { name: `b4-key-${Date.now()}`, curve: "CURVE_SECP256K1", addressFormats: [] },
  };
  const init = await stampedRequest(stamper, body);
  const res = await app.request("/public/v1/submit/create_private_keys", init);
  expect(res.status).toBe(200);
  const json = (await res.json()) as {
    activity: { status: string; result: { createPrivateKeysResult: { privateKeyIds: string[]; addresses: { address: string }[] } } };
  };
  expect(json.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
  return {
    privateKeyId: json.activity.result.createPrivateKeysResult.privateKeyIds[0],
    address: json.activity.result.createPrivateKeysResult.addresses[0].address as `0x${string}`,
  };
}

/** Sign a 32-byte digest (0x-hex) through Kryard's raw-payload NO_OP path and
 *  return a viem-serialized 65-byte signature (r||s||v). */
async function signDigest(signWith: string, digest: Hex): Promise<Hex> {
  const body = {
    type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: {
      signWith,
      payload: digest,
      encoding: "PAYLOAD_ENCODING_HEXADECIMAL",
      hashFunction: "HASH_FUNCTION_NO_OP",
    },
  };
  const init = await stampedRequest(stamper, body);
  const res = await app.request("/public/v1/submit/sign_raw_payload", init);
  expect(res.status).toBe(200);
  const json = (await res.json()) as {
    activity: { status: string; result: { signRawPayloadResult: { r: string; s: string; v: string } } };
  };
  expect(json.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
  const { r, s, v } = json.activity.result.signRawPayloadResult;
  // Kryard returns v as "00"/"01" (yParity). viem wants r/s 0x-hex + yParity.
  return serializeSignature({
    r: `0x${r}` as Hex,
    s: `0x${s}` as Hex,
    yParity: v === "01" ? 1 : 0,
  });
}

describe("signMessage / signTypedData parity (B4)", () => {
  it("skip message when go is absent", () => {
    if (!goAvailable) console.warn("[signTypedData.int.test] Go toolchain absent — skipped.");
    expect(true).toBe(true);
  });

  it("signMessage (EIP-191): viem.verifyMessage accepts Kryard's signature", async () => {
    if (!goAvailable) return;
    const { privateKeyId, address } = await createKey();

    const message = "Kryard drop-in: sign this EIP-191 message";
    const digest = hashMessage(message); // EIP-191 personal_sign digest
    const signature = await signDigest(privateKeyId, digest);

    const ok = await verifyMessage({ address, message, signature });
    expect(ok).toBe(true);

    // Negative control: a different message must NOT verify against this signature.
    const bad = await verifyMessage({ address, message: message + "!", signature });
    expect(bad).toBe(false);
  });

  it("signTypedData (EIP-712): viem.verifyTypedData accepts Kryard's signature", async () => {
    if (!goAvailable) return;
    const { privateKeyId, address } = await createKey();

    const domain: TypedDataDomain = {
      name: "Kryard",
      version: "1",
      chainId: 11155111,
      verifyingContract: "0x0000000000000000000000000000000000000000",
    };
    const types = {
      Transfer: [
        { name: "to", type: "address" },
        { name: "amount", type: "uint256" },
      ],
    } as const;
    const primaryType = "Transfer" as const;
    const message = {
      to: "0x000000000000000000000000000000000000dEaD",
      amount: 1000000000000000000n,
    } as const;

    const digest = hashTypedData({ domain, types, primaryType, message });
    const signature = await signDigest(privateKeyId, digest);

    const ok = await verifyTypedData({ address, domain, types, primaryType, message, signature });
    expect(ok).toBe(true);

    // Negative control: tampering the typed-data value must NOT verify.
    const badMessage = { ...message, amount: 2000000000000000000n };
    const bad = await verifyTypedData({ address, domain, types, primaryType, message: badMessage, signature });
    expect(bad).toBe(false);
  });

  it("signMessage is deterministic (RFC-6979): identical digest → identical signature", async () => {
    if (!goAvailable) return;
    const { privateKeyId } = await createKey();
    const digest = hashMessage("determinism probe");
    const a = await signDigest(privateKeyId, digest);
    const b = await signDigest(privateKeyId, digest);
    // Deterministic ECDSA: same key + same digest ⇒ byte-identical signature.
    expect(a).toBe(b);
  });
});
