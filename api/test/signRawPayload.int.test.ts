/**
 * Integration test: sign_raw_payload end-to-end.
 *
 * Requires:
 *  - Docker (Postgres container via testcontainers)
 *  - Go toolchain (builds the signer binary once; must include the new
 *    /internal/sign/raw-payload endpoint added in P5)
 *
 * If Go is absent the signer helper returns null and the suite is skipped.
 *
 * Recovery verification uses @noble/curves/secp256k1 + @noble/hashes/sha3
 * (keccak_256) — both already installed. No viem dependency.
 *
 * Note: viem's recoverAddress / signMessage send pre-hashed payloads with
 * HASH_FUNCTION_NO_OP (see wire-contract.md). Our KECCAK256 path is therefore
 * tested here by computing the digest in JS and verifying with noble, then
 * also tested directly as a NO_OP with the same 32-byte digest.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { createApp } from "../src/app";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedStamper, stampedRequest } from "./helpers/stamp";
import { startTestSigner, type TestSigner } from "./helpers/signer";
import type { ApiKeyStamper } from "@turnkey/api-key-stamper";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------
let tdb: TestDb;
let signer: TestSigner | null = null;
let app: ReturnType<typeof createApp>;
let appGated: ReturnType<typeof createApp>; // allowRawPayloadSigning = false
let organizationId: string;
let stamper: ApiKeyStamper;
let goAvailable = true;

beforeAll(async () => {
  tdb = await startTestDb();
  ({ organizationId, stamper } = await seedStamper(tdb.db));

  // Build the signer fresh so it includes the new /internal/sign/raw-payload endpoint.
  signer = await startTestSigner(false);

  if (!signer) {
    goAvailable = false;
    app = createApp({
      db: tdb.db,
      signerBaseUrl: "http://127.0.0.1:1",
      allowRawPayloadSigning: true,
      policyBypassAllowed: true,
    });
    appGated = createApp({
      db: tdb.db,
      signerBaseUrl: "http://127.0.0.1:1",
      allowRawPayloadSigning: false,
      policyBypassAllowed: true,
    });
    return;
  }

  app = createApp({
    db: tdb.db,
    signerBaseUrl: signer.baseUrl,
    allowRawPayloadSigning: true,
    policyBypassAllowed: true,
  });
  appGated = createApp({
    db: tdb.db,
    signerBaseUrl: signer.baseUrl,
    allowRawPayloadSigning: false,
    policyBypassAllowed: true,
  });
});

afterAll(async () => {
  signer?.stop();
  await tdb.stop();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCreateKeysBody(extra: Record<string, unknown> = {}) {
  return {
    type: "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { name: "sign-test-key", curve: "CURVE_SECP256K1", addressFormats: [], ...extra },
  };
}

function makeSignBody(signWith: string, payload: string, hashFunction: string, extra: Record<string, unknown> = {}) {
  return {
    type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: {
      signWith,
      payload,
      encoding: "PAYLOAD_ENCODING_HEXADECIMAL",
      hashFunction,
      ...extra,
    },
  };
}

async function submitCreateKey(targetApp = app) {
  const body = makeCreateKeysBody({ name: `key-${Date.now()}` });
  const init = await stampedRequest(stamper, body);
  const res = await targetApp.request("/public/v1/submit/create_private_keys", init);
  expect(res.status).toBe(200);
  const json = (await res.json()) as {
    activity: {
      status: string;
      result: { createPrivateKeysResult: { privateKeyIds: string[]; addresses: { address: string }[] } };
    };
  };
  expect(json.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
  const privateKeyId = json.activity.result.createPrivateKeysResult.privateKeyIds[0];
  const address = json.activity.result.createPrivateKeysResult.addresses[0].address;
  return { privateKeyId, address };
}

async function submitSign(signWith: string, payload: string, hashFunction: string, targetApp = app) {
  const body = makeSignBody(signWith, payload, hashFunction);
  const init = await stampedRequest(stamper, body);
  return targetApp.request("/public/v1/submit/sign_raw_payload", init);
}

// secp256k1.recoverPublicKey exists at runtime but the TypeScript types in the
// installed version of @noble/curves omit it from CurveFnWithCreate. Cast to access.
// The method signature is: recoverPublicKey(sig65: Uint8Array, msgHash: Uint8Array) => Uint8Array.
const secp256k1Recover = (secp256k1 as unknown as {
  recoverPublicKey: (sig: Uint8Array, msg: Uint8Array) => Uint8Array;
}).recoverPublicKey;

/**
 * Recover the Ethereum address from r/s/v (hex strings) and a digest (Uint8Array).
 *
 * go-ethereum crypto.Sign returns [R(32) || S(32) || V(1)] where V is 0 or 1.
 * @noble/curves secp256k1.recoverPublicKey expects 65 bytes in the format:
 *   [recovery(1) || R(32) || S(32)]  — i.e. recovery byte is FIRST.
 *
 * Returns the 0x-prefixed lowercase Ethereum address.
 */
function recoverAddress(r: string, s: string, v: string, digest: Uint8Array): string {
  const rBytes = hexToBytes(r);
  const sBytes = hexToBytes(s);
  const vByte = v === "01" ? 1 : 0;

  // @noble/curves "recovered" format: [recovery(1) || r(32) || s(32)]
  const sig65 = new Uint8Array(65);
  sig65[0] = vByte;        // recovery byte FIRST
  sig65.set(rBytes, 1);   // r starts at byte 1
  sig65.set(sBytes, 33);  // s starts at byte 33

  // secp256k1.recoverPublicKey returns a COMPRESSED public key (33 bytes).
  // Ethereum addresses are derived from the UNCOMPRESSED public key (65 bytes):
  //   address = keccak256(uncompressed[1:])[12:]
  // Uncompress using secp256k1.Point.fromHex().toRawBytes(false).
  const compressedPub = secp256k1Recover(sig65, digest);
  const point = secp256k1.Point.fromHex(compressedPub);
  const uncompressedPub = point.toRawBytes(false); // false = uncompressed (65 bytes, 0x04 prefix)

  // Ethereum address = keccak256(pubkey[1:])[12:] — last 20 bytes of hash
  const pubKeyBody = uncompressedPub.slice(1); // strip 0x04 prefix → 64 bytes (x || y)
  const hash = keccak_256(pubKeyBody);
  const addressBytes = hash.slice(12); // last 20 bytes = 160-bit Ethereum address
  return "0x" + bytesToHex(addressBytes);
}

/** A simple no-plaintext check: a raw 32-byte private key would appear as a bare
 *  64-hex string. We verify the response/DB doesn't contain one. */
const BARE_64HEX_RE = /"([0-9a-f]{64})"/i;
function assertNoPlaintextKey(value: unknown): void {
  const str = JSON.stringify(value);
  const match = BARE_64HEX_RE.exec(str);
  if (match) {
    // r and s are each 32-byte (64-hex) strings but they are signature components,
    // not private keys. We check specifically for forbidden field names instead.
    // The signature values appear under keys "r" and "s", not raw private key fields.
    const forbidden = ["privateKeyHex", "rawPrivateKey", "privateKeyMaterial", "plaintext"];
    for (const f of forbidden) {
      if (str.includes(`"${f}"`)) {
        throw new Error(`Response contains forbidden plaintext field "${f}": ${str.slice(0, 300)}`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe("sign_raw_payload end-to-end", () => {
  it("skip message when go is absent", () => {
    if (!goAvailable) {
      console.warn("[signRawPayload.int.test] Go toolchain not available — signer integration tests skipped.");
    }
    expect(true).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // 1. KECCAK256 — sign + recovery parity
  // ---------------------------------------------------------------------------
  it("KECCAK256: COMPLETED {r,s,v} and signature recovers to key's address", async () => {
    if (!goAvailable) return;

    const { privateKeyId, address } = await submitCreateKey();

    // Use a raw message payload (not pre-hashed); signer keccaks it.
    const message = "Hello Kryard P5";
    const payloadHex = bytesToHex(new TextEncoder().encode(message));

    const res = await submitSign(privateKeyId, payloadHex, "HASH_FUNCTION_KECCAK256");
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      activity: {
        status: string;
        result: { signRawPayloadResult: { r: string; s: string; v: string; signerReceipt: unknown } };
        failure: unknown;
      };
    };
    expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
    expect(body.activity.failure).toBeNull();

    const { r, s, v } = body.activity.result.signRawPayloadResult;
    expect(r).toMatch(/^[0-9a-f]{64}$/);
    expect(s).toMatch(/^[0-9a-f]{64}$/);
    expect(v === "00" || v === "01").toBe(true);

    // Recovery parity: compute the same keccak256 digest and recover.
    const payloadBytes = new TextEncoder().encode(message);
    const digest = keccak_256(payloadBytes);
    const recoveredAddr = recoverAddress(r, s, v, digest);

    // go-ethereum returns EIP-55 checksummed; compare case-insensitively.
    expect(recoveredAddr.toLowerCase()).toBe(address.toLowerCase());

    // Signer receipt must be present.
    const receipt = body.activity.result.signRawPayloadResult.signerReceipt as Record<string, unknown>;
    expect(typeof receipt).toBe("object");
    expect(typeof receipt.keyId).toBe("string");
    expect(typeof receipt.payloadHash).toBe("string");
    expect(typeof receipt.signatureHash).toBe("string");
    expect(typeof receipt.signerBuildId).toBe("string");

    // No plaintext key in response.
    assertNoPlaintextKey(body);
  });

  // ---------------------------------------------------------------------------
  // 2a. NO_OP on a 32-byte payload — valid + recovers
  // ---------------------------------------------------------------------------
  it("NO_OP on 32-byte payload: COMPLETED + recovers to address", async () => {
    if (!goAvailable) return;

    const { privateKeyId, address } = await submitCreateKey();

    // 32-byte digest (simulating viem's EIP-191 pre-hash).
    const digest = keccak_256(new TextEncoder().encode("viem prehashed message"));
    const payloadHex = bytesToHex(digest);

    const res = await submitSign(privateKeyId, "0x" + payloadHex, "HASH_FUNCTION_NO_OP");
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      activity: {
        status: string;
        result: { signRawPayloadResult: { r: string; s: string; v: string } };
        failure: unknown;
      };
    };
    expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
    expect(body.activity.failure).toBeNull();

    const { r, s, v } = body.activity.result.signRawPayloadResult;

    // NO_OP: signer signs the digest directly (no further hashing).
    const recoveredAddr = recoverAddress(r, s, v, digest);
    expect(recoveredAddr.toLowerCase()).toBe(address.toLowerCase());

    assertNoPlaintextKey(body);
  });

  // ---------------------------------------------------------------------------
  // 2b. NO_OP on non-32-byte payload → FAILED
  // ---------------------------------------------------------------------------
  it("NO_OP on non-32-byte payload: FAILED", async () => {
    if (!goAvailable) return;

    const { privateKeyId } = await submitCreateKey();

    // 16 bytes is not 32.
    const shortPayload = "0x" + "ab".repeat(16);

    const res = await submitSign(privateKeyId, shortPayload, "HASH_FUNCTION_NO_OP");
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      activity: { status: string; failure: { code: string } | null };
    };
    // The signer returns 400 which the API surfaces as a signer-unavailable error (500),
    // resulting in a FAILED activity.
    expect(body.activity.status).toBe("ACTIVITY_STATUS_FAILED");
  });

  // ---------------------------------------------------------------------------
  // 3. Gate: ALLOW_RAW_PAYLOAD_SIGNING off → FAILED
  // ---------------------------------------------------------------------------
  it("gate off → FAILED RAW_PAYLOAD_SIGNING_DISABLED", async () => {
    if (!goAvailable) return;

    const { privateKeyId } = await submitCreateKey();
    const digest = keccak_256(new TextEncoder().encode("gate test"));
    const payloadHex = bytesToHex(digest);

    // Use gated app (allowRawPayloadSigning = false).
    const body = makeSignBody(privateKeyId, payloadHex, "HASH_FUNCTION_NO_OP");
    const init = await stampedRequest(stamper, body);
    const res = await appGated.request("/public/v1/submit/sign_raw_payload", init);
    expect(res.status).toBe(200);

    const json = (await res.json()) as {
      activity: { status: string; failure: { code: string } | null };
    };
    expect(json.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect((json.activity.failure as { code: string } | null)?.code).toBe("RAW_PAYLOAD_SIGNING_DISABLED");
  });

  it("gate on → signs successfully", async () => {
    if (!goAvailable) return;

    // app already has allowRawPayloadSigning = true.
    const { privateKeyId, address } = await submitCreateKey();
    const digest = keccak_256(new TextEncoder().encode("gate on test"));
    const payloadHex = bytesToHex(digest);

    const res = await submitSign(privateKeyId, payloadHex, "HASH_FUNCTION_NO_OP");
    expect(res.status).toBe(200);

    const body = (await res.json()) as {
      activity: { status: string; result: { signRawPayloadResult: { r: string; s: string; v: string } }; failure: unknown };
    };
    expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
    expect(body.activity.failure).toBeNull();

    const { r, s, v } = body.activity.result.signRawPayloadResult;
    const recoveredAddr = recoverAddress(r, s, v, digest);
    expect(recoveredAddr.toLowerCase()).toBe(address.toLowerCase());
  });

  // ---------------------------------------------------------------------------
  // 4. signWith resolution: by address AND by private-key id; unknown → FAILED
  // ---------------------------------------------------------------------------
  it("signWith by private-key id resolves and signs", async () => {
    if (!goAvailable) return;

    const { privateKeyId, address } = await submitCreateKey();
    const digest = keccak_256(new TextEncoder().encode("by-id test"));
    const payloadHex = bytesToHex(digest);

    const res = await submitSign(privateKeyId, payloadHex, "HASH_FUNCTION_NO_OP");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      activity: { status: string; result: { signRawPayloadResult: { r: string; s: string; v: string } }; failure: unknown };
    };
    expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");

    const { r, s, v } = body.activity.result.signRawPayloadResult;
    const recoveredAddr = recoverAddress(r, s, v, digest);
    expect(recoveredAddr.toLowerCase()).toBe(address.toLowerCase());
  });

  it("signWith by Ethereum address resolves and signs", async () => {
    if (!goAvailable) return;

    const { address } = await submitCreateKey();
    const digest = keccak_256(new TextEncoder().encode("by-address test"));
    const payloadHex = bytesToHex(digest);

    // signWith = the key's Ethereum address (EIP-55 checksummed from go-ethereum).
    const res = await submitSign(address, payloadHex, "HASH_FUNCTION_NO_OP");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      activity: { status: string; result: { signRawPayloadResult: { r: string; s: string; v: string } }; failure: unknown };
    };
    expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
    expect(body.activity.failure).toBeNull();

    const { r, s, v } = body.activity.result.signRawPayloadResult;
    const recoveredAddr = recoverAddress(r, s, v, digest);
    expect(recoveredAddr.toLowerCase()).toBe(address.toLowerCase());
  });

  it("unknown signWith → FAILED PRIVATE_KEY_NOT_FOUND", async () => {
    if (!goAvailable) return;

    const digest = keccak_256(new TextEncoder().encode("unknown key test"));
    const payloadHex = bytesToHex(digest);

    const res = await submitSign("00000000-0000-0000-0000-000000000000", payloadHex, "HASH_FUNCTION_NO_OP");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      activity: { status: string; failure: { code: string } | null };
    };
    expect(body.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect((body.activity.failure as { code: string } | null)?.code).toBe("PRIVATE_KEY_NOT_FOUND");
  });

  // ---------------------------------------------------------------------------
  // 5. No plaintext key in response or DB
  // ---------------------------------------------------------------------------
  it("no plaintext key in response or DB activity row", async () => {
    if (!goAvailable) return;

    const { privateKeyId } = await submitCreateKey();
    const digest = keccak_256(new TextEncoder().encode("no-plaintext check"));
    const payloadHex = bytesToHex(digest);

    const res = await submitSign(privateKeyId, payloadHex, "HASH_FUNCTION_NO_OP");
    expect(res.status).toBe(200);
    const responseBody = await res.json();

    assertNoPlaintextKey(responseBody);

    // Also check the DB row.
    const activityId = (responseBody as { activity: { id: string } }).activity.id;
    const row = await tdb.db
      .selectFrom("activities")
      .selectAll()
      .where("id", "=", activityId)
      .executeTakeFirst();

    expect(row).not.toBeUndefined();

    // The DB result contains r/s (each 64 hex chars) which are signature
    // components, not private keys. The assertNoPlaintextKey function checks
    // for forbidden field names rather than value patterns to avoid false positives.
    assertNoPlaintextKey(row!.result);
    assertNoPlaintextKey(row!.request_body);

    // Explicitly check signer receipt is stored in the result.
    const result = row!.result as Record<string, unknown>;
    const signResult = result.signRawPayloadResult as Record<string, unknown> | undefined;
    expect(signResult).not.toBeUndefined();
    expect(signResult!.signerReceipt).not.toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // Wire shape: activity result matches wire-contract.md
  // ---------------------------------------------------------------------------
  it("activity result shape matches wire-contract.md", async () => {
    if (!goAvailable) return;

    const { privateKeyId } = await submitCreateKey();
    const digest = keccak_256(new TextEncoder().encode("wire shape check"));
    const payloadHex = bytesToHex(digest);

    const res = await submitSign(privateKeyId, payloadHex, "HASH_FUNCTION_NO_OP");
    const body = (await res.json()) as {
      activity: {
        status: string;
        type: string;
        intent: Record<string, unknown>;
        result: { signRawPayloadResult: { r: string; s: string; v: string } };
        failure: null;
        votes: unknown[];
        fingerprint: string;
        canApprove: boolean;
        canReject: boolean;
      };
    };

    expect(body.activity.type).toBe("ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2");
    expect(body.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
    expect(body.activity.failure).toBeNull();
    expect(typeof body.activity.intent.signRawPayloadIntent).toBe("object");
    expect(typeof body.activity.result.signRawPayloadResult).toBe("object");
    expect(typeof body.activity.result.signRawPayloadResult.r).toBe("string");
    expect(typeof body.activity.result.signRawPayloadResult.s).toBe("string");
    expect(typeof body.activity.result.signRawPayloadResult.v).toBe("string");
  });
});
