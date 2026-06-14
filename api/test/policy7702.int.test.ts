/**
 * Integration test: EIP-7702 (type-4) delegation policy — Workstream A (AC: 7702 path).
 *
 * For a type-4 tx the `to` is the user's OWN delegated EOA, so policy does NOT
 * pin `to`; instead it requires every authorization delegate target to be in
 * wallet_delegate_allowlist for the (key, chain). This verifies:
 *   - a 7702 call whose authorization delegates to the allowlisted delegate
 *     impl, with an allowed selector + chain → ALLOW + signs (type-4 output).
 *   - a 7702 call delegating to an UNLISTED impl → DENY (DELEGATE_NOT_ALLOWED),
 *     signer not asked to sign.
 *   - a 7702 call on a chain with no rule → DENY (CHAIN_NOT_ALLOWED).
 *
 * Requires Docker (Postgres) + the Go signer (parses + signs type-4). Skips if Go
 * is absent.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import { serializeTransaction, getAddress, type Hex } from "viem";
import { createApp } from "../src/app";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedStamper, stampedRequest } from "./helpers/stamp";
import { startTestSigner, type TestSigner } from "./helpers/signer";
import type { ApiKeyStamper } from "@turnkey/api-key-stamper";

const SWEEP_SELECTOR = "0x7fea8778";
const CHAIN_ID = 1;
// The allowlisted delegate implementation (checksummed).
const DELEGATE_IMPL = getAddress("0x00000000000000000000000000000000deadbeef");
// A different, NOT-allowlisted delegate impl.
const EVIL_DELEGATE = getAddress("0x00000000000000000000000000000000baddcafe");

// A user EOA (the depositor) that signs the 7702 authorization client-side.
const USER_PRIV = ("0x" + "22".repeat(32)) as Hex;
const userAccount = privateKeyToAccount(USER_PRIV);

let tdb: TestDb;
let signer: TestSigner | null = null;
let app: ReturnType<typeof createApp>;
let organizationId: string;
let actorId: string;
let stamper: ApiKeyStamper;
let goAvailable = true;
let privateKeyId: string; // the relayer key (Kryard-custodied)

beforeAll(async () => {
  tdb = await startTestDb();
  ({ organizationId, actorId, stamper } = await seedStamper(tdb.db));

  signer = await startTestSigner(false);
  if (!signer) {
    goAvailable = false;
    app = createApp({ db: tdb.db, signerBaseUrl: "http://127.0.0.1:1" });
    return;
  }
  app = createApp({ db: tdb.db, signerBaseUrl: signer.baseUrl });

  // Relayer key, created inside the signer.
  const createBody = {
    type: "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { name: "relayer-7702", curve: "CURVE_SECP256K1", addressFormats: [] },
  };
  const init = await stampedRequest(stamper, createBody);
  const res = await app.request("/public/v1/submit/create_private_keys", init);
  const json = (await res.json()) as {
    activity: { result: { createPrivateKeysResult: { privateKeyIds: string[] } } };
  };
  privateKeyId = json.activity.result.createPrivateKeysResult.privateKeyIds[0];

  // Seed the 7702 call policy on chain 1: binding + rule (selector) + delegate allowlist.
  await tdb.db.insertInto("policy_bindings").values({
    id: randomUUID(),
    organization_id: organizationId,
    actor_id: actorId,
    resource_type: "private_key",
    resource_id: privateKeyId,
    allowed_activity_type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
  }).execute();

  await tdb.db.insertInto("wallet_policy_rules").values({
    id: randomUUID(),
    organization_id: organizationId,
    private_key_id: privateKeyId,
    chain_id: String(CHAIN_ID),
    allow_raw_payload_signing: false,
    max_native_value_wei: "0",
    method_selector_allowlist: JSON.stringify([SWEEP_SELECTOR]),
  }).execute();

  await tdb.db.insertInto("wallet_delegate_allowlist").values({
    id: randomUUID(),
    organization_id: organizationId,
    private_key_id: privateKeyId,
    chain_id: String(CHAIN_ID),
    delegate_address: DELEGATE_IMPL,
  }).execute();
});

afterAll(async () => {
  signer?.stop();
  await tdb.stop();
});

/** Build an UNSIGNED type-4 tx: the user delegates their EOA to `delegate`, and
 *  the relayer's tx calls `to` (defaults to the user's own EOA) with example
 *  calldata. `to` is overridable to exercise the `to ∈ authorities` guard. */
async function buildUnsignedSetCodeTx(
  delegate: Hex,
  chainId: number,
  to: Hex = userAccount.address,
): Promise<string> {
  const auth = await userAccount.signAuthorization({ contractAddress: delegate, chainId, nonce: 0 });
  return serializeTransaction({
    type: "eip7702",
    chainId,
    nonce: 0,
    maxPriorityFeePerGas: 1_000_000_000n,
    maxFeePerGas: 1_000_000_000n,
    gas: 200_000n,
    to,
    value: 0n,
    data: SWEEP_SELECTOR,
    authorizationList: [auth],
  });
}

async function submitSetCodeTx(unsignedTransaction: string) {
  const body = {
    type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { signWith: privateKeyId, unsignedTransaction, type: "TRANSACTION_TYPE_ETHEREUM" },
  };
  const init = await stampedRequest(stamper, body);
  const res = await app.request("/public/v1/submit/sign_transaction", init);
  return (await res.json()) as {
    activity: {
      status: string;
      result: { signTransactionResult?: { signedTransaction: string } };
      failure: { code: string } | null;
    };
  };
}

describe("EIP-7702 call policy (Workstream A)", () => {
  it("skip when go is absent", () => {
    if (!goAvailable) console.warn("[policy7702.int] Go toolchain absent — skipped.");
    expect(true).toBe(true);
  });

  it("allowed delegate + selector + chain → ALLOW + signs a type-4 tx", async () => {
    if (!goAvailable) return;
    const unsigned = await buildUnsignedSetCodeTx(DELEGATE_IMPL, CHAIN_ID);
    const json = await submitSetCodeTx(unsigned);

    expect(json.activity.status).toBe("ACTIVITY_STATUS_COMPLETED");
    expect(json.activity.failure).toBeNull();
    const signed = json.activity.result.signTransactionResult?.signedTransaction;
    // Turnkey wire format: hex WITHOUT 0x; type-4 → starts with the 0x04 type byte.
    expect(signed).toBeDefined();
    expect(signed).not.toMatch(/^0x/);
    expect(signed).toMatch(/^04/);
  });

  it("delegate NOT in allowlist → DENY (DELEGATE_NOT_ALLOWED)", async () => {
    if (!goAvailable) return;
    const unsigned = await buildUnsignedSetCodeTx(EVIL_DELEGATE, CHAIN_ID);
    const json = await submitSetCodeTx(unsigned);

    expect(json.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect(json.activity.failure?.code).toBe("DELEGATE_NOT_ALLOWED");
  });

  it("`to` is NOT an authorizing EOA → DENY (DESTINATION_NOT_ALLOWED)", async () => {
    if (!goAvailable) return;
    // Valid, allowlisted-delegate authorization from the user, but the tx is
    // pointed at a DIFFERENT address the user never authorized. The delegate
    // check passes; the `to ∈ authorities` guard must still deny.
    const otherTarget = getAddress("0x000000000000000000000000000000000000c0de");
    const unsigned = await buildUnsignedSetCodeTx(DELEGATE_IMPL, CHAIN_ID, otherTarget);
    const json = await submitSetCodeTx(unsigned);

    expect(json.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect(json.activity.failure?.code).toBe("DESTINATION_NOT_ALLOWED");
  });

  it("chain with no rule → DENY (CHAIN_NOT_ALLOWED)", async () => {
    if (!goAvailable) return;
    // chain 999 has no wallet_policy_rules row, even though the delegate is the
    // allowlisted impl — fail-closed on the unknown chain.
    const unsigned = await buildUnsignedSetCodeTx(DELEGATE_IMPL, 999);
    const json = await submitSetCodeTx(unsigned);

    expect(json.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect(json.activity.failure?.code).toBe("CHAIN_NOT_ALLOWED");
  });
});
