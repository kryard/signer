/**
 * Unit tests for the policy engine (src/policy.ts).
 *
 * These tests use an in-process Postgres container (testcontainers) to provide
 * real DB semantics without mocking. Each test seeds its own org/actor/key/policy.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedApiKey } from "./helpers/seed";
import { evaluatePolicy } from "../src/policy";

let tdb: TestDb;

beforeAll(async () => {
  tdb = await startTestDb();
});

afterAll(async () => {
  await tdb.stop();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SIGN_TX_TYPE = "ACTIVITY_TYPE_SIGN_TRANSACTION_V2";
const SIGN_RAW_TYPE = "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2";
const SWEEP_SELECTOR = "0x7fea8778";
const CHAIN_1 = "1"; // Ethereum mainnet
const CHAIN_10 = "10"; // Optimism
const ROUTER_CHAIN1 = "0xRouter0000000000000000000000000000000001";
const ROUTER_CHAIN10 = "0xRouter0000000000000000000000000000000010";

async function seedOrg(nameSuffix: string) {
  const { organizationId, actorId } = await seedApiKey(
    tdb.db,
    `0xpubkey${Date.now()}${nameSuffix}`,
    "SIGNATURE_SCHEME_TK_API_P256",
  );
  return { organizationId, actorId };
}

async function seedKey(organizationId: string) {
  const { randomUUID } = await import("node:crypto");
  const privateKeyId = randomUUID();
  await tdb.db.insertInto("private_keys").values({
    id: privateKeyId,
    organization_id: organizationId,
    name: "test-key",
    curve: "CURVE_SECP256K1",
    public_key: "0x" + "ab".repeat(33),
    addresses: JSON.stringify(["0xTestAddr"]),
    encrypted_private_key: "enc",
    encrypted_data_key: "dek",
    kms_provider: "local",
    kms_key_id: "test",
    encryption_context: JSON.stringify({ private_key_id: privateKeyId, organization_id: organizationId, environment: "test", purpose: "wallet-signing" }),
  }).execute();
  return privateKeyId;
}

async function seedPolicyBinding(
  organizationId: string,
  actorId: string,
  privateKeyId: string,
  activityType: string,
) {
  const { randomUUID } = await import("node:crypto");
  await tdb.db.insertInto("policy_bindings").values({
    id: randomUUID(),
    organization_id: organizationId,
    actor_id: actorId,
    resource_type: "private_key",
    resource_id: privateKeyId,
    allowed_activity_type: activityType,
  }).execute();
}

async function seedRule(
  organizationId: string,
  privateKeyId: string,
  chainId: string,
  opts: {
    allowRawPayloadSigning?: boolean;
    maxNativeValueWei?: string;
    methodSelectorAllowlist?: string[];
  } = {},
) {
  const { randomUUID } = await import("node:crypto");
  await tdb.db.insertInto("wallet_policy_rules").values({
    id: randomUUID(),
    organization_id: organizationId,
    private_key_id: privateKeyId,
    chain_id: chainId,
    allow_raw_payload_signing: opts.allowRawPayloadSigning ?? false,
    max_native_value_wei: opts.maxNativeValueWei ?? "0",
    method_selector_allowlist: JSON.stringify(opts.methodSelectorAllowlist ?? [SWEEP_SELECTOR]),
  }).execute();
}

async function seedDestination(
  organizationId: string,
  privateKeyId: string,
  chainId: string,
  address: string,
) {
  const { randomUUID } = await import("node:crypto");
  await tdb.db.insertInto("wallet_destination_allowlist").values({
    id: randomUUID(),
    organization_id: organizationId,
    private_key_id: privateKeyId,
    chain_id: chainId,
    address,
  }).execute();
}

function makeTxFields(overrides: {
  chainId?: string;
  to?: string;
  value?: string;
  methodSelector?: string;
  gas?: number;
  nonce?: number;
} = {}) {
  return {
    chainId: overrides.chainId ?? `0x${CHAIN_1}`,
    to: overrides.to ?? ROUTER_CHAIN1,
    value: overrides.value ?? "0x0",
    nonce: overrides.nonce ?? 0,
    gas: overrides.gas ?? 21000,
    data: "0x7fea8778",
    methodSelector: overrides.methodSelector ?? SWEEP_SELECTOR,
    maxFeePerGas: "0x3b9aca00",
    maxPriorityFeePerGas: "0x3b9aca00",
    gasPrice: "",
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("policy engine — no policy configured", () => {
  it("returns DENY NO_POLICY_CONFIGURED when org has no policy_bindings (fail-closed default)", async () => {
    const { organizationId, actorId } = await seedOrg("nopolicy-closed");
    const privateKeyId = await seedKey(organizationId);

    // policyBypassAllowed defaults false → fail-closed
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields(),
    });

    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("NO_POLICY_CONFIGURED");
    expect(result.isPolicyBypassed).toBe(false);
  });

  it("returns ALLOW (bypass) when org has no policy_bindings and policyBypassAllowed=true", async () => {
    const { organizationId, actorId } = await seedOrg("nopolicy-open");
    const privateKeyId = await seedKey(organizationId);

    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields(),
      policyBypassAllowed: true,
    });

    expect(result.outcome).toBe("ALLOW");
    expect(result.isPolicyBypassed).toBe(true);
  });

  it("seeded org is not bypassed: isPolicyBypassed === false", async () => {
    const { organizationId, actorId } = await seedOrg("seeded-no-bypass");
    const privateKeyId = await seedKey(organizationId);
    // Seed a policy binding so the org has at least one binding.
    await seedPolicyBinding(organizationId, actorId, privateKeyId, SIGN_TX_TYPE);
    await seedRule(organizationId, privateKeyId, CHAIN_1, {
      methodSelectorAllowlist: [SWEEP_SELECTOR],
      maxNativeValueWei: "0",
    });
    await seedDestination(organizationId, privateKeyId, CHAIN_1, ROUTER_CHAIN1);

    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields(),
    });

    expect(result.outcome).toBe("ALLOW");
    expect(result.isPolicyBypassed).toBe(false);
  });
});

describe("policy engine — sign_transaction", () => {
  let organizationId: string;
  let actorId: string;
  let privateKeyId: string;

  beforeAll(async () => {
    ({ organizationId, actorId } = await seedOrg("signtx"));
    privateKeyId = await seedKey(organizationId);
    await seedPolicyBinding(organizationId, actorId, privateKeyId, SIGN_TX_TYPE);
    await seedRule(organizationId, privateKeyId, CHAIN_1, {
      methodSelectorAllowlist: [SWEEP_SELECTOR],
      maxNativeValueWei: "0",
    });
    await seedDestination(organizationId, privateKeyId, CHAIN_1, ROUTER_CHAIN1);
  });

  it("conforming tx → ALLOW", async () => {
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ chainId: "0x1", to: ROUTER_CHAIN1 }),
    });
    expect(result.outcome).toBe("ALLOW");
    expect(result.isPolicyBypassed).toBe(false);
    expect(result.evaluatedInputHash).toBeTruthy();
  });

  it("DENY — wrong actor (different actorId)", async () => {
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId: "00000000-0000-0000-0000-000000000000",
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields(),
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("ACTOR_NOT_BOUND");
  });

  it("DENY — deleted key (KEY_INACTIVE)", async () => {
    // Create a separate key and mark it deleted.
    const deletedKeyId = await seedKey(organizationId);
    await seedPolicyBinding(organizationId, actorId, deletedKeyId, SIGN_TX_TYPE);
    await tdb.db.updateTable("private_keys")
      .set({ deleted_at: new Date() })
      .where("id", "=", deletedKeyId)
      .execute();

    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId: deletedKeyId,
      txFields: makeTxFields(),
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("KEY_INACTIVE");
  });

  it("DENY — chain not in rules (CHAIN_NOT_ALLOWED)", async () => {
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ chainId: "0x999", to: ROUTER_CHAIN1 }),
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("CHAIN_NOT_ALLOWED");
  });

  it("DENY — value exceeds limit (VALUE_LIMIT)", async () => {
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ value: "0x1" }), // 1 wei > 0 max
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("VALUE_LIMIT");
  });

  it("DENY — wrong method selector (METHOD_NOT_ALLOWED)", async () => {
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ methodSelector: "0xdeadbeef" }),
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("METHOD_NOT_ALLOWED");
  });

  it("DENY — destination not allowed (DESTINATION_NOT_ALLOWED)", async () => {
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ to: "0xWrongAddress0000000000000000000000000" }),
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("DESTINATION_NOT_ALLOWED");
  });

  it("DENY — cross-chain router: router for chain-10 on chain-1 tx (DESTINATION_NOT_ALLOWED)", async () => {
    // Set up chain-10 rule + destination. Try to use chain-10 router on chain-1 tx.
    await seedRule(organizationId, privateKeyId, CHAIN_10, {
      methodSelectorAllowlist: [SWEEP_SELECTOR],
      maxNativeValueWei: "0",
    });
    await seedDestination(organizationId, privateKeyId, CHAIN_10, ROUTER_CHAIN10);

    // chain-1 tx with chain-10 router address → DENY (chain_id=1, to=ROUTER_CHAIN10
    // does not exist in allowlist for chain_id=1).
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ chainId: "0x1", to: ROUTER_CHAIN10 }),
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("DESTINATION_NOT_ALLOWED");
  });
});

describe("policy engine — sign_raw_payload", () => {
  let organizationId: string;
  let actorId: string;
  let privateKeyId: string;

  beforeAll(async () => {
    ({ organizationId, actorId } = await seedOrg("signraw"));
    privateKeyId = await seedKey(organizationId);
    await seedPolicyBinding(organizationId, actorId, privateKeyId, SIGN_RAW_TYPE);
  });

  it("DENY — allow_raw_payload_signing=false (RAW_PAYLOAD_DISABLED)", async () => {
    // No rule with allow_raw_payload_signing=true for this key.
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_RAW_TYPE,
      privateKeyId,
      rawPayload: "0xdeadbeef",
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("RAW_PAYLOAD_DISABLED");
  });

  it("ALLOW — allow_raw_payload_signing=true", async () => {
    // Seed a rule with allow_raw_payload_signing=true.
    await seedRule(organizationId, privateKeyId, CHAIN_1, {
      allowRawPayloadSigning: true,
      methodSelectorAllowlist: [],
    });
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_RAW_TYPE,
      privateKeyId,
      rawPayload: "0xdeadbeef",
    });
    expect(result.outcome).toBe("ALLOW");
    expect(result.isPolicyBypassed).toBe(false);
  });
});

describe("policy engine — empty selector rejection", () => {
  let organizationId: string;
  let actorId: string;
  let privateKeyId: string;

  beforeAll(async () => {
    ({ organizationId, actorId } = await seedOrg("emptyselector"));
    privateKeyId = await seedKey(organizationId);
    await seedPolicyBinding(organizationId, actorId, privateKeyId, SIGN_TX_TYPE);
    // Allowlist includes the empty string "" to test that even a misconfigured allowlist
    // can't open dataless txs.
    await seedRule(organizationId, privateKeyId, CHAIN_1, {
      methodSelectorAllowlist: ["", SWEEP_SELECTOR],
      maxNativeValueWei: "1000000000000000000", // 1 ETH max (so value is not the limiting factor)
    });
    await seedDestination(organizationId, privateKeyId, CHAIN_1, ROUTER_CHAIN1);
  });

  it("tx with empty data (no methodSelector) → DENY METHOD_NOT_ALLOWED", async () => {
    // methodSelector = "" means data < 4 bytes / native transfer.
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ methodSelector: "" }),
    });
    expect(result.outcome).toBe("DENY");
    expect(result.reasonCode).toBe("METHOD_NOT_ALLOWED");
  });

  it("tx with allowlisted selector still allowed when allowlist contains it", async () => {
    const result = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ methodSelector: SWEEP_SELECTOR }),
    });
    expect(result.outcome).toBe("ALLOW");
  });
});

describe("policy engine — evaluatedInputHash", () => {
  it("hash is deterministic and changes when input changes", async () => {
    const { organizationId, actorId } = await seedOrg("hash");
    const privateKeyId = await seedKey(organizationId);

    const txFields = makeTxFields();
    const r1 = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields,
    });
    const r2 = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields,
    });
    // Same input → same hash.
    expect(r1.evaluatedInputHash).toBe(r2.evaluatedInputHash);

    // Different txFields → different hash.
    const r3 = await evaluatePolicy(tdb.db, {
      organizationId,
      actorId,
      activityType: SIGN_TX_TYPE,
      privateKeyId,
      txFields: makeTxFields({ chainId: "0x2" }),
    });
    expect(r3.evaluatedInputHash).not.toBe(r1.evaluatedInputHash);
  });
});
