/**
 * Integration test: Track A console data plane (/admin/dev/* org-scoped endpoints).
 *
 * Requires Docker (Postgres container via testcontainers). No Go signer needed —
 * all rows are seeded directly into the database.
 *
 * Covers:
 *  - orgs list / org detail (+404)
 *  - wallets list NEVER leaks ciphertext / encryption context
 *  - activities list + detail (with policy decisions + audit events), cross-org 404
 *  - policies aggregate (bindings / rules / destinations)
 *  - destination add + delete; rule delete is org-scoped (wrong org → 404, no delete)
 *  - binding delete; api-key disable (+wrong-org 404)
 *  - missing X-Dev-Admin-Token → 401
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { createApp } from "../src/app";
import { startTestDb, type TestDb } from "./helpers/pg";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------
let tdb: TestDb;
let app: ReturnType<typeof createApp>;

const TOKEN = "tok";
const H = { "X-Dev-Admin-Token": TOKEN };
const JH = { ...H, "content-type": "application/json" };

const ENC_PRIVATE_KEY = "ciphertext-private-key-SECRET-AAAA";
const ENC_DATA_KEY = "ciphertext-data-key-SECRET-BBBB";
const ENC_CONTEXT_MARKER = "purpose-wallet-signing-marker";

let org1: string;
let org2: string;
let actor1: string;
let actor2: string;
let apiKey1: string;
let pk1: string; // private key in org1
let pk2: string; // private key in org2
let act1: string; // activity in org1
let act2: string; // activity in org2
let binding1: string;
let rule1: string; // rule in org1
let rule2: string; // rule in org2 (cross-org delete target)
let dest1: string;

async function seedPrivateKey(orgId: string, name: string): Promise<string> {
  const row = await tdb.db
    .insertInto("private_keys")
    .values({
      organization_id: orgId,
      name,
      curve: "CURVE_SECP256K1",
      public_key: "02" + "ab".repeat(32),
      addresses: JSON.stringify(["0x1111111111111111111111111111111111111111"]),
      encrypted_private_key: ENC_PRIVATE_KEY,
      encrypted_data_key: ENC_DATA_KEY,
      kms_provider: "local",
      kms_key_id: "kms-key-1",
      encryption_context: JSON.stringify({ purpose: ENC_CONTEXT_MARKER }),
    })
    .returning("id")
    .executeTakeFirstOrThrow();
  return row.id;
}

async function seedActivity(orgId: string, actorId: string, fingerprint: string): Promise<string> {
  const row = await tdb.db
    .insertInto("activities")
    .values({
      organization_id: orgId,
      type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
      status: "ACTIVITY_STATUS_COMPLETED",
      request_body: JSON.stringify({ type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2" }),
      canonical_hash: "hash-" + fingerprint,
      intent: JSON.stringify({ signTransactionIntent: { unsignedTransaction: "0x02" } }),
      result: JSON.stringify({ signTransactionResult: { signedTransaction: "0x02ff" } }),
      failure: null,
      fingerprint,
      timestamp_ms: String(Date.now()),
      actor_id: actorId,
      auth_method: "API_KEY",
      signer_receipt: JSON.stringify({ keyId: "k1", publicKey: "02aa" }),
    })
    .returning("id")
    .executeTakeFirstOrThrow();
  return row.id;
}

beforeAll(async () => {
  tdb = await startTestDb();
  app = createApp({
    db: tdb.db,
    signerBaseUrl: "http://127.0.0.1:1", // never called in this suite
    devAdminEnabled: true,
    devAdminToken: TOKEN,
  });

  // Two orgs, each with an actor.
  org1 = (await tdb.db.insertInto("organizations").values({ name: "org-one" }).returning("id").executeTakeFirstOrThrow()).id;
  org2 = (await tdb.db.insertInto("organizations").values({ name: "org-two" }).returning("id").executeTakeFirstOrThrow()).id;
  actor1 = (await tdb.db.insertInto("actors").values({ organization_id: org1, name: "actor-one" }).returning("id").executeTakeFirstOrThrow()).id;
  actor2 = (await tdb.db.insertInto("actors").values({ organization_id: org2, name: "actor-two" }).returning("id").executeTakeFirstOrThrow()).id;

  apiKey1 = (
    await tdb.db
      .insertInto("api_keys")
      .values({ organization_id: org1, actor_id: actor1, public_key: "03" + "cd".repeat(32), scheme: "SIGNATURE_SCHEME_TK_API_P256", name: "console-key" })
      .returning("id")
      .executeTakeFirstOrThrow()
  ).id;

  pk1 = await seedPrivateKey(org1, "wallet-one");
  pk2 = await seedPrivateKey(org2, "wallet-two");

  act1 = await seedActivity(org1, actor1, "fp-org1");
  act2 = await seedActivity(org2, actor2, "fp-org2");

  // Policy decision + audit event attached to act1.
  await tdb.db
    .insertInto("policy_decisions")
    .values({
      organization_id: org1,
      activity_id: act1,
      private_key_id: pk1,
      outcome: "ALLOW",
      reason_code: "ALLOW",
      evaluated_input_hash: "ee".repeat(32),
      policy_version: "v1",
    })
    .execute();

  await tdb.db
    .insertInto("audit_events")
    .values({
      organization_id: org1,
      actor_id: actor1,
      activity_id: act1,
      event_type: "activity_submitted",
      metadata: JSON.stringify({ activityType: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2" }),
    })
    .execute();

  // Policy rows: binding + rule + destination in org1; a rule in org2.
  binding1 = (
    await tdb.db
      .insertInto("policy_bindings")
      .values({
        organization_id: org1,
        actor_id: actor1,
        resource_type: "private_key",
        resource_id: pk1,
        allowed_activity_type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
      })
      .returning("id")
      .executeTakeFirstOrThrow()
  ).id;

  rule1 = (
    await tdb.db
      .insertInto("wallet_policy_rules")
      .values({
        organization_id: org1,
        private_key_id: pk1,
        chain_id: "1",
        allow_raw_payload_signing: false,
        max_native_value_wei: "0",
        method_selector_allowlist: JSON.stringify(["0x7fea8778"]),
      })
      .returning("id")
      .executeTakeFirstOrThrow()
  ).id;

  rule2 = (
    await tdb.db
      .insertInto("wallet_policy_rules")
      .values({
        organization_id: org2,
        private_key_id: pk2,
        chain_id: "10",
        allow_raw_payload_signing: false,
        max_native_value_wei: "0",
        method_selector_allowlist: JSON.stringify(["0x7fea8778"]),
      })
      .returning("id")
      .executeTakeFirstOrThrow()
  ).id;

  dest1 = (
    await tdb.db
      .insertInto("wallet_destination_allowlist")
      .values({
        organization_id: org1,
        private_key_id: pk1,
        chain_id: "1",
        address: "0x2222222222222222222222222222222222222222",
      })
      .returning("id")
      .executeTakeFirstOrThrow()
  ).id;
});

afterAll(async () => {
  await tdb.stop();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("admin console data plane", () => {
  // ── Auth gating ────────────────────────────────────────────────────────────
  it("missing X-Dev-Admin-Token → 401", async () => {
    const res = await app.request("/admin/dev/orgs");
    expect(res.status).toBe(401);
  });

  it("wrong X-Dev-Admin-Token → 401", async () => {
    const res = await app.request("/admin/dev/orgs", { headers: { "X-Dev-Admin-Token": "wrong" } });
    expect(res.status).toBe(401);
  });

  // ── Orgs ───────────────────────────────────────────────────────────────────
  it("GET /admin/dev/orgs lists organizations (id, name, createdAt)", async () => {
    const res = await app.request("/admin/dev/orgs", { headers: H });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { organizations: { id: string; name: string; createdAt: string }[] };
    const ids = json.organizations.map((o) => o.id);
    expect(ids).toContain(org1);
    expect(ids).toContain(org2);
    const one = json.organizations.find((o) => o.id === org1)!;
    expect(one.name).toBe("org-one");
    expect(typeof one.createdAt).toBe("string");
  });

  it("GET /admin/dev/orgs/:orgId returns org + actors + apiKeys", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}`, { headers: H });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      organization: { id: string; name: string };
      actors: { id: string; name: string }[];
      apiKeys: { id: string; actorId: string; publicKey: string; scheme: string; disabledAt: string | null }[];
    };
    expect(json.organization.id).toBe(org1);
    expect(json.actors).toHaveLength(1);
    expect(json.actors[0].id).toBe(actor1);
    expect(json.apiKeys).toHaveLength(1);
    expect(json.apiKeys[0].id).toBe(apiKey1);
    expect(json.apiKeys[0].actorId).toBe(actor1);
    expect(json.apiKeys[0].disabledAt).toBeNull();
  });

  it("GET /admin/dev/orgs/:orgId → 404 for unknown org", async () => {
    const res = await app.request(`/admin/dev/orgs/${randomUUID()}`, { headers: H });
    expect(res.status).toBe(404);
  });

  it("GET /admin/dev/orgs/:orgId → 400 for non-UUID orgId", async () => {
    const res = await app.request("/admin/dev/orgs/not-a-uuid", { headers: H });
    expect(res.status).toBe(400);
  });

  // ── Wallets ────────────────────────────────────────────────────────────────
  it("wallets list returns metadata and NEVER ciphertext / encryption context", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}/wallets`, { headers: H });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { wallets: Record<string, unknown>[] };
    expect(json.wallets).toHaveLength(1);
    const w = json.wallets[0];
    expect(w.id).toBe(pk1);
    expect(w.name).toBe("wallet-one");
    expect(w.curve).toBe("CURVE_SECP256K1");
    expect(typeof w.publicKey).toBe("string");
    expect(Array.isArray(w.addresses)).toBe(true);
    expect(w.deletedAt).toBeNull();

    // Hard ban: no ciphertext, DEK, encryption context, or kms fields anywhere.
    const raw = JSON.stringify(json);
    expect(raw).not.toContain(ENC_PRIVATE_KEY);
    expect(raw).not.toContain(ENC_DATA_KEY);
    expect(raw).not.toContain(ENC_CONTEXT_MARKER);
    expect(raw).not.toMatch(/encrypted/i);
    expect(raw).not.toMatch(/encryptionContext/i);
    expect(raw).not.toMatch(/kms/i);
  });

  it("wallets list is org-scoped (org2 does not see org1's wallet)", async () => {
    const res = await app.request(`/admin/dev/orgs/${org2}/wallets`, { headers: H });
    const json = (await res.json()) as { wallets: { id: string }[] };
    expect(json.wallets.map((w) => w.id)).toEqual([pk2]);
  });

  // ── Activities ─────────────────────────────────────────────────────────────
  it("activities list returns camelCase summaries, org-scoped", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}/activities?limit=50`, { headers: H });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { activities: Record<string, unknown>[] };
    expect(json.activities).toHaveLength(1);
    const a = json.activities[0];
    expect(a.id).toBe(act1);
    expect(a.type).toBe("ACTIVITY_TYPE_SIGN_TRANSACTION_V2");
    expect(a.status).toBe("ACTIVITY_STATUS_COMPLETED");
    expect(a.fingerprint).toBe("fp-org1");
    expect(a.actorId).toBe(actor1);
    expect(typeof a.timestampMs).toBe("string");
    expect(typeof a.createdAt).toBe("string");
  });

  it("activities list clamps an oversized limit instead of failing", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}/activities?limit=99999`, { headers: H });
    expect(res.status).toBe(200);
  });

  it("activities list rejects a non-integer limit with 400", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}/activities?limit=abc`, { headers: H });
    expect(res.status).toBe(400);
  });

  it("activity detail returns full row + policyDecisions + auditEvents", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}/activities/${act1}`, { headers: H });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      activity: Record<string, unknown>;
      policyDecisions: Record<string, unknown>[];
      auditEvents: Record<string, unknown>[];
    };
    expect(json.activity.id).toBe(act1);
    expect(json.activity.intent).toEqual({ signTransactionIntent: { unsignedTransaction: "0x02" } });
    expect(json.activity.result).toEqual({ signTransactionResult: { signedTransaction: "0x02ff" } });
    expect(json.activity.failure).toBeNull();
    expect(json.activity.signerReceipt).toEqual({ keyId: "k1", publicKey: "02aa" });

    expect(json.policyDecisions).toHaveLength(1);
    expect(json.policyDecisions[0].outcome).toBe("ALLOW");
    expect(json.policyDecisions[0].reasonCode).toBe("ALLOW");
    expect(json.policyDecisions[0].privateKeyId).toBe(pk1);

    expect(json.auditEvents).toHaveLength(1);
    expect(json.auditEvents[0].eventType).toBe("activity_submitted");
    expect(json.auditEvents[0].activityId).toBe(act1);
  });

  it("activity detail is org-scoped: org2's activity via org1 path → 404", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}/activities/${act2}`, { headers: H });
    expect(res.status).toBe(404);
  });

  it("activity detail → 404 for unknown activity", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}/activities/${randomUUID()}`, { headers: H });
    expect(res.status).toBe(404);
  });

  // ── Policies aggregate ─────────────────────────────────────────────────────
  it("policies aggregate returns org-scoped bindings, rules, destinations", async () => {
    const res = await app.request(`/admin/dev/orgs/${org1}/policies`, { headers: H });
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      bindings: Record<string, unknown>[];
      rules: Record<string, unknown>[];
      destinations: Record<string, unknown>[];
    };
    expect(json.bindings).toHaveLength(1);
    expect(json.bindings[0].id).toBe(binding1);
    expect(json.bindings[0].actorId).toBe(actor1);
    expect(json.bindings[0].resourceId).toBe(pk1);

    expect(json.rules).toHaveLength(1);
    expect(json.rules[0].id).toBe(rule1);
    expect(json.rules[0].privateKeyId).toBe(pk1);
    expect(json.rules[0].chainId).toBe("1");
    expect(json.rules[0].allowRawPayloadSigning).toBe(false);
    expect(json.rules[0].maxNativeValueWei).toBe("0");
    expect(json.rules[0].methodSelectorAllowlist).toEqual(["0x7fea8778"]);

    expect(json.destinations).toHaveLength(1);
    expect(json.destinations[0].id).toBe(dest1);
    expect(json.destinations[0].address).toBe("0x2222222222222222222222222222222222222222");
  });

  // ── Destination add + delete ───────────────────────────────────────────────
  it("destination add → { id }, then org-scoped delete → ok, repeat delete → 404", async () => {
    const addRes = await app.request("/admin/dev/policy/destination", {
      method: "POST",
      headers: JH,
      body: JSON.stringify({
        organizationId: org1,
        privateKeyId: pk1,
        chainId: "1",
        address: "0x3333333333333333333333333333333333333333",
      }),
    });
    expect(addRes.status).toBe(200);
    const { id } = (await addRes.json()) as { id: string };
    expect(typeof id).toBe("string");

    const delRes = await app.request(`/admin/dev/policy/destination/${id}?organizationId=${org1}`, {
      method: "DELETE",
      headers: H,
    });
    expect(delRes.status).toBe(200);
    expect(await delRes.json()).toEqual({ ok: true });

    const delAgain = await app.request(`/admin/dev/policy/destination/${id}?organizationId=${org1}`, {
      method: "DELETE",
      headers: H,
    });
    expect(delAgain.status).toBe(404);
  });

  it("destination add with another org's privateKeyId → 404 (cross-org guard)", async () => {
    const res = await app.request("/admin/dev/policy/destination", {
      method: "POST",
      headers: JH,
      body: JSON.stringify({
        organizationId: org1,
        privateKeyId: pk2, // belongs to org2
        chainId: "1",
        address: "0x4444444444444444444444444444444444444444",
      }),
    });
    expect(res.status).toBe(404);
  });

  it("destination add with missing fields → 400", async () => {
    const res = await app.request("/admin/dev/policy/destination", {
      method: "POST",
      headers: JH,
      body: JSON.stringify({ organizationId: org1 }),
    });
    expect(res.status).toBe(400);
  });

  // ── Rule delete: org scoping is enforced ───────────────────────────────────
  it("deleting org2's rule with org1's orgId → 404 and row survives", async () => {
    const res = await app.request(`/admin/dev/policy/rule/${rule2}?organizationId=${org1}`, {
      method: "DELETE",
      headers: H,
    });
    expect(res.status).toBe(404);

    const stillThere = await tdb.db
      .selectFrom("wallet_policy_rules")
      .select("id")
      .where("id", "=", rule2)
      .executeTakeFirst();
    expect(stillThere).toBeDefined();
  });

  it("deleting org2's rule with the CORRECT orgId → ok", async () => {
    const res = await app.request(`/admin/dev/policy/rule/${rule2}?organizationId=${org2}`, {
      method: "DELETE",
      headers: H,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    const gone = await tdb.db
      .selectFrom("wallet_policy_rules")
      .select("id")
      .where("id", "=", rule2)
      .executeTakeFirst();
    expect(gone).toBeUndefined();
  });

  it("rule delete without organizationId query param → 400", async () => {
    const res = await app.request(`/admin/dev/policy/rule/${rule1}`, { method: "DELETE", headers: H });
    expect(res.status).toBe(400);
  });

  // ── Binding delete ─────────────────────────────────────────────────────────
  it("binding delete is org-scoped and works with the right org", async () => {
    const wrongOrg = await app.request(`/admin/dev/policy/binding/${binding1}?organizationId=${org2}`, {
      method: "DELETE",
      headers: H,
    });
    expect(wrongOrg.status).toBe(404);

    const res = await app.request(`/admin/dev/policy/binding/${binding1}?organizationId=${org1}`, {
      method: "DELETE",
      headers: H,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  // ── API key disable ────────────────────────────────────────────────────────
  it("api-key disable with wrong org → 404, key stays enabled", async () => {
    const res = await app.request(`/admin/dev/api-key/${apiKey1}/disable`, {
      method: "POST",
      headers: JH,
      body: JSON.stringify({ organizationId: org2 }),
    });
    expect(res.status).toBe(404);

    const row = await tdb.db
      .selectFrom("api_keys")
      .select("disabled_at")
      .where("id", "=", apiKey1)
      .executeTakeFirstOrThrow();
    expect(row.disabled_at).toBeNull();
  });

  it("api-key disable with correct org → { ok: true } and disabled_at is set", async () => {
    const res = await app.request(`/admin/dev/api-key/${apiKey1}/disable`, {
      method: "POST",
      headers: JH,
      body: JSON.stringify({ organizationId: org1 }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    const row = await tdb.db
      .selectFrom("api_keys")
      .select("disabled_at")
      .where("id", "=", apiKey1)
      .executeTakeFirstOrThrow();
    expect(row.disabled_at).not.toBeNull();
  });
});
