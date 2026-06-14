import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { p256 } from "@noble/curves/p256";
import { bytesToHex } from "@noble/hashes/utils";
import { ApiKeyStamper } from "@turnkey/api-key-stamper";
import { createApp } from "../src/app";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedStamper, stampedRequest, P256_PRIV, P256_PUB } from "./helpers/stamp";

let tdb: TestDb;
let app: ReturnType<typeof createApp>;
let organizationId: string;
let actorId: string;
let stamper: ApiKeyStamper;

beforeAll(async () => {
  tdb = await startTestDb();
  app = createApp({ db: tdb.db, signerBaseUrl: "http://localhost:9999" });
  ({ organizationId, actorId, stamper } = await seedStamper(tdb.db));
});
afterAll(async () => {
  await tdb.stop();
});

function makeBody(extra: Record<string, unknown> = {}) {
  return {
    type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { signWith: "0xabc", type: "TRANSACTION_TYPE_ETHEREUM", unsignedTransaction: "02ea" },
    ...extra,
  };
}

describe("X-Stamp authentication", () => {
  it("valid stamp → 200 FAILED activity, actor_id set, audit row written", async () => {
    const body = makeBody();
    const init = await stampedRequest(stamper, body);
    const res = await app.request("/public/v1/submit/sign_transaction", init);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { activity: { id: string; status: string } };
    expect(json.activity.status).toBe("ACTIVITY_STATUS_FAILED");

    // Verify actor_id is persisted on the activity row.
    const row = await tdb.db
      .selectFrom("activities")
      .select(["actor_id", "auth_method"])
      .where("id", "=", json.activity.id)
      .executeTakeFirstOrThrow();
    expect(row.actor_id).toBe(actorId);
    expect(row.auth_method).toBe("SIGNATURE_SCHEME_TK_API_P256");

    // Verify api_key_used audit event was written.
    const auditRow = await tdb.db
      .selectFrom("audit_events")
      .selectAll()
      .where("organization_id", "=", organizationId)
      .where("event_type", "=", "api_key_used")
      .executeTakeFirst();
    expect(auditRow).not.toBeNull();
    expect(auditRow?.actor_id).toBe(actorId);
  });

  it("missing X-Stamp → 401", async () => {
    const body = makeBody();
    const res = await app.request("/public/v1/submit/sign_transaction", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(401);
    const json = (await res.json()) as { message: string };
    expect(json.message).toContain("missing X-Stamp");
  });

  it("tampered body (stamp over different bytes) → 401", async () => {
    const body = makeBody();
    // Stamp the original body, then submit a different body string.
    const bodyStr = JSON.stringify(body);
    const { stampHeaderValue } = await stamper.stamp(bodyStr);
    const tamperedBody = { ...body, type: "ACTIVITY_TYPE_CREATE_WALLET" };
    const res = await app.request("/public/v1/submit/sign_transaction", {
      method: "POST",
      headers: { "content-type": "application/json", "X-Stamp": stampHeaderValue },
      body: JSON.stringify(tamperedBody),
    });
    expect(res.status).toBe(401);
    const json = (await res.json()) as { message: string };
    expect(json.message).toContain("invalid stamp signature");
  });

  it("unknown public key (not seeded) → 401", async () => {
    const unknownPriv = "0202020202020202020202020202020202020202020202020202020202020202";
    const unknownPub = bytesToHex(p256.getPublicKey(unknownPriv, true));
    const unknownStamper = new ApiKeyStamper({ apiPublicKey: unknownPub, apiPrivateKey: unknownPriv });
    const body = makeBody();
    const init = await stampedRequest(unknownStamper, body);
    const res = await app.request("/public/v1/submit/sign_transaction", init);
    expect(res.status).toBe(401);
    const json = (await res.json()) as { message: string };
    expect(json.message).toContain("unknown or disabled API key");
  });

  it("org mismatch (body org ≠ key org) → 403", async () => {
    const body = makeBody({ organizationId: "00000000-0000-0000-0000-000000000000" });
    const init = await stampedRequest(stamper, body);
    const res = await app.request("/public/v1/submit/sign_transaction", init);
    expect(res.status).toBe(403);
    const json = (await res.json()) as { message: string };
    expect(json.message).toContain("not permitted for this organization");
  });

  it("stale timestampMs → 400 with 'activity timestamp is not current'", async () => {
    const staleTs = String(Date.now() - 120_000); // 2 minutes ago — beyond 60s window
    const body = makeBody({ timestampMs: staleTs });
    const init = await stampedRequest(stamper, body);
    const res = await app.request("/public/v1/submit/sign_transaction", init);
    expect(res.status).toBe(400);
    const json = (await res.json()) as { message: string };
    expect(json.message).toContain("activity timestamp is not current");
  });
});
