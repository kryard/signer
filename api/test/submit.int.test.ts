import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createApp } from "../src/app";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedStamper, stampedRequest } from "./helpers/stamp";
import type { ApiKeyStamper } from "@turnkey/api-key-stamper";

let tdb: TestDb;
let app: ReturnType<typeof createApp>;
let organizationId: string;
let stamper: ApiKeyStamper;

beforeAll(async () => {
  tdb = await startTestDb();
  app = createApp({ db: tdb.db, signerBaseUrl: "http://localhost:9999" });
  ({ organizationId, stamper } = await seedStamper(tdb.db));
});
afterAll(async () => {
  await tdb.stop();
});

async function submit(body: Record<string, unknown>) {
  const init = await stampedRequest(stamper, body);
  return app.request("/public/v1/submit/sign_transaction", init);
}

function makeBase() {
  return {
    type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { signWith: "0xabc", type: "TRANSACTION_TYPE_ETHEREUM", unsignedTransaction: "02ea" },
  };
}

describe("idempotent submit (P1: returns FAILED, no signer)", () => {
  it("creates a single-nested FAILED activity for an unimplemented type", async () => {
    const res = await submit(makeBase());
    expect(res.status).toBe(200);
    const body = (await res.json()) as { activity: Record<string, unknown> };
    expect(body.activity.type).toBe("ACTIVITY_TYPE_SIGN_TRANSACTION_V2");
    expect(body.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect((body.activity.result as Record<string, unknown>).activity).toBeUndefined();
    expect(body.activity.failure).not.toBeNull();
  });

  it("returns the SAME activity id for an identical body (idempotent)", async () => {
    const base = makeBase();
    const a = (await (await submit(base)).json()) as { activity: { id: string } };
    const b = (await (await submit(base)).json()) as { activity: { id: string } };
    expect(b.activity.id).toBe(a.activity.id);
  });

  it("creates a NEW activity when timestampMs changes", async () => {
    const base = makeBase();
    const a = (await (await submit(base)).json()) as { activity: { id: string } };
    const c = (await (await submit({ ...base, timestampMs: String(Date.now() + 1) })).json()) as {
      activity: { id: string };
    };
    expect(c.activity.id).not.toBe(a.activity.id);
  });

  it("returns a 400 Turnkey error envelope for an unrecognized activity type", async () => {
    // Real Turnkey rejects unknown types at the boundary (HTTP 400), NOT a 200 FAILED.
    const base = makeBase();
    const init = await stampedRequest(stamper, { ...base, type: "ACTIVITY_TYPE_NONSENSE" });
    const res = await app.request("/public/v1/submit/sign_transaction", init);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code: number; message: string; details: unknown[]; turnkeyErrorCode: string };
    expect(body.code).toBe(3);
    expect(body.message).toContain("Invalid activity type");
    expect(body).toHaveProperty("details");
    expect(body).toHaveProperty("turnkeyErrorCode");
  });
});
