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

function makeBase(extra: Record<string, unknown> = {}) {
  return {
    type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: {},
    ...extra,
  };
}

async function submit(body: Record<string, unknown>) {
  const init = await stampedRequest(stamper, body);
  return app.request("/public/v1/submit/sign_transaction", init);
}

async function query(path: string, body: Record<string, unknown>) {
  const init = await stampedRequest(stamper, body);
  return app.request(`/public/v1/query/${path}`, init);
}

describe("query endpoints", () => {
  it("whoami returns the organization id", async () => {
    const res = await query("whoami", { organizationId, timestampMs: String(Date.now()) });
    expect(res.status).toBe(200);
    expect((await res.json()) as Record<string, unknown>).toMatchObject({ organizationId });
  });

  it("get_activity returns the stored single-nested activity", async () => {
    const created = (await (await submit(makeBase())).json()) as { activity: { id: string } };
    const res = await query("get_activity", { organizationId, activityId: created.activity.id, timestampMs: String(Date.now()) });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { activity: { id: string } };
    expect(body.activity.id).toBe(created.activity.id);
  });

  it("get_activity 404s for an unknown id", async () => {
    const res = await query("get_activity", { organizationId, activityId: "00000000-0000-0000-0000-000000000000", timestampMs: String(Date.now()) });
    expect(res.status).toBe(404);
  });

  it("list_activities returns recent activities for the org", async () => {
    await submit(makeBase());
    const res = await query("list_activities", { organizationId, timestampMs: String(Date.now()) });
    const body = (await res.json()) as { activities: unknown[] };
    expect(Array.isArray(body.activities)).toBe(true);
    expect(body.activities.length).toBeGreaterThan(0);
  });
});
