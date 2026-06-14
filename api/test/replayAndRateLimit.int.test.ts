/**
 * Integration tests: pre-cutover hardening (migration 006).
 *
 *  - Stamp replay: re-presenting the SAME X-Stamp header is 401'd for queries
 *    and for not-yet-recorded submissions; a byte-identical replay of an
 *    already-recorded submit stays allowed (idempotency contract).
 *  - Rate limiting: submits beyond the per-org fixed-window limit are 429'd
 *    before any signing work; other orgs are unaffected.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { ApiKeyStamper } from "@turnkey/api-key-stamper";
import { createApp } from "../src/app";
import { startTestDb, type TestDb } from "./helpers/pg";
import { seedStamper, stampedRequest } from "./helpers/stamp";

let tdb: TestDb;
let organizationId: string;
let stamper: ApiKeyStamper;

beforeAll(async () => {
  tdb = await startTestDb();
  ({ organizationId, stamper } = await seedStamper(tdb.db));
});
afterAll(async () => {
  await tdb.stop();
});

function makeApp(opts: { replayProtection?: boolean; submitRateLimitPerMinute?: number } = {}) {
  return createApp({
    db: tdb.db,
    signerBaseUrl: "http://localhost:9999",
    replayProtection: opts.replayProtection ?? true,
    submitRateLimitPerMinute: opts.submitRateLimitPerMinute ?? 0, // default off here; replay tests don't want 429s
  });
}

function submitBody(extra: Record<string, unknown> = {}) {
  return {
    type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
    organizationId,
    timestampMs: String(Date.now()),
    parameters: { signWith: "0xabc", type: "TRANSACTION_TYPE_ETHEREUM", unsignedTransaction: "02ea" },
    ...extra,
  };
}

describe("stamp replay protection", () => {
  it("replaying the same stamp on a QUERY → 401", async () => {
    const app = makeApp();
    const body = { organizationId, timestampMs: String(Date.now()) };
    const init = await stampedRequest(stamper, body);

    const first = await app.request("/public/v1/query/whoami", init);
    expect(first.status).toBe(200);

    // Byte-identical replay: same header, same body string.
    const replay = await app.request("/public/v1/query/whoami", init);
    expect(replay.status).toBe(401);
    const json = (await replay.json()) as { message: string };
    expect(json.message).toContain("replay");
  });

  it("byte-identical replay of a RECORDED submit stays allowed (idempotency contract)", async () => {
    const app = makeApp();
    const body = submitBody();
    const init = await stampedRequest(stamper, body);

    const first = await app.request("/public/v1/submit/sign_transaction", init);
    expect(first.status).toBe(200);
    const a = (await first.json()) as { activity: { id: string } };

    // Same stamp + same body again: the submit is recorded in idempotency_keys,
    // so the replay is the benign idempotent retry and returns the SAME activity.
    const second = await app.request("/public/v1/submit/sign_transaction", init);
    expect(second.status).toBe(200);
    const b = (await second.json()) as { activity: { id: string } };
    expect(b.activity.id).toBe(a.activity.id);
  });

  it("fresh stamps over distinct bodies are unaffected", async () => {
    const app = makeApp();
    for (let i = 0; i < 3; i++) {
      const init = await stampedRequest(stamper, {
        organizationId,
        timestampMs: String(Date.now() + i),
      });
      const res = await app.request("/public/v1/query/whoami", init);
      expect(res.status).toBe(200);
    }
  });

  it("replayProtection: false disables the check (dev/test escape hatch)", async () => {
    const app = makeApp({ replayProtection: false });
    const init = await stampedRequest(stamper, { organizationId, timestampMs: String(Date.now()) });
    expect((await app.request("/public/v1/query/whoami", init)).status).toBe(200);
    expect((await app.request("/public/v1/query/whoami", init)).status).toBe(200);
  });
});

describe("submit rate limiting", () => {
  it("submits beyond the per-minute limit → 429; queries unaffected", async () => {
    const app = makeApp({ submitRateLimitPerMinute: 2 });

    const s1 = await app.request(
      "/public/v1/submit/sign_transaction",
      await stampedRequest(stamper, submitBody({ timestampMs: String(Date.now()) })),
    );
    expect(s1.status).toBe(200);
    const s2 = await app.request(
      "/public/v1/submit/sign_transaction",
      await stampedRequest(stamper, submitBody({ timestampMs: String(Date.now() + 1) })),
    );
    expect(s2.status).toBe(200);

    const s3 = await app.request(
      "/public/v1/submit/sign_transaction",
      await stampedRequest(stamper, submitBody({ timestampMs: String(Date.now() + 2) })),
    );
    expect(s3.status).toBe(429);
    const json = (await s3.json()) as { message: string };
    expect(json.message).toContain("rate limit exceeded");

    // Queries are NOT rate-limited by the submit limiter.
    const q = await app.request(
      "/public/v1/query/whoami",
      await stampedRequest(stamper, { organizationId, timestampMs: String(Date.now() + 3) }),
    );
    expect(q.status).toBe(200);
  });

  it("limit 0 disables rate limiting", async () => {
    const app = makeApp({ submitRateLimitPerMinute: 0 });
    for (let i = 10; i < 14; i++) {
      const res = await app.request(
        "/public/v1/submit/sign_transaction",
        await stampedRequest(stamper, submitBody({ timestampMs: String(Date.now() + i) })),
      );
      expect(res.status).toBe(200);
    }
  });
});
