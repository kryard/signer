/**
 * rateLimit.ts — fixed-window submit rate limiting per organization (P8
 * hardening backlog). DB-backed so it works identically on Workers + tests;
 * the (key, window_start) primary key makes the UPSERT increment atomic.
 *
 * Window = 1 minute. Exceeding the limit throws TurnkeyError(429) BEFORE any
 * signing work. limit <= 0 disables (used by tests / explicit opt-out).
 */
import { sql, type Kysely } from "kysely";
import type { Database } from "./db";
import { TurnkeyError } from "./errors";

const WINDOW_MS = 60_000;

// Keep ~5 minutes of windows; older rows are swept opportunistically.
const RETAIN_WINDOWS = 5;
const CLEANUP_ONE_IN = 50;

export async function checkSubmitRateLimit(
  db: Kysely<Database>,
  organizationId: string,
  limitPerMinute: number,
  now: number,
): Promise<void> {
  if (limitPerMinute <= 0) return;

  const windowStart = new Date(Math.floor(now / WINDOW_MS) * WINDOW_MS);
  const key = `submit:${organizationId}`;

  const row = await db
    .insertInto("rate_limit_counters")
    .values({ key, window_start: windowStart, count: 1 })
    .onConflict((oc) =>
      oc.columns(["key", "window_start"]).doUpdateSet({
        count: sql`rate_limit_counters.count + 1`,
      }),
    )
    .returning("count")
    .executeTakeFirstOrThrow();

  if (row.count > limitPerMinute) {
    throw new TurnkeyError(
      429,
      `rate limit exceeded: ${limitPerMinute} submit requests per minute per organization`,
    );
  }

  if (Math.floor(Math.random() * CLEANUP_ONE_IN) === 0) {
    await db
      .deleteFrom("rate_limit_counters")
      .where("window_start", "<", new Date(now - RETAIN_WINDOWS * WINDOW_MS))
      .execute()
      .catch(() => {});
  }
}
