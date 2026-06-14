import { Kysely, sql } from "kysely";

/**
 * 006 — pre-cutover hardening (P8 runbook backlog):
 *
 * used_stamps: replay-nonce store. Each accepted X-Stamp's signature hash is
 * recorded; presenting the same stamp twice within the freshness window is a
 * replay and is rejected. Rows expire (expires_at) and are deleted
 * opportunistically — the primary key makes the INSERT ... ON CONFLICT the
 * atomic dedup check.
 *
 * rate_limit_counters: fixed-window submit rate limiting per organization.
 * (key = "submit:<org_id>", window_start = minute bucket). UPSERT increments
 * atomically; exceeding the limit returns 429 before any signing work.
 */
export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable("used_stamps")
    .addColumn("stamp_hash", "text", (c) => c.primaryKey())
    .addColumn("organization_id", "text", (c) => c.notNull())
    .addColumn("expires_at", "timestamptz", (c) => c.notNull())
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  // Cleanup scans delete by expiry.
  await db.schema
    .createIndex("used_stamps_expires_at_idx")
    .on("used_stamps")
    .column("expires_at")
    .execute();

  await db.schema
    .createTable("rate_limit_counters")
    .addColumn("key", "text", (c) => c.notNull())
    .addColumn("window_start", "timestamptz", (c) => c.notNull())
    .addColumn("count", "integer", (c) => c.notNull().defaultTo(0))
    .addPrimaryKeyConstraint("rate_limit_counters_pk", ["key", "window_start"])
    .execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable("rate_limit_counters").execute();
  await db.schema.dropTable("used_stamps").execute();
}
