import { Kysely, sql } from "kysely";

/**
 * 007 — audit hash-chain serialization (P7 review F6/F9; AC-H2).
 *
 * Adds a monotonic `seq` to audit_events so the chain has a deterministic
 * total order per org (created_at alone ties on same-ms inserts, and the random
 * uuid id is no tiebreak). Combined with the per-org advisory lock in
 * recordAuditEvent, the read-prev-hash + insert becomes atomic → no chain fork
 * under concurrency, and verifyAuditChain replays in true insert order.
 *
 * Existing rows are backfilled in created_at order; future inserts get the
 * default from the sequence.
 */
export async function up(db: Kysely<unknown>): Promise<void> {
  await sql`CREATE SEQUENCE IF NOT EXISTS audit_events_seq`.execute(db);
  await sql`ALTER TABLE audit_events ADD COLUMN seq bigint`.execute(db);

  // Backfill deterministically by (created_at, id).
  await sql`
    WITH ordered AS (
      SELECT id, row_number() OVER (ORDER BY created_at, id) AS rn FROM audit_events
    )
    UPDATE audit_events ae SET seq = o.rn FROM ordered o WHERE ae.id = o.id
  `.execute(db);

  await sql`SELECT setval('audit_events_seq', GREATEST((SELECT COALESCE(MAX(seq), 0) FROM audit_events), 1))`.execute(db);
  await sql`ALTER TABLE audit_events ALTER COLUMN seq SET DEFAULT nextval('audit_events_seq')`.execute(db);
  await sql`ALTER TABLE audit_events ALTER COLUMN seq SET NOT NULL`.execute(db);

  await db.schema
    .createIndex("audit_events_org_seq_idx")
    .on("audit_events")
    .columns(["organization_id", "seq"])
    .execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropIndex("audit_events_org_seq_idx").execute();
  await sql`ALTER TABLE audit_events DROP COLUMN seq`.execute(db);
  await sql`DROP SEQUENCE IF EXISTS audit_events_seq`.execute(db);
}
