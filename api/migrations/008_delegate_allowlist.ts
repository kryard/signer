import { Kysely, sql } from "kysely";

/**
 * 008 — EIP-7702 delegate-implementation allowlist (Workstream A).
 *
 * For a type-4 (EIP-7702) sweep, the transaction `to` is the user's OWN delegated
 * EOA — variable per user — so the wallet_destination_allowlist (which pins `to`)
 * does not apply. The security-relevant value is instead the delegation TARGET:
 * the SweepDelegate implementation each authorization points to. This table
 * allowlists those delegate impls per (private_key_id, chain_id); a type-4 tx
 * whose authorization delegates to an address NOT in this list is denied
 * (DELEGATE_NOT_ALLOWED), fail-closed.
 */
export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable("wallet_delegate_allowlist")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("private_key_id", "uuid", (c) => c.notNull().references("private_keys.id"))
    .addColumn("chain_id", "bigint", (c) => c.notNull())
    .addColumn("delegate_address", "text", (c) => c.notNull())
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .addUniqueConstraint("wallet_delegate_allowlist_key_chain_addr", [
      "private_key_id",
      "chain_id",
      "delegate_address",
    ])
    .execute();

  await db.schema
    .createIndex("wallet_delegate_allowlist_key_chain_idx")
    .on("wallet_delegate_allowlist")
    .columns(["private_key_id", "chain_id"])
    .execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable("wallet_delegate_allowlist").execute();
}
