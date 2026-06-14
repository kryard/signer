import { Kysely, sql } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  // Add signer_receipt column to activities for persisting signing receipts.
  await db.schema
    .alterTable("activities")
    .addColumn("signer_receipt", "jsonb")
    .execute();

  // Add hash chain columns to audit_events.
  await db.schema
    .alterTable("audit_events")
    .addColumn("previous_event_hash", "text")
    .execute();
  await db.schema
    .alterTable("audit_events")
    .addColumn("event_hash", "text")
    .execute();

  // policy_bindings: which actor may run which activity type on which resource.
  await db.schema
    .createTable("policy_bindings")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("actor_id", "uuid", (c) => c.notNull().references("actors.id"))
    .addColumn("resource_type", "text", (c) => c.notNull())
    .addColumn("resource_id", "uuid", (c) => c.notNull())
    .addColumn("allowed_activity_type", "text", (c) => c.notNull())
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema
    .createIndex("policy_bindings_actor_resource_idx")
    .on("policy_bindings")
    .columns(["organization_id", "actor_id", "resource_id", "allowed_activity_type"])
    .execute();

  // wallet_policy_rules: per (private_key_id, chain_id) signing limits.
  await db.schema
    .createTable("wallet_policy_rules")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("private_key_id", "uuid", (c) => c.notNull().references("private_keys.id"))
    .addColumn("chain_id", "bigint", (c) => c.notNull())
    .addColumn("allow_raw_payload_signing", "boolean", (c) => c.notNull().defaultTo(false))
    .addColumn("max_native_value_wei", "numeric", (c) => c.notNull().defaultTo(0))
    .addColumn("method_selector_allowlist", "jsonb", (c) => c.notNull().defaultTo(sql`'[]'::jsonb`))
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema
    .createIndex("wallet_policy_rules_key_chain_idx")
    .on("wallet_policy_rules")
    .columns(["private_key_id", "chain_id"])
    .execute();

  // wallet_destination_allowlist: allowed (to) addresses per (private_key_id, chain_id).
  await db.schema
    .createTable("wallet_destination_allowlist")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("private_key_id", "uuid", (c) => c.notNull().references("private_keys.id"))
    .addColumn("chain_id", "bigint", (c) => c.notNull())
    .addColumn("address", "text", (c) => c.notNull())
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .addUniqueConstraint("wallet_destination_allowlist_key_chain_addr", [
      "private_key_id",
      "chain_id",
      "address",
    ])
    .execute();

  // policy_decisions: immutable record of each policy evaluation.
  await db.schema
    .createTable("policy_decisions")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("activity_id", "uuid", (c) => c.notNull().references("activities.id"))
    .addColumn("private_key_id", "uuid", (c) => c.notNull().references("private_keys.id"))
    .addColumn("outcome", "text", (c) => c.notNull())
    .addColumn("reason_code", "text", (c) => c.notNull())
    .addColumn("evaluated_input_hash", "text", (c) => c.notNull())
    .addColumn("policy_version", "text", (c) => c.notNull().defaultTo("v1"))
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema
    .createIndex("policy_decisions_activity_idx")
    .on("policy_decisions")
    .columns(["activity_id"])
    .execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable("policy_decisions").ifExists().execute();
  await db.schema.dropTable("wallet_destination_allowlist").ifExists().execute();
  await db.schema.dropTable("wallet_policy_rules").ifExists().execute();
  await db.schema.dropTable("policy_bindings").ifExists().execute();
  await db.schema.alterTable("audit_events").dropColumn("event_hash").execute();
  await db.schema.alterTable("audit_events").dropColumn("previous_event_hash").execute();
  await db.schema.alterTable("activities").dropColumn("signer_receipt").execute();
}
