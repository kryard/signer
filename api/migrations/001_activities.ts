import { Kysely, sql } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable("activities")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "text", (c) => c.notNull())
    .addColumn("type", "text", (c) => c.notNull())
    .addColumn("status", "text", (c) => c.notNull())
    .addColumn("request_body", "jsonb", (c) => c.notNull())
    .addColumn("canonical_hash", "text", (c) => c.notNull())
    .addColumn("intent", "jsonb", (c) => c.notNull().defaultTo(sql`'{}'::jsonb`))
    .addColumn("result", "jsonb", (c) => c.notNull().defaultTo(sql`'{}'::jsonb`))
    .addColumn("failure", "jsonb")
    .addColumn("fingerprint", "text", (c) => c.notNull())
    .addColumn("timestamp_ms", "text", (c) => c.notNull())
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .addColumn("updated_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema
    .createIndex("activities_org_created_idx")
    .on("activities")
    .columns(["organization_id", "created_at"])
    .execute();

  await db.schema
    .createTable("idempotency_keys")
    .addColumn("organization_id", "text", (c) => c.notNull())
    .addColumn("idempotency_hash", "text", (c) => c.notNull())
    .addColumn("activity_id", "uuid", (c) => c.notNull().references("activities.id"))
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .addPrimaryKeyConstraint("idempotency_pk", ["organization_id", "idempotency_hash"])
    .execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable("idempotency_keys").ifExists().execute();
  await db.schema.dropTable("activities").ifExists().execute();
}
