import { Kysely, sql } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable("private_keys")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("name", "text", (c) => c.notNull())
    .addColumn("curve", "text", (c) => c.notNull())
    .addColumn("public_key", "text", (c) => c.notNull())
    .addColumn("addresses", "jsonb", (c) => c.notNull())
    .addColumn("encrypted_private_key", "text", (c) => c.notNull())
    .addColumn("encrypted_data_key", "text", (c) => c.notNull())
    .addColumn("kms_provider", "text", (c) => c.notNull())
    .addColumn("kms_key_id", "text", (c) => c.notNull())
    .addColumn("encryption_context", "jsonb", (c) => c.notNull())
    .addColumn("created_by_activity_id", "uuid")
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .addColumn("deleted_at", "timestamptz")
    .execute();

  await db.schema
    .createIndex("private_keys_org_created_idx")
    .on("private_keys")
    .columns(["organization_id", "created_at"])
    .execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable("private_keys").ifExists().execute();
}
