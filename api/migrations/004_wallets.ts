import { Kysely, sql } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable("wallets")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("name", "text", (c) => c.notNull())
    .addColumn("created_by_activity_id", "uuid", (c) => c.references("activities.id"))
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .addColumn("deleted_at", "timestamptz")
    .execute();

  await db.schema
    .createTable("wallet_accounts")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("wallet_id", "uuid", (c) => c.notNull().references("wallets.id"))
    .addColumn("private_key_id", "uuid", (c) => c.notNull().references("private_keys.id"))
    .addColumn("curve", "text", (c) => c.notNull())
    .addColumn("address_format", "text", (c) => c.notNull())
    .addColumn("address", "text", (c) => c.notNull())
    .addColumn("path", "text")
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema
    .createIndex("wallet_accounts_org_wallet_idx")
    .on("wallet_accounts")
    .columns(["organization_id", "wallet_id"])
    .execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropTable("wallet_accounts").ifExists().execute();
  await db.schema.dropTable("wallets").ifExists().execute();
}
