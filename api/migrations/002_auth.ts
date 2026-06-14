import { Kysely, sql } from "kysely";

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema.createTable("organizations")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("name", "text", (c) => c.notNull())
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema.createTable("actors")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("name", "text", (c) => c.notNull())
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema.createTable("api_keys")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull().references("organizations.id"))
    .addColumn("actor_id", "uuid", (c) => c.notNull().references("actors.id"))
    .addColumn("public_key", "text", (c) => c.notNull().unique())
    .addColumn("scheme", "text", (c) => c.notNull())
    .addColumn("name", "text", (c) => c.notNull())
    .addColumn("disabled_at", "timestamptz")
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema.createTable("audit_events")
    .addColumn("id", "uuid", (c) => c.primaryKey().defaultTo(sql`gen_random_uuid()`))
    .addColumn("organization_id", "uuid", (c) => c.notNull())
    .addColumn("actor_id", "uuid")
    .addColumn("activity_id", "uuid")
    .addColumn("event_type", "text", (c) => c.notNull())
    .addColumn("metadata", "jsonb", (c) => c.notNull().defaultTo(sql`'{}'::jsonb`))
    .addColumn("created_at", "timestamptz", (c) => c.notNull().defaultTo(sql`now()`))
    .execute();

  await db.schema.alterTable("activities").addColumn("actor_id", "uuid").execute();
  await db.schema.alterTable("activities").addColumn("auth_method", "text").execute();
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.alterTable("activities").dropColumn("auth_method").execute();
  await db.schema.alterTable("activities").dropColumn("actor_id").execute();
  await db.schema.dropTable("audit_events").ifExists().execute();
  await db.schema.dropTable("api_keys").ifExists().execute();
  await db.schema.dropTable("actors").ifExists().execute();
  await db.schema.dropTable("organizations").ifExists().execute();
}
