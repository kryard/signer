import type { Kysely } from "kysely";
import type { Database } from "../../src/db";

export async function seedApiKey(
  db: Kysely<Database>,
  publicKey: string,
  scheme: string,
): Promise<{ organizationId: string; actorId: string }> {
  const org = await db.insertInto("organizations").values({ name: "root" }).returning("id").executeTakeFirstOrThrow();
  const actor = await db.insertInto("actors").values({ organization_id: org.id, name: "relayer" }).returning("id").executeTakeFirstOrThrow();
  await db.insertInto("api_keys").values({
    organization_id: org.id, actor_id: actor.id, public_key: publicKey, scheme, name: "relayer-key",
  }).execute();
  return { organizationId: org.id, actorId: actor.id };
}
