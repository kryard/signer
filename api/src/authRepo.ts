import type { Kysely } from "kysely";
import type { Database } from "./db";

export interface ResolvedApiKey {
  id: string;
  actor_id: string;
  organization_id: string;
  scheme: string;
  disabled_at: Date | null;
}

/** Find an active API key by its stamp public key. */
export async function findApiKeyByPublicKey(
  db: Kysely<Database>,
  publicKey: string,
): Promise<ResolvedApiKey | null> {
  const row = await db
    .selectFrom("api_keys")
    .select(["id", "actor_id", "organization_id", "scheme", "disabled_at"])
    .where("public_key", "=", publicKey)
    .executeTakeFirst();
  if (!row || row.disabled_at) return null;
  return row as ResolvedApiKey;
}
