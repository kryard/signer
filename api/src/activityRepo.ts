import type { Kysely } from "kysely";
import type { Database } from "./db";
import type { ActivityRow } from "./types";
import type { ActivityStatus } from "./enums";

/**
 * Optional private_key row data returned by handlers.
 * When present, insertActivity writes this row inside the same transaction
 * that inserts the activity + idempotency key — no orphan key possible.
 */
export interface NewPrivateKey {
  id: string;
  organizationId: string;
  name: string;
  curve: string;
  publicKey: string;
  addresses: string;         // JSON.stringify(string[])
  encryptedPrivateKey: string;
  encryptedDataKey: string;
  kmsProvider: string;
  kmsKeyId: string;
  encryptionContext: string; // JSON.stringify(Record<string, string>)
}

/** Wallet row data to insert atomically with an activity. */
export interface NewWallet {
  id: string;
  organizationId: string;
  name: string;
}

/** Wallet account row data to insert atomically with an activity. */
export interface NewWalletAccount {
  id: string;
  organizationId: string;
  walletId: string;
  privateKeyId: string;
  curve: string;
  addressFormat: string;
  address: string;
  path: string | null;
}

export interface NewActivity {
  organizationId: string;
  type: string;
  status: ActivityStatus;
  requestBody: unknown;
  canonicalHash: string;
  intent: unknown;
  result: unknown;
  failure: unknown | null;
  fingerprint: string;
  timestampMs: string;
  actorId?: string | null;
  authMethod?: string | null;
  /** Signer receipt to persist on the activity row (P7). */
  signerReceipt?: unknown | null;
  /** Private key rows to insert atomically with the activity (arrays; all or nothing). */
  privateKeys?: NewPrivateKey[];
  /** Wallet rows to insert atomically with the activity. */
  wallets?: NewWallet[];
  /** Wallet account rows to insert atomically with the activity. */
  walletAccounts?: NewWalletAccount[];
}

/** Return the activity already recorded for this (org, idempotencyHash), or null. */
export async function findByIdempotency(
  db: Kysely<Database>,
  organizationId: string,
  idempotencyHash: string,
): Promise<ActivityRow | null> {
  const row = await db
    .selectFrom("idempotency_keys")
    .innerJoin("activities", "activities.id", "idempotency_keys.activity_id")
    .selectAll("activities")
    .where("idempotency_keys.organization_id", "=", organizationId)
    .where("idempotency_keys.idempotency_hash", "=", idempotencyHash)
    .executeTakeFirst();
  return (row as ActivityRow | undefined) ?? null;
}

/** Insert an activity + its idempotency key atomically; return the stored row.
 *  Concurrency: on a unique violation (23505) the competing request either
 *  committed (its activity is found and returned) or rolled back (we retry the
 *  insert). Bounded retries avoid a transient 500 on idempotent races. */
export async function insertActivity(
  db: Kysely<Database>,
  idempotencyHash: string,
  a: NewActivity,
): Promise<ActivityRow> {
  const MAX_ATTEMPTS = 3;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      return await db.transaction().execute(async (tx) => {
        const activity = await tx
          .insertInto("activities")
          .values({
            organization_id: a.organizationId,
            type: a.type,
            status: a.status,
            // jsonb columns: pg sends a string value as-is (no double-encode), so
            // we stringify explicitly. Do NOT also pass a JS object here.
            request_body: JSON.stringify(a.requestBody),
            canonical_hash: a.canonicalHash,
            intent: JSON.stringify(a.intent),
            result: JSON.stringify(a.result),
            failure: a.failure === null ? null : JSON.stringify(a.failure),
            fingerprint: a.fingerprint,
            timestamp_ms: a.timestampMs,
            actor_id: a.actorId ?? null,
            auth_method: a.authMethod ?? null,
            signer_receipt: a.signerReceipt == null ? null : JSON.stringify(a.signerReceipt),
          })
          .returningAll()
          .executeTakeFirstOrThrow();
        await tx
          .insertInto("idempotency_keys")
          .values({
            organization_id: a.organizationId,
            idempotency_hash: idempotencyHash,
            activity_id: activity.id,
          })
          .execute();

        // Insert private_key rows atomically. On idempotency unique-violation the
        // whole transaction rolls back — no orphan key/wallet/account possible.
        for (const pk of a.privateKeys ?? []) {
          await tx
            .insertInto("private_keys")
            .values({
              id: pk.id,
              organization_id: pk.organizationId,
              name: pk.name,
              curve: pk.curve,
              public_key: pk.publicKey,
              addresses: pk.addresses,
              encrypted_private_key: pk.encryptedPrivateKey,
              encrypted_data_key: pk.encryptedDataKey,
              kms_provider: pk.kmsProvider,
              kms_key_id: pk.kmsKeyId,
              encryption_context: pk.encryptionContext,
              created_by_activity_id: activity.id,
            })
            .execute();
        }

        // Insert wallet rows atomically (created_by_activity_id bound here).
        for (const w of a.wallets ?? []) {
          await tx
            .insertInto("wallets")
            .values({
              id: w.id,
              organization_id: w.organizationId,
              name: w.name,
              created_by_activity_id: activity.id,
            })
            .execute();
        }

        // Insert wallet_accounts rows atomically.
        for (const wa of a.walletAccounts ?? []) {
          await tx
            .insertInto("wallet_accounts")
            .values({
              id: wa.id,
              organization_id: wa.organizationId,
              wallet_id: wa.walletId,
              private_key_id: wa.privateKeyId,
              curve: wa.curve,
              address_format: wa.addressFormat,
              address: wa.address,
              path: wa.path,
            })
            .execute();
        }

        return activity as ActivityRow;
      });
    } catch (err) {
      if (!isUniqueViolation(err)) throw err;
      // A concurrent request won the race: return its activity if it committed.
      const existing = await findByIdempotency(db, a.organizationId, idempotencyHash);
      if (existing) return existing;
      // Else the competitor rolled back; retry the insert (unless out of attempts).
      if (attempt === MAX_ATTEMPTS) throw err;
    }
  }
  // Unreachable: the loop returns or throws on every path.
  throw new Error("insertActivity: exhausted retries");
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "23505";
}

export async function getActivityById(
  db: Kysely<Database>,
  organizationId: string,
  id: string,
): Promise<ActivityRow | null> {
  const row = await db
    .selectFrom("activities")
    .selectAll()
    .where("organization_id", "=", organizationId)
    .where("id", "=", id)
    .executeTakeFirst();
  return (row as ActivityRow | undefined) ?? null;
}

export async function listActivities(
  db: Kysely<Database>,
  organizationId: string,
  limit = 20,
): Promise<ActivityRow[]> {
  const rows = await db
    .selectFrom("activities")
    .selectAll()
    .where("organization_id", "=", organizationId)
    .orderBy("created_at", "desc")
    .limit(limit)
    .execute();
  return rows as ActivityRow[];
}
