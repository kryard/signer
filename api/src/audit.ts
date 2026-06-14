import { sql, type Kysely } from "kysely";
import type { Database } from "./db";
import { canonicalize, sha256Hex } from "./canonicalJson";

/** Core event fields that are hashed (excludes generated id/created_at). */
interface EventCore {
  organizationId: string;
  actorId: string | null | undefined;
  activityId: string | null | undefined;
  eventType: string;
  metadata: unknown;
}

/** Compute the audit hash chain entry.
 *  event_hash = sha256(previousEventHash || canonical_json(eventCore))
 *  where `previousEventHash` is "" when there is no prior event. */
async function computeEventHash(
  previousEventHash: string,
  eventCore: EventCore,
): Promise<string> {
  const canonicalCore = canonicalize({
    organizationId: eventCore.organizationId,
    actorId: eventCore.actorId ?? null,
    activityId: eventCore.activityId ?? null,
    eventType: eventCore.eventType,
    metadata: eventCore.metadata ?? {},
  });
  return sha256Hex(previousEventHash + canonicalCore);
}

/** Write an audit event with hash-chain linking. Best-effort: a failed audit
 *  insert must NOT fail the underlying operation — it is logged instead.
 *
 *  The chain is serialized PER ORG with a transaction-scoped advisory lock so
 *  the read-previous-hash + insert is atomic: two concurrent events for the same
 *  org can't both chain off the same prior hash (which would fork the chain).
 *  The monotonic `seq` (migration 007) gives a deterministic replay order;
 *  different orgs take different lock keys and never contend. */
export async function recordAuditEvent(
  db: Kysely<Database>,
  e: {
    organizationId: string;
    actorId?: string | null;
    activityId?: string | null;
    eventType: string;
    metadata?: unknown;
  },
): Promise<void> {
  try {
    await db.transaction().execute(async (trx) => {
      // Serialize this org's chain for the duration of the transaction.
      await sql`select pg_advisory_xact_lock(hashtext(${e.organizationId}))`.execute(trx);

      const latest = await trx
        .selectFrom("audit_events")
        .select(["event_hash"])
        .where("organization_id", "=", e.organizationId)
        .orderBy("seq", "desc")
        .limit(1)
        .executeTakeFirst();

      const previousEventHash = latest?.event_hash ?? "";

      const eventCore: EventCore = {
        organizationId: e.organizationId,
        actorId: e.actorId ?? null,
        activityId: e.activityId ?? null,
        eventType: e.eventType,
        metadata: e.metadata ?? {},
      };
      const eventHash = await computeEventHash(previousEventHash, eventCore);

      await trx.insertInto("audit_events").values({
        organization_id: e.organizationId,
        actor_id: e.actorId ?? null,
        activity_id: e.activityId ?? null,
        event_type: e.eventType,
        metadata: JSON.stringify(e.metadata ?? {}),
        previous_event_hash: previousEventHash || null,
        event_hash: eventHash,
      }).execute();
    });
  } catch (err) {
    console.warn(`audit write failed for ${e.eventType}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Verify the audit hash chain for an organization.
 *  Reads all events (ordered by created_at ASC) and checks each event_hash
 *  matches sha256(previous_event_hash || canonical_json(event_core)).
 *  Returns { valid: true } or { valid: false, firstBadId: string }.
 */
export async function verifyAuditChain(
  db: Kysely<Database>,
  organizationId: string,
): Promise<{ valid: true } | { valid: false; firstBadId: string }> {
  const events = await db
    .selectFrom("audit_events")
    .select([
      "id",
      "organization_id",
      "actor_id",
      "activity_id",
      "event_type",
      "metadata",
      "previous_event_hash",
      "event_hash",
    ])
    .where("organization_id", "=", organizationId)
    .orderBy("seq", "asc")
    .execute();

  for (const ev of events) {
    const previousEventHash = ev.previous_event_hash ?? "";
    const eventCore: EventCore = {
      organizationId: ev.organization_id,
      actorId: ev.actor_id ?? null,
      activityId: ev.activity_id ?? null,
      eventType: ev.event_type,
      metadata: ev.metadata,
    };
    const expected = await computeEventHash(previousEventHash, eventCore);
    if (expected !== ev.event_hash) {
      return { valid: false, firstBadId: ev.id };
    }
  }

  return { valid: true };
}
