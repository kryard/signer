import type { Kysely } from "kysely";
import type { Database } from "./db";
import { TurnkeyError } from "./errors";
import { decodeStamp, verifyStamp } from "./stamp";
import { findApiKeyByPublicKey } from "./authRepo";
import { canonicalize, sha256Hex } from "./canonicalJson";

// Freshness window: a stamp is only accepted if the body's timestampMs is within
// this of `now`. Combined with the used_stamps replay-nonce store below, a
// captured stamp cannot be replayed at all: the signature binds the exact body,
// the body binds timestampMs, and the stamp hash is single-use.
export const FRESHNESS_WINDOW_MS = 60_000;

// used_stamps rows outlive the freshness window on both sides (clock skew is
// |now - ts| <= window, so a stamp can surface up to one window "early").
const STAMP_TTL_MS = 2 * FRESHNESS_WINDOW_MS;

// Opportunistic cleanup probability — roughly one DELETE per N authenticated
// requests keeps the table bounded without a scheduler.
const CLEANUP_ONE_IN = 50;

export interface AuthContext {
  actorId: string;
  organizationId: string;
  apiKeyId: string;
  authMethod: string;
}

/**
 * Replay-nonce check (P8 hardening): record sha256(stamp signature) with a TTL;
 * a second presentation of the same stamp is a replay and is rejected — with
 * ONE exemption. Because the signature binds the exact body bytes, a replayed
 * stamp always accompanies a byte-identical request; if that request is a
 * SUBMIT already recorded in idempotency_keys, replaying it is a benign
 * idempotent retry (same activity returned, zero new side effects) and must
 * stay allowed — deterministic (RFC-6979) stampers re-sign identical bodies to
 * identical signatures, so blocking would break Turnkey's idempotency contract.
 * Queries and not-yet-recorded submissions are hard-blocked.
 */
async function checkStampReplay(
  db: Kysely<Database>,
  signatureHex: string,
  organizationId: string,
  rawBody: string,
  now: number,
): Promise<void> {
  const stampHash = await sha256Hex(signatureHex);
  const inserted = await db
    .insertInto("used_stamps")
    .values({
      stamp_hash: stampHash,
      organization_id: organizationId,
      expires_at: new Date(now + STAMP_TTL_MS),
    })
    .onConflict((oc) => oc.doNothing())
    .executeTakeFirst();

  if (inserted.numInsertedOrUpdatedRows === 0n) {
    // Idempotent-retry exemption: same hash computation as dispatchSubmit.
    const idempotencyHash = await sha256Hex(
      canonicalize(JSON.parse(rawBody) as Record<string, unknown>),
    );
    const existing = await db
      .selectFrom("idempotency_keys")
      .select("activity_id")
      .where("organization_id", "=", organizationId)
      .where("idempotency_hash", "=", idempotencyHash)
      .executeTakeFirst();
    if (!existing) {
      throw new TurnkeyError(401, "stamp replay detected: this signature was already used");
    }
  }

  // Opportunistic expiry sweep (no scheduler in the Workers runtime).
  if (Math.floor(Math.random() * CLEANUP_ONE_IN) === 0) {
    await db
      .deleteFrom("used_stamps")
      .where("expires_at", "<", new Date(now))
      .execute()
      .catch(() => {});
  }
}

/** Verify the X-Stamp over the raw body, resolve the actor, enforce org match + freshness + single-use. */
export async function authenticate(
  db: Kysely<Database>,
  rawBody: string,
  stampHeader: string | undefined,
  bodyOrganizationId: string,
  bodyTimestampMs: string,
  now: number,
  options: { replayProtection?: boolean } = {},
): Promise<AuthContext> {
  const { replayProtection = true } = options;

  if (!stampHeader) throw new TurnkeyError(401, "missing X-Stamp header");
  let stamp;
  try {
    stamp = decodeStamp(stampHeader);
  } catch {
    throw new TurnkeyError(401, "malformed X-Stamp");
  }
  if (!verifyStamp(stamp, rawBody)) throw new TurnkeyError(401, "invalid stamp signature");

  const apiKey = await findApiKeyByPublicKey(db, stamp.publicKey);
  if (!apiKey) throw new TurnkeyError(401, "unknown or disabled API key");
  // Defense-in-depth: the presented scheme must match the registered key's scheme,
  // so a key can't be exercised under a different (future, same-length) curve.
  if (apiKey.scheme !== stamp.scheme) {
    throw new TurnkeyError(401, "stamp scheme does not match registered key");
  }
  if (apiKey.organization_id !== bodyOrganizationId) {
    throw new TurnkeyError(403, "API key not permitted for this organization");
  }

  const ts = Number(bodyTimestampMs);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > FRESHNESS_WINDOW_MS) {
    throw new TurnkeyError(400, `activity timestamp is not current: ${bodyTimestampMs}`);
  }

  // Single-use check LAST — only valid, fresh, authorized stamps consume a nonce.
  if (replayProtection) {
    await checkStampReplay(db, stamp.signature, apiKey.organization_id, rawBody, now);
  }

  return { actorId: apiKey.actor_id, organizationId: apiKey.organization_id, apiKeyId: apiKey.id, authMethod: stamp.scheme };
}
