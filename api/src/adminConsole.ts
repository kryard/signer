/**
 * adminConsole.ts — org-scoped data-plane helpers for the SaaS console.
 *
 * Consumed by the token-gated /admin/dev/* endpoints mounted in app.ts (inside
 * the `devAdminEnabled` block, behind requireToken / X-Dev-Admin-Token).
 *
 * Security invariants (do not relax):
 *  - EVERY query filters organization_id — cross-org reads/deletes are bugs.
 *  - NEVER select or return encrypted_private_key, encrypted_data_key,
 *    encryption_context, kms_provider, or kms_key_id.
 *  - Fail closed: invalid params → TurnkeyError(400); not found → 404.
 */

import type { Kysely } from "kysely";
import type { Database } from "./db";
import { TurnkeyError } from "./errors";

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CHAIN_ID_RE = /^\d{1,38}$/; // decimal string for a bigint column

/** Validate a path/query/body param as a UUID; throws TurnkeyError(400) otherwise. */
export function requireUuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new TurnkeyError(400, `${label} must be a UUID`);
  }
  return value;
}

/** Parse + clamp a ?limit= query param to [1, 200]; default 50. */
export function clampLimit(raw: string | undefined): number {
  if (raw === undefined || raw === "") return 50;
  const n = Number(raw);
  if (!Number.isInteger(n)) throw new TurnkeyError(400, "limit must be an integer");
  return Math.min(200, Math.max(1, n));
}

function isoOrNull(d: Date | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

function iso(d: Date): string {
  return new Date(d).toISOString();
}

/** jsonb columns come back parsed from pg; be defensive about string storage. */
function asArray(v: unknown): unknown[] {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") {
    try {
      const parsed: unknown = JSON.parse(v);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

export interface OrgSummary {
  id: string;
  name: string;
  createdAt: string;
}

export async function listOrgs(db: Kysely<Database>): Promise<OrgSummary[]> {
  const rows = await db
    .selectFrom("organizations")
    .select(["id", "name", "created_at"])
    .orderBy("created_at", "desc")
    .limit(100)
    .execute();
  return rows.map((r) => ({ id: r.id, name: r.name, createdAt: iso(r.created_at) }));
}

export interface OrgDetail {
  organization: OrgSummary;
  actors: { id: string; name: string; createdAt: string }[];
  apiKeys: {
    id: string;
    actorId: string;
    name: string;
    publicKey: string;
    scheme: string;
    disabledAt: string | null;
    createdAt: string;
  }[];
}

export async function getOrgDetail(db: Kysely<Database>, orgId: string): Promise<OrgDetail> {
  const org = await db
    .selectFrom("organizations")
    .select(["id", "name", "created_at"])
    .where("id", "=", orgId)
    .executeTakeFirst();
  if (!org) throw new TurnkeyError(404, "organization not found");

  const actors = await db
    .selectFrom("actors")
    .select(["id", "name", "created_at"])
    .where("organization_id", "=", orgId)
    .orderBy("created_at", "desc")
    .execute();

  const apiKeys = await db
    .selectFrom("api_keys")
    .select(["id", "actor_id", "name", "public_key", "scheme", "disabled_at", "created_at"])
    .where("organization_id", "=", orgId)
    .orderBy("created_at", "desc")
    .execute();

  return {
    organization: { id: org.id, name: org.name, createdAt: iso(org.created_at) },
    actors: actors.map((a) => ({ id: a.id, name: a.name, createdAt: iso(a.created_at) })),
    apiKeys: apiKeys.map((k) => ({
      id: k.id,
      actorId: k.actor_id,
      name: k.name,
      publicKey: k.public_key,
      scheme: k.scheme,
      disabledAt: isoOrNull(k.disabled_at),
      createdAt: iso(k.created_at),
    })),
  };
}

// ---------------------------------------------------------------------------
// Wallets (private_keys metadata — NEVER ciphertext)
// ---------------------------------------------------------------------------

export interface ConsoleWallet {
  id: string;
  name: string;
  curve: string;
  publicKey: string;
  addresses: unknown[];
  createdAt: string;
  deletedAt: string | null;
}

export async function listOrgWallets(db: Kysely<Database>, orgId: string): Promise<ConsoleWallet[]> {
  // Explicit column list — encrypted_private_key / encrypted_data_key /
  // encryption_context / kms_* must never leave the data layer.
  const rows = await db
    .selectFrom("private_keys")
    .select(["id", "name", "curve", "public_key", "addresses", "created_at", "deleted_at"])
    .where("organization_id", "=", orgId)
    .orderBy("created_at", "desc")
    .execute();
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    curve: r.curve,
    publicKey: r.public_key,
    addresses: asArray(r.addresses),
    createdAt: iso(r.created_at),
    deletedAt: isoOrNull(r.deleted_at),
  }));
}

// ---------------------------------------------------------------------------
// Activities
// ---------------------------------------------------------------------------

export interface ConsoleActivitySummary {
  id: string;
  type: string;
  status: string;
  fingerprint: string;
  timestampMs: string;
  actorId: string | null;
  createdAt: string;
}

export async function listOrgActivities(
  db: Kysely<Database>,
  orgId: string,
  limit: number,
  before?: Date,
): Promise<ConsoleActivitySummary[]> {
  let query = db
    .selectFrom("activities")
    .select(["id", "type", "status", "fingerprint", "timestamp_ms", "actor_id", "created_at"])
    .where("organization_id", "=", orgId)
    .orderBy("created_at", "desc")
    .limit(limit);
  // Cursor pagination: pass the last row's createdAt to fetch the next page.
  if (before) query = query.where("created_at", "<", before);
  const rows = await query.execute();
  return rows.map((r) => ({
    id: r.id,
    type: r.type,
    status: r.status,
    fingerprint: r.fingerprint,
    timestampMs: r.timestamp_ms,
    actorId: r.actor_id,
    createdAt: iso(r.created_at),
  }));
}

export interface ConsoleActivityDetail {
  activity: Record<string, unknown>;
  policyDecisions: Record<string, unknown>[];
  auditEvents: Record<string, unknown>[];
}

export async function getOrgActivity(
  db: Kysely<Database>,
  orgId: string,
  activityId: string,
): Promise<ConsoleActivityDetail> {
  const row = await db
    .selectFrom("activities")
    .selectAll()
    .where("organization_id", "=", orgId)
    .where("id", "=", activityId)
    .executeTakeFirst();
  if (!row) throw new TurnkeyError(404, "activity not found");

  const decisions = await db
    .selectFrom("policy_decisions")
    .selectAll()
    .where("organization_id", "=", orgId)
    .where("activity_id", "=", activityId)
    .orderBy("created_at", "asc")
    .execute();

  const events = await db
    .selectFrom("audit_events")
    .selectAll()
    .where("organization_id", "=", orgId)
    .where("activity_id", "=", activityId)
    .orderBy("created_at", "asc")
    .execute();

  return {
    activity: {
      id: row.id,
      organizationId: row.organization_id,
      type: row.type,
      status: row.status,
      requestBody: row.request_body,
      canonicalHash: row.canonical_hash,
      intent: row.intent,
      result: row.result,
      failure: row.failure,
      fingerprint: row.fingerprint,
      timestampMs: row.timestamp_ms,
      actorId: row.actor_id,
      authMethod: row.auth_method,
      signerReceipt: row.signer_receipt,
      createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at),
    },
    policyDecisions: decisions.map((d) => ({
      id: d.id,
      activityId: d.activity_id,
      privateKeyId: d.private_key_id,
      outcome: d.outcome,
      reasonCode: d.reason_code,
      evaluatedInputHash: d.evaluated_input_hash,
      policyVersion: d.policy_version,
      createdAt: iso(d.created_at),
    })),
    auditEvents: events.map((e) => ({
      id: e.id,
      actorId: e.actor_id,
      activityId: e.activity_id,
      eventType: e.event_type,
      metadata: e.metadata,
      previousEventHash: e.previous_event_hash,
      eventHash: e.event_hash,
      createdAt: iso(e.created_at),
    })),
  };
}

// ---------------------------------------------------------------------------
// Policies (bindings + rules + destination allowlist)
// ---------------------------------------------------------------------------

export interface ConsolePolicies {
  bindings: Record<string, unknown>[];
  rules: Record<string, unknown>[];
  destinations: Record<string, unknown>[];
}

export async function listOrgPolicies(db: Kysely<Database>, orgId: string): Promise<ConsolePolicies> {
  const bindings = await db
    .selectFrom("policy_bindings")
    .selectAll()
    .where("organization_id", "=", orgId)
    .orderBy("created_at", "desc")
    .execute();

  const rules = await db
    .selectFrom("wallet_policy_rules")
    .selectAll()
    .where("organization_id", "=", orgId)
    .orderBy("created_at", "desc")
    .execute();

  const destinations = await db
    .selectFrom("wallet_destination_allowlist")
    .selectAll()
    .where("organization_id", "=", orgId)
    .orderBy("created_at", "desc")
    .execute();

  return {
    bindings: bindings.map((b) => ({
      id: b.id,
      actorId: b.actor_id,
      resourceType: b.resource_type,
      resourceId: b.resource_id,
      allowedActivityType: b.allowed_activity_type,
      createdAt: iso(b.created_at),
    })),
    rules: rules.map((r) => ({
      id: r.id,
      privateKeyId: r.private_key_id,
      chainId: String(r.chain_id),
      allowRawPayloadSigning: r.allow_raw_payload_signing,
      maxNativeValueWei: String(r.max_native_value_wei),
      methodSelectorAllowlist: asArray(r.method_selector_allowlist),
      createdAt: iso(r.created_at),
    })),
    destinations: destinations.map((d) => ({
      id: d.id,
      privateKeyId: d.private_key_id,
      chainId: String(d.chain_id),
      address: d.address,
      createdAt: iso(d.created_at),
    })),
  };
}

// ---------------------------------------------------------------------------
// Destination allowlist management
// ---------------------------------------------------------------------------

export interface AddDestinationInput {
  organizationId?: unknown;
  privateKeyId?: unknown;
  chainId?: unknown;
  address?: unknown;
}

export async function addDestination(
  db: Kysely<Database>,
  input: AddDestinationInput,
): Promise<{ id: string }> {
  const organizationId = requireUuid(input.organizationId, "organizationId");
  const privateKeyId = requireUuid(input.privateKeyId, "privateKeyId");
  const chainId = typeof input.chainId === "string" ? input.chainId : "";
  const address = typeof input.address === "string" ? input.address.trim() : "";
  if (!CHAIN_ID_RE.test(chainId)) throw new TurnkeyError(400, "chainId must be a decimal string");
  if (!address) throw new TurnkeyError(400, "address is required");

  // Cross-org guard: the key must belong to the caller's organization.
  const key = await db
    .selectFrom("private_keys")
    .select("id")
    .where("id", "=", privateKeyId)
    .where("organization_id", "=", organizationId)
    .executeTakeFirst();
  if (!key) throw new TurnkeyError(404, "private key not found in organization");

  try {
    const row = await db
      .insertInto("wallet_destination_allowlist")
      .values({
        organization_id: organizationId,
        private_key_id: privateKeyId,
        chain_id: chainId,
        address,
      })
      .returning("id")
      .executeTakeFirstOrThrow();
    return { id: row.id };
  } catch (err: unknown) {
    // 23505 = unique_violation on (private_key_id, chain_id, address).
    if ((err as { code?: string }).code === "23505") {
      throw new TurnkeyError(400, "destination already allowlisted for this key and chain");
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Org-scoped deletes (rule / destination / binding)
// ---------------------------------------------------------------------------

async function deleteOrgScoped(
  db: Kysely<Database>,
  table: "wallet_policy_rules" | "wallet_destination_allowlist" | "policy_bindings",
  orgId: string,
  id: string,
  label: string,
): Promise<{ ok: true }> {
  const res = await db
    .deleteFrom(table)
    .where("id", "=", id)
    .where("organization_id", "=", orgId)
    .executeTakeFirst();
  if (res.numDeletedRows === 0n) throw new TurnkeyError(404, `${label} not found`);
  return { ok: true };
}

export function deletePolicyRule(db: Kysely<Database>, orgId: string, id: string): Promise<{ ok: true }> {
  return deleteOrgScoped(db, "wallet_policy_rules", orgId, id, "policy rule");
}

export function deleteDestination(db: Kysely<Database>, orgId: string, id: string): Promise<{ ok: true }> {
  return deleteOrgScoped(db, "wallet_destination_allowlist", orgId, id, "destination");
}

export function deletePolicyBinding(db: Kysely<Database>, orgId: string, id: string): Promise<{ ok: true }> {
  return deleteOrgScoped(db, "policy_bindings", orgId, id, "policy binding");
}

// ---------------------------------------------------------------------------
// Organization settings
// ---------------------------------------------------------------------------

export async function renameOrg(
  db: Kysely<Database>,
  orgId: string,
  name: unknown,
): Promise<{ ok: true; name: string }> {
  const trimmed = typeof name === "string" ? name.trim() : "";
  if (!trimmed || trimmed.length > 120) {
    throw new TurnkeyError(400, "name is required (1-120 chars)");
  }
  const res = await db
    .updateTable("organizations")
    .set({ name: trimmed })
    .where("id", "=", orgId)
    .executeTakeFirst();
  if (res.numUpdatedRows === 0n) throw new TurnkeyError(404, "organization not found");
  return { ok: true, name: trimmed };
}

// ---------------------------------------------------------------------------
// API key disable
// ---------------------------------------------------------------------------

export async function disableApiKey(
  db: Kysely<Database>,
  orgId: string,
  apiKeyId: string,
): Promise<{ ok: true }> {
  const res = await db
    .updateTable("api_keys")
    .set({ disabled_at: new Date() })
    .where("id", "=", apiKeyId)
    .where("organization_id", "=", orgId)
    .executeTakeFirst();
  if (res.numUpdatedRows === 0n) throw new TurnkeyError(404, "api key not found");
  return { ok: true };
}
