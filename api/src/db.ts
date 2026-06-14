import { Kysely, PostgresDialect, type Generated } from "kysely";
import pg from "pg";
import { Pool as NeonPool } from "@neondatabase/serverless";

export interface ActivitiesTable {
  id: Generated<string>; // gen_random_uuid()
  organization_id: string;
  type: string;
  status: string;
  request_body: unknown;
  canonical_hash: string;
  intent: unknown;
  result: unknown;
  failure: unknown | null;
  fingerprint: string;
  timestamp_ms: string;
  actor_id: string | null;
  auth_method: string | null;
  signer_receipt: unknown | null; // jsonb — added in migration 005
  created_at: Generated<Date>; // default now()
  updated_at: Generated<Date>; // default now()
}

export interface IdempotencyKeysTable {
  organization_id: string;
  idempotency_hash: string;
  activity_id: string;
  created_at: Generated<Date>; // default now()
}

export interface OrganizationsTable {
  id: Generated<string>; // gen_random_uuid()
  name: string;
  created_at: Generated<Date>; // default now()
}

export interface ActorsTable {
  id: Generated<string>; // gen_random_uuid()
  organization_id: string;
  name: string;
  created_at: Generated<Date>; // default now()
}

export interface ApiKeysTable {
  id: Generated<string>; // gen_random_uuid()
  organization_id: string;
  actor_id: string;
  public_key: string;
  scheme: string;
  name: string;
  disabled_at: Date | null;
  created_at: Generated<Date>; // default now()
}

export interface AuditEventsTable {
  id: Generated<string>; // gen_random_uuid()
  organization_id: string;
  actor_id: string | null;
  activity_id: string | null;
  event_type: string;
  metadata: unknown;
  previous_event_hash: string | null; // added in migration 005
  event_hash: string | null;           // added in migration 005
  seq: Generated<string>;              // bigint, monotonic order (migration 007)
  created_at: Generated<Date>; // default now()
}

export interface PolicyBindingsTable {
  id: Generated<string>;
  organization_id: string;
  actor_id: string;
  resource_type: string;
  resource_id: string;
  allowed_activity_type: string;
  created_at: Generated<Date>;
}

export interface WalletPolicyRulesTable {
  id: Generated<string>;
  organization_id: string;
  private_key_id: string;
  chain_id: string; // bigint stored as string in JS
  allow_raw_payload_signing: boolean;
  max_native_value_wei: string; // numeric stored as string
  method_selector_allowlist: unknown; // jsonb array of selector strings
  created_at: Generated<Date>;
}

export interface WalletDestinationAllowlistTable {
  id: Generated<string>;
  organization_id: string;
  private_key_id: string;
  chain_id: string; // bigint stored as string
  address: string;
  created_at: Generated<Date>;
}

export interface WalletDelegateAllowlistTable {
  id: Generated<string>;
  organization_id: string;
  private_key_id: string;
  chain_id: string; // bigint stored as string
  delegate_address: string; // EIP-7702 delegation target (SweepDelegate impl)
  created_at: Generated<Date>;
}

export interface PolicyDecisionsTable {
  id: Generated<string>;
  organization_id: string;
  activity_id: string;
  private_key_id: string;
  outcome: string; // "ALLOW" | "DENY"
  reason_code: string;
  evaluated_input_hash: string;
  policy_version: string;
  created_at: Generated<Date>;
}

export interface PrivateKeysTable {
  id: Generated<string>; // gen_random_uuid()
  organization_id: string;
  name: string;
  curve: string;
  public_key: string;
  addresses: unknown; // jsonb
  encrypted_private_key: string;
  encrypted_data_key: string;
  kms_provider: string;
  kms_key_id: string;
  encryption_context: unknown; // jsonb
  created_by_activity_id: string | null;
  created_at: Generated<Date>; // default now()
  deleted_at: Date | null;
}

export interface WalletsTable {
  id: Generated<string>; // gen_random_uuid()
  organization_id: string;
  name: string;
  created_by_activity_id: string | null;
  created_at: Generated<Date>; // default now()
  deleted_at: Date | null;
}

export interface WalletAccountsTable {
  id: Generated<string>; // gen_random_uuid()
  organization_id: string;
  wallet_id: string;
  private_key_id: string;
  curve: string;
  address_format: string;
  address: string;
  path: string | null;
  created_at: Generated<Date>; // default now()
}

export interface UsedStampsTable {
  stamp_hash: string; // sha256 of the stamp signature — the replay-dedup key
  organization_id: string;
  expires_at: Date;
  created_at: Generated<Date>;
}

export interface RateLimitCountersTable {
  key: string; // e.g. "submit:<organization_id>"
  window_start: Date; // minute bucket
  count: number;
}

export interface Database {
  activities: ActivitiesTable;
  idempotency_keys: IdempotencyKeysTable;
  organizations: OrganizationsTable;
  actors: ActorsTable;
  api_keys: ApiKeysTable;
  audit_events: AuditEventsTable;
  private_keys: PrivateKeysTable;
  wallets: WalletsTable;
  wallet_accounts: WalletAccountsTable;
  policy_bindings: PolicyBindingsTable;
  wallet_policy_rules: WalletPolicyRulesTable;
  wallet_destination_allowlist: WalletDestinationAllowlistTable;
  wallet_delegate_allowlist: WalletDelegateAllowlistTable;
  policy_decisions: PolicyDecisionsTable;
  used_stamps: UsedStampsTable;
  rate_limit_counters: RateLimitCountersTable;
}

/** Build a Kysely instance from a Postgres connection string (Node + Workers). */
export function makeDb(connectionString: string): Kysely<Database> {
  return new Kysely<Database>({
    dialect: new PostgresDialect({ pool: new pg.Pool({ connectionString, max: 5 }) }),
  });
}

/**
 * Build a Kysely instance using the Neon serverless driver.
 *
 * Use this in Cloudflare Workers when DATABASE_DRIVER="neon".
 * The Neon Pool is pg-wire-compatible so Kysely's PostgresDialect works as-is.
 *
 * Note on regions: Neon has no Seoul region — the recommended dev region is
 * Tokyo (ap-northeast-1). The signer Lambda (Seoul) does not touch the DB,
 * so this adds no signing latency.
 *
 * Alternative (no code needed): configure a Hyperdrive config pointing at Neon
 * and keep DATABASE_DRIVER unset — Hyperdrive handles connection pooling in that path.
 */
export function makeNeonDb(connectionString: string): Kysely<Database> {
  // NeonPool is pg-wire-compatible; PostgresDialect works as-is.
  // In Cloudflare Workers, @neondatabase/serverless uses the Workers-native
  // WebSocket API automatically — no extra configuration required.
  const pool = new NeonPool({ connectionString });
  return new Kysely<Database>({
    dialect: new PostgresDialect({ pool }),
  });
}
