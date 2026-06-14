import type { ActivityStatus } from "./enums";

/** Incoming Turnkey-shaped submit body. Unknown fields are preserved in raw. */
export interface SubmitRequest {
  type: string;
  organizationId: string;
  timestampMs: string;
  parameters?: Record<string, unknown>;
}

/** A persisted activity row (DB shape; see migration 001 + 002). */
export interface ActivityRow {
  id: string;
  organization_id: string;
  type: string;
  status: ActivityStatus;
  request_body: unknown;
  canonical_hash: string;
  intent: unknown;
  result: unknown;
  failure: unknown | null;
  fingerprint: string;
  timestamp_ms: string;
  actor_id: string | null;
  auth_method: string | null;
  created_at: Date;
  updated_at: Date;
}

/** Protobuf-style timestamp as Turnkey returns it. */
export interface ProtoTimestamp {
  seconds: string;
  nanos: string;
}

/** The single-nested activity envelope (matches wire-contract.md). */
export interface ActivityEnvelope {
  activity: {
    id: string;
    organizationId: string;
    status: ActivityStatus;
    type: string;
    intent: Record<string, unknown>;
    result: Record<string, unknown>;
    votes: unknown[];
    fingerprint: string;
    canApprove: boolean;
    canReject: boolean;
    createdAt: ProtoTimestamp;
    updatedAt: ProtoTimestamp;
    failure: unknown | null;
  };
}
