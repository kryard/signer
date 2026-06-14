import type { ActivityRow, ActivityEnvelope } from "./types";
import { toProtoTimestamp } from "./time";

/** Map a persisted activity row to the single-nested Turnkey envelope. */
export function toActivityEnvelope(row: ActivityRow): ActivityEnvelope {
  return {
    activity: {
      id: row.id,
      organizationId: row.organization_id,
      status: row.status,
      type: row.type,
      intent: (row.intent as Record<string, unknown>) ?? {},
      result: (row.result as Record<string, unknown>) ?? {},
      votes: [],
      fingerprint: row.fingerprint,
      canApprove: false,
      // Real Turnkey returns canReject:true on captured (COMPLETED) responses.
      // Provisional until the consensus/approval model lands (P7); match observed.
      canReject: true,
      createdAt: toProtoTimestamp(row.created_at),
      updatedAt: toProtoTimestamp(row.updated_at),
      failure: row.failure ?? null,
    },
  };
}
