import { describe, it, expect } from "vitest";
import { toActivityEnvelope } from "../src/activityResponse";
import { ACTIVITY_STATUS } from "../src/enums";
import type { ActivityRow } from "../src/types";

const row: ActivityRow = {
  id: "act-1",
  organization_id: "org-1",
  type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
  status: ACTIVITY_STATUS.FAILED,
  request_body: {},
  canonical_hash: "abc",
  intent: {},
  result: {},
  failure: { code: "UNSUPPORTED", message: "not implemented in P1" },
  fingerprint: "sha256:abc",
  timestamp_ms: "1780000000000",
  actor_id: null,
  auth_method: null,
  created_at: new Date(1780422786000),
  updated_at: new Date(1780422786000),
};

describe("toActivityEnvelope", () => {
  it("produces the single-nested shape (no result.activity)", () => {
    const env = toActivityEnvelope(row);
    expect(env.activity.id).toBe("act-1");
    expect(env.activity.status).toBe("ACTIVITY_STATUS_FAILED");
    expect(env.activity.createdAt).toEqual({ seconds: "1780422786", nanos: "0" });
    expect(env.activity.votes).toEqual([]);
    expect(env.activity.canReject).toBe(true);
    expect(env.activity.failure).toEqual({ code: "UNSUPPORTED", message: "not implemented in P1" });
    // Guard against regressing to the wrong double-nested shape.
    expect((env.activity.result as Record<string, unknown>).activity).toBeUndefined();
  });
});
