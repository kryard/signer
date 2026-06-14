export const ACTIVITY_STATUS = {
  COMPLETED: "ACTIVITY_STATUS_COMPLETED",
  FAILED: "ACTIVITY_STATUS_FAILED",
  PENDING: "ACTIVITY_STATUS_PENDING",
} as const;
export type ActivityStatus = (typeof ACTIVITY_STATUS)[keyof typeof ACTIVITY_STATUS];

/** Activity types Kryard recognizes (from ADR-002 / wire contract). */
export const ACTIVITY_TYPE = {
  CREATE_PRIVATE_KEYS: "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
  SIGN_RAW_PAYLOAD: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
  SIGN_TRANSACTION: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
  CREATE_WALLET: "ACTIVITY_TYPE_CREATE_WALLET",
  CREATE_WALLET_ACCOUNTS: "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
} as const;
export type ActivityType = (typeof ACTIVITY_TYPE)[keyof typeof ACTIVITY_TYPE];

/** Recognized at the boundary. P1 implements NONE of the behaviors yet, so all
 *  recognized types still resolve to FAILED until their phase lands. */
export const RECOGNIZED_ACTIVITY_TYPES: ReadonlySet<string> = new Set(Object.values(ACTIVITY_TYPE));
