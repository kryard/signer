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

/** Supported signing curves. */
export const CURVE = {
  SECP256K1: "CURVE_SECP256K1", // EVM (and other secp256k1 chains)
  ED25519: "CURVE_ED25519", // Solana and other ed25519 chains
} as const;
export type Curve = (typeof CURVE)[keyof typeof CURVE];

/** Address formats derived from a key's public key. */
export const ADDRESS_FORMAT = {
  ETHEREUM: "ADDRESS_FORMAT_ETHEREUM", // EIP-55 0x… (secp256k1)
  SOLANA: "ADDRESS_FORMAT_SOLANA", // base58 (ed25519)
} as const;
export type AddressFormat = (typeof ADDRESS_FORMAT)[keyof typeof ADDRESS_FORMAT];

/** Hash applied to the payload before signing. */
export const HASH_FUNCTION = {
  KECCAK256: "HASH_FUNCTION_KECCAK256", // secp256k1
  NO_OP: "HASH_FUNCTION_NO_OP", // secp256k1, pre-hashed 32-byte digest
  NOT_APPLICABLE: "HASH_FUNCTION_NOT_APPLICABLE", // ed25519 (signs the message directly)
} as const;
export type HashFunction = (typeof HASH_FUNCTION)[keyof typeof HASH_FUNCTION];
