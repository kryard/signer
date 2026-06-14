import type { Kysely } from "kysely";
import type { Database } from "./db";
import type { SubmitRequest, ActivityRow } from "./types";
import type { AuthContext } from "./auth";
import type { ActivityType, ActivityStatus } from "./enums";
import { canonicalize, sha256Hex } from "./canonicalJson";
import { ACTIVITY_STATUS, ACTIVITY_TYPE, RECOGNIZED_ACTIVITY_TYPES } from "./enums";
import { TurnkeyError } from "./errors";
import { findByIdempotency, insertActivity } from "./activityRepo";
import type { NewPrivateKey, NewWallet, NewWalletAccount } from "./activityRepo";
import {
  createKey,
  signRawPayload,
  signTransaction as signerSignTransaction,
  parseTransaction,
  plainFetch,
  SignerMismatchError,
  SignerError,
} from "./signerClient";
import type { SignerCreateKeyRequest, SignerSignRawPayloadRequest, SignerSignTransactionRequest, SignerFetch } from "./signerClient";
import { resolveSignWith } from "./privateKeyRepo";
import { evaluatePolicy } from "./policy";
import { recordAuditEvent } from "./audit";

/** Context passed to every activity handler. */
export interface HandlerContext {
  db: Kysely<Database>;
  req: SubmitRequest;
  auth: AuthContext | undefined;
  signerBaseUrl: string;
  /** Gate for raw-payload signing. Defaults false; replaced by policy check in P7. */
  allowRawPayloadSigning: boolean;
  /**
   * When true, orgs with zero policy_bindings are allowed through (bypass mode).
   * Defaults false (fail-closed). Set via POLICY_BYPASS_ALLOWED=true for dev/test only.
   */
  policyBypassAllowed: boolean;
  /** Transport for signer HTTP calls (plain or SigV4). Defaults to plainFetch. */
  signerFetch: SignerFetch;
}

/** Return value of every activity handler: the fields to persist on the activity row.
 *
 *  Side-effect arrays (privateKeys, wallets, walletAccounts) are written inside the
 *  SAME transaction as the activity + idempotency key, so there is no window where
 *  orphan rows can exist (CRITICAL-2). All or nothing: an idempotency race rolls
 *  back the whole transaction. */
export interface HandlerResult {
  status: ActivityStatus;
  intent: unknown;
  result: unknown;
  failure: unknown | null;
  /** Private key rows to persist atomically with the activity. */
  privateKeys?: NewPrivateKey[];
  /** Wallet rows to persist atomically with the activity. */
  wallets?: NewWallet[];
  /** Wallet account rows to persist atomically with the activity. */
  walletAccounts?: NewWalletAccount[];
  /** Signer receipt to persist on the activity row (P7). */
  signerReceipt?: unknown;
  /** Policy decision data to record after activity insert (P7). */
  policyDecision?: {
    privateKeyId: string;
    outcome: string;
    reasonCode: string;
    evaluatedInputHash: string;
  };
}

type ActivityHandler = (ctx: HandlerContext) => Promise<HandlerResult>;

// ---------------------------------------------------------------------------
// notImplemented — used for recognized-but-unimplemented activity types.
// Preserves the pre-handler-map FAILED behavior so existing tests still pass.
// ---------------------------------------------------------------------------
const notImplemented: ActivityHandler = async ({ req }) => ({
  status: ACTIVITY_STATUS.FAILED,
  intent: {},
  result: {},
  failure: { code: "ACTIVITY_NOT_IMPLEMENTED", message: `${req.type} is not implemented yet` },
});

// ---------------------------------------------------------------------------
// create_private_keys handler
// ---------------------------------------------------------------------------
const createPrivateKeys: ActivityHandler = async ({ req, signerBaseUrl, signerFetch }) => {
  const params = (req.parameters ?? {}) as Record<string, unknown>;
  const name = typeof params.name === "string" ? params.name : "unnamed";
  const environment = typeof params.environment === "string" ? params.environment : "production";
  const importPrivateKeyHex = typeof params.importPrivateKeyHex === "string"
    ? params.importPrivateKeyHex
    : undefined;

  // Generate a stable private_key_id for this key before we call the signer,
  // so the encryption context is bound to a real id that we will store.
  const { randomUUID } = await import("node:crypto");
  const privateKeyId = randomUUID();

  const signerReq: SignerCreateKeyRequest = {
    organizationId: req.organizationId,
    privateKeyId,
    environment,
    name,
    ...(importPrivateKeyHex !== undefined ? { importPrivateKeyHex } : {}),
  };

  const signerResp = await createKey(signerBaseUrl, signerReq, signerFetch);

  // Do NOT insert the private_keys row here. Return the key data in HandlerResult
  // so that dispatchSubmit can write it atomically with the activity row inside a
  // single transaction (CRITICAL-2: no orphan key possible on concurrent identical
  // requests — the idempotency unique-violation rolls back the whole transaction).
  const addresses = signerResp.addresses;
  const primaryAddress = addresses[0] ?? "";

  const privateKey: NewPrivateKey = {
    id: privateKeyId,
    organizationId: req.organizationId,
    name,
    curve: signerResp.curve,
    publicKey: signerResp.publicKey,
    addresses: JSON.stringify(addresses),
    encryptedPrivateKey: signerResp.encryptedPrivateKey,
    encryptedDataKey: signerResp.encryptedDataKey,
    kmsProvider: signerResp.kmsProvider,
    kmsKeyId: signerResp.kmsKeyId,
    encryptionContext: JSON.stringify(signerResp.encryptionContext),
  };

  return {
    status: ACTIVITY_STATUS.COMPLETED,
    intent: {
      createPrivateKeysIntent: {
        privateKeys: [{ privatekeyName: name, curve: signerResp.curve, addressFormats: [] }],
      },
    },
    result: {
      createPrivateKeysResult: {
        privateKeyIds: [privateKeyId],
        addresses: [{ address: primaryAddress }],
      },
    },
    failure: null,
    privateKeys: [privateKey],
  };
};

// ---------------------------------------------------------------------------
// Helper: mint one secp256k1 key via the signer + build NewPrivateKey row data.
// ---------------------------------------------------------------------------
async function mintKey(
  signerBaseUrl: string,
  organizationId: string,
  name: string,
  environment: string,
  signerFetch: SignerFetch = plainFetch,
): Promise<{ privateKey: NewPrivateKey; address: string; privateKeyId: string }> {
  const { randomUUID } = await import("node:crypto");
  const privateKeyId = randomUUID();

  const signerReq: SignerCreateKeyRequest = {
    organizationId,
    privateKeyId,
    environment,
    name,
  };

  const signerResp = await createKey(signerBaseUrl, signerReq, signerFetch);
  const primaryAddress = signerResp.addresses[0] ?? "";

  const privateKey: NewPrivateKey = {
    id: privateKeyId,
    organizationId,
    name,
    curve: signerResp.curve,
    publicKey: signerResp.publicKey,
    addresses: JSON.stringify(signerResp.addresses),
    encryptedPrivateKey: signerResp.encryptedPrivateKey,
    encryptedDataKey: signerResp.encryptedDataKey,
    kmsProvider: signerResp.kmsProvider,
    kmsKeyId: signerResp.kmsKeyId,
    encryptionContext: JSON.stringify(signerResp.encryptionContext),
  };

  return { privateKey, address: primaryAddress, privateKeyId };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const MAX_ACCOUNTS = 20;

// ---------------------------------------------------------------------------
// create_wallet handler
// ---------------------------------------------------------------------------
const createWallet: ActivityHandler = async ({ req, signerBaseUrl, signerFetch }) => {
  const params = (req.parameters ?? {}) as Record<string, unknown>;
  const walletName = typeof params.walletName === "string" ? params.walletName : "unnamed";
  const environment = typeof params.environment === "string" ? params.environment : "production";
  const accountsParam = Array.isArray(params.accounts) ? params.accounts as Record<string, unknown>[] : [];

  if (accountsParam.length > MAX_ACCOUNTS) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: {},
      result: {},
      failure: { code: "TOO_MANY_ACCOUNTS", message: "max 20 accounts per request" },
    };
  }

  const { randomUUID } = await import("node:crypto");
  const walletId = randomUUID();

  const wallet: NewWallet = {
    id: walletId,
    organizationId: req.organizationId,
    name: walletName,
  };

  // Provision accounts if requested (same path as create_wallet_accounts).
  const privateKeys: NewPrivateKey[] = [];
  const walletAccounts: NewWalletAccount[] = [];
  const addresses: string[] = [];

  for (const acct of accountsParam) {
    const acctName = typeof acct.name === "string" ? acct.name : walletName;
    const curve = typeof acct.curve === "string" ? acct.curve : "CURVE_SECP256K1";
    const addressFormat = typeof acct.addressFormat === "string" ? acct.addressFormat : "ADDRESS_FORMAT_ETHEREUM";
    const path = typeof acct.path === "string" ? acct.path : null;

    const { privateKey, address, privateKeyId } = await mintKey(
      signerBaseUrl,
      req.organizationId,
      acctName,
      environment,
      signerFetch,
    );

    const walletAccountId = randomUUID();
    const walletAccount: NewWalletAccount = {
      id: walletAccountId,
      organizationId: req.organizationId,
      walletId,
      privateKeyId,
      curve,
      addressFormat,
      address,
      path,
    };

    privateKeys.push(privateKey);
    walletAccounts.push(walletAccount);
    addresses.push(address);
  }

  return {
    status: ACTIVITY_STATUS.COMPLETED,
    intent: {
      createWalletIntent: {
        walletName,
        accounts: accountsParam,
      },
    },
    result: {
      createWalletResult: {
        walletId,
        addresses,
      },
    },
    failure: null,
    wallets: [wallet],
    privateKeys,
    walletAccounts,
  };
};

// ---------------------------------------------------------------------------
// create_wallet_accounts handler
// ---------------------------------------------------------------------------
const createWalletAccounts: ActivityHandler = async ({ req, db, signerBaseUrl, signerFetch }) => {
  const params = (req.parameters ?? {}) as Record<string, unknown>;
  const walletId = typeof params.walletId === "string" ? params.walletId : "";
  const environment = typeof params.environment === "string" ? params.environment : "production";
  const accountsParam = Array.isArray(params.accounts) ? params.accounts as Record<string, unknown>[] : [];

  if (!walletId) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: {},
      result: {},
      failure: { code: "MISSING_WALLET_ID", message: "walletId is required" },
    };
  }

  // HIGH: Verify wallet belongs to the calling organization before minting any keys.
  const walletRow = await db
    .selectFrom("wallets")
    .select(["id"])
    .where("id", "=", walletId)
    .where("organization_id", "=", req.organizationId)
    .where("deleted_at", "is", null)
    .executeTakeFirst();

  if (!walletRow) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: {},
      result: {},
      failure: { code: "WALLET_NOT_FOUND", message: "wallet not found or not owned by organization" },
    };
  }

  if (accountsParam.length > MAX_ACCOUNTS) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: {},
      result: {},
      failure: { code: "TOO_MANY_ACCOUNTS", message: "max 20 accounts per request" },
    };
  }

  const { randomUUID } = await import("node:crypto");
  const privateKeys: NewPrivateKey[] = [];
  const walletAccounts: NewWalletAccount[] = [];
  const addresses: string[] = [];

  for (const acct of accountsParam) {
    const acctName = typeof acct.name === "string" ? acct.name : "account";
    const curve = typeof acct.curve === "string" ? acct.curve : "CURVE_SECP256K1";
    const addressFormat = typeof acct.addressFormat === "string" ? acct.addressFormat : "ADDRESS_FORMAT_ETHEREUM";
    const path = typeof acct.path === "string" ? acct.path : null;

    const { privateKey, address, privateKeyId } = await mintKey(
      signerBaseUrl,
      req.organizationId,
      acctName,
      environment,
      signerFetch,
    );

    const walletAccountId = randomUUID();
    const walletAccount: NewWalletAccount = {
      id: walletAccountId,
      organizationId: req.organizationId,
      walletId,
      privateKeyId,
      curve,
      addressFormat,
      address,
      path,
    };

    privateKeys.push(privateKey);
    walletAccounts.push(walletAccount);
    addresses.push(address);
  }

  return {
    status: ACTIVITY_STATUS.COMPLETED,
    intent: {
      createWalletAccountsIntent: {
        walletId,
        accounts: accountsParam,
      },
    },
    result: {
      createWalletAccountsResult: {
        addresses,
      },
    },
    failure: null,
    privateKeys,
    walletAccounts,
  };
};

// ---------------------------------------------------------------------------
// sign_raw_payload handler
// ---------------------------------------------------------------------------
const signRawPayloadHandler: ActivityHandler = async ({ req, db, signerBaseUrl, auth, allowRawPayloadSigning, policyBypassAllowed, signerFetch }) => {
  const params = (req.parameters ?? {}) as Record<string, unknown>;
  const signWith = typeof params.signWith === "string" ? params.signWith : "";
  const payload = typeof params.payload === "string" ? params.payload : "";
  const encoding = typeof params.encoding === "string" ? params.encoding : "PAYLOAD_ENCODING_HEXADECIMAL";
  const hashFunction = typeof params.hashFunction === "string" ? params.hashFunction : "HASH_FUNCTION_NO_OP";

  if (!signWith) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: { signRawPayloadIntent: params },
      result: {},
      failure: { code: "MISSING_SIGN_WITH", message: "signWith is required" },
    };
  }

  // Resolve signWith (Ethereum address or private-key id) to the ciphertext row.
  const keyRow = await resolveSignWith(db, req.organizationId, signWith);
  if (!keyRow) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: { signRawPayloadIntent: params },
      result: {},
      failure: { code: "PRIVATE_KEY_NOT_FOUND", message: `key not found for signWith: ${signWith}` },
    };
  }

  const actorId = auth?.actorId ?? "";
  // Fail-closed (security): never proceed without an authenticated actor. An empty
  // actorId must NOT skip policy — otherwise the path below reaches ALLOW unchecked.
  if (!actorId) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: {},
      result: {},
      failure: { code: "ACTOR_NOT_BOUND", message: "no authenticated actor for policy evaluation" },
    };
  }
  let policyResult;
  if (actorId) {
    policyResult = await evaluatePolicy(db, {
      organizationId: req.organizationId,
      actorId,
      activityType: req.type,
      privateKeyId: keyRow.id,
      rawPayload: payload,
      policyBypassAllowed,
    });

    if (policyResult.outcome === "DENY") {
      return {
        status: ACTIVITY_STATUS.FAILED,
        intent: { signRawPayloadIntent: params },
        result: {},
        failure: { code: policyResult.reasonCode, message: `policy denied: ${policyResult.reasonCode}` },
        policyDecision: {
          privateKeyId: keyRow.id,
          outcome: "DENY",
          reasonCode: policyResult.reasonCode,
          evaluatedInputHash: policyResult.evaluatedInputHash,
        },
      };
    }
  }

  // Env gate (backwards-compat): when no policy is configured for the org, fall back
  // to the allowRawPayloadSigning env flag. When policy IS configured and allows raw
  // payload, the env gate is bypassed (policy governs).
  const policyBypassed = policyResult === undefined || policyResult.isPolicyBypassed;
  if (policyBypassed && !allowRawPayloadSigning) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: { signRawPayloadIntent: params },
      result: {},
      failure: { code: "RAW_PAYLOAD_SIGNING_DISABLED", message: "raw payload signing is disabled; set ALLOW_RAW_PAYLOAD_SIGNING=true to enable" },
    };
  }

  // Forward the ciphertext + encryption context to the signer.
  // The API never decrypts — only the signer does.
  const signerReq: SignerSignRawPayloadRequest = {
    organizationId: req.organizationId,
    privateKeyId: keyRow.id,
    environment: keyRow.encryptionContext.environment ?? "production",
    encryptedPrivateKey: keyRow.encryptedPrivateKey,
    encryptedDataKey: keyRow.encryptedDataKey,
    kmsKeyId: keyRow.kmsKeyId,
    kmsProvider: keyRow.kmsProvider,
    encryptionContext: keyRow.encryptionContext,
    payload,
    hashFunction,
    evaluatedInputHash: policyResult?.evaluatedInputHash,
    activityType: req.type,
  };

  let signerResp;
  try {
    signerResp = await signRawPayload(signerBaseUrl, signerReq, signerFetch);
  } catch (err) {
    if (err instanceof SignerMismatchError) {
      // Emit a high-severity audit event for the mismatch.
      await recordAuditEvent(db, {
        organizationId: req.organizationId,
        actorId: auth?.actorId,
        eventType: "SIGNER_REQUEST_MISMATCH",
        metadata: { privateKeyId: keyRow.id, activityType: req.type },
      });
      return {
        status: ACTIVITY_STATUS.FAILED,
        intent: { signRawPayloadIntent: params },
        result: {},
        failure: { code: "SIGNER_REQUEST_MISMATCH", message: "signer policy re-check failed: evaluatedInputHash mismatch" },
        policyDecision: policyResult ? {
          privateKeyId: keyRow.id,
          outcome: "DENY",
          reasonCode: "SIGNER_REQUEST_MISMATCH",
          evaluatedInputHash: policyResult.evaluatedInputHash,
        } : undefined,
      };
    }
    if (err instanceof SignerError) {
      // Transient errors (5xx) → PENDING; hard errors (4xx) → FAILED.
      return {
        status: err.isTransient ? ACTIVITY_STATUS.PENDING : ACTIVITY_STATUS.FAILED,
        intent: { signRawPayloadIntent: params },
        result: {},
        failure: { code: "SIGNER_ERROR", message: err.message },
      };
    }
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: { signRawPayloadIntent: params },
      result: {},
      failure: { code: "SIGNER_ERROR", message: "signer returned an error; check payload and hash function" },
    };
  }

  return {
    status: ACTIVITY_STATUS.COMPLETED,
    intent: {
      signRawPayloadIntent: {
        signWith,
        payload,
        encoding,
        hashFunction,
      },
    },
    result: {
      signRawPayloadResult: {
        r: signerResp.r,
        s: signerResp.s,
        v: signerResp.v,
        // signerReceipt included in result for backwards-compat with existing tests.
        // Also persisted separately in activities.signer_receipt (P7).
        signerReceipt: signerResp.signerReceipt,
      },
    },
    failure: null,
    signerReceipt: signerResp.signerReceipt,
    policyDecision: policyResult ? {
      privateKeyId: keyRow.id,
      outcome: "ALLOW",
      reasonCode: "ALLOW",
      evaluatedInputHash: policyResult.evaluatedInputHash,
    } : undefined,
  };
};

// ---------------------------------------------------------------------------
// sign_transaction handler
// ---------------------------------------------------------------------------
const signTransactionHandler: ActivityHandler = async ({ req, db, signerBaseUrl, auth, policyBypassAllowed, signerFetch }) => {
  const params = (req.parameters ?? {}) as Record<string, unknown>;
  const signWith = typeof params.signWith === "string" ? params.signWith : "";
  const unsignedTransaction =
    typeof params.unsignedTransaction === "string" ? params.unsignedTransaction : "";
  const txType =
    typeof params.type === "string" ? params.type : "TRANSACTION_TYPE_ETHEREUM";

  if (!signWith) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: { signTransactionIntent: params },
      result: {},
      failure: { code: "MISSING_SIGN_WITH", message: "signWith is required" },
    };
  }

  if (!unsignedTransaction) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: { signTransactionIntent: params },
      result: {},
      failure: { code: "MISSING_UNSIGNED_TRANSACTION", message: "unsignedTransaction is required" },
    };
  }

  // Resolve signWith (Ethereum address or private-key id) to the ciphertext row.
  // The API never decrypts — we pass ciphertext + encryption context to the signer.
  let keyRow;
  try {
    keyRow = await resolveSignWith(db, req.organizationId, signWith);
  } catch {
    // Postgres may reject malformed UUIDs with a syntax error; treat as not found.
    keyRow = null;
  }
  if (!keyRow) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: { signTransactionIntent: params },
      result: {},
      failure: {
        code: "PRIVATE_KEY_NOT_FOUND",
        message: `key not found for signWith: ${signWith}`,
      },
    };
  }

  // Policy evaluation: parse tx fields first (no signing), then evaluate policy.
  const actorId = auth?.actorId ?? "";
  // Fail-closed (security): never proceed without an authenticated actor. An empty
  // actorId must NOT skip policy — otherwise the path below reaches ALLOW unchecked.
  if (!actorId) {
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: {},
      result: {},
      failure: { code: "ACTOR_NOT_BOUND", message: "no authenticated actor for policy evaluation" },
    };
  }
  let policyResult;

  if (actorId) {
    // Parse tx fields via signer parse endpoint (no key, no signing).
    let txFields;
    try {
      txFields = await parseTransaction(signerBaseUrl, { unsignedTransaction }, signerFetch);
    } catch {
      return {
        status: ACTIVITY_STATUS.FAILED,
        intent: { signTransactionIntent: params },
        result: {},
        failure: { code: "TX_PARSE_ERROR", message: "failed to parse unsignedTransaction for policy evaluation" },
      };
    }

    policyResult = await evaluatePolicy(db, {
      organizationId: req.organizationId,
      actorId,
      activityType: req.type,
      privateKeyId: keyRow.id,
      txFields,
      policyBypassAllowed,
    });

    if (policyResult.outcome === "DENY") {
      return {
        status: ACTIVITY_STATUS.FAILED,
        intent: { signTransactionIntent: params },
        result: {},
        failure: { code: policyResult.reasonCode, message: `policy denied: ${policyResult.reasonCode}` },
        policyDecision: {
          privateKeyId: keyRow.id,
          outcome: "DENY",
          reasonCode: policyResult.reasonCode,
          evaluatedInputHash: policyResult.evaluatedInputHash,
        },
      };
    }
  }

  // Forward the ciphertext + encryption context to the signer.
  // The API service NEVER decrypts keys — only the signer does.
  const signerReq: SignerSignTransactionRequest = {
    organizationId: req.organizationId,
    privateKeyId: keyRow.id,
    environment: keyRow.encryptionContext.environment ?? "production",
    encryptedPrivateKey: keyRow.encryptedPrivateKey,
    encryptedDataKey: keyRow.encryptedDataKey,
    kmsKeyId: keyRow.kmsKeyId,
    kmsProvider: keyRow.kmsProvider,
    encryptionContext: keyRow.encryptionContext,
    unsignedTransaction,
    type: txType,
    evaluatedInputHash: policyResult?.evaluatedInputHash,
    activityType: req.type,
  };

  let signerResp;
  try {
    signerResp = await signerSignTransaction(signerBaseUrl, signerReq, signerFetch);
  } catch (err) {
    if (err instanceof SignerMismatchError) {
      // High-severity audit event for the mismatch.
      await recordAuditEvent(db, {
        organizationId: req.organizationId,
        actorId: auth?.actorId,
        eventType: "SIGNER_REQUEST_MISMATCH",
        metadata: { privateKeyId: keyRow.id, activityType: req.type },
      });
      return {
        status: ACTIVITY_STATUS.FAILED,
        intent: { signTransactionIntent: params },
        result: {},
        failure: { code: "SIGNER_REQUEST_MISMATCH", message: "signer policy re-check failed: evaluatedInputHash mismatch" },
        policyDecision: policyResult ? {
          privateKeyId: keyRow.id,
          outcome: "DENY",
          reasonCode: "SIGNER_REQUEST_MISMATCH",
          evaluatedInputHash: policyResult.evaluatedInputHash,
        } : undefined,
      };
    }
    if (err instanceof SignerError) {
      // Transient errors (5xx) → PENDING; hard errors (4xx) → FAILED.
      return {
        status: err.isTransient ? ACTIVITY_STATUS.PENDING : ACTIVITY_STATUS.FAILED,
        intent: { signTransactionIntent: params },
        result: {},
        failure: {
          code: "SIGNER_ERROR",
          message: err.message,
        },
      };
    }
    return {
      status: ACTIVITY_STATUS.FAILED,
      intent: { signTransactionIntent: params },
      result: {},
      failure: {
        code: "SIGNER_ERROR",
        message: "signer returned an error; check unsignedTransaction encoding",
      },
    };
  }

  return {
    status: ACTIVITY_STATUS.COMPLETED,
    intent: {
      signTransactionIntent: {
        signWith,
        unsignedTransaction,
        type: txType,
      },
    },
    result: {
      signTransactionResult: {
        // Strip the 0x prefix to match Turnkey's wire format byte-for-byte
        // (frozen contract: signedTransaction is hex WITHOUT 0x — see
        // tools/compat-harness/wire-contract.md). The signer-internal API returns
        // it 0x-prefixed; a drop-in client that prepends 0x before broadcast would
        // otherwise get "0x0x…".
        signedTransaction: signerResp.signedTransaction.replace(/^0x/i, ""),
        // fields is stashed here for metadata; not part of the public Turnkey wire shape.
        fields: signerResp.fields,
        // signerReceipt is included in result for backwards-compat with existing tests.
        // It is also persisted separately in activities.signer_receipt (P7).
        signerReceipt: signerResp.signerReceipt,
      },
    },
    failure: null,
    signerReceipt: signerResp.signerReceipt,
    policyDecision: policyResult ? {
      privateKeyId: keyRow.id,
      outcome: "ALLOW",
      reasonCode: "ALLOW",
      evaluatedInputHash: policyResult.evaluatedInputHash,
    } : undefined,
  };
};

// ---------------------------------------------------------------------------
// Per-type handler map. Every recognized type must appear here.
// ---------------------------------------------------------------------------
const HANDLERS: Record<ActivityType, ActivityHandler> = {
  [ACTIVITY_TYPE.CREATE_PRIVATE_KEYS]: createPrivateKeys,
  [ACTIVITY_TYPE.SIGN_RAW_PAYLOAD]: signRawPayloadHandler,
  [ACTIVITY_TYPE.SIGN_TRANSACTION]: signTransactionHandler,
  [ACTIVITY_TYPE.CREATE_WALLET]: createWallet,
  [ACTIVITY_TYPE.CREATE_WALLET_ACCOUNTS]: createWalletAccounts,
};

// ---------------------------------------------------------------------------
// dispatchSubmit — idempotency + handler dispatch + persistence.
// ---------------------------------------------------------------------------

/** Idempotently record a submitted activity via the handler map.
 *  - Unknown activity type → 400 TurnkeyError (matches real Turnkey; never stored).
 *  - Recognized type → delegate to the per-type handler. */
export async function dispatchSubmit(
  db: Kysely<Database>,
  req: SubmitRequest,
  auth?: AuthContext,
  signerBaseUrl = "http://localhost:8081",
  allowRawPayloadSigning = false,
  policyBypassAllowed = false,
  signerFetch: SignerFetch = plainFetch,
): Promise<ActivityRow> {
  if (!RECOGNIZED_ACTIVITY_TYPES.has(req.type)) {
    throw new TurnkeyError(400, `Invalid activity type: ("${req.type}"), try updating your SDK versions`);
  }

  // Idempotency hash covers the FULL body (incl. timestampMs): identical bodies
  // collapse, a changed timestamp makes a new activity (Turnkey's rule).
  // NOTE: The hash is computed over the ORIGINAL request body (including any
  // importPrivateKeyHex) so that identical import requests still collapse to the
  // same activity. The raw key is stripped from the PERSISTED copy only (see below).
  const canonicalHash = await sha256Hex(canonicalize(req));

  const existing = await findByIdempotency(db, req.organizationId, canonicalHash);
  if (existing) return existing;

  // Fingerprint identifies WHAT is being done (type + parameters), independent of
  // timestamp, so retries of the same intent share a fingerprint.
  const fingerprint = `sha256:${await sha256Hex(canonicalize({ type: req.type, parameters: req.parameters ?? {} }))}`;

  const handler = HANDLERS[req.type as ActivityType];
  // handler is always defined because RECOGNIZED_ACTIVITY_TYPES mirrors HANDLERS keys,
  // but keep the guard to satisfy the type-checker.
  if (!handler) {
    throw new TurnkeyError(400, `Invalid activity type: ("${req.type}"), try updating your SDK versions`);
  }

  const ctx: HandlerContext = {
    db,
    req,
    auth,
    signerBaseUrl,
    allowRawPayloadSigning,
    policyBypassAllowed,
    signerFetch,
  };
  const handlerResult = await handler(ctx);

  // CRITICAL-1: Scrub importPrivateKeyHex from the request body before it is
  // persisted to the activities table. The raw private key must NEVER reach
  // Postgres. The idempotency hash above was computed over the original body so
  // identical imports still collapse correctly.
  const { importPrivateKeyHex: _stripped, ...parametersWithoutKey } =
    (req.parameters ?? {}) as Record<string, unknown>;
  const safeRequestBody: SubmitRequest = {
    ...req,
    parameters: parametersWithoutKey,
  };

  const row = await insertActivity(db, canonicalHash, {
    organizationId: req.organizationId,
    type: req.type,
    status: handlerResult.status,
    // Store the scrubbed copy — importPrivateKeyHex removed.
    requestBody: safeRequestBody,
    canonicalHash,
    intent: handlerResult.intent,
    result: handlerResult.result,
    failure: handlerResult.failure,
    fingerprint,
    timestampMs: req.timestampMs,
    actorId: auth?.actorId ?? null,
    authMethod: auth?.authMethod ?? null,
    signerReceipt: handlerResult.signerReceipt ?? null,
    // Side-effect arrays written atomically (CRITICAL-2: idempotency race rolls
    // back everything, no orphan rows ever committed).
    privateKeys: handlerResult.privateKeys,
    wallets: handlerResult.wallets,
    walletAccounts: handlerResult.walletAccounts,
  });

  // Persist the policy decision (if any) — best-effort, non-atomic with the activity.
  if (handlerResult.policyDecision) {
    const pd = handlerResult.policyDecision;
    try {
      await db.insertInto("policy_decisions").values({
        organization_id: req.organizationId,
        activity_id: row.id,
        private_key_id: pd.privateKeyId,
        outcome: pd.outcome,
        reason_code: pd.reasonCode,
        evaluated_input_hash: pd.evaluatedInputHash,
        policy_version: "v1",
      }).execute();
    } catch (err) {
      console.warn(`policy_decisions insert failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return row;
}
