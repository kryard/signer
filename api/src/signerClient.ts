import { AwsClient } from "aws4fetch";
import { TurnkeyError } from "./errors";

// ---------------------------------------------------------------------------
// Transport abstraction — allows injecting SigV4 for Lambda Function URL (IAM)
// or plain fetch for local / unauthenticated signer endpoints.
// ---------------------------------------------------------------------------

/** A fetch-compatible function used to call the signer. */
export type SignerFetch = (url: string, init: RequestInit) => Promise<Response>;

/** Plain fetch transport (default — local signer, no IAM auth). */
export const plainFetch: SignerFetch = (url, init) => fetch(url, init);

/** SigV4 fetch transport for Lambda Function URL with `authorization_type = AWS_IAM`.
 *
 * The `service` is `"lambda"` — that is what AWS Function URLs require for
 * SigV4 signing regardless of the actual AWS service name in the ARN.
 */
export function sigv4Fetch(creds: {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  sessionToken?: string;
}): SignerFetch {
  const client = new AwsClient({
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    sessionToken: creds.sessionToken,
    region: creds.region,
    service: "lambda",
  });
  return (url, init) => client.fetch(url, init);
}

/** Thrown when the signer returns 409 SIGNER_REQUEST_MISMATCH.
 *  This is a HARD failure — the policy binding hash did not match what the
 *  signer was about to sign. The activity must be marked FAILED. */
export class SignerMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignerMismatchError";
  }
}

/** Thrown when the signer returns a non-409, non-2xx response.
 *  isTransient=true means the activity should be marked PENDING (retryable),
 *  false means FAILED. */
export class SignerError extends Error {
  readonly httpStatus: number;
  readonly isTransient: boolean;
  constructor(httpStatus: number, message: string, isTransient: boolean) {
    super(message);
    this.name = "SignerError";
    this.httpStatus = httpStatus;
    this.isTransient = isTransient;
  }
}

/** Request body for POST /internal/keys/create. */
export interface SignerCreateKeyRequest {
  organizationId: string;
  privateKeyId: string;
  environment: string;
  name: string;
  importPrivateKeyHex?: string;
}

/** Response body from POST /internal/keys/create.
 *  All key material is encrypted; no plaintext is ever returned. */
export interface SignerCreateKeyResponse {
  privateKeyId: string;
  publicKey: string;
  addresses: string[];
  curve: string;
  encryptedPrivateKey: string; // base64(nonce||GCM(privKey)) under DEK
  encryptedDataKey: string;    // base64(wrapped DEK)
  kmsProvider: string;
  kmsKeyId: string;
  encryptionContext: Record<string, string>;
}

/** Request body for POST /internal/sign/raw-payload. */
export interface SignerSignRawPayloadRequest {
  organizationId: string;
  privateKeyId: string;
  environment: string;
  encryptedPrivateKey: string; // base64
  encryptedDataKey: string;    // base64
  kmsKeyId: string;
  kmsProvider: string;         // "local" | "aws"; forwarded from the key row
  encryptionContext: Record<string, string>;
  payload: string;      // hex string (with or without 0x prefix)
  hashFunction: string; // HASH_FUNCTION_KECCAK256 | HASH_FUNCTION_NO_OP
  /** Policy binding hash to re-check in the signer. If present, signer verifies it. */
  evaluatedInputHash?: string;
  /** Activity type forwarded for the evaluatedInputHash computation in the signer. */
  activityType?: string;
}

/** Signer receipt returned with each signing operation. */
export interface SignerReceipt {
  keyId: string;
  publicKey: string;
  payloadHash: string;
  signatureHash: string;
  signerBuildId: string;
}

/** Response body from POST /internal/sign/raw-payload. */
export interface SignerSignRawPayloadResponse {
  r: string; // 32-byte hex, no 0x
  s: string; // 32-byte hex, no 0x
  v: string; // "00" or "01"
  signerReceipt: SignerReceipt;
}

/** Request body for POST /internal/parse/transaction (decode-only, no key material). */
export interface SignerParseTransactionRequest {
  unsignedTransaction: string; // hex string (with or without 0x prefix)
}

/** Request body for POST /internal/sign/transaction. */
export interface SignerSignTransactionRequest {
  organizationId: string;
  privateKeyId: string;
  environment: string;
  encryptedPrivateKey: string; // base64
  encryptedDataKey: string;    // base64
  kmsKeyId: string;
  kmsProvider: string;         // "local" | "aws"; forwarded from the key row
  encryptionContext: Record<string, string>;
  unsignedTransaction: string; // hex string (with or without 0x prefix)
  type: string;                // e.g. TRANSACTION_TYPE_ETHEREUM
  /** Policy binding hash to re-check in the signer. If present, signer verifies it. */
  evaluatedInputHash?: string;
  /** Activity type forwarded for the evaluatedInputHash computation in the signer. */
  activityType?: string;
}

/** Policy-relevant fields extracted from the decoded transaction. */
export interface TxFields {
  chainId: string;
  to?: string;
  value: string;
  nonce: number;
  gas: number;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  gasPrice?: string;
  data: string;
  methodSelector?: string;
  /** EIP-7702 (type-4) delegation target addresses from the authorization_list.
   *  Present only for type-4 txs; policy allowlists these delegate impls since
   *  the tx `to` is the user's own delegated EOA, not a fixed router. */
  authorizationAddresses?: string[];
  /** EIP-7702 (type-4) recovered authorizing EOAs (one per authorization).
   *  Policy requires the tx `to` to be one of these — a 7702 sweep must call an
   *  EOA that actually authorized the delegation, never an arbitrary target. */
  authorizationAuthorities?: string[];
}

/** Response body from POST /internal/sign/transaction. */
export interface SignerSignTransactionResponse {
  signedTransaction: string; // 0x-prefixed hex
  fields: TxFields;
  signerReceipt: SignerReceipt;
}

/**
 * POST ${baseUrl}/internal/parse/transaction — ask the signer to decode and
 * extract policy-relevant fields from an unsigned EVM transaction WITHOUT signing.
 * No key material required. Used by the API to get tx fields for policy evaluation
 * BEFORE the signer is asked to sign.
 *
 * Throws TurnkeyError(400) on malformed tx, TurnkeyError(500) on signer unavailable.
 */
export async function parseTransaction(
  baseUrl: string,
  input: SignerParseTransactionRequest,
  signerFetch: SignerFetch = plainFetch,
): Promise<TxFields> {
  let res: Response;
  try {
    res = await signerFetch(`${baseUrl}/internal/parse/transaction`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new TurnkeyError(500, "signer unavailable");
  }

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new TurnkeyError(res.status >= 400 && res.status < 500 ? 400 : 500, `signer parse error: ${body}`);
  }

  return res.json() as Promise<TxFields>;
}

/**
 * POST ${baseUrl}/internal/sign/transaction — ask the signer to decrypt the
 * envelope-encrypted key, decode+sign the unsigned EVM transaction, zeroize
 * the key, and return the signed transaction plus policy-relevant fields.
 * The API service NEVER decrypts keys.
 *
 * Throws TurnkeyError(500) on any non-2xx response.
 */
export async function signTransaction(
  baseUrl: string,
  input: SignerSignTransactionRequest,
  signerFetch: SignerFetch = plainFetch,
): Promise<SignerSignTransactionResponse> {
  let res: Response;
  try {
    res = await signerFetch(`${baseUrl}/internal/sign/transaction`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new TurnkeyError(500, "signer unavailable");
  }

  if (res.status === 409) {
    // SIGNER_REQUEST_MISMATCH: the signer's policy re-check failed.
    throw new SignerMismatchError("SIGNER_REQUEST_MISMATCH: evaluatedInputHash mismatch");
  }

  if (!res.ok) {
    // 4xx = hard failure (bad request); 5xx = transient (treat as PENDING).
    const isTransient = res.status >= 500;
    throw new SignerError(res.status, "signer sign_transaction error", isTransient);
  }

  return res.json() as Promise<SignerSignTransactionResponse>;
}

/**
 * POST ${baseUrl}/internal/sign/raw-payload — ask the signer to decrypt the
 * envelope-encrypted key, sign the payload, zeroize the key, and return r/s/v
 * plus a signer receipt. The API service NEVER decrypts keys.
 *
 * Throws TurnkeyError(500) on any non-2xx response.
 */
export async function signRawPayload(
  baseUrl: string,
  input: SignerSignRawPayloadRequest,
  signerFetch: SignerFetch = plainFetch,
): Promise<SignerSignRawPayloadResponse> {
  let res: Response;
  try {
    res = await signerFetch(`${baseUrl}/internal/sign/raw-payload`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new TurnkeyError(500, "signer unavailable");
  }

  if (res.status === 409) {
    // SIGNER_REQUEST_MISMATCH: the signer's policy re-check failed.
    throw new SignerMismatchError("SIGNER_REQUEST_MISMATCH: evaluatedInputHash mismatch");
  }

  if (!res.ok) {
    // 4xx = hard failure; 5xx = transient.
    const isTransient = res.status >= 500;
    throw new SignerError(res.status, "signer sign_raw_payload error", isTransient);
  }

  return res.json() as Promise<SignerSignRawPayloadResponse>;
}

/**
 * POST ${baseUrl}/internal/keys/create — ask the signer to generate (or import)
 * and envelope-encrypt a secp256k1 key pair.
 *
 * Throws TurnkeyError(500, "signer unavailable") on any non-2xx response so that
 * the activity is recorded as retriable PENDING rather than a hard failure.
 */
export async function createKey(
  baseUrl: string,
  input: SignerCreateKeyRequest,
  signerFetch: SignerFetch = plainFetch,
): Promise<SignerCreateKeyResponse> {
  let res: Response;
  try {
    res = await signerFetch(`${baseUrl}/internal/keys/create`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
      // Prevent a hung signer from blocking the request indefinitely.
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new TurnkeyError(500, "signer unavailable");
  }

  if (!res.ok) {
    const isTransient = res.status >= 500;
    throw new SignerError(res.status, "signer unavailable", isTransient);
  }

  return res.json() as Promise<SignerCreateKeyResponse>;
}
