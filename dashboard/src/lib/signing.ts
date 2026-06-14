/**
 * signing.ts — the EVM signing playground pipeline (ported from the old
 * single-file dashboard, src/dashboard.ts).
 *
 * Builds an unsigned EIP-1559 transaction with viem, wraps it in a Turnkey
 * ACTIVITY_TYPE_SIGN_TRANSACTION_V2 body, X-Stamps the EXACT raw JSON string,
 * and POSTs that same string through the same-origin proxy. The response is the
 * Turnkey-shaped activity envelope.
 */
import {
  recoverTransactionAddress,
  serializeTransaction,
  type Hex,
  type TransactionSerialized,
} from "viem";
import { buildStamp, STAMP_HEADER_NAME, type StampIdentity } from "./stamp";

export interface TxFormValues {
  chainId: string;
  to: string;
  data: string;
  valueWei: string;
  nonce: string;
  gas: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
}

/** Defaults mirroring the old dev dashboard's prefills. */
export const DEFAULT_TX: TxFormValues = {
  chainId: "1",
  to: "0x1111111111111111111111111111111111111111",
  data: "0x7fea8778",
  valueWei: "0",
  nonce: "0",
  gas: "100000",
  maxFeePerGas: "30000000000",
  maxPriorityFeePerGas: "1000000000",
};

/** Serialize the unsigned EIP-1559 transaction. Throws on invalid input. */
export function buildUnsignedTx(values: TxFormValues): Hex {
  return serializeTransaction({
    chainId: Number(values.chainId),
    nonce: Number(values.nonce),
    to: values.to as Hex,
    value: BigInt(values.valueWei || "0"),
    data: values.data as Hex,
    gas: BigInt(values.gas),
    maxFeePerGas: BigInt(values.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(values.maxPriorityFeePerGas),
  });
}

/** The exact raw body string for sign_transaction (this string gets stamped). */
export function buildSignTransactionBody(
  organizationId: string,
  privateKeyId: string,
  unsignedTransaction: string,
): string {
  return JSON.stringify({
    type: "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
    timestampMs: String(Date.now()),
    organizationId,
    parameters: {
      signWith: privateKeyId,
      unsignedTransaction,
      type: "TRANSACTION_TYPE_ETHEREUM",
    },
  });
}

export interface SignResult {
  status: string;
  activityId?: string;
  signedTransaction?: string;
  raw: unknown;
}

/** POST the raw stamped body through the same-origin proxy. */
export async function submitSignTransaction(
  identity: StampIdentity,
  rawBody: string,
  fetchFn: (input: string, init?: RequestInit) => Promise<Response> = (i, init) => fetch(i, init),
): Promise<SignResult> {
  const stamp = buildStamp(identity, rawBody);
  const res = await fetchFn("/api/public/v1/submit/sign_transaction", {
    method: "POST",
    headers: { "content-type": "application/json", [STAMP_HEADER_NAME]: stamp },
    body: rawBody, // the exact string that was stamped — never re-serialize
  });
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  if (!res.ok) {
    const message =
      typeof json === "object" && json !== null && "message" in json
        ? String((json as { message: unknown }).message)
        : `HTTP ${res.status}`;
    throw new Error(message);
  }

  const activity =
    typeof json === "object" && json !== null
      ? ((json as { activity?: Record<string, unknown> }).activity ?? {})
      : {};
  const result = (activity.result ?? {}) as Record<string, unknown>;
  const signTxResult = (result.signTransactionResult ?? {}) as Record<string, unknown>;
  const signed = signTxResult.signedTransaction ?? signTxResult.signed_transaction;

  return {
    status: typeof activity.status === "string" ? activity.status : "UNKNOWN",
    activityId: typeof activity.id === "string" ? activity.id : undefined,
    signedTransaction: typeof signed === "string" ? signed : undefined,
    raw: json,
  };
}

/** Recover the signer address from a signed tx (0x-prefixed RLP). */
export async function recoverSigner(signedTransaction: string): Promise<string> {
  // viem narrows by the leading type byte (0x02 = EIP-1559 etc.); our string is
  // runtime-validated by viem itself, so the assertion to the union is safe.
  return recoverTransactionAddress({
    serializedTransaction: signedTransaction as TransactionSerialized,
  });
}
