/**
 * policy.ts — Deterministic, pure policy engine for Kryard.
 *
 * evaluatePolicy is the single entry point. It checks:
 *  1. Actor binding (policy_bindings) — ACTOR_NOT_BOUND
 *  2. Key is active (not deleted) — KEY_INACTIVE
 *  3. For sign_transaction: chain allowed, value limit, method selector, destination
 *  4. For sign_raw_payload: allow_raw_payload_signing flag
 *
 * The evaluatedInputHash binds the policy decision to the exact payload that will
 * be signed, so the signer can verify it did not drift.
 */

import type { Kysely } from "kysely";
import type { Database } from "./db";
import type { TxFields } from "./signerClient";
import { canonicalize, sha256Hex } from "./canonicalJson";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PolicyOutcome = "ALLOW" | "DENY";

export type PolicyReasonCode =
  | "ALLOW"
  | "ACTOR_NOT_BOUND"
  | "KEY_INACTIVE"
  | "CHAIN_NOT_ALLOWED"
  | "VALUE_LIMIT"
  | "METHOD_NOT_ALLOWED"
  | "DESTINATION_NOT_ALLOWED"
  | "DELEGATE_NOT_ALLOWED"
  | "RAW_PAYLOAD_DISABLED"
  | "NO_POLICY_CONFIGURED";

export interface PolicyResult {
  outcome: PolicyOutcome;
  reasonCode: PolicyReasonCode;
  /** sha256(canonical_json({ activityType, privateKeyId, txFields|payload })) */
  evaluatedInputHash: string;
  /** True when no policy_bindings exist for the org (no-policy bypass — env gate still applies). */
  isPolicyBypassed: boolean;
}

export interface EvaluatePolicyInput {
  organizationId: string;
  actorId: string;
  activityType: string; // ACTIVITY_TYPE_SIGN_TRANSACTION_V2 | ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2
  privateKeyId: string;
  /** Decoded tx fields — required for sign_transaction. */
  txFields?: TxFields;
  /** Raw payload string — required for sign_raw_payload. */
  rawPayload?: string;
  /**
   * When true, an org with zero policy_bindings is allowed through (bypass mode).
   * Defaults to false (fail-closed): no policy configured → DENY NO_POLICY_CONFIGURED.
   * Set via POLICY_BYPASS_ALLOWED=true env var for dev/test environments only.
   */
  policyBypassAllowed?: boolean;
}

// ---------------------------------------------------------------------------
// evaluatedInputHash helpers
// ---------------------------------------------------------------------------

/** Normalize txFields to a canonical form where all fields are always present.
 *  Optional fields default to "" so Go and TS produce the same hash. */
function normalizeTxFields(txFields: TxFields): Record<string, unknown> {
  const base: Record<string, unknown> = {
    chainId: txFields.chainId ?? "",
    data: txFields.data ?? "",
    gas: txFields.gas ?? 0,
    gasPrice: txFields.gasPrice ?? "",
    maxFeePerGas: txFields.maxFeePerGas ?? "",
    maxPriorityFeePerGas: txFields.maxPriorityFeePerGas ?? "",
    methodSelector: txFields.methodSelector ?? "",
    nonce: txFields.nonce ?? 0,
    to: txFields.to ?? "",
    value: txFields.value ?? "",
  };
  // Bind the EIP-7702 delegation targets into the hash ONLY when present, so the
  // signer's re-check catches a swapped authorization for type-4 txs. Omitted for
  // type-2/legacy so their evaluatedInputHash stays byte-identical (the signer
  // applies the same "only when non-empty" rule). Order is preserved (authorization
  // order), matching the signer.
  const authAddresses = txFields.authorizationAddresses ?? [];
  if (authAddresses.length > 0) {
    base.authorizationAddresses = authAddresses;
  }
  const authAuthorities = txFields.authorizationAuthorities ?? [];
  if (authAuthorities.length > 0) {
    base.authorizationAuthorities = authAuthorities;
  }
  return base;
}

async function computeInputHash(
  activityType: string,
  privateKeyId: string,
  txFields: TxFields | undefined,
  rawPayload: string | undefined,
): Promise<string> {
  const data: Record<string, unknown> = { activityType, privateKeyId };
  if (txFields !== undefined) {
    data.txFields = normalizeTxFields(txFields);
  } else if (rawPayload !== undefined) {
    data.payload = rawPayload;
  }
  return sha256Hex(canonicalize(data));
}

// ---------------------------------------------------------------------------
// Main engine
// ---------------------------------------------------------------------------

export async function evaluatePolicy(
  db: Kysely<Database>,
  input: EvaluatePolicyInput,
): Promise<PolicyResult> {
  const { organizationId, actorId, activityType, privateKeyId, txFields, rawPayload, policyBypassAllowed = false } = input;

  // Pre-compute the hash regardless of outcome, so even DENY records an honest hash.
  const evaluatedInputHash = await computeInputHash(activityType, privateKeyId, txFields, rawPayload);

  const deny = (reasonCode: PolicyReasonCode): PolicyResult => ({
    outcome: "DENY",
    reasonCode,
    evaluatedInputHash,
    isPolicyBypassed: false,
  });

  const allow = (isPolicyBypassed = false): PolicyResult => ({
    outcome: "ALLOW",
    reasonCode: "ALLOW",
    evaluatedInputHash,
    isPolicyBypassed,
  });

  // 1. Check if any policy_bindings exist for this org.
  const anyBinding = await db
    .selectFrom("policy_bindings")
    .select(["id"])
    .where("organization_id", "=", organizationId)
    .executeTakeFirst();

  if (!anyBinding) {
    // No policy configured for this org.
    // Fail-closed by default: DENY with NO_POLICY_CONFIGURED.
    // Only allow bypass in dev/test when policyBypassAllowed=true.
    if (policyBypassAllowed) {
      return allow(true);
    }
    return deny("NO_POLICY_CONFIGURED");
  }

  // Guard: actorId must be present on a signing path when policy is configured.
  // An empty actorId would bypass all actor-binding checks — deny it explicitly.
  if (!actorId) {
    return deny("ACTOR_NOT_BOUND");
  }

  // Actor binding: actorId must have a policy_bindings row for this activity + key.
  const binding = await db
    .selectFrom("policy_bindings")
    .select(["id"])
    .where("organization_id", "=", organizationId)
    .where("actor_id", "=", actorId)
    .where("resource_id", "=", privateKeyId)
    .where("allowed_activity_type", "=", activityType)
    .executeTakeFirst();

  if (!binding) {
    return deny("ACTOR_NOT_BOUND");
  }

  // 2. Key must be active (not deleted).
  const keyRow = await db
    .selectFrom("private_keys")
    .select(["id"])
    .where("id", "=", privateKeyId)
    .where("organization_id", "=", organizationId)
    .where("deleted_at", "is", null)
    .executeTakeFirst();

  if (!keyRow) {
    return deny("KEY_INACTIVE");
  }

  // 3. Activity-type-specific checks.
  if (activityType === "ACTIVITY_TYPE_SIGN_TRANSACTION_V2") {
    return evaluateSignTransactionPolicy(db, organizationId, privateKeyId, txFields, deny, allow);
  }

  if (activityType === "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2") {
    return evaluateSignRawPayloadPolicy(db, organizationId, privateKeyId, deny, allow);
  }

  // Unknown activity type should not reach here (submit.ts filters earlier).
  return deny("ACTOR_NOT_BOUND");
}

async function evaluateSignTransactionPolicy(
  db: Kysely<Database>,
  organizationId: string,
  privateKeyId: string,
  txFields: TxFields | undefined,
  deny: (code: PolicyReasonCode) => PolicyResult,
  allow: () => PolicyResult,
): Promise<PolicyResult> {
  if (!txFields) {
    return deny("CHAIN_NOT_ALLOWED");
  }

  // Parse chainId from hex (e.g. "0x1" → 1n).
  const chainIdHex = txFields.chainId.replace(/^0x/i, "");
  const chainIdBigInt = chainIdHex ? BigInt(`0x${chainIdHex}`) : 0n;
  const chainIdStr = chainIdBigInt.toString();

  // 3a. A wallet_policy_rules row must exist for (private_key_id, chain_id).
  const rule = await db
    .selectFrom("wallet_policy_rules")
    .select(["id", "max_native_value_wei", "method_selector_allowlist"])
    .where("organization_id", "=", organizationId)
    .where("private_key_id", "=", privateKeyId)
    .where("chain_id", "=", chainIdStr)
    .executeTakeFirst();

  if (!rule) {
    return deny("CHAIN_NOT_ALLOWED");
  }

  // 3b. value <= max_native_value_wei (stored as numeric string; default "0").
  const valueHex = txFields.value.replace(/^0x/i, "");
  const valueBigInt = valueHex ? BigInt(`0x${valueHex}`) : 0n;
  const maxValueBigInt = BigInt(rule.max_native_value_wei ?? "0");

  if (valueBigInt > maxValueBigInt) {
    return deny("VALUE_LIMIT");
  }

  // 3c. methodSelector must be in method_selector_allowlist.
  // Empty selector (data < 4 bytes / native transfer) is ALWAYS denied: a dataless
  // tx never carries a method call, and a misconfigured [""] allowlist must not open arbitrary
  // value-less/dataless transfers.
  const allowlist = rule.method_selector_allowlist as string[];
  const selector = txFields.methodSelector ?? "";

  if (selector === "") {
    return deny("METHOD_NOT_ALLOWED");
  }

  if (!allowlist.includes(selector)) {
    return deny("METHOD_NOT_ALLOWED");
  }

  // 3d. Destination check — splits by transaction type:
  //
  //   - EIP-7702 (type-4): the tx `to` is the user's OWN delegated EOA (variable
  //     per user), so pinning `to` is meaningless. Instead, EVERY authorization
  //     delegate target must be in wallet_delegate_allowlist for this (key, chain)
  //     — i.e. the EOA may only delegate to a known delegate implementation.
  //     A single unlisted delegate denies the whole tx (fail-closed).
  //
  //   - type-2 / legacy: the `to` (the target contract) must be in
  //     wallet_destination_allowlist for this (key, chain).
  const authAddresses = txFields.authorizationAddresses ?? [];
  if (authAddresses.length > 0) {
    // (i) Every authorization must delegate to an allowlisted delegate impl.
    for (const delegate of authAddresses) {
      const delegateRow = await db
        .selectFrom("wallet_delegate_allowlist")
        .select(["id"])
        .where("organization_id", "=", organizationId)
        .where("private_key_id", "=", privateKeyId)
        .where("chain_id", "=", chainIdStr)
        .where("delegate_address", "ilike", delegate) // case-insensitive EIP-55
        .executeTakeFirst();
      if (!delegateRow) {
        return deny("DELEGATE_NOT_ALLOWED");
      }
    }

    // (ii) The tx `to` MUST be one of the recovered authorizing EOAs. In a 7702
    // call the relayer calls the user's OWN delegated EOA; `to` and the
    // authorization_list are otherwise independent fields, so without this an
    // allowlisted delegate could be paired with an arbitrary `to` (a target the
    // user never authorized). Fail-closed: no recovered authorities ⇒ deny.
    const authorities = (txFields.authorizationAuthorities ?? []).map((a) => a.toLowerCase());
    const toAddr = (txFields.to ?? "").toLowerCase();
    if (toAddr === "" || !authorities.includes(toAddr)) {
      return deny("DESTINATION_NOT_ALLOWED");
    }

    return allow();
  }

  // type-2 / legacy: (private_key_id, chain_id, to) must be in
  // wallet_destination_allowlist. The (chain_id, to) pair is checked as a unit —
  // a router for chain A is NOT allowed on a chain-B tx even if the address
  // appears in some other chain's row.
  const toAddr = txFields.to ?? "";
  const destRow = await db
    .selectFrom("wallet_destination_allowlist")
    .select(["id"])
    .where("organization_id", "=", organizationId)
    .where("private_key_id", "=", privateKeyId)
    .where("chain_id", "=", chainIdStr)
    .where("address", "ilike", toAddr) // case-insensitive EIP-55 vs lowercase
    .executeTakeFirst();

  if (!destRow) {
    return deny("DESTINATION_NOT_ALLOWED");
  }

  return allow();
}

async function evaluateSignRawPayloadPolicy(
  db: Kysely<Database>,
  organizationId: string,
  privateKeyId: string,
  deny: (code: PolicyReasonCode) => PolicyResult,
  allow: () => PolicyResult,
): Promise<PolicyResult> {
  // Any wallet_policy_rules row for this key that has allow_raw_payload_signing=true.
  const rule = await db
    .selectFrom("wallet_policy_rules")
    .select(["allow_raw_payload_signing"])
    .where("organization_id", "=", organizationId)
    .where("private_key_id", "=", privateKeyId)
    .where("allow_raw_payload_signing", "=", true)
    .executeTakeFirst();

  if (!rule) {
    return deny("RAW_PAYLOAD_DISABLED");
  }

  return allow();
}
