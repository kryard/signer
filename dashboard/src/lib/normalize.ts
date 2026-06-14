/**
 * normalize.ts — tolerant mapping from raw /admin/dev/* JSON (camelCase, with
 * occasional envelope / id-field variations) into the console's normalized
 * shapes (see types.ts). Keeping this separate from the client keeps both
 * files small and lets a future ProdClient reuse the same normalizers.
 */
import type {
  ActivityFull,
  ActivitySummary,
  ApiKey,
  OrgSummary,
  PolicyBinding,
  PolicyDestination,
  PolicyRule,
  Wallet,
} from "./types";

export type Raw = Record<string, unknown>;

export function asRecord(v: unknown): Raw {
  return typeof v === "object" && v !== null ? (v as Raw) : {};
}

export function asArray(v: unknown, ...envelopeKeys: string[]): Raw[] {
  if (Array.isArray(v)) return v.map(asRecord);
  const rec = asRecord(v);
  for (const key of envelopeKeys) {
    if (Array.isArray(rec[key])) return (rec[key] as unknown[]).map(asRecord);
  }
  return [];
}

export function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

export function id(raw: Raw, ...keys: string[]): string {
  for (const key of keys) {
    const v = str(raw[key]);
    if (v) return v;
  }
  return "";
}

export function strArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  if (typeof v === "string") {
    // Tolerate JSON-stringified arrays from the DB layer.
    try {
      const parsed: unknown = JSON.parse(v);
      if (Array.isArray(parsed)) return parsed.filter((x): x is string => typeof x === "string");
    } catch {
      return [];
    }
  }
  return [];
}

// ── entity normalizers ───────────────────────────────────────────────────────

export function toOrgSummary(raw: Raw): OrgSummary {
  return {
    id: id(raw, "organizationId", "id"),
    name: str(raw.name) ?? "(unnamed)",
    createdAt: str(raw.createdAt),
  };
}

export function toApiKey(raw: Raw): ApiKey {
  return {
    id: id(raw, "apiKeyId", "id"),
    name: str(raw.name),
    publicKey: str(raw.publicKey) ?? "",
    scheme: str(raw.scheme) ?? "",
    // The API reports disabledAt (ISO string | null); older shapes used a flag.
    disabled: raw.disabled === true || raw.status === "disabled" || raw.disabledAt != null,
    createdAt: str(raw.createdAt),
  };
}

export function toWallet(raw: Raw): Wallet {
  const addresses = strArray(raw.addresses);
  const single = str(raw.address);
  return {
    id: id(raw, "privateKeyId", "id"),
    name: str(raw.name),
    curve: str(raw.curve),
    publicKey: str(raw.publicKey),
    addresses: addresses.length > 0 ? addresses : single ? [single] : [],
    createdAt: str(raw.createdAt),
  };
}

export function toActivitySummary(raw: Raw): ActivitySummary {
  return {
    id: id(raw, "activityId", "id"),
    type: str(raw.type) ?? "UNKNOWN",
    status: str(raw.status) ?? "UNKNOWN",
    createdAt: str(raw.createdAt),
  };
}

export function toActivityFull(raw: Raw): ActivityFull {
  return {
    ...toActivitySummary(raw),
    intent: raw.intent,
    result: raw.result,
    failure: raw.failure,
    policyDecision: raw.policyDecision != null ? asRecord(raw.policyDecision) : null,
    signerReceipt: raw.signerReceipt,
    raw,
  };
}

export function toBinding(raw: Raw): PolicyBinding {
  return {
    id: id(raw, "bindingId", "id"),
    actorId: str(raw.actorId),
    resourceType: str(raw.resourceType),
    resourceId: str(raw.resourceId),
    allowedActivityType: str(raw.allowedActivityType),
    createdAt: str(raw.createdAt),
  };
}

export function toRule(raw: Raw): PolicyRule {
  return {
    id: id(raw, "ruleId", "id"),
    privateKeyId: str(raw.privateKeyId),
    chainId: str(raw.chainId) ?? (typeof raw.chainId === "number" ? String(raw.chainId) : undefined),
    allowRawPayloadSigning: raw.allowRawPayloadSigning === true,
    maxNativeValueWei: str(raw.maxNativeValueWei),
    methodSelectorAllowlist: strArray(raw.methodSelectorAllowlist),
    createdAt: str(raw.createdAt),
  };
}

export function toDestination(raw: Raw): PolicyDestination {
  return {
    id: id(raw, "destinationId", "id"),
    privateKeyId: str(raw.privateKeyId),
    chainId: str(raw.chainId),
    address: str(raw.address) ?? "",
    createdAt: str(raw.createdAt),
  };
}
