/**
 * Normalized console-side data shapes. The DevAdminClient maps the raw
 * /admin/dev/* responses (camelCase) into these so pages never depend on
 * transport-level field spellings — a future ProdClient maps the X-Stamp'd
 * public API into the same shapes.
 */

export interface OrgSummary {
  id: string;
  name: string;
  createdAt?: string;
}

export interface Actor {
  id: string;
  name: string;
}

export interface ApiKey {
  id: string;
  name?: string;
  publicKey: string;
  scheme: string;
  disabled: boolean;
  createdAt?: string;
}

export interface OrgDetail extends OrgSummary {
  actors: Actor[];
  apiKeys: ApiKey[];
}

export interface Wallet {
  id: string; // privateKeyId
  name?: string;
  curve?: string;
  publicKey?: string;
  addresses: string[];
  createdAt?: string;
}

export interface ActivitySummary {
  id: string;
  type: string;
  status: string;
  createdAt?: string;
}

export interface PolicyDecision {
  outcome?: string;
  reasonCode?: string;
  evaluatedInputHash?: string;
  [key: string]: unknown;
}

export interface ActivityFull extends ActivitySummary {
  intent?: unknown;
  result?: unknown;
  failure?: unknown;
  policyDecision?: PolicyDecision | null;
  signerReceipt?: unknown;
  raw: unknown;
}

export interface PolicyBinding {
  id: string;
  actorId?: string;
  resourceType?: string;
  resourceId?: string;
  allowedActivityType?: string;
  createdAt?: string;
}

export interface PolicyRule {
  id: string;
  privateKeyId?: string;
  chainId?: string;
  allowRawPayloadSigning: boolean;
  maxNativeValueWei?: string;
  methodSelectorAllowlist: string[];
  createdAt?: string;
}

export interface PolicyDestination {
  id: string;
  privateKeyId?: string;
  chainId?: string;
  address: string;
  createdAt?: string;
}

export interface Policies {
  bindings: PolicyBinding[];
  rules: PolicyRule[];
  destinations: PolicyDestination[];
}

export interface CreateOrgResult {
  organizationId: string;
  actorId: string;
  actorName?: string;
}

export interface CreateWalletResult {
  privateKeyId: string;
  address: string;
  publicKey: string;
}

export interface SeedPolicyInput {
  organizationId: string;
  actorId: string;
  privateKeyId: string;
  chainId: string;
  methodSelector: string;
  destinationAddress: string;
  maxNativeValueWei?: string;
  /** Defaults to ACTIVITY_TYPE_SIGN_TRANSACTION_V2. */
  allowedActivityType?: string;
}

export interface ServiceStatus {
  /** "ok" | "disabled" | "unreachable" | "http <code>" per service. */
  api: string;
  signer: string;
}

export interface AddDestinationInput {
  organizationId: string;
  privateKeyId: string;
  chainId: string;
  address: string;
}

export interface RegisterApiKeyInput {
  organizationId: string;
  actorId: string;
  publicKey: string;
  scheme: string;
  name?: string;
}
