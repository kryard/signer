/**
 * client.ts — the console's data layer and prod-switch seam.
 *
 * Pages depend ONLY on the `KryardClient` interface. `DevAdminClient` talks to
 * the same-origin `/api/admin/dev/*` bootstrap endpoints (the kryard-app worker
 * injects the admin token server-side). A future `ProdClient` implementing the
 * X-Stamp'd public API can swap in with zero page edits.
 */
import {
  asArray,
  asRecord,
  id,
  str,
  toActivityFull,
  toActivitySummary,
  toApiKey,
  toBinding,
  toDestination,
  toOrgSummary,
  toRule,
  toWallet,
  type Raw,
} from "./normalize";
import type {
  ActivityFull,
  ActivitySummary,
  AddDestinationInput,
  CreateOrgResult,
  CreateWalletResult,
  OrgDetail,
  OrgSummary,
  Policies,
  RegisterApiKeyInput,
  SeedPolicyInput,
  ServiceStatus,
  Wallet,
} from "./types";

export interface KryardClient {
  listOrgs(): Promise<OrgSummary[]>;
  createOrg(name: string): Promise<CreateOrgResult>;
  getOrg(orgId: string): Promise<OrgDetail>;
  listWallets(orgId: string): Promise<Wallet[]>;
  createWallet(orgId: string, name?: string): Promise<CreateWalletResult>;
  listActivities(orgId: string, limit?: number, before?: string): Promise<ActivitySummary[]>;
  getActivity(orgId: string, activityId: string): Promise<ActivityFull>;
  getPolicies(orgId: string): Promise<Policies>;
  seedPolicy(input: SeedPolicyInput): Promise<void>;
  addDestination(input: AddDestinationInput): Promise<void>;
  deleteRule(orgId: string, id: string): Promise<void>;
  deleteDestination(orgId: string, id: string): Promise<void>;
  deleteBinding(orgId: string, id: string): Promise<void>;
  registerApiKey(input: RegisterApiKeyInput): Promise<{ apiKeyId: string }>;
  disableApiKey(orgId: string, id: string): Promise<void>;
  renameOrg(orgId: string, name: string): Promise<void>;
  /** Environment health (api/signer) for the Settings page. */
  getStatus(): Promise<ServiceStatus>;
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Error carrying the HTTP status + best-effort server message. */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export class DevAdminClient implements KryardClient {
  private readonly fetchFn: FetchLike;
  private readonly base: string;

  constructor(fetchFn?: FetchLike, base = "/api/admin/dev") {
    this.fetchFn = fetchFn ?? ((input, init) => fetch(input, init));
    this.base = base;
  }

  private async request(method: string, path: string, body?: unknown): Promise<unknown> {
    const init: RequestInit = { method };
    if (body !== undefined) {
      init.headers = { "content-type": "application/json" };
      init.body = JSON.stringify(body);
    }
    const res = await this.fetchFn(this.base + path, init);
    const text = await res.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = text;
    }
    if (!res.ok) {
      const rec = asRecord(json);
      const message =
        str(rec.message) ??
        str(rec.error) ??
        (typeof json === "string" && json ? json : `HTTP ${res.status}`);
      throw new ApiError(res.status, message);
    }
    return json;
  }

  async listOrgs(): Promise<OrgSummary[]> {
    const json = await this.request("GET", "/orgs");
    return asArray(json, "orgs", "organizations").map(toOrgSummary);
  }

  async createOrg(name: string): Promise<CreateOrgResult> {
    const raw = asRecord(await this.request("POST", "/org", { name }));
    return {
      organizationId: id(raw, "organizationId"),
      actorId: id(raw, "actorId"),
      actorName: str(raw.actorName),
    };
  }

  async getOrg(orgId: string): Promise<OrgDetail> {
    const raw = asRecord(await this.request("GET", `/orgs/${encodeURIComponent(orgId)}`));
    const org = asRecord(raw.organization ?? raw.org);
    const root: Raw = Object.keys(org).length > 0 ? org : raw;
    return {
      ...toOrgSummary(root),
      actors: asArray(raw.actors ?? root.actors, "actors").map((a) => ({
        id: id(a, "actorId", "id"),
        name: str(a.name) ?? "(unnamed)",
      })),
      apiKeys: asArray(raw.apiKeys ?? root.apiKeys, "apiKeys").map(toApiKey),
    };
  }

  async listWallets(orgId: string): Promise<Wallet[]> {
    const json = await this.request("GET", `/orgs/${encodeURIComponent(orgId)}/wallets`);
    return asArray(json, "wallets", "privateKeys").map(toWallet);
  }

  async createWallet(orgId: string, name?: string): Promise<CreateWalletResult> {
    const raw = asRecord(
      await this.request("POST", "/wallet", { organizationId: orgId, ...(name ? { name } : {}) }),
    );
    return {
      privateKeyId: id(raw, "privateKeyId"),
      address: str(raw.address) ?? "",
      publicKey: str(raw.publicKey) ?? "",
    };
  }

  async listActivities(orgId: string, limit?: number, before?: string): Promise<ActivitySummary[]> {
    const params = new URLSearchParams();
    if (limit != null) params.set("limit", String(limit));
    if (before) params.set("before", before);
    const qs = params.size > 0 ? `?${params.toString()}` : "";
    const json = await this.request("GET", `/orgs/${encodeURIComponent(orgId)}/activities${qs}`);
    return asArray(json, "activities").map(toActivitySummary);
  }

  async getActivity(orgId: string, activityId: string): Promise<ActivityFull> {
    const json = await this.request(
      "GET",
      `/orgs/${encodeURIComponent(orgId)}/activities/${encodeURIComponent(activityId)}`,
    );
    const raw = asRecord(json);
    const nested = asRecord(raw.activity);
    const full = toActivityFull(Object.keys(nested).length > 0 ? nested : raw);
    // The detail endpoint returns policyDecisions/auditEvents as SIBLINGS of
    // the activity — lift the first decision into the page's singular slot and
    // keep the whole response as `raw` so audit events stay visible in the
    // JSON viewer.
    const decisions = asArray(raw.policyDecisions, "policyDecisions");
    return {
      ...full,
      policyDecision: full.policyDecision ?? (decisions.length > 0 ? decisions[0] : null),
      raw: json,
    };
  }

  async getPolicies(orgId: string): Promise<Policies> {
    const raw = asRecord(await this.request("GET", `/orgs/${encodeURIComponent(orgId)}/policies`));
    return {
      bindings: asArray(raw.bindings, "bindings").map(toBinding),
      rules: asArray(raw.rules, "rules").map(toRule),
      destinations: asArray(raw.destinations, "destinations").map(toDestination),
    };
  }

  async seedPolicy(input: SeedPolicyInput): Promise<void> {
    await this.request("POST", "/policy", input);
  }

  async addDestination(input: AddDestinationInput): Promise<void> {
    await this.request("POST", "/policy/destination", input);
  }

  private async deletePolicyEntity(kind: string, orgId: string, entityId: string): Promise<void> {
    await this.request(
      "DELETE",
      `/policy/${kind}/${encodeURIComponent(entityId)}?organizationId=${encodeURIComponent(orgId)}`,
    );
  }

  deleteRule(orgId: string, ruleId: string): Promise<void> {
    return this.deletePolicyEntity("rule", orgId, ruleId);
  }

  deleteDestination(orgId: string, destinationId: string): Promise<void> {
    return this.deletePolicyEntity("destination", orgId, destinationId);
  }

  deleteBinding(orgId: string, bindingId: string): Promise<void> {
    return this.deletePolicyEntity("binding", orgId, bindingId);
  }

  async registerApiKey(input: RegisterApiKeyInput): Promise<{ apiKeyId: string }> {
    const raw = asRecord(await this.request("POST", "/api-key", input));
    return { apiKeyId: id(raw, "apiKeyId") };
  }

  async disableApiKey(orgId: string, apiKeyId: string): Promise<void> {
    await this.request("POST", `/api-key/${encodeURIComponent(apiKeyId)}/disable`, {
      organizationId: orgId,
    });
  }

  async renameOrg(orgId: string, name: string): Promise<void> {
    await this.request("POST", `/orgs/${encodeURIComponent(orgId)}/rename`, { name });
  }

  async getStatus(): Promise<ServiceStatus> {
    const raw = asRecord(await this.request("GET", "/status"));
    return {
      api: str(raw.api) ?? "unknown",
      signer: str(raw.signer) ?? "unknown",
    };
  }
}

/**
 * Local OSS dev mode selection.
 *
 * Two modes, chosen at build time by Vite env vars:
 *
 *  - DEPLOYED (default): the dashboard is served by the kryard-app worker
 *    (src/worker/index.ts), which proxies same-origin `/api/admin/dev/*` to the
 *    real API and injects the admin token server-side. The browser stays
 *    same-origin (no CORS) and never sees a token. Base = `/api/admin/dev`.
 *
 *  - LOCAL (`VITE_LOCAL=true`): the dashboard talks DIRECTLY to a local API at
 *    `VITE_API_BASE` (default http://localhost:8787) with NO Cloudflare Access
 *    and NO admin token. The API is expected to expose `/admin/dev/*` openly on
 *    localhost (dev-only). This is the zero-auth path for OSS contributors —
 *    `pnpm dev` the API in services/api, then `npm run dev` here. See
 *    .env.example.
 */
const LOCAL = import.meta.env.VITE_LOCAL === "true";

/** True when the dashboard is running in zero-auth localhost mode. */
export const isLocalMode = LOCAL;

const LOCAL_API_BASE = (import.meta.env.VITE_API_BASE ?? "http://localhost:8787").replace(/\/$/, "");

/**
 * Base URL for the admin/dev bootstrap endpoints.
 *  - LOCAL: `<VITE_API_BASE>/admin/dev` (direct, no proxy, no token)
 *  - DEPLOYED: `/api/admin/dev` (same-origin worker proxy, token injected server-side)
 */
const CLIENT_BASE = LOCAL ? `${LOCAL_API_BASE}/admin/dev` : "/api/admin/dev";

/** Singleton client used by the app. Swap implementation here for prod. */
export const client: KryardClient = new DevAdminClient(undefined, CLIENT_BASE);
