import { Hono, type Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { Kysely } from "kysely";
import type { Database } from "./db";
import type { SubmitRequest } from "./types";
import { dispatchSubmit } from "./submit";
import { toActivityEnvelope } from "./activityResponse";
import { TurnkeyError } from "./errors";
import { getActivityById, listActivities } from "./activityRepo";
import { getPrivateKey, listPrivateKeys } from "./privateKeyRepo";
import { getWallet, listWallets, getWalletAccount, listWalletAccounts } from "./walletRepo";
import { authenticate, type AuthContext } from "./auth";
import { recordAuditEvent } from "./audit";
import { plainFetch, type SignerFetch } from "./signerClient";
import { createDevOrg, registerApiKey, createDevWallet, seedPolicy } from "./admin";
import { checkSubmitRateLimit } from "./rateLimit";
import {
  listOrgs,
  getOrgDetail,
  listOrgWallets,
  listOrgActivities,
  getOrgActivity,
  listOrgPolicies,
  addDestination,
  deletePolicyRule,
  deleteDestination,
  deletePolicyBinding,
  disableApiKey,
  renameOrg,
  requireUuid,
  clampLimit,
} from "./adminConsole";

export interface AppDeps {
  db: Kysely<Database>;
  signerBaseUrl: string;
  /** Gate for raw-payload signing. Defaults false. Set ALLOW_RAW_PAYLOAD_SIGNING=true to enable. */
  allowRawPayloadSigning?: boolean;
  /**
   * When true, orgs with zero policy_bindings are allowed through (bypass mode).
   * Defaults false (fail-closed). Set POLICY_BYPASS_ALLOWED=true in dev/test only.
   */
  policyBypassAllowed?: boolean;
  /**
   * Transport for signer HTTP calls. Defaults to `plainFetch`.
   * Set to `sigv4Fetch(creds)` when SIGNER_AUTH=sigv4 (Lambda Function URL / AWS_IAM).
   */
  signerFetch?: SignerFetch;
  /**
   * DEV ONLY. When true, mounts the unauthenticated /admin/dev/* bootstrap
   * endpoints and the GET /dev signing dashboard. Default false. Never enable
   * on a publicly reachable deployment. Optionally require a shared token via
   * devAdminToken (matched against the X-Dev-Admin-Token header).
   */
  devAdminEnabled?: boolean;
  devAdminToken?: string;
  /**
   * Single-use stamps (replay-nonce store). Default true (fail-closed).
   * Disable only in tests that deliberately reuse a stamp.
   */
  replayProtection?: boolean;
  /**
   * Max /public/v1/submit/* requests per minute per organization.
   * Default 120; <= 0 disables. Set via SUBMIT_RATE_LIMIT env.
   */
  submitRateLimitPerMinute?: number;
}

type Vars = { auth: AuthContext; body: Record<string, unknown>; rawBody: string };

const SUBMIT_PATHS = [
  "create_private_keys",
  "sign_raw_payload",
  "sign_transaction",
  "create_wallet",
  "create_wallet_accounts",
];

export function createApp(deps: AppDeps): Hono<{ Variables: Vars }> {
  const app = new Hono<{ Variables: Vars }>();
  const {
    db,
    signerBaseUrl,
    allowRawPayloadSigning = false,
    policyBypassAllowed = false,
    signerFetch = plainFetch,
    devAdminEnabled = false,
    devAdminToken = "",
    replayProtection = true,
    submitRateLimitPerMinute = 120,
  } = deps;

  // All thrown TurnkeyErrors serialize to the Turnkey HTTP error envelope.
  app.onError((err, c) => {
    if (err instanceof TurnkeyError) {
      return c.json(err.body, err.httpStatus as ContentfulStatusCode);
    }
    return c.json({ code: 2, message: "internal error", details: [], turnkeyErrorCode: "" }, 500);
  });

  app.get("/internal/health", (c) => c.json({ status: "ok" }));

  // Auth middleware: read raw body once, verify X-Stamp, stash auth + parsed body on context.
  app.use("/public/v1/*", async (c, next) => {
    const rawBody = await c.req.text();
    let body: Record<string, unknown>;
    try {
      body = rawBody ? (JSON.parse(rawBody) as Record<string, unknown>) : {};
    } catch {
      throw new TurnkeyError(400, "invalid request");
    }
    const auth = await authenticate(
      db,
      rawBody,
      c.req.header("X-Stamp"),
      String(body.organizationId ?? ""),
      String(body.timestampMs ?? ""),
      Date.now(),
      { replayProtection },
    );
    await recordAuditEvent(db, {
      organizationId: auth.organizationId,
      actorId: auth.actorId,
      eventType: "api_key_used",
      metadata: { apiKeyId: auth.apiKeyId },
    });
    c.set("auth", auth);
    c.set("body", body);
    c.set("rawBody", rawBody);
    await next();
  });

  for (const p of SUBMIT_PATHS) {
    app.post(`/public/v1/submit/${p}`, async (c) => {
      const body = c.get("body") as unknown as SubmitRequest;
      if (!body || typeof body.type !== "string" || typeof body.organizationId !== "string" ||
          typeof body.timestampMs !== "string") {
        throw new TurnkeyError(400, "invalid request");
      }
      const auth = c.get("auth");
      // Rate limit BEFORE any signing/DB work (fixed window per organization).
      await checkSubmitRateLimit(db, auth.organizationId, submitRateLimitPerMinute, Date.now());
      const row = await dispatchSubmit(db, body, auth, signerBaseUrl, allowRawPayloadSigning, policyBypassAllowed, signerFetch);
      await recordAuditEvent(db, {
        organizationId: auth.organizationId,
        actorId: auth.actorId,
        activityId: row.id,
        eventType: "activity_submitted",
        metadata: { activityType: row.type },
      });
      return c.json(toActivityEnvelope(row));
    });
  }

  app.post("/public/v1/query/whoami", async (c) => {
    const auth = c.get("auth");
    return c.json({ organizationId: auth.organizationId });
  });

  app.post("/public/v1/query/get_activity", async (c) => {
    const body = c.get("body");
    const auth = c.get("auth");
    const activityId = body.activityId;
    if (!auth.organizationId || typeof activityId !== "string") throw new TurnkeyError(400, "invalid request");
    const row = await getActivityById(db, auth.organizationId, activityId);
    if (!row) throw new TurnkeyError(404, "activity not found");
    return c.json(toActivityEnvelope(row));
  });

  app.post("/public/v1/query/list_activities", async (c) => {
    const auth = c.get("auth");
    if (!auth.organizationId) throw new TurnkeyError(400, "invalid request");
    const rows = await listActivities(db, auth.organizationId);
    return c.json({ activities: rows.map((r) => toActivityEnvelope(r).activity) });
  });

  // B4: private key query endpoints — returns ONLY public metadata, never ciphertext.
  app.post("/public/v1/query/get_private_key", async (c) => {
    const body = c.get("body");
    const auth = c.get("auth");
    const privateKeyId = body.privateKeyId;
    if (!auth.organizationId || typeof privateKeyId !== "string") {
      throw new TurnkeyError(400, "invalid request");
    }
    const row = await getPrivateKey(db, auth.organizationId, privateKeyId);
    if (!row) throw new TurnkeyError(404, "private key not found");
    return c.json({ privateKey: row });
  });

  app.post("/public/v1/query/list_private_keys", async (c) => {
    const auth = c.get("auth");
    if (!auth.organizationId) throw new TurnkeyError(400, "invalid request");
    const rows = await listPrivateKeys(db, auth.organizationId);
    return c.json({ privateKeys: rows });
  });

  // Wallet query endpoints — public metadata only, never ciphertext.
  app.post("/public/v1/query/get_wallet", async (c) => {
    const body = c.get("body");
    const auth = c.get("auth");
    const walletId = body.walletId;
    if (!auth.organizationId || typeof walletId !== "string") {
      throw new TurnkeyError(400, "invalid request");
    }
    const row = await getWallet(db, auth.organizationId, walletId);
    if (!row) throw new TurnkeyError(404, "wallet not found");
    return c.json({ wallet: row });
  });

  app.post("/public/v1/query/list_wallets", async (c) => {
    const auth = c.get("auth");
    if (!auth.organizationId) throw new TurnkeyError(400, "invalid request");
    const rows = await listWallets(db, auth.organizationId);
    return c.json({ wallets: rows });
  });

  app.post("/public/v1/query/get_wallet_account", async (c) => {
    const body = c.get("body");
    const auth = c.get("auth");
    const walletAccountId = body.walletAccountId;
    if (!auth.organizationId || typeof walletAccountId !== "string") {
      throw new TurnkeyError(400, "invalid request");
    }
    const row = await getWalletAccount(db, auth.organizationId, walletAccountId);
    if (!row) throw new TurnkeyError(404, "wallet account not found");
    return c.json({ walletAccount: row });
  });

  app.post("/public/v1/query/list_wallet_accounts", async (c) => {
    const body = c.get("body");
    const auth = c.get("auth");
    const walletId = body.walletId;
    if (!auth.organizationId || typeof walletId !== "string") {
      throw new TurnkeyError(400, "invalid request");
    }
    const rows = await listWalletAccounts(db, auth.organizationId, walletId);
    return c.json({ walletAccounts: rows });
  });

  // ── DEV bootstrap endpoints (consumed by the kryard-app dashboard) ─────────
  // Gated by devAdminEnabled. These create the first org/actor/api-key, so they
  // are protected by a REQUIRED shared token (devAdminToken) — the kryard-app
  // worker (behind Cloudflare Access) injects it server-side. The dashboard UI
  // itself lives in the separate kryard-app worker, NOT here.
  if (devAdminEnabled) {
    const requireToken = (c: Context<{ Variables: Vars }>) => {
      if (devAdminToken && c.req.header("X-Dev-Admin-Token") !== devAdminToken) {
        throw new TurnkeyError(401, "invalid or missing X-Dev-Admin-Token");
      }
    };

    app.post("/admin/dev/org", async (c) => {
      requireToken(c);
      const body = (await c.req.json().catch(() => ({}))) as { name?: string };
      return c.json(await createDevOrg(db, body.name ?? "dev-org"));
    });

    app.post("/admin/dev/api-key", async (c) => {
      requireToken(c);
      const body = (await c.req.json()) as {
        organizationId: string; actorId: string; publicKey: string; scheme?: string; name?: string;
      };
      return c.json(await registerApiKey(db, body));
    });

    app.post("/admin/dev/wallet", async (c) => {
      requireToken(c);
      const body = (await c.req.json()) as { organizationId: string; name?: string };
      return c.json(await createDevWallet(db, signerBaseUrl, body, signerFetch));
    });

    app.post("/admin/dev/policy", async (c) => {
      requireToken(c);
      const body = (await c.req.json()) as Parameters<typeof seedPolicy>[1];
      return c.json(await seedPolicy(db, body));
    });

    // ── Console data plane (Track A) — org-scoped reads + policy management ──
    // Same gating as the bootstrap endpoints above: devAdminEnabled + token.
    // Every helper in adminConsole.ts filters organization_id and never
    // returns key ciphertext or encryption context.

    app.get("/admin/dev/orgs", async (c) => {
      requireToken(c);
      return c.json({ organizations: await listOrgs(db) });
    });

    app.get("/admin/dev/orgs/:orgId", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.param("orgId"), "orgId");
      return c.json(await getOrgDetail(db, orgId));
    });

    app.get("/admin/dev/orgs/:orgId/wallets", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.param("orgId"), "orgId");
      return c.json({ wallets: await listOrgWallets(db, orgId) });
    });

    app.get("/admin/dev/orgs/:orgId/activities", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.param("orgId"), "orgId");
      const limit = clampLimit(c.req.query("limit"));
      // Optional ISO-timestamp cursor: return rows created strictly before it.
      const beforeRaw = c.req.query("before");
      let before: Date | undefined;
      if (beforeRaw) {
        const parsed = new Date(beforeRaw);
        if (Number.isNaN(parsed.getTime())) {
          throw new TurnkeyError(400, "before must be an ISO timestamp");
        }
        before = parsed;
      }
      return c.json({ activities: await listOrgActivities(db, orgId, limit, before) });
    });

    app.get("/admin/dev/orgs/:orgId/activities/:activityId", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.param("orgId"), "orgId");
      const activityId = requireUuid(c.req.param("activityId"), "activityId");
      return c.json(await getOrgActivity(db, orgId, activityId));
    });

    app.get("/admin/dev/orgs/:orgId/policies", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.param("orgId"), "orgId");
      return c.json(await listOrgPolicies(db, orgId));
    });

    app.post("/admin/dev/policy/destination", async (c) => {
      requireToken(c);
      const body = (await c.req.json().catch(() => ({}))) as Parameters<typeof addDestination>[1];
      return c.json(await addDestination(db, body));
    });

    app.delete("/admin/dev/policy/rule/:id", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.query("organizationId"), "organizationId");
      const id = requireUuid(c.req.param("id"), "id");
      return c.json(await deletePolicyRule(db, orgId, id));
    });

    app.delete("/admin/dev/policy/destination/:id", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.query("organizationId"), "organizationId");
      const id = requireUuid(c.req.param("id"), "id");
      return c.json(await deleteDestination(db, orgId, id));
    });

    app.delete("/admin/dev/policy/binding/:id", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.query("organizationId"), "organizationId");
      const id = requireUuid(c.req.param("id"), "id");
      return c.json(await deletePolicyBinding(db, orgId, id));
    });

    app.post("/admin/dev/api-key/:id/disable", async (c) => {
      requireToken(c);
      const id = requireUuid(c.req.param("id"), "id");
      const body = (await c.req.json().catch(() => ({}))) as { organizationId?: unknown };
      const orgId = requireUuid(body.organizationId, "organizationId");
      return c.json(await disableApiKey(db, orgId, id));
    });

    app.post("/admin/dev/orgs/:orgId/rename", async (c) => {
      requireToken(c);
      const orgId = requireUuid(c.req.param("orgId"), "orgId");
      const body = (await c.req.json().catch(() => ({}))) as { name?: unknown };
      return c.json(await renameOrg(db, orgId, body.name));
    });

    // Environment status for the console Settings page: pings the signer
    // /internal/health through the same transport the signing paths use.
    // Failures are reported, never thrown — the page renders either way.
    app.get("/admin/dev/status", async (c) => {
      requireToken(c);
      const ping = async (base: string, fetcher: SignerFetch): Promise<string> => {
        // Normalize the trailing slash (Function URLs from terraform end in "/").
        const url = `${base.replace(/\/$/, "")}/internal/health`;
        try {
          // 10s: the signer Lambda's cold start (large Go binary) can exceed 5s,
          // which previously reported a healthy-but-cold signer as unreachable.
          const res = await fetcher(url, {
            method: "GET",
            signal: AbortSignal.timeout(10_000),
          });
          return res.ok ? "ok" : `http ${res.status}`;
        } catch {
          return "unreachable";
        }
      };
      return c.json({
        api: "ok",
        signer: await ping(signerBaseUrl, signerFetch),
      });
    });
  }

  return app;
}
