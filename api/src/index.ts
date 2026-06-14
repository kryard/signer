import type { Kysely } from "kysely";
import { createApp } from "./app";
import { makeDb, makeNeonDb, type Database } from "./db";
import { plainFetch, sigv4Fetch } from "./signerClient";

interface Env {
  /** Cloudflare Hyperdrive binding — used only when DATABASE_DRIVER is not "neon". */
  HYPERDRIVE?: { connectionString: string };
  SIGNER_BASE_URL: string;
  ALLOW_RAW_PAYLOAD_SIGNING?: string;
  /** When "true", orgs with zero policy_bindings are bypassed (dev/test only). Defaults false (fail-closed). */
  POLICY_BYPASS_ALLOWED?: string;
  /**
   * Database driver selector.
   * "neon"  → Neon serverless driver (Workers-native; no Hyperdrive needed).
   *           Requires DATABASE_URL set to a Neon connection string.
   *           Neon has no Seoul region — use Tokyo (ap-northeast-1) for dev.
   * (omit)  → Hyperdrive + pg (default; HYPERDRIVE binding must be configured).
   *           Alternatively, Hyperdrive can be pointed at Neon with no code change.
   */
  DATABASE_DRIVER?: string;
  /** Neon connection string — required when DATABASE_DRIVER="neon". */
  DATABASE_URL?: string;
  /**
   * Signer auth mode.
   * "sigv4" → SigV4-sign every signer request (for Lambda Function URL / AWS_IAM auth).
   *           Requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION.
   * (omit)  → plain fetch (default; no signing).
   */
  SIGNER_AUTH?: string;
  /** AWS invoke-only access key ID — required when SIGNER_AUTH="sigv4". */
  AWS_ACCESS_KEY_ID?: string;
  /** AWS invoke-only secret access key — required when SIGNER_AUTH="sigv4". */
  AWS_SECRET_ACCESS_KEY?: string;
  /** AWS region for the signer Lambda — required when SIGNER_AUTH="sigv4". */
  AWS_REGION?: string;
  /** DEV ONLY. "true" mounts /admin/dev/* + the GET /dev dashboard. Default off. */
  DEV_ADMIN_ENABLED?: string;
  /** Optional shared token required on /admin/dev/* via X-Dev-Admin-Token. */
  DEV_ADMIN_TOKEN?: string;
  /** "false" disables the single-use stamp store. Default on (fail-closed). */
  REPLAY_PROTECTION?: string;
  /** Max submit requests per minute per org. Default 120; "0" disables. */
  SUBMIT_RATE_LIMIT?: string;
}

// In the Workers runtime a DB connection is an I/O object that CANNOT be shared
// across requests ("Cannot perform I/O on behalf of a different request"). So
// build the db (and the Hono app) PER REQUEST — caching the Neon serverless Pool
// at module scope hangs the second request. The app is cheap to construct; the
// Neon Pool connects lazily and is closed after the response via ctx.waitUntil.
function buildDb(env: Env): Kysely<Database> {
  if (env.DATABASE_DRIVER === "neon") {
    if (!env.DATABASE_URL) throw new Error("DATABASE_URL is required when DATABASE_DRIVER=neon");
    return makeNeonDb(env.DATABASE_URL);
  }
  if (!env.HYPERDRIVE) {
    throw new Error("HYPERDRIVE binding is required when DATABASE_DRIVER is not 'neon'");
  }
  return makeDb(env.HYPERDRIVE.connectionString);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (!env.SIGNER_BASE_URL) {
      throw new Error("SIGNER_BASE_URL is required but was not set");
    }
    const db = buildDb(env);
    const signerFetch =
      env.SIGNER_AUTH === "sigv4"
        ? sigv4Fetch({
            accessKeyId: env.AWS_ACCESS_KEY_ID ?? "",
            secretAccessKey: env.AWS_SECRET_ACCESS_KEY ?? "",
            region: env.AWS_REGION ?? "us-east-1",
          })
        : plainFetch;

    const app = createApp({
      db,
      signerBaseUrl: env.SIGNER_BASE_URL,
      allowRawPayloadSigning: env.ALLOW_RAW_PAYLOAD_SIGNING === "true",
      policyBypassAllowed: env.POLICY_BYPASS_ALLOWED === "true",
      signerFetch,
      devAdminEnabled: env.DEV_ADMIN_ENABLED === "true",
      devAdminToken: env.DEV_ADMIN_TOKEN ?? "",
      replayProtection: env.REPLAY_PROTECTION !== "false",
      submitRateLimitPerMinute:
        env.SUBMIT_RATE_LIMIT !== undefined ? Number(env.SUBMIT_RATE_LIMIT) : 120,
    });

    try {
      // Responses are buffered (c.json / c.html), so closing the connection
      // after app.fetch resolves is safe and avoids leaking Neon connections.
      return await app.fetch(request);
    } finally {
      ctx.waitUntil(db.destroy().catch(() => {}));
    }
  },
};
