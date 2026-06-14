/**
 * kryard-app worker — serves the Kryard console SPA + same-origin API proxy.
 *
 * Static assets (the Vite-built SPA in ./dist) are served by wrangler's
 * `assets` binding with SPA fallback; this worker code only ever sees requests
 * that the assets layer routes to it (`/api/*` via run_worker_first, plus
 * `/healthz`).
 *
 * The proxy forwards "/api/<rest>" → "<API_BASE>/<rest>". This keeps the
 * browser same-origin (no CORS) and lets the worker inject the admin token
 * server-side for /admin/* bootstrap calls — the browser never sees it.
 *
 * The whole worker should sit behind Cloudflare Access (SSO). Gate it at the
 * route in the Cloudflare Zero Trust dashboard.
 *
 * Bindings:
 *   API_BASE        (var)    — base URL of the Kryard API (e.g. http://localhost:8787
 *                              for dev, or your own API host in prod)
 *   DEV_ADMIN_TOKEN (secret) — injected as X-Dev-Admin-Token on /api/admin/* calls;
 *                              set via `wrangler secret put DEV_ADMIN_TOKEN`, never committed
 */
import { Hono } from "hono";

interface Env {
  API_BASE: string;
  DEV_ADMIN_TOKEN?: string;
}

const app = new Hono<{ Bindings: Env }>();

app.get("/healthz", (c) => c.json({ status: "ok" }));

// Same-origin proxy: /api/<rest> → <API_BASE>/<rest>.
app.all("/api/*", async (c) => {
  const apiBase = (c.env.API_BASE || "").replace(/\/$/, "");
  if (!apiBase) return c.json({ error: "API_BASE not configured" }, 500);

  const rest = c.req.path.replace(/^\/api/, ""); // keep leading slash
  const target = apiBase + rest + (new URL(c.req.url).search || "");

  // Forward the client's headers (incl. X-Stamp for signing requests). Drop
  // hop-by-hop / host headers. Inject the admin token only on bootstrap calls.
  const headers = new Headers(c.req.raw.headers);
  headers.delete("host");
  headers.delete("content-length");
  if (rest.startsWith("/admin/") && c.env.DEV_ADMIN_TOKEN) {
    headers.set("X-Dev-Admin-Token", c.env.DEV_ADMIN_TOKEN);
  }

  const method = c.req.method;
  const body = method === "GET" || method === "HEAD" ? undefined : await c.req.raw.arrayBuffer();

  const res = await fetch(target, { method, headers, body });
  // Pass the API response straight back.
  return new Response(res.body, { status: res.status, headers: res.headers });
});

export default app;
