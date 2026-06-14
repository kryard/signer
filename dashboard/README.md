# Kryard Dashboard

A Vite + React console for the Kryard wallet-infrastructure API (Turnkey-compatible
signing core): organizations, wallets, keys, policies, activities, and a signing
playground. Ships as a static SPA optionally served by a small Cloudflare Worker
that proxies same-origin API calls.

## Pages

Overview, Wallets, Wallet detail, Keys (API keys), Policies, Activities,
Activity detail, Sign, Settings, Profile.

## Local development (zero-auth)

For local dev the dashboard runs in a **zero-auth localhost mode**: it talks
directly to a local Kryard API with **no Cloudflare Access and no admin token**.

1. Install deps:

   ```bash
   npm install
   ```

2. Enable local mode:

   ```bash
   cp .env.example .env.local
   ```

   `.env.local` sets:
   - `VITE_LOCAL=true` — direct-to-API mode (no worker proxy, no token)
   - `VITE_API_BASE=http://localhost:8787` — your local Kryard API base URL

   In this mode the client calls `<VITE_API_BASE>/admin/dev/*` directly, and the
   Profile/Settings pages show a friendly "running locally, no auth" state.

3. Start the local Kryard API (in `services/api`) listening on `VITE_API_BASE`.

4. Run the dev server:

   ```bash
   npm run dev
   ```

   Opens on http://localhost:5173. (Vite's `/api` proxy in `vite.config.ts` is a
   fallback for same-origin-style local calls; the direct `VITE_API_BASE` path is
   the primary local mode.)

## Scripts

| Script             | Description                                    |
| ------------------ | ---------------------------------------------- |
| `npm run dev`      | Vite dev server                                |
| `npm run build`    | Type-check + production build to `./dist`      |
| `npm run typecheck`| `tsc -b`                                        |
| `npm run test`     | Vitest unit tests                              |
| `npm run preview`  | Preview the production build                   |

## Deployed mode (Cloudflare Worker)

When **not** in local mode, the dashboard is served by the `kryard-app` worker
(`src/worker/index.ts`). The worker serves the built SPA from `./dist` and proxies
same-origin `/api/*` calls to your API (`API_BASE`), injecting an admin token
server-side on `/admin/*` bootstrap calls so the browser never sees it.

Configuration (see `wrangler.jsonc`):

- `API_BASE` (var) — your Kryard API base URL. The committed default is a
  localhost placeholder; override it per deployment.
- `DEV_ADMIN_TOKEN` (secret) — set with `wrangler secret put DEV_ADMIN_TOKEN`.
  **Never commit it.**

Put the route behind Cloudflare Access (SSO); the dashboard surfaces the Access
identity on the Profile page and degrades gracefully when Access is absent.

```bash
npm run deploy   # build + wrangler deploy
```
