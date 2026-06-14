# Local development

Run the whole stack on your machine — **no AWS account required**. The signer uses
an in-process KMS provider by default, and the dashboard runs with no auth.

## Prerequisites

- Go (for `signer/`)
- Node.js + [pnpm](https://pnpm.io) (for `api/` and `dashboard/`)
- Docker (for Postgres via `docker compose`)

## 1. Start Postgres

```bash
docker compose up -d           # Postgres on localhost:5432 (db/user/pass: kryard)
```

## 2. Run the signer

The signer defaults to an **in-process AES-256-GCM** KMS provider — dev/test only.

```bash
cd signer
export KMS_PROVIDER=local
export KMS_MASTER_KEY=$(openssl rand -hex 32)   # 32-byte key, 64 hex chars
export SIGNER_ADDR=:8081
go run ./cmd/signer
```

The signer now listens on `http://localhost:8081` (private internal API).

## 3. Run the API

```bash
cd api
pnpm install
export DATABASE_URL="postgres://kryard:kryard@localhost:5432/kryard"
export SIGNER_BASE_URL="http://localhost:8081"   # no SIGNER_AUTH → plain http (local)
export DEV_ADMIN_ENABLED=true                     # mounts /admin/dev/* bootstrap endpoints
pnpm migrate                                      # apply migrations 001–008
pnpm dev                                          # wrangler dev on http://localhost:8787
```

> Leaving `DEV_ADMIN_TOKEN` unset keeps the `/admin/dev/*` bootstrap endpoints open
> for local use. Set it (and the dashboard's deployed proxy injects it) for any
> non-local environment.

## 4. Run the dashboard

```bash
cd dashboard
npm install
# .env.local
echo "VITE_LOCAL=true"                  >  .env.local
echo "VITE_API_BASE=http://localhost:8787" >> .env.local
npm run dev                              # http://localhost:5173
```

In `VITE_LOCAL` mode the dashboard talks directly to the local API with **no
Cloudflare Access and no admin token**. Open it, create an org, generate a signing
identity, create a wallet, and use the Sign playground.

## Using the SDK locally

The API speaks the Turnkey-compatible activity API, so the published
[`@kryard/sdk`](https://www.npmjs.com/package/@kryard/sdk) drives your local signer
exactly like the hosted one — just point `baseUrl` at `http://localhost:8787`.

Every signing call is **X-Stamp-authenticated and org-scoped** — the same code path
as production, so there's no "no-auth" signing mode. What's different locally is that
you can **mint your own** org + API key for free through the unauthenticated
`/admin/dev/*` bootstrap (enabled by `DEV_ADMIN_ENABLED=true`); no managed account.

### One-liner (SDK helper)

```ts
import { bootstrapLocalClient } from "@kryard/sdk"; // >= 0.3.0

// Generates a P-256 API keypair, mints an org, registers the key, returns a client.
const { client, organizationId, apiPublicKey, apiPrivateKey } = await bootstrapLocalClient({
  baseUrl: "http://localhost:8787",
  // devAdminToken: process.env.DEV_ADMIN_TOKEN, // only if you set DEV_ADMIN_TOKEN
});

const { addresses } = await client.createPrivateKey({ name: "local-evm", curve: "CURVE_SECP256K1" });
```

Persist `apiPublicKey` / `apiPrivateKey` and pass them back as `apiKey` next run to
reuse the same org.

### By hand (any SDK version / any language)

The helper is just two POSTs to the bootstrap, then a normal stamped client:

```bash
# 1. mint an org (+ default actor)
curl -s localhost:8787/admin/dev/org -d '{"name":"sdk-local"}' -H 'content-type: application/json'
# → { "organizationId": "...", "actorId": "...", "actorName": "dev-actor" }

# 2. register YOUR compressed P-256 public key as an API key
curl -s localhost:8787/admin/dev/api-key -H 'content-type: application/json' \
  -d '{"organizationId":"<org>","actorId":"<actor>","publicKey":"<compressed-p256-pubkey-hex>"}'
```

Then construct a `KryardClient` (or any Turnkey-protocol client) with that org id and a
stamper over the matching private key. If you set `DEV_ADMIN_TOKEN`, send it as the
`X-Dev-Admin-Token` header on both bootstrap calls.

### Signing needs a policy (or bypass)

Creating keys and queries work with just the minted org + key. **Signing** additionally
goes through policy evaluation — for a frictionless local loop, run the API with
`POLICY_BYPASS_ALLOWED=true` (an org with zero policy bindings is then allowed through):

```bash
cd api && SIGNER_BASE_URL=http://localhost:8081 DEV_ADMIN_ENABLED=true \
  POLICY_BYPASS_ALLOWED=true pnpm dev
```

Otherwise seed a policy (`POST /admin/dev/policy`, or via the dashboard) before signing.

## Using the local-kms emulator (optional)

To exercise the **AWS KMS** code path without a real account, start the bundled
[local-kms](https://github.com/nsmith5/local-kms) emulator and point the signer at it:

```bash
docker compose --profile kms up -d        # KMS emulator on localhost:8089

cd signer
export KMS_PROVIDER=aws
export KMS_ENDPOINT=http://localhost:8089
export KMS_KEY_ID=alias/kryard-dev-wallet-signing   # seeded by infra/local-kms/seed.yaml
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
go run ./cmd/signer
```

This runs the exact same `aws` provider used in production; only `KMS_ENDPOINT`
differs. Unset it to talk to real AWS KMS.

## Tests

```bash
cd signer    && go test ./...      # no Docker needed
cd api       && pnpm test          # integration tests need Docker (Testcontainers)
cd dashboard && npm test
```
