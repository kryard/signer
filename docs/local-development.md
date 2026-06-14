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
