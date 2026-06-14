# api

The **Turnkey-compatible EVM signing API** — a Cloudflare Worker (Hono) over
Postgres. It records every operation as an immutable **activity**, evaluates
**policy**, and calls the [`signer/`](../signer) for the actual cryptography. It
**never** has KMS decrypt permission and never sees plaintext key material.

It speaks the Turnkey wire format, so an existing Turnkey integration can cut over by
swapping `TURNKEY_BASE_URL`.

## Surface

`POST`-based, idempotent on identical bodies, authenticated with an `X-Stamp` header
(an API-key signature over the canonical request body).

| Submit | Query |
| --- | --- |
| `/public/v1/submit/create_private_keys` | `/public/v1/query/get_activity` |
| `/public/v1/submit/sign_raw_payload` | `/public/v1/query/list_activities` |
| `/public/v1/submit/sign_transaction` | `/public/v1/query/get_private_key` |
| `/public/v1/submit/create_wallet` | `/public/v1/query/list_wallets` |
| `/public/v1/submit/create_wallet_accounts` | `/public/v1/query/whoami` |

`/admin/dev/*` bootstrap endpoints (create the first org / actor / API key) are
mounted only when `DEV_ADMIN_ENABLED=true`, and protected by `DEV_ADMIN_TOKEN` **when
that token is set** — leave it unset for fully local, token-less dev.

## Build & test

```bash
pnpm install
pnpm typecheck      # tsc --noEmit
pnpm test           # Vitest — integration tests need Docker (Testcontainers Postgres)
pnpm migrate        # apply migrations 001–008 (DATABASE_URL required)
pnpm dev            # wrangler dev on http://localhost:8787
```

## Run (local dev)

```bash
export DATABASE_URL="postgres://kryard:kryard@localhost:5432/kryard"
export SIGNER_BASE_URL="http://localhost:8081"   # the signer; SIGNER_AUTH=plain for local
export DEV_ADMIN_ENABLED=true                     # leave DEV_ADMIN_TOKEN unset for no-auth local
pnpm migrate && pnpm dev
```

See [docs/local-development.md](../docs/local-development.md) for the full stack.

## Configuration

Secrets (`DATABASE_URL`, `DEV_ADMIN_TOKEN`, AWS credentials) are set via
`wrangler secret put` or `.dev.vars` — never committed. See `.dev.vars.example`.

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | Postgres connection string. |
| `SIGNER_BASE_URL` | URL of the signer (e.g. `http://localhost:8081`). |
| `SIGNER_AUTH` | `plain` (local) or `sigv4` (AWS Lambda Function URL with IAM). |
| `DEV_ADMIN_ENABLED` | `true` to mount `/admin/dev/*` bootstrap endpoints. |
| `DEV_ADMIN_TOKEN` | Optional shared token required on `/admin/dev/*` when set. |
| `ALLOW_RAW_PAYLOAD_SIGNING` | `true` to permit raw-payload signing (dev). |
| `AWS_REGION` / `AWS_*` | For `SIGNER_AUTH=sigv4` (signing requests to the signer Function URL). |

## How signing works

1. A client submits an activity (e.g. `sign_transaction`) with an `X-Stamp`.
2. The API verifies the stamp, deduplicates by `SHA-256(canonical_json(body))`, and
   evaluates policy — recording a policy decision with an evaluated-input hash.
3. On approval it calls the signer, which re-verifies that hash before signing and
   returns a signature plus a receipt. A denial never reaches the signer.
