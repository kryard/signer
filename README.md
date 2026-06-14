# Kryard

**Open-source, Turnkey-compatible EVM signing infrastructure.**

Kryard is a remote key-signing service: create private keys and wallets, define
signing policies, and request EVM signatures over a **Turnkey-wire-compatible** API —
**without your application ever touching private key material**. Private keys are
generated inside an isolated signer and encrypted at rest with envelope encryption;
the API tier can never decrypt them.

It's a drop-in for Turnkey's secp256k1 EVM signing: cutover is a single
`TURNKEY_BASE_URL` swap.

```
Client / SDK / Dashboard
  →  api/      Turnkey-compatible API (Cloudflare Worker, Hono)  — activity + policy engine
  →  signer/   Isolated signer (Go)                              — the only component that decrypts keys
  →  KMS       AWS KMS  or  local provider                       — envelope encryption
  →  Postgres                                                    — activities, audit, policy, encrypted keys
```

## What's in the box

| Path | What |
| --- | --- |
| **`api/`** | The Turnkey-compatible HTTP API — activities, idempotency, `X-Stamp` auth, a deterministic policy engine, and EVM transaction / raw-payload signing. Cloudflare Worker (Hono) over Postgres. |
| **`signer/`** | The isolated Go signer. Generates secp256k1 keys, signs EVM transactions (legacy / EIP-1559 / EIP-7702) and raw payloads, and does KMS envelope encryption. Audited crypto only (go-ethereum). |
| **`dashboard/`** | A React console — keys, wallets, policies, activities, and a signing playground. Runs locally with no auth. |
| **`infra/aws-dev/`** | Terraform for a dev profile: a KMS key + the signer as an AWS Lambda behind an IAM-auth Function URL. |

## Why Kryard

- **The API never decrypts keys.** Only the signer holds KMS decrypt permission, on a
  surface with no public ingress. A compromise of the application tier cannot expose
  a private key.
- **Every operation is an auditable activity**, with `SHA-256(canonical_json(body))`
  idempotency scoped per organization.
- **Signing is policy-bound.** A deterministic, fail-closed policy engine gates every
  signature; the signer re-verifies the policy decision before signing.
- **No hand-rolled crypto.** secp256k1, ECDSA, Keccak-256, RLP, and address derivation
  come from go-ethereum.
- **Runs with no cloud.** The signer ships an in-process KMS provider, so the whole
  stack runs on your laptop — and the same code path runs against real AWS KMS in
  production.

## Quickstart

Run the full stack locally — **no AWS account required**:

```bash
docker compose up -d                 # Postgres

cd signer && KMS_PROVIDER=local KMS_MASTER_KEY=$(openssl rand -hex 32) go run ./cmd/signer &

cd api && pnpm install \
  && DATABASE_URL=postgres://kryard:kryard@localhost:5432/kryard pnpm migrate \
  && SIGNER_BASE_URL=http://localhost:8081 DEV_ADMIN_ENABLED=true pnpm dev &

cd dashboard && npm install \
  && printf 'VITE_LOCAL=true\nVITE_API_BASE=http://localhost:8787\n' > .env.local \
  && npm run dev
```

Open <http://localhost:5173>. Full walkthrough: **[docs/local-development.md](docs/local-development.md)**.

## Documentation

- [Architecture](docs/architecture.md) — components, invariants, the KMS seam, the API surface.
- [Local development](docs/local-development.md) — run everything locally; the local-kms emulator option.
- Component READMEs: [`api/`](api/README.md) · [`signer/`](signer/README.md) · [`dashboard/`](dashboard/README.md) · [`infra/aws-dev/`](infra/aws-dev/README.md).

## Scope

This repository is the **signing core**. The hosted Kryard product adds capabilities
on top (a managed EIP-7702 relay for gasless transactions, billing, and more) that
are **not** part of this repository.

## Related

- [`@kryard/relay-sdk`](https://www.npmjs.com/package/@kryard/relay-sdk) — client SDK for Kryard's managed relay.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for third-party attributions (the signer
depends on go-ethereum, LGPL-3.0, as an unmodified dependency).
