# Architecture

Kryard is a remote EVM key-signing service with a **Turnkey-wire-compatible** HTTP
API. Applications create private keys and wallets, define signing policies, and
request signatures **without ever handling private key material directly**.

## Components

```
Client / SDK / Dashboard
  →  api/        Turnkey-compatible HTTP API (Cloudflare Worker, Hono)   — activity + policy engine
  →  signer/     Isolated signer (Go)                                    — the custody boundary
  →  KMS         AWS KMS  or  local provider                             — envelope encrypt/decrypt
  →  Postgres                                                            — activities, audit, policy, encrypted keys
```

- **`api/`** — the public, Turnkey-shaped API. It records every operation as an
  immutable **activity**, evaluates **policy**, and calls the signer. It never has
  KMS decrypt permission and never sees plaintext key material.
- **`signer/`** — an isolated service exposing a **private internal API only**
  (`/internal/sign/*`, `/internal/keys/create`, `/internal/health`). It generates
  keys, signs, and is the only component that can decrypt wallet keys.
- **`infra/aws-dev/`** — Terraform for a dev profile: a KMS key + the signer as an
  AWS Lambda behind an IAM-authenticated Function URL.
- **`dashboard/`** — a React console for keys, wallets, policies, activities, and a
  signing playground. Runs locally with no auth for development.

## Three invariants

1. **The API never decrypts wallet keys.** Only the signer holds IAM permission to
   call KMS decrypt, and it runs with no public ingress. Envelope encryption: a
   per-key data encryption key (DEK) encrypts the private key; the DEK is wrapped by
   a KMS key. The KMS **encryption context** (`organization_id`, `private_key_id`,
   `environment`, `purpose`) is verified on every decrypt.

2. **Every sensitive operation is an immutable `activity`** — the unit of work,
   idempotency, and audit. Idempotency is `SHA-256(canonical_json(request_body))`
   scoped per organization; identical bodies return the existing activity.

3. **Signing is bound to activity + policy.** The API records a policy decision
   (outcome, reason code, evaluated-input hash); the signer re-checks that the
   payload it is about to sign matches that hash before signing, and refuses on
   mismatch.

## The KMS seam

Key custody crosses a single interface — the `kms.Provider` in `signer/internal/kms`,
selected by `kms.FromEnv` (`KMS_PROVIDER`):

| `KMS_PROVIDER` | Backend | Use |
| --- | --- | --- |
| `local` | In-process AES-256-GCM (`KMS_MASTER_KEY`) | Local dev / tests **only** — never production |
| `aws` | AWS KMS (`KMS_KEY_ID`, optional `KMS_ENDPOINT`) | Real AWS, or a local-kms emulator via `KMS_ENDPOINT` |

The same signer binary runs in every mode — switching backends is configuration, not
code. See [local-development.md](./local-development.md).

## Public API surface

Turnkey-shaped, `POST`-based, idempotent on identical bodies. Authentication is an
`X-Stamp` header (an API-key signature over the canonical request body).

| Submit | Query |
| --- | --- |
| `/public/v1/submit/create_private_keys` | `/public/v1/query/get_activity` |
| `/public/v1/submit/sign_raw_payload` | `/public/v1/query/list_activities` |
| `/public/v1/submit/sign_transaction` | `/public/v1/query/get_private_key` |
| `/public/v1/submit/create_wallet` | `/public/v1/query/list_wallets` |
| `/public/v1/submit/create_wallet_accounts` | `/public/v1/query/whoami` |

## Crypto

The signer does **not** hand-roll cryptography. secp256k1, ECDSA, Keccak-256, RLP,
EVM transaction types, and Ethereum address derivation all come from
[go-ethereum](https://github.com/ethereum/go-ethereum); AES-256-GCM and SHA-256 are
Go standard library.
