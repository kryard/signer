# signer

The isolated **EVM signer**. It generates secp256k1 keys, signs EVM transactions
(legacy / EIP-1559 / EIP-7702) and raw payloads, and performs **KMS envelope
encryption** so private keys are never stored or returned in plaintext.

It exposes a **private internal API only** — never public ingress. The
[`api/`](../api) service calls it; end users never reach it directly.

## Crypto

No hand-rolled cryptography. secp256k1, ECDSA, Keccak-256, RLP, EVM transaction
types, and Ethereum address derivation come from
[go-ethereum](https://github.com/ethereum/go-ethereum); AES-256-GCM and SHA-256 are
the Go standard library.

## Build & test

```bash
go build ./cmd/signer     # the HTTP signer
go test ./...             # unit tests (no Docker needed)
go test -race ./...
go vet ./...
```

## Run (local dev)

```bash
export KMS_PROVIDER=local
export KMS_MASTER_KEY=$(openssl rand -hex 32)   # 32 bytes / 64 hex chars — dev only
export SIGNER_ADDR=:8081
go run ./cmd/signer
```

## KMS providers

Key custody crosses one interface — `kms.Provider`, selected by `kms.FromEnv`:

| `KMS_PROVIDER` | Required env | Notes |
| --- | --- | --- |
| `local` (default) | `KMS_MASTER_KEY` (64 hex) | In-process AES-256-GCM. **Dev/test only — never production.** |
| `aws` | `KMS_KEY_ID` | Real AWS KMS. Credentials from the standard AWS chain. |

For `aws`, set `KMS_ENDPOINT` to point at a local AWS-KMS emulator (e.g. the bundled
`local-kms` — see [docs/local-development.md](../docs/local-development.md)); leave it
unset for real AWS KMS. The same binary runs every mode — backend choice is config.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `KMS_PROVIDER` | No (default `local`) | `local` or `aws`. |
| `KMS_MASTER_KEY` | When `local` | 32-byte AES key as 64 hex chars. Dev/test only. |
| `KMS_KEY_ID` | When `aws` | KMS key id, ARN, or `alias/...`. |
| `KMS_ENDPOINT` | No | Custom AWS KMS endpoint (e.g. a local-kms emulator). |
| `SIGNER_ADDR` | No (default `:8081`) | Listen address. |
| `ALLOW_KEY_IMPORT` | No (default `false`) | Enable the guarded private-key import path. Security-sensitive; enable only for controlled migrations. |

## Internal API

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/internal/health` | Health check. |
| `POST` | `/internal/keys/create` | Generate (or, if allowed, import) a secp256k1 key; return its encrypted blob + address. |
| `POST` | `/internal/parse/transaction` | Decode an unsigned EVM transaction (no signing). |
| `POST` | `/internal/sign/raw-payload` | ECDSA-sign a 32-byte payload. |
| `POST` | `/internal/sign/transaction` | Parse and sign an EVM transaction. |

## Deploying as a Lambda

`scripts/build-lambda.sh` builds a `bootstrap` zip from `cmd/signer-lambda`; the
[`infra/aws-dev/`](../infra/aws-dev) Terraform provisions the KMS key + Lambda +
Function URL.
