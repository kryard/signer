# Contributing to Kryard

Thanks for your interest in contributing! This document covers how to get set up and
the one legal step we require before we can merge code.

## Contributor License Agreement (required)

Before we can accept a code contribution, you must sign our
**[Contributor License Agreement](CLA.md)**. It's quick and you only do it once.

When you open your first pull request, an automated check (CLA Assistant) will post a
comment. To sign, reply on the PR with exactly:

> I have read the CLA Document and I hereby sign the CLA

The check then turns green. If you contribute on behalf of a company, see the
**Corporate Contributions** section of the [CLA](CLA.md).

Why a CLA? Kryard is developed under an open-core model: this repository is
open source (Apache-2.0), while a hosted commercial product is built on top. The CLA
lets us include your contribution in both — it grants us the right to license your
contribution under the Apache-2.0 terms here and under commercial terms in the hosted
product, while you retain copyright to your work.

## Getting set up

Run the whole stack locally — no AWS account required. See
**[docs/local-development.md](docs/local-development.md)** for the full walkthrough,
and the per-component READMEs:

- [`api/`](api/README.md) — TypeScript (Cloudflare Worker, Hono)
- [`signer/`](signer/README.md) — Go
- [`dashboard/`](dashboard/README.md) — React (Vite)
- [`infra/aws-dev/`](infra/aws-dev/README.md) — Terraform

## Before you open a PR

- **Keep the scope tight.** This repository is the signing core. Features specific to
  the hosted product (e.g. a managed relay, billing, multi-tenant orchestration) are
  out of scope here.
- **Tests pass.**
  - `signer/`: `go test ./...` (and `go vet ./...`)
  - `api/`: `pnpm typecheck` and `pnpm test` (integration tests need Docker)
  - `dashboard/`: `npm run typecheck`, `npm test`, `npm run build`
- **No secrets.** Never commit credentials, `.dev.vars`, real KMS key IDs, AWS
  account IDs, or Terraform state.
- **Crypto:** do not hand-roll cryptography. Use the audited libraries already in the
  tree (go-ethereum, @noble, AWS SDK).

## Reporting security issues

Please do not open public issues for security vulnerabilities. Email
**security@kryard.com** instead.
