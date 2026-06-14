#!/usr/bin/env bash
#
# dev.sh — run `wrangler dev` for the dev/test profile (ADR-007: Neon driver).
#
# The Worker uses the Neon serverless driver (DATABASE_DRIVER=neon) and never
# touches Hyperdrive. But `wrangler dev` still requires a local connection
# string for the HYPERDRIVE binding declared in wrangler.jsonc. This wrapper
# points that emulation at the same Neon DATABASE_URL from .dev.vars, so a plain
# `pnpm dev` just works.
#
# DATABASE_URL is read WITHOUT shell-sourcing .dev.vars: Neon URLs contain `&`
# (multiple query params), which would break `source`.

set -euo pipefail
cd "$(dirname "$0")/.."   # → services/api

DB_URL="${DATABASE_URL:-}"
if [ -z "$DB_URL" ] && [ -f .dev.vars ]; then
  DB_URL="$(grep -E '^[[:space:]]*DATABASE_URL[[:space:]]*=' .dev.vars | head -1 | sed -E 's/^[[:space:]]*DATABASE_URL[[:space:]]*=[[:space:]]*//')"
fi

if [ -z "$DB_URL" ] || printf '%s' "$DB_URL" | grep -q '__PASTE'; then
  echo "dev.sh: DATABASE_URL is unset or still a placeholder — set it in services/api/.dev.vars" >&2
  exit 1
fi

# Satisfy wrangler's Hyperdrive local-emulation requirement (binding name:
# HYPERDRIVE). Newer wrangler uses the CLOUDFLARE_ prefix; set both so the
# wrapper works across versions without a deprecation warning.
export CLOUDFLARE_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="$DB_URL"
export WRANGLER_HYPERDRIVE_LOCAL_CONNECTION_STRING_HYPERDRIVE="$DB_URL"

exec npx wrangler dev "$@"
