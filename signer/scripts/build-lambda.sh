#!/usr/bin/env bash
#
# build-lambda.sh — build the Lambda deployment zip for the dev profile (ADR-007).
#
# Produces (under signer/dist/):
#   - signer-lambda.zip    (cmd/signer-lambda   → bootstrap)
#
# The zip contains a single `bootstrap` binary built for the AWS
# provided.al2023 custom runtime on arm64 (matches the architectures/handler
# in the dev-lambda Terraform config).
#
# Usage:
#   ./scripts/build-lambda.sh
#
# Terraform then references the zip via:
#   -var signer_lambda_zip=signer/dist/signer-lambda.zip

set -euo pipefail

cd "$(dirname "$0")/.."   # → signer

DIST="dist"
mkdir -p "$DIST"

build() {
  local cmd="$1" zip_name="$2"
  echo "→ building ./cmd/${cmd} → ${DIST}/${zip_name}"
  # CGO disabled for a static binary; -trimpath + -s -w for a smaller, reproducible build.
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -ldflags='-s -w' -o "${DIST}/bootstrap" "./cmd/${cmd}"
  # The zip must contain the binary at its root, named exactly `bootstrap`.
  (cd "$DIST" && zip -q -X "$zip_name" bootstrap && rm -f bootstrap)
}

build signer-lambda signer-lambda.zip

echo "done:"
ls -la "${DIST}"/*.zip