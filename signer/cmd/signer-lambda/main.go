// Package main is the Lambda entrypoint for the Kryard signer service.
//
// It wraps the existing api.NewServer http.Handler for a Lambda Function URL
// (payload format v2, same as API Gateway HTTP API v2). The adapter
// (algnhsa) auto-detects the event type, so the same binary works with both
// Function URLs and API Gateway HTTP APIs.
//
// Env vars (same as the EC2 binary):
//   - KMS_PROVIDER: "aws" (required in Lambda; "local" is dev/test only)
//   - KMS_KEY_ID:   KMS key ID / ARN / alias (required when KMS_PROVIDER=aws)
//   - ALLOW_KEY_IMPORT: "true" to enable the guarded import path (default off)
//
// The Lambda execution role must have kms:Encrypt, kms:Decrypt, and
// kms:DescribeKey on the wallet-signing KMS key (same grant as the EC2 role).
package main

import (
	"context"
	"log"
	"os"

	"github.com/akrylysov/algnhsa"

	"kryard/signer/internal/api"
	"kryard/signer/internal/kms"
)

func main() {
	provider, err := kms.FromEnv(context.Background())
	if err != nil {
		log.Fatalf("signer-lambda: %v", err)
	}

	allowImport := os.Getenv("ALLOW_KEY_IMPORT") == "true"
	if allowImport {
		log.Print("WARNING: key import is ENABLED (ALLOW_KEY_IMPORT=true) — use only for controlled migrations")
	}

	deps := api.Deps{
		KMSProvider: provider,
		AllowImport: allowImport,
	}

	srv := api.NewServer(deps)
	log.Printf("signer-lambda starting (KMS provider: %s)", provider.Name())

	// ListenAndServe starts the aws-lambda-go runtime. It blocks until the
	// Lambda environment shuts down. algnhsa auto-detects API GW v1/v2 and
	// ALB events; Lambda Function URL events use the same v2 payload format.
	algnhsa.ListenAndServe(srv, nil)
}
