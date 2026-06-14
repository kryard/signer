package kms

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
)

// FromEnv constructs a Provider from environment variables.
//
// KMS_PROVIDER selects the backend ("local" or "aws"; defaults to "local"):
//   - "local":  KMS_MASTER_KEY must be a 32-byte hex string. Dev/test only.
//   - "aws":    KMS_KEY_ID must be a KMS key ID, ARN, or alias. Credentials
//     are loaded from the default AWS chain (env, instance metadata, etc.).
//     KMS_ENDPOINT (optional) overrides the KMS service endpoint, e.g. to point
//     at a local-kms Docker emulator ("http://localhost:8081"). When unset the
//     real AWS KMS endpoint is used.
//
// Returns an error instead of calling log.Fatal — callers decide how to handle
// the failure (the cmd/signer entrypoint logs and exits; the Lambda entrypoint
// logs and returns a startup error to the runtime).
func FromEnv(ctx context.Context) (Provider, error) {
	switch os.Getenv("KMS_PROVIDER") {
	case "aws":
		keyID := os.Getenv("KMS_KEY_ID")
		if keyID == "" {
			return nil, fmt.Errorf("kms: KMS_KEY_ID is required when KMS_PROVIDER=aws")
		}
		var opts []AWSOption
		if endpoint := os.Getenv("KMS_ENDPOINT"); endpoint != "" {
			opts = append(opts, WithEndpoint(endpoint))
		}
		provider, err := NewAWS(ctx, keyID, opts...)
		if err != nil {
			return nil, fmt.Errorf("kms: failed to initialize AWS KMS provider: %w", err)
		}
		return provider, nil

	case "", "local":
		masterKeyHex := os.Getenv("KMS_MASTER_KEY")
		if masterKeyHex == "" {
			return nil, fmt.Errorf("kms: KMS_MASTER_KEY is required when KMS_PROVIDER=local (32-byte hex key)")
		}
		masterKeyBytes, err := hex.DecodeString(masterKeyHex)
		if err != nil {
			return nil, fmt.Errorf("kms: KMS_MASTER_KEY is not valid hex: %w", err)
		}
		provider, err := NewLocal(masterKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("kms: failed to initialize local KMS provider: %w", err)
		}
		return provider, nil

	default:
		return nil, fmt.Errorf("kms: unknown KMS_PROVIDER %q (want \"local\" or \"aws\")", os.Getenv("KMS_PROVIDER"))
	}
}
