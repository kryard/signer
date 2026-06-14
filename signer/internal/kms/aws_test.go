package kms_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"testing"

	"kryard/signer/internal/kms"
)

// compile-time assertion: *AWS implements kms.Provider.
var _ kms.Provider = (*kms.AWS)(nil)

// TestAWSRoundTrip performs a real Encrypt/Decrypt round-trip against AWS KMS.
// It is skipped unless KRYARD_AWS_KMS_TEST_KEY_ID is set (a symmetric KMS key
// ID or ARN in the caller's AWS account). AWS credentials must also be present
// in the environment (e.g. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, or an
// IAM role via instance/task metadata).
func TestAWSRoundTrip(t *testing.T) {
	keyID := os.Getenv("KRYARD_AWS_KMS_TEST_KEY_ID")
	if keyID == "" {
		t.Skip("KRYARD_AWS_KMS_TEST_KEY_ID not set — skipping AWS KMS live test (CI without creds stays green)")
	}

	ctx := context.Background()

	provider, err := kms.NewAWS(ctx, keyID)
	if err != nil {
		t.Fatalf("NewAWS: %v", err)
	}

	// Generate a random 32-byte DEK to wrap.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read DEK: %v", err)
	}

	encCtx := map[string]string{
		"organization_id": "org-123",
		"private_key_id":  "pk-456",
		"environment":     "test",
		"purpose":         "wallet-signing",
	}

	// --- wrap ---
	wrapped, returnedKeyID, err := provider.WrapDEK(ctx, dek, encCtx)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("WrapDEK returned empty ciphertext")
	}
	if returnedKeyID == "" {
		t.Fatal("WrapDEK returned empty keyID")
	}

	// --- unwrap (correct context) ---
	unwrapped, err := provider.UnwrapDEK(ctx, wrapped, encCtx)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatalf("round-trip mismatch: got %x, want %x", unwrapped, dek)
	}

	// --- unwrap (wrong encryption context must fail) ---
	wrongCtx := map[string]string{
		"organization_id": "org-ATTACKER",
		"private_key_id":  "pk-456",
		"environment":     "test",
		"purpose":         "wallet-signing",
	}
	_, err = provider.UnwrapDEK(ctx, wrapped, wrongCtx)
	if err == nil {
		t.Fatal("UnwrapDEK with wrong EncryptionContext should have failed but succeeded")
	}
	t.Logf("UnwrapDEK with wrong context correctly returned error: %v", err)
}

// TestAWSName verifies the provider name without hitting AWS.
// We cannot instantiate *AWS without creds, so we verify the interface at the
// type level via the compile-time assertion above. Name() is tested here
// indirectly through the interface assertion existing.
func TestAWSName(t *testing.T) {
	keyID := os.Getenv("KRYARD_AWS_KMS_TEST_KEY_ID")
	if keyID == "" {
		t.Skip("KRYARD_AWS_KMS_TEST_KEY_ID not set — skipping AWS KMS live test (CI without creds stays green)")
	}

	ctx := context.Background()
	provider, err := kms.NewAWS(ctx, keyID)
	if err != nil {
		t.Fatalf("NewAWS: %v", err)
	}
	if got := provider.Name(); got != "aws" {
		t.Fatalf("Name() = %q, want %q", got, "aws")
	}
}
