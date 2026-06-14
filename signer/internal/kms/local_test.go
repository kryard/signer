package kms_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"kryard/signer/internal/kms"
)

func newTestLocal(t *testing.T) kms.Provider {
	t.Helper()
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	p, err := kms.NewLocal(masterKey)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	return p
}

func TestLocalWrapUnwrapRoundTrip(t *testing.T) {
	p := newTestLocal(t)
	ctx := context.Background()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	encCtx := map[string]string{
		"organization_id": "org-123",
		"private_key_id":  "pk-456",
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}

	wrapped, keyID, err := p.WrapDEK(ctx, dek, encCtx)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if keyID == "" {
		t.Fatal("WrapDEK returned empty keyID")
	}
	if len(wrapped) == 0 {
		t.Fatal("WrapDEK returned empty wrapped key")
	}

	unwrapped, err := p.UnwrapDEK(ctx, wrapped, encCtx)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatalf("round-trip mismatch: got %x, want %x", unwrapped, dek)
	}
}

func TestLocalUnwrapWrongContextFails(t *testing.T) {
	p := newTestLocal(t)
	ctx := context.Background()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	encCtx := map[string]string{
		"organization_id": "org-123",
		"private_key_id":  "pk-456",
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}

	wrapped, _, err := p.WrapDEK(ctx, dek, encCtx)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	wrongCtx := map[string]string{
		"organization_id": "org-ATTACKER",
		"private_key_id":  "pk-456",
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}
	_, err = p.UnwrapDEK(ctx, wrapped, wrongCtx)
	if err == nil {
		t.Fatal("UnwrapDEK with wrong context should have failed but succeeded")
	}
}

func TestLocalUnwrapTamperedCiphertextFails(t *testing.T) {
	p := newTestLocal(t)
	ctx := context.Background()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	encCtx := map[string]string{
		"organization_id": "org-123",
		"private_key_id":  "pk-456",
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}

	wrapped, _, err := p.WrapDEK(ctx, dek, encCtx)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Flip a byte in the ciphertext portion (after the 12-byte nonce)
	tampered := make([]byte, len(wrapped))
	copy(tampered, wrapped)
	tampered[15] ^= 0xFF

	_, err = p.UnwrapDEK(ctx, tampered, encCtx)
	if err == nil {
		t.Fatal("UnwrapDEK with tampered ciphertext should have failed but succeeded")
	}
}

func TestLocalName(t *testing.T) {
	p := newTestLocal(t)
	if p.Name() != "local" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "local")
	}
}

func TestLocalNewLocalRejectsWrongKeySize(t *testing.T) {
	_, err := kms.NewLocal([]byte("tooshort"))
	if err == nil {
		t.Fatal("NewLocal with short key should fail")
	}
}
