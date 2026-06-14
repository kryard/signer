package envelope_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"

	"kryard/signer/internal/envelope"
	"kryard/signer/internal/kms"
)

func newTestProvider(t *testing.T) kms.Provider {
	t.Helper()
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	p, err := kms.NewLocal(masterKey)
	if err != nil {
		t.Fatalf("kms.NewLocal: %v", err)
	}
	return p
}

func TestEnvelopeRoundTrip(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	plaintext := []byte("super-secret-private-key-material")
	encCtx := map[string]string{
		"organization_id": "org-abc",
		"private_key_id":  "pk-xyz",
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}

	enc, err := envelope.Encrypt(ctx, p, plaintext, encCtx)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := envelope.Decrypt(ctx, p, enc, encCtx)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %x, want %x", got, plaintext)
	}
}

func TestEnvelopeDecryptWrongContextFails(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	plaintext := []byte("private-key-bytes")
	encCtx := map[string]string{
		"organization_id": "org-abc",
		"private_key_id":  "pk-xyz",
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}

	enc, err := envelope.Encrypt(ctx, p, plaintext, encCtx)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrongCtx := map[string]string{
		"organization_id": "org-EVIL",
		"private_key_id":  "pk-xyz",
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}
	_, err = envelope.Decrypt(ctx, p, enc, wrongCtx)
	if err == nil {
		t.Fatal("Decrypt with wrong encryption context should have failed but succeeded")
	}
}

func TestEncryptedStructContainsNoPlaintext(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	// Use a distinctive plaintext pattern that would be easy to spot
	plaintext := []byte("PLAINTEXT-PRIVATE-KEY-DO-NOT-STORE")
	encCtx := map[string]string{
		"organization_id": "org-abc",
		"private_key_id":  "pk-xyz",
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}

	enc, err := envelope.Encrypt(ctx, p, plaintext, encCtx)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Serialize the Encrypted struct to JSON and verify plaintext is not present
	data, err := json.Marshal(enc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if bytes.Contains(data, plaintext) {
		t.Fatalf("Encrypted struct JSON contains plaintext: %s", data)
	}
	// Also check that the Ciphertext field (raw bytes) does not equal plaintext
	if bytes.Equal(enc.Ciphertext, plaintext) {
		t.Fatal("Encrypted.Ciphertext equals plaintext (not encrypted)")
	}
}

func TestEncryptedStructFields(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	plaintext := []byte("key-material")
	encCtx := map[string]string{
		"organization_id": "org-1",
		"private_key_id":  "pk-1",
		"environment":     "prod",
		"purpose":         "wallet-signing",
	}

	enc, err := envelope.Encrypt(ctx, p, plaintext, encCtx)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(enc.Ciphertext) == 0 {
		t.Error("Encrypted.Ciphertext is empty")
	}
	if len(enc.WrappedDEK) == 0 {
		t.Error("Encrypted.WrappedDEK is empty")
	}
	if enc.KMSKeyID == "" {
		t.Error("Encrypted.KMSKeyID is empty")
	}
	if enc.KMSProvider == "" {
		t.Error("Encrypted.KMSProvider is empty")
	}
}
