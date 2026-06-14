package api_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

// TestCreateAndSignEd25519RoundTrip creates an ed25519 (Solana) key and signs a raw
// message with HASH_FUNCTION_NOT_APPLICABLE, then verifies the ed25519 signature
// against the returned public key.
func TestCreateAndSignEd25519RoundTrip(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-ed-001",
		"privateKeyId":   "pk-ed-001",
		"environment":    "dev",
		"name":           "solana-key",
		"curve":          "CURVE_ED25519",
	})
	if createRec.Code != 200 {
		t.Fatalf("create status = %d; body: %s", createRec.Code, createRec.Body.String())
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	if createResp["curve"] != "CURVE_ED25519" {
		t.Errorf("curve = %v, want CURVE_ED25519", createResp["curve"])
	}
	pubHex := createResp["publicKey"].(string)
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("publicKey %q invalid: %v (len %d)", pubHex, err, len(pubBytes))
	}
	addr := createResp["addresses"].([]any)[0].(string)
	if strings.HasPrefix(addr, "0x") {
		t.Errorf("ed25519 address %q should be a base58 Solana address, not 0x", addr)
	}
	if dec, _ := base58.Decode(addr); hex.EncodeToString(dec) != pubHex {
		t.Errorf("address %q does not base58-decode to the public key", addr)
	}

	encCtx := createResp["encryptionContext"].(map[string]any)
	encCtxStr := make(map[string]string, len(encCtx))
	for k, v := range encCtx {
		encCtxStr[k] = v.(string)
	}

	// Sign an arbitrary message (stand-in for a Solana tx message) — no pre-hash.
	message := []byte("solana transaction message v0")
	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-ed-001",
		"privateKeyId":        "pk-ed-001",
		"environment":         "dev",
		"curve":               "CURVE_ED25519",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"payload":             hex.EncodeToString(message),
		"hashFunction":        "HASH_FUNCTION_NOT_APPLICABLE",
	})
	if signRec.Code != 200 {
		t.Fatalf("sign status = %d; body: %s", signRec.Code, signRec.Body.String())
	}
	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign: %v", err)
	}

	if signResp["v"] != "00" {
		t.Errorf("ed25519 v = %v, want 00", signResp["v"])
	}
	rBytes, _ := hex.DecodeString(signResp["r"].(string))
	sBytes, _ := hex.DecodeString(signResp["s"].(string))
	sig := append(append([]byte{}, rBytes...), sBytes...)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("reconstructed sig len = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubBytes, message, sig) {
		t.Error("ed25519 signature did not verify against the returned public key")
	}

	receipt := signResp["signerReceipt"].(map[string]any)
	if receipt["publicKey"] != pubHex {
		t.Errorf("receipt.publicKey = %v, want %s", receipt["publicKey"], pubHex)
	}
}

// TestSignEd25519RejectsWrongHashFunction verifies an ed25519 key must use
// HASH_FUNCTION_NOT_APPLICABLE (a secp256k1 hash function is rejected).
func TestSignEd25519RejectsWrongHashFunction(t *testing.T) {
	srv := newTestServer(t, false)
	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-ed-002", "privateKeyId": "pk-ed-002",
		"environment": "dev", "name": "solana-key-2", "curve": "CURVE_ED25519",
	})
	if createRec.Code != 200 {
		t.Fatalf("create status = %d", createRec.Code)
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	encCtx := createResp["encryptionContext"].(map[string]any)
	encCtxStr := make(map[string]string, len(encCtx))
	for k, v := range encCtx {
		encCtxStr[k] = v.(string)
	}
	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId": "org-ed-002", "privateKeyId": "pk-ed-002", "environment": "dev",
		"curve":               "CURVE_ED25519",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"payload":             hex.EncodeToString([]byte("x")),
		"hashFunction":        "HASH_FUNCTION_KECCAK256",
	})
	if signRec.Code != 400 {
		t.Fatalf("expected 400 for ed25519 with KECCAK256, got %d; body: %s", signRec.Code, signRec.Body.String())
	}
}
