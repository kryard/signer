package api_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

// encCtxStrings converts the createResp encryptionContext (map[string]any) to a
// map[string]string suitable for the sign request body.
func encCtxStrings(t *testing.T, createResp map[string]any) map[string]string {
	t.Helper()
	encCtx := createResp["encryptionContext"].(map[string]any)
	out := make(map[string]string, len(encCtx))
	for k, v := range encCtx {
		out[k] = v.(string)
	}
	return out
}

// firstAddress reads the first entry of the create response's addresses array.
// The OSS create response keeps the addresses field as a flat []string (the
// curve's single default address).
func firstAddress(t *testing.T, createResp map[string]any) string {
	t.Helper()
	addrs, ok := createResp["addresses"].([]any)
	if !ok || len(addrs) == 0 {
		t.Fatalf("addresses missing or empty: %v", createResp["addresses"])
	}
	return addrs[0].(string)
}

func decodeCreate(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d; body: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return resp
}

// TestCreateAndSignEd25519RoundTrip creates an ed25519 (Solana) key, signs a raw
// message with HASH_FUNCTION_NOT_APPLICABLE, and verifies the ed25519 signature.
func TestCreateAndSignEd25519RoundTrip(t *testing.T) {
	srv := newTestServer(t, false)

	createResp := decodeCreate(t, postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-ed-001",
		"privateKeyId":   "pk-ed-001",
		"environment":    "dev",
		"name":           "solana-key",
		"curve":          "CURVE_ED25519",
	}))

	if createResp["curve"] != "CURVE_ED25519" {
		t.Errorf("curve = %v, want CURVE_ED25519", createResp["curve"])
	}
	pubHex := createResp["publicKey"].(string)
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("publicKey %q invalid: %v (len %d)", pubHex, err, len(pubBytes))
	}
	addr := firstAddress(t, createResp)
	if strings.HasPrefix(addr, "0x") {
		t.Errorf("ed25519 address %q should be base58 Solana, not 0x", addr)
	}
	if dec, _ := base58.Decode(addr); hex.EncodeToString(dec) != pubHex {
		t.Errorf("address %q does not base58-decode to the public key", addr)
	}

	message := []byte("solana transaction message v0")
	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-ed-001",
		"privateKeyId":        "pk-ed-001",
		"environment":         "dev",
		"curve":               "CURVE_ED25519",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStrings(t, createResp),
		"payload":             hex.EncodeToString(message),
		"hashFunction":        "HASH_FUNCTION_NOT_APPLICABLE",
	})
	if signRec.Code != http.StatusOK {
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

// TestSignEd25519RejectsWrongHashFunction: ed25519 must use NOT_APPLICABLE.
func TestSignEd25519RejectsWrongHashFunction(t *testing.T) {
	srv := newTestServer(t, false)
	createResp := decodeCreate(t, postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-ed-002", "privateKeyId": "pk-ed-002",
		"environment": "dev", "name": "solana-key-2", "curve": "CURVE_ED25519",
	}))
	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId": "org-ed-002", "privateKeyId": "pk-ed-002", "environment": "dev",
		"curve":               "CURVE_ED25519",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStrings(t, createResp),
		"payload":             hex.EncodeToString([]byte("x")),
		"hashFunction":        "HASH_FUNCTION_KECCAK256",
	})
	if signRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for ed25519 with KECCAK256, got %d; body: %s", signRec.Code, signRec.Body.String())
	}
}

// TestCreateAndSignP256RoundTrip creates a P-256 key, signs a 32-byte digest with
// HASH_FUNCTION_NO_OP, and verifies the ECDSA-P256 signature.
func TestCreateAndSignP256RoundTrip(t *testing.T) {
	srv := newTestServer(t, false)

	createResp := decodeCreate(t, postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-p256-001",
		"privateKeyId":   "pk-p256-001",
		"environment":    "dev",
		"name":           "p256-key",
		"curve":          "CURVE_P256",
	}))

	if createResp["curve"] != "CURVE_P256" {
		t.Errorf("curve = %v, want CURVE_P256", createResp["curve"])
	}
	pubHex := createResp["publicKey"].(string)
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != 33 {
		t.Fatalf("publicKey %q invalid: %v (len %d)", pubHex, err, len(pubBytes))
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubBytes)
	if x == nil {
		t.Fatal("publicKey is not a valid compressed P-256 point")
	}
	// For P-256 the default address is the compressed public key hex itself.
	if addr := firstAddress(t, createResp); addr != pubHex {
		t.Errorf("p256 address = %q, want compressed pubkey %q", addr, pubHex)
	}

	digestArr := sha256.Sum256([]byte("p256 raw payload digest"))
	digest := digestArr[:]
	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-p256-001",
		"privateKeyId":        "pk-p256-001",
		"environment":         "dev",
		"curve":               "CURVE_P256",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStrings(t, createResp),
		"payload":             hex.EncodeToString(digest),
		"hashFunction":        "HASH_FUNCTION_NO_OP",
	})
	if signRec.Code != http.StatusOK {
		t.Fatalf("sign status = %d; body: %s", signRec.Code, signRec.Body.String())
	}
	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign: %v", err)
	}
	if signResp["v"] != "00" {
		t.Errorf("p256 v = %v, want 00", signResp["v"])
	}
	rBytes, _ := hex.DecodeString(signResp["r"].(string))
	sBytes, _ := hex.DecodeString(signResp["s"].(string))
	if len(rBytes) != 32 || len(sBytes) != 32 {
		t.Fatalf("r/s len = %d/%d, want 32/32", len(rBytes), len(sBytes))
	}
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !ecdsa.Verify(pub, digest, r, s) {
		t.Error("P-256 signature did not verify against the returned public key")
	}
	receipt := signResp["signerReceipt"].(map[string]any)
	if receipt["publicKey"] != pubHex {
		t.Errorf("receipt.publicKey = %v, want %s", receipt["publicKey"], pubHex)
	}
}

// TestSignP256RejectsNonNoOp: p256 requires HASH_FUNCTION_NO_OP.
func TestSignP256RejectsNonNoOp(t *testing.T) {
	srv := newTestServer(t, false)
	createResp := decodeCreate(t, postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-p256-002", "privateKeyId": "pk-p256-002",
		"environment": "dev", "name": "p256-key-2", "curve": "CURVE_P256",
	}))
	digest := sha256.Sum256([]byte("x"))
	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId": "org-p256-002", "privateKeyId": "pk-p256-002", "environment": "dev",
		"curve":               "CURVE_P256",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStrings(t, createResp),
		"payload":             hex.EncodeToString(digest[:]),
		"hashFunction":        "HASH_FUNCTION_KECCAK256",
	})
	if signRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for p256 with KECCAK256, got %d; body: %s", signRec.Code, signRec.Body.String())
	}
}

// TestCreateKeyUnknownCurveReturns400 ensures an unknown curve is rejected.
func TestCreateKeyUnknownCurveReturns400(t *testing.T) {
	srv := newTestServer(t, false)
	rec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-x", "privateKeyId": "pk-x",
		"environment": "dev", "name": "x", "curve": "CURVE_BOGUS",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown curve, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
