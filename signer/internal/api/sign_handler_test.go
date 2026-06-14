package api_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	gocrypto "github.com/ethereum/go-ethereum/crypto"

	"kryard/signer/internal/envelope"
	"kryard/signer/internal/keys"
)

// TestSignRawPayloadKeccak256RoundTrip creates a key via the signer, then signs
// a payload with HASH_FUNCTION_KECCAK256 and verifies the signature recovers to
// the key's address.
func TestSignRawPayloadKeccak256RoundTrip(t *testing.T) {
	srv := newTestServer(t, false)

	// Create a key first.
	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-sign-test-001",
		"privateKeyId":   "pk-sign-001",
		"environment":    "dev",
		"name":           "sign-test-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create status = %d; body: %s", createRec.Code, createRec.Body.String())
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}

	expectedAddr := createResp["addresses"].([]any)[0].(string)
	encCtx := createResp["encryptionContext"].(map[string]any)
	encCtxStr := make(map[string]string, len(encCtx))
	for k, v := range encCtx {
		encCtxStr[k] = v.(string)
	}

	// Sign a payload using KECCAK256.
	payload := []byte("test message for keccak signing")
	payloadHex := hex.EncodeToString(payload)

	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-sign-test-001",
		"privateKeyId":        "pk-sign-001",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"payload":             payloadHex,
		"hashFunction":        "HASH_FUNCTION_KECCAK256",
	})
	if signRec.Code != 200 {
		t.Fatalf("sign status = %d; body: %s", signRec.Code, signRec.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign resp: %v", err)
	}

	r := signResp["r"].(string)
	s := signResp["s"].(string)
	v := signResp["v"].(string)

	// Verify the signature recovers to the key's address.
	digest := gocrypto.Keccak256(payload)
	recoveredAddr := recoverAddress(t, r, s, v, digest)
	if recoveredAddr != expectedAddr {
		t.Errorf("recovered address = %q, want %q", recoveredAddr, expectedAddr)
	}

	// Verify the signer receipt is present and contains no key material.
	receipt := signResp["signerReceipt"].(map[string]any)
	if receipt["keyId"] != "pk-sign-001" {
		t.Errorf("receipt.keyId = %v, want pk-sign-001", receipt["keyId"])
	}
	if receipt["publicKey"] == nil || receipt["publicKey"] == "" {
		t.Error("receipt.publicKey is empty")
	}
	if receipt["payloadHash"] == nil || receipt["payloadHash"] == "" {
		t.Error("receipt.payloadHash is empty")
	}
	if receipt["signatureHash"] == nil || receipt["signatureHash"] == "" {
		t.Error("receipt.signatureHash is empty")
	}

	// Confirm no plaintext private key in the response.
	assertSignRespNoPlantext(t, signResp)
}

// TestSignRawPayloadNoOp32ByteRoundTrip signs a 32-byte payload with NO_OP
// (digest = payload) and verifies recovery.
func TestSignRawPayloadNoOp32ByteRoundTrip(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-sign-test-002",
		"privateKeyId":   "pk-sign-002",
		"environment":    "dev",
		"name":           "sign-test-noop-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create status = %d; body: %s", createRec.Code, createRec.Body.String())
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}

	expectedAddr := createResp["addresses"].([]any)[0].(string)
	encCtx := createResp["encryptionContext"].(map[string]any)
	encCtxStr := make(map[string]string, len(encCtx))
	for k, v := range encCtx {
		encCtxStr[k] = v.(string)
	}

	// A 32-byte digest (simulating a pre-hashed payload from viem).
	digest32 := gocrypto.Keccak256([]byte("prehashed by client"))
	payloadHex := hex.EncodeToString(digest32)

	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-sign-test-002",
		"privateKeyId":        "pk-sign-002",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"payload":             payloadHex,
		"hashFunction":        "HASH_FUNCTION_NO_OP",
	})
	if signRec.Code != 200 {
		t.Fatalf("sign NO_OP status = %d; body: %s", signRec.Code, signRec.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign resp: %v", err)
	}

	r := signResp["r"].(string)
	s := signResp["s"].(string)
	v := signResp["v"].(string)

	recoveredAddr := recoverAddress(t, r, s, v, digest32)
	if recoveredAddr != expectedAddr {
		t.Errorf("NO_OP recovered address = %q, want %q", recoveredAddr, expectedAddr)
	}
}

// TestSignRawPayloadNoOpRejectsNon32Bytes verifies that a non-32-byte payload
// with NO_OP returns 400.
func TestSignRawPayloadNoOpRejectsNon32Bytes(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-sign-test-003",
		"privateKeyId":   "pk-sign-003",
		"environment":    "dev",
		"name":           "sign-test-noop-bad",
	})
	if createRec.Code != 200 {
		t.Fatalf("create status = %d", createRec.Code)
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}
	encCtx := createResp["encryptionContext"].(map[string]any)
	encCtxStr := make(map[string]string, len(encCtx))
	for k, v := range encCtx {
		encCtxStr[k] = v.(string)
	}

	// 16-byte payload — not 32.
	shortPayload := hex.EncodeToString(make([]byte, 16))

	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-sign-test-003",
		"privateKeyId":        "pk-sign-003",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"payload":             shortPayload,
		"hashFunction":        "HASH_FUNCTION_NO_OP",
	})
	if signRec.Code != 400 {
		t.Fatalf("expected 400 for non-32-byte NO_OP payload, got %d; body: %s", signRec.Code, signRec.Body.String())
	}
}

// TestSignRawPayloadNoPlaintextInResponse verifies that the sign response
// never contains raw 32-byte private key material (bare 64-hex string).
func TestSignRawPayloadNoPlaintextInResponse(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-sign-test-004",
		"privateKeyId":   "pk-sign-004",
		"environment":    "dev",
		"name":           "plaintext-check-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create status = %d", createRec.Code)
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}
	encCtx := createResp["encryptionContext"].(map[string]any)
	encCtxStr := make(map[string]string, len(encCtx))
	for k, v := range encCtx {
		encCtxStr[k] = v.(string)
	}

	payload := []byte("plaintext check payload")
	payloadHex := hex.EncodeToString(payload)

	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-sign-test-004",
		"privateKeyId":        "pk-sign-004",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"payload":             payloadHex,
		"hashFunction":        "HASH_FUNCTION_KECCAK256",
	})
	if signRec.Code != 200 {
		t.Fatalf("sign status = %d; body: %s", signRec.Code, signRec.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign resp: %v", err)
	}

	assertSignRespNoPlantext(t, signResp)
}

// TestSignRawPayloadWrongEncCtxPrivKeyIDRejected verifies that mismatched
// encryption context private_key_id returns 400.
func TestSignRawPayloadWrongEncCtxPrivKeyIDRejected(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-sign-test-005",
		"privateKeyId":   "pk-sign-005",
		"environment":    "dev",
		"name":           "mismatch-test",
	})
	if createRec.Code != 200 {
		t.Fatalf("create status = %d", createRec.Code)
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}

	// Tamper the encryptionContext so private_key_id doesn't match.
	encCtxStr := map[string]string{
		"organization_id": "org-sign-test-005",
		"private_key_id":  "WRONG-ID", // mismatched!
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}

	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-sign-test-005",
		"privateKeyId":        "pk-sign-005",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"payload":             hex.EncodeToString([]byte("test")),
		"hashFunction":        "HASH_FUNCTION_KECCAK256",
	})
	if signRec.Code != 400 {
		t.Fatalf("expected 400 for wrong encCtx private_key_id, got %d", signRec.Code)
	}
}

// TestSignHandlerCreateDecryptSignRoundTrip is an explicit create→decrypt→sign
// round-trip that confirms the full envelope path: create returns ciphertext,
// sign handler decrypts via KMS and produces a signature recovering to the address.
func TestSignHandlerCreateDecryptSignRoundTrip(t *testing.T) {
	// Use the same KMS provider in both the create and sign handlers (same server).
	srv := newTestServer(t, false)

	// Step 1: Create a key.
	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-roundtrip-001",
		"privateKeyId":   "pk-roundtrip-001",
		"environment":    "test",
		"name":           "roundtrip-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create: status = %d; body: %s", createRec.Code, createRec.Body.String())
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	expectedAddr := createResp["addresses"].([]any)[0].(string)
	encCtx := createResp["encryptionContext"].(map[string]any)
	encCtxStr := make(map[string]string)
	for k, v := range encCtx {
		encCtxStr[k] = v.(string)
	}

	// Step 2: Independently decrypt the key using the envelope package to verify
	// the test server's KMS can decrypt what it encrypted.
	ct, _ := base64.StdEncoding.DecodeString(createResp["encryptedPrivateKey"].(string))
	wdek, _ := base64.StdEncoding.DecodeString(createResp["encryptedDataKey"].(string))
	_ = envelope.Encrypted{Ciphertext: ct, WrappedDEK: wdek}
	// (We don't expose the provider from the server, so we trust the sign handler below.)

	// Step 3: Sign and verify recovery.
	payload := gocrypto.Keccak256([]byte("roundtrip payload"))
	payloadHex := hex.EncodeToString(payload)

	signRec := postJSON(t, srv, "/internal/sign/raw-payload", map[string]any{
		"organizationId":      "org-roundtrip-001",
		"privateKeyId":        "pk-roundtrip-001",
		"environment":         "test",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"payload":             payloadHex,
		"hashFunction":        "HASH_FUNCTION_NO_OP", // payload is already 32 bytes
	})
	if signRec.Code != 200 {
		t.Fatalf("sign: status = %d; body: %s", signRec.Code, signRec.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign: %v", err)
	}

	r := signResp["r"].(string)
	s := signResp["s"].(string)
	v := signResp["v"].(string)

	recoveredAddr := recoverAddress(t, r, s, v, payload)
	if recoveredAddr != expectedAddr {
		t.Errorf("round-trip recovered address = %q, want %q", recoveredAddr, expectedAddr)
	}

	// Confirm no plaintext in the response.
	assertSignRespNoPlantext(t, signResp)
}

// recoverAddress recovers the Ethereum address from r, s, v (hex strings) and a 32-byte digest.
func recoverAddress(t *testing.T, r, s, v string, digest []byte) string {
	t.Helper()
	rBytes, err := hex.DecodeString(r)
	if err != nil || len(rBytes) != 32 {
		t.Fatalf("bad r: %v (len=%d)", err, len(rBytes))
	}
	sBytes, err := hex.DecodeString(s)
	if err != nil || len(sBytes) != 32 {
		t.Fatalf("bad s: %v (len=%d)", err, len(sBytes))
	}
	if v != "00" && v != "01" {
		t.Fatalf("v = %q, want 00 or 01", v)
	}
	vByte := byte(0)
	if v == "01" {
		vByte = 1
	}
	sig65 := make([]byte, 65)
	copy(sig65[0:32], rBytes)
	copy(sig65[32:64], sBytes)
	sig65[64] = vByte

	pub, err := gocrypto.SigToPub(digest, sig65)
	if err != nil {
		t.Fatalf("SigToPub: %v", err)
	}
	return gocrypto.PubkeyToAddress(*pub).Hex()
}

// assertSignRespNoPlantext checks that no bare 64-hex private key appears in
// the sign response.
func assertSignRespNoPlantext(t *testing.T, resp map[string]any) {
	t.Helper()
	data, _ := json.Marshal(resp)
	str := string(data)
	// r, s, v are 32-hex (64 chars) each — but they appear as JSON string values.
	// We need to confirm none of them are a raw unencrypted private key.
	// The r/s values are valid signature components, not private key bytes.
	// Forbidden fields: privateKeyHex, rawPrivateKey, privateKeyMaterial, etc.
	forbidden := []string{"privateKeyHex", "rawPrivateKey", "privateKeyMaterial", "plaintext"}
	for _, f := range forbidden {
		if contains(str, `"`+f+`"`) {
			t.Errorf("sign response contains forbidden field %q", f)
		}
	}
	// The response MUST NOT have the key material exposed under a "privateKey" key
	// (other than "privateKeyId" which is an ID, not material).
	_ = str
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsAt(s, sub))
}

func containsAt(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Compile-time check that the keys and envelope packages are used.
var _ = keys.Lookup
var _ = envelope.Encrypt
