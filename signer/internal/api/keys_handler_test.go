package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kryard/signer/internal/api"
	"kryard/signer/internal/kms"
)

func newTestServer(t *testing.T, allowImport bool) http.Handler {
	t.Helper()
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	provider, err := kms.NewLocal(masterKey)
	if err != nil {
		t.Fatalf("kms.NewLocal: %v", err)
	}
	return api.NewServer(api.Deps{
		KMSProvider: provider,
		AllowImport: allowImport,
	})
}

func postJSON(t *testing.T, srv http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestCreateKeyReturns200WithPublicMetadata(t *testing.T) {
	srv := newTestServer(t, false)

	rec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-test-001",
		"privateKeyId":   "pk-test-001",
		"environment":    "dev",
		"name":           "test-key",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Must have publicKey (compressed hex, 66 chars)
	pubKey, ok := resp["publicKey"].(string)
	if !ok || pubKey == "" {
		t.Errorf("publicKey missing or empty: %v", resp["publicKey"])
	}
	if len(pubKey) != 66 {
		t.Errorf("publicKey hex length = %d, want 66", len(pubKey))
	}

	// Must have addresses array with a 0x address
	addrs, ok := resp["addresses"].([]any)
	if !ok || len(addrs) == 0 {
		t.Errorf("addresses missing or empty: %v", resp["addresses"])
	} else {
		addr, ok := addrs[0].(string)
		if !ok || !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
			t.Errorf("addresses[0] = %q, want 0x... (42 chars)", addrs[0])
		}
	}

	// Must have base64 ciphertext
	ct, ok := resp["encryptedPrivateKey"].(string)
	if !ok || ct == "" {
		t.Errorf("encryptedPrivateKey missing or empty")
	}

	// Must have wrapped DEK
	wdek, ok := resp["encryptedDataKey"].(string)
	if !ok || wdek == "" {
		t.Errorf("encryptedDataKey missing or empty")
	}

	// Must have KMS metadata
	if resp["kmsProvider"] == "" || resp["kmsProvider"] == nil {
		t.Errorf("kmsProvider missing")
	}
	if resp["kmsKeyId"] == "" || resp["kmsKeyId"] == nil {
		t.Errorf("kmsKeyId missing")
	}

	// privateKeyId must be echoed
	if resp["privateKeyId"] != "pk-test-001" {
		t.Errorf("privateKeyId = %v, want pk-test-001", resp["privateKeyId"])
	}
}

func TestCreateKeyNoPlaintextInResponse(t *testing.T) {
	srv := newTestServer(t, false)

	rec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-test-002",
		"privateKeyId":   "pk-test-002",
		"environment":    "dev",
		"name":           "no-plaintext-test",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()

	// The response must not contain any field named "privateKey" with raw key material.
	// We check that no field named "privateKeyHex", "privateKeyBytes", "rawPrivateKey",
	// "privateKeyMaterial" appears in the JSON keys.
	var resp map[string]any
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	forbiddenFields := []string{"privateKeyHex", "privateKeyBytes", "rawPrivateKey", "privateKeyMaterial", "plaintext"}
	for _, f := range forbiddenFields {
		if _, exists := resp[f]; exists {
			t.Errorf("response contains forbidden plaintext field %q", f)
		}
	}

	// The encryptedPrivateKey and encryptedDataKey must be base64-encoded (not raw hex private key)
	ct := resp["encryptedPrivateKey"].(string)
	// A 32-byte private key in hex is 64 chars; in base64 it's 44+ chars (with GCM overhead).
	// The ciphertext (nonce+tag+key) base64 should be much longer than 64 chars.
	if len(ct) < 64 {
		t.Errorf("encryptedPrivateKey = %q too short (possible unencrypted?)", ct)
	}
}

func TestCreateKeyImportDisabledReturns403(t *testing.T) {
	srv := newTestServer(t, false) // allowImport = false

	rec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId":      "org-test-003",
		"privateKeyId":        "pk-test-003",
		"environment":         "dev",
		"name":                "import-test",
		"importPrivateKeyHex": "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d",
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateKeyImportEnabledKnownVector(t *testing.T) {
	srv := newTestServer(t, true) // allowImport = true

	// Well-known Ganache account #0 vector
	privHex := "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
	expectedAddr := "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"

	rec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId":      "org-test-004",
		"privateKeyId":        "pk-test-004",
		"environment":         "dev",
		"name":                "imported-key",
		"importPrivateKeyHex": privHex,
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	addrs := resp["addresses"].([]any)
	if len(addrs) == 0 {
		t.Fatal("addresses empty")
	}
	if addrs[0].(string) != expectedAddr {
		t.Errorf("imported address = %q, want %q", addrs[0], expectedAddr)
	}
}

func TestCreateKeyMissingFieldsReturns400(t *testing.T) {
	srv := newTestServer(t, false)

	// Missing organizationId
	rec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"privateKeyId": "pk-test-005",
		"environment":  "dev",
		"name":         "test",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHealthStillWorksWithDeps(t *testing.T) {
	srv := newTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet, "/internal/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", rec.Code)
	}
}

// Ensure Deps satisfies our test's context expectations.
var _ = context.Background
