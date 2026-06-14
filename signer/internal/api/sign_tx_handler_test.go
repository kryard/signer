package api_test

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	gocrypto "github.com/ethereum/go-ethereum/crypto"
)

// eip1559UnsignedTxHex is a fixed EIP-1559 unsigned tx for Sepolia (chainId=11155111):
//
//	nonce=0, maxPriorityFeePerGas=1e9, maxFeePerGas=1e9, gas=21000,
//	to=0x000000000000000000000000000000000000dEaD, value=0, data=[], accessList=[]
const eip1559UnsignedTxHex = "0x02ea83aa36a780843b9aca00843b9aca0082520894000000000000000000000000000000000000dead8080c0"

// TestSignTransactionEIP1559RoundTrip creates a key, then calls /internal/sign/transaction
// with a fixed EIP-1559 unsigned tx and verifies the signed tx recovers to the key address.
func TestSignTransactionEIP1559RoundTrip(t *testing.T) {
	srv := newTestServer(t, false)

	// Step 1: create a key.
	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-signtx-001",
		"privateKeyId":   "pk-signtx-001",
		"environment":    "dev",
		"name":           "signtx-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create key status = %d; body: %s", createRec.Code, createRec.Body.String())
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

	// Step 2: sign the fixed EIP-1559 unsigned tx.
	signRec := postJSON(t, srv, "/internal/sign/transaction", map[string]any{
		"organizationId":      "org-signtx-001",
		"privateKeyId":        "pk-signtx-001",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"unsignedTransaction": eip1559UnsignedTxHex,
		"type":                "TRANSACTION_TYPE_ETHEREUM",
	})
	if signRec.Code != 200 {
		t.Fatalf("sign tx status = %d; body: %s", signRec.Code, signRec.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign tx resp: %v", err)
	}

	// Verify the response has signedTransaction.
	signedTx, ok := signResp["signedTransaction"].(string)
	if !ok || signedTx == "" {
		t.Fatalf("signedTransaction missing or empty: %v", signResp["signedTransaction"])
	}
	if !strings.HasPrefix(signedTx, "0x") {
		t.Errorf("signedTransaction should start with 0x, got: %q", signedTx[:min(10, len(signedTx))])
	}

	// Verify the signed tx recovers to the key's address.
	chainID := big.NewInt(11155111)
	recoveredAddr := recoverAddrFromSignedTxHex(t, signedTx, chainID)
	if !strings.EqualFold(recoveredAddr, expectedAddr) {
		t.Errorf("recovered address = %q, want %q", recoveredAddr, expectedAddr)
	}

	// Verify the signer receipt is present.
	receipt, ok := signResp["signerReceipt"].(map[string]any)
	if !ok || receipt == nil {
		t.Fatal("signerReceipt missing in sign tx response")
	}
	if receipt["keyId"] != "pk-signtx-001" {
		t.Errorf("signerReceipt.keyId = %v, want pk-signtx-001", receipt["keyId"])
	}
	if receipt["publicKey"] == nil || receipt["publicKey"] == "" {
		t.Error("signerReceipt.publicKey is empty")
	}
	if receipt["payloadHash"] == nil || receipt["payloadHash"] == "" {
		t.Error("signerReceipt.payloadHash is empty")
	}
	if receipt["signatureHash"] == nil || receipt["signatureHash"] == "" {
		t.Error("signerReceipt.signatureHash is empty")
	}

	// Verify fields are present.
	fields, ok := signResp["fields"].(map[string]any)
	if !ok || fields == nil {
		t.Fatal("fields missing in sign tx response")
	}
	if fields["chainId"] == nil {
		t.Error("fields.chainId missing")
	}
	if fields["gas"] == nil {
		t.Error("fields.gas missing")
	}

	// Confirm no plaintext private key in the response.
	assertSignRespNoPlantext(t, signResp)
}

// TestSignTransactionFieldExtraction verifies that the extracted fields
// match the values encoded in the fixed EIP-1559 test vector.
func TestSignTransactionFieldExtraction(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-signtx-fields-001",
		"privateKeyId":   "pk-signtx-fields-001",
		"environment":    "dev",
		"name":           "signtx-fields-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create key status = %d; body: %s", createRec.Code, createRec.Body.String())
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

	signRec := postJSON(t, srv, "/internal/sign/transaction", map[string]any{
		"organizationId":      "org-signtx-fields-001",
		"privateKeyId":        "pk-signtx-fields-001",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"unsignedTransaction": eip1559UnsignedTxHex,
		"type":                "TRANSACTION_TYPE_ETHEREUM",
	})
	if signRec.Code != 200 {
		t.Fatalf("sign tx status = %d; body: %s", signRec.Code, signRec.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign tx resp: %v", err)
	}

	fields := signResp["fields"].(map[string]any)

	// ChainID = 11155111 = 0xaa36a7
	if !strings.EqualFold(fields["chainId"].(string), "0xaa36a7") {
		t.Errorf("fields.chainId = %q, want 0xaa36a7", fields["chainId"])
	}
	// To = 0x000...dEaD
	if !strings.EqualFold(fields["to"].(string), "0x000000000000000000000000000000000000dEaD") {
		t.Errorf("fields.to = %q, want 0x000...dEaD", fields["to"])
	}
	// Value = "0x0"
	if !strings.EqualFold(fields["value"].(string), "0x0") {
		t.Errorf("fields.value = %q, want 0x0", fields["value"])
	}
	// Nonce = 0
	if int(fields["nonce"].(float64)) != 0 {
		t.Errorf("fields.nonce = %v, want 0", fields["nonce"])
	}
	// Gas = 21000
	if int(fields["gas"].(float64)) != 21000 {
		t.Errorf("fields.gas = %v, want 21000", fields["gas"])
	}
	// MethodSelector should be absent (empty data)
	if sel, exists := fields["methodSelector"]; exists && sel != "" && sel != nil {
		t.Errorf("fields.methodSelector = %v, want absent/empty for empty data", sel)
	}
}

// TestSignTransactionMissingFieldReturns400 verifies that missing required fields return 400.
func TestSignTransactionMissingFieldReturns400(t *testing.T) {
	srv := newTestServer(t, false)

	// Missing unsignedTransaction.
	rec := postJSON(t, srv, "/internal/sign/transaction", map[string]any{
		"organizationId":      "org-signtx-bad-001",
		"privateKeyId":        "pk-signtx-bad-001",
		"environment":         "dev",
		"encryptedPrivateKey": "aGVsbG8=", // base64("hello")
		"encryptedDataKey":    "d29ybGQ=", // base64("world")
		"encryptionContext":   map[string]string{"private_key_id": "pk-signtx-bad-001"},
		// unsignedTransaction is absent
	})
	if rec.Code != 400 {
		t.Fatalf("expected 400 for missing unsignedTransaction, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSignTransactionWrongEncCtxRejected verifies that mismatched encryption context
// private_key_id returns 400 (custody invariant).
func TestSignTransactionWrongEncCtxRejected(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-signtx-mismatch-001",
		"privateKeyId":   "pk-signtx-mismatch-001",
		"environment":    "dev",
		"name":           "mismatch-signtx-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create key status = %d", createRec.Code)
	}
	var createResp map[string]any
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}

	// Tamper the encryption context.
	tampered := map[string]string{
		"organization_id": "org-signtx-mismatch-001",
		"private_key_id":  "WRONG-KEY-ID", // mismatch
		"environment":     "dev",
		"purpose":         "wallet-signing",
	}

	rec := postJSON(t, srv, "/internal/sign/transaction", map[string]any{
		"organizationId":      "org-signtx-mismatch-001",
		"privateKeyId":        "pk-signtx-mismatch-001",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   tampered,
		"unsignedTransaction": eip1559UnsignedTxHex,
	})
	if rec.Code != 400 {
		t.Fatalf("expected 400 for mismatched encCtx private_key_id, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSignTransactionMalformedTxHexReturns400 verifies that a malformed
// unsignedTransaction returns 400.
func TestSignTransactionMalformedTxHexReturns400(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-signtx-malformed-001",
		"privateKeyId":   "pk-signtx-malformed-001",
		"environment":    "dev",
		"name":           "malformed-signtx-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create key status = %d", createRec.Code)
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

	rec := postJSON(t, srv, "/internal/sign/transaction", map[string]any{
		"organizationId":      "org-signtx-malformed-001",
		"privateKeyId":        "pk-signtx-malformed-001",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"unsignedTransaction": "0xdeadbeef_not_valid_rlp!@#",
	})
	if rec.Code != 400 {
		t.Fatalf("expected 400 for malformed tx hex, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSignTransactionNoPlaintextInResponse confirms the sign tx response
// contains no raw private key material.
func TestSignTransactionNoPlaintextInResponse(t *testing.T) {
	srv := newTestServer(t, false)

	createRec := postJSON(t, srv, "/internal/keys/create", map[string]string{
		"organizationId": "org-signtx-noplain-001",
		"privateKeyId":   "pk-signtx-noplain-001",
		"environment":    "dev",
		"name":           "noplain-signtx-key",
	})
	if createRec.Code != 200 {
		t.Fatalf("create key status = %d", createRec.Code)
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

	signRec := postJSON(t, srv, "/internal/sign/transaction", map[string]any{
		"organizationId":      "org-signtx-noplain-001",
		"privateKeyId":        "pk-signtx-noplain-001",
		"environment":         "dev",
		"encryptedPrivateKey": createResp["encryptedPrivateKey"],
		"encryptedDataKey":    createResp["encryptedDataKey"],
		"kmsKeyId":            createResp["kmsKeyId"],
		"encryptionContext":   encCtxStr,
		"unsignedTransaction": eip1559UnsignedTxHex,
	})
	if signRec.Code != 200 {
		t.Fatalf("sign tx status = %d; body: %s", signRec.Code, signRec.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signRec.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode sign tx resp: %v", err)
	}

	assertSignRespNoPlantext(t, signResp)
}

// recoverAddrFromSignedTxHex decodes a signed tx hex and recovers the sender address.
func recoverAddrFromSignedTxHex(t *testing.T, signedTxHex string, chainID *big.Int) string {
	t.Helper()

	hexStr := signedTxHex
	if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
		hexStr = hexStr[2:]
	}

	raw := make([]byte, len(hexStr)/2)
	if _, err := hexDecodeString(raw, hexStr); err != nil {
		t.Fatalf("hex decode signed tx: %v", err)
	}

	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	signer := types.LatestSignerForChainID(chainID)
	addr, err := types.Sender(signer, &tx)
	if err != nil {
		t.Fatalf("types.Sender: %v", err)
	}
	return addr.Hex()
}

// hexDecodeString decodes hex into dst. We can't import encoding/hex in _test
// without the package, so use go-ethereum's crypto as an intermediary.
func hexDecodeString(dst []byte, src string) (int, error) {
	// Use crypto package which is already imported.
	// Actually we use the standard approach via gocrypto.
	b := gocrypto.Keccak256([]byte{}) // just to use the import
	_ = b
	// Use FromHex from go-ethereum common package.
	// Since we already import encoding/hex in keys_handler_test via recoverAddress,
	// we inline it here.
	for i := 0; i < len(dst); i++ {
		hi := hexVal(src[2*i])
		lo := hexVal(src[2*i+1])
		if hi == 255 || lo == 255 {
			return i, &hexError{i * 2}
		}
		dst[i] = hi<<4 | lo
	}
	return len(dst), nil
}

type hexError struct{ pos int }

func (e *hexError) Error() string {
	return "invalid hex character at position"
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 255
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
