package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ethereum/go-ethereum/crypto"

	"kryard/signer/internal/canonicaljson"
	"kryard/signer/internal/envelope"
	"kryard/signer/internal/evmtx"
)

// signTransactionRequest is the request body for POST /internal/sign/transaction.
// The ciphertext fields are forwarded verbatim from Postgres by the API service.
// The API service NEVER decrypts keys.
type signTransactionRequest struct {
	OrganizationID      string            `json:"organizationId"`
	PrivateKeyID        string            `json:"privateKeyId"`
	Environment         string            `json:"environment"`
	EncryptedPrivateKey string            `json:"encryptedPrivateKey"` // base64
	EncryptedDataKey    string            `json:"encryptedDataKey"`    // base64
	KMSKeyID            string            `json:"kmsKeyId"`
	KMSProvider         string            `json:"kmsProvider"` // "local" | "aws"; forwarded from the key row
	EncryptionContext   map[string]string `json:"encryptionContext"`
	UnsignedTransaction string            `json:"unsignedTransaction"` // hex (with or without 0x)
	Type                string            `json:"type"`                // e.g. TRANSACTION_TYPE_ETHEREUM
	// EvaluatedInputHash is the hash the API computed when evaluating policy.
	// When non-empty, the signer re-computes it and refuses on mismatch (409).
	EvaluatedInputHash string `json:"evaluatedInputHash,omitempty"`
	// ActivityType is forwarded for the evaluatedInputHash re-check.
	ActivityType string `json:"activityType,omitempty"`
}

// txFieldsResponse carries the policy-relevant fields extracted from the decoded tx.
type txFieldsResponse struct {
	ChainID              string `json:"chainId"`
	To                   string `json:"to,omitempty"`
	Value                string `json:"value"`
	Nonce                uint64 `json:"nonce"`
	Gas                  uint64 `json:"gas"`
	MaxFeePerGas         string `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas,omitempty"`
	GasPrice             string `json:"gasPrice,omitempty"`
	Data                 string `json:"data"`
	MethodSelector       string `json:"methodSelector,omitempty"`
	// AuthorizationAddresses are the EIP-7702 delegation targets (type-4 only);
	// omitted for type-2/legacy. Policy allowlists these delegate impls.
	AuthorizationAddresses []string `json:"authorizationAddresses,omitempty"`
	// AuthorizationAuthorities are the recovered authorizing EOAs (type-4 only);
	// policy requires the tx `to` to be one of these.
	AuthorizationAuthorities []string `json:"authorizationAuthorities,omitempty"`
}

// signTransactionResponse is the response for POST /internal/sign/transaction.
// It MUST NOT contain any plaintext key material.
type signTransactionResponse struct {
	SignedTransaction string                `json:"signedTransaction"` // 0x-prefixed hex
	Fields            txFieldsResponse      `json:"fields"`
	SignerReceipt     signerReceiptResponse `json:"signerReceipt"`
}

func (s *Server) handleSignTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Nil KMS provider guard: refuse sign operations if the KMS provider is not configured.
	if s.deps.KMSProvider == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "signer not configured: KMSProvider is nil",
		})
		return
	}

	var req signTransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	// Validate required fields.
	if req.OrganizationID == "" || req.PrivateKeyID == "" || req.Environment == "" ||
		req.EncryptedPrivateKey == "" || req.EncryptedDataKey == "" ||
		req.UnsignedTransaction == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "organizationId, privateKeyId, environment, encryptedPrivateKey, encryptedDataKey, and unsignedTransaction are required",
		})
		return
	}

	// Defense-in-depth: encryption context's private_key_id must match the request.
	if encCtxID, ok := req.EncryptionContext["private_key_id"]; !ok || encCtxID != req.PrivateKeyID {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "encryptionContext.private_key_id does not match privateKeyId",
		})
		return
	}

	// Decode the base64 ciphertext blobs.
	ciphertext, err := base64.StdEncoding.DecodeString(req.EncryptedPrivateKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "encryptedPrivateKey: invalid base64: " + err.Error(),
		})
		return
	}
	wrappedDEK, err := base64.StdEncoding.DecodeString(req.EncryptedDataKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "encryptedDataKey: invalid base64: " + err.Error(),
		})
		return
	}

	// Rebuild the Encrypted value from the request fields.
	// Use the kmsProvider forwarded from the key row; fall back to "local" only
	// when absent so that existing integrations keep working without a forced
	// migration (the fallback is the only provider supported today).
	kmsProvider := req.KMSProvider
	if kmsProvider == "" {
		kmsProvider = "local"
	}
	enc := envelope.Encrypted{
		Ciphertext:  ciphertext,
		WrappedDEK:  wrappedDEK,
		KMSKeyID:    req.KMSKeyID,
		KMSProvider: kmsProvider,
	}

	// Decrypt the private key inside the signer. The API service NEVER decrypts.
	privKeyBytes, err := envelope.Decrypt(r.Context(), s.deps.KMSProvider, enc, req.EncryptionContext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "envelope decryption failed: " + err.Error(),
		})
		return
	}

	// Convert raw private key bytes to an ECDSA key for signing.
	ecKey, err := crypto.ToECDSA(privKeyBytes)

	// ZEROIZE the raw private key bytes immediately regardless of outcome.
	zeroize(privKeyBytes)

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("invalid private key: %v", err),
		})
		return
	}

	// Decode and sign the unsigned transaction using go-ethereum's audited
	// core/types + rlp libraries. We NEVER hand-roll RLP or ECDSA.
	signResult, err := evmtx.SignUnsignedTx(req.UnsignedTransaction, ecKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "transaction signing failed: " + err.Error(),
		})
		return
	}

	// EvaluatedInputHash re-check (P7 binding): if the API passed a hash,
	// the signer recomputes it over the fields it actually signed and refuses
	// on mismatch. This prevents a TOCTOU race where policy was evaluated on
	// different fields than what the signer sees.
	if req.EvaluatedInputHash != "" {
		activityType := req.ActivityType
		if activityType == "" {
			activityType = "ACTIVITY_TYPE_SIGN_TRANSACTION_V2"
		}
		txFieldsForHash := map[string]any{
			"chainId":              signResult.Fields.ChainID,
			"data":                 signResult.Fields.Data,
			"gas":                  float64(signResult.Fields.Gas),
			"maxFeePerGas":         signResult.Fields.MaxFeePerGas,
			"maxPriorityFeePerGas": signResult.Fields.MaxPriorityFeePerGas,
			"gasPrice":             signResult.Fields.GasPrice,
			"methodSelector":       signResult.Fields.MethodSelector,
			"nonce":                float64(signResult.Fields.Nonce),
			"to":                   signResult.Fields.To,
			"value":                signResult.Fields.Value,
		}
		// Bind EIP-7702 delegation targets ONLY when present, matching the API
		// side (policy.ts normalizeTxFields). Omitted for type-2/legacy so their
		// hash is unchanged; for type-4 it makes a swapped authorization fail the
		// re-check. Order is the authorization_list order (same on both sides).
		if len(signResult.Fields.AuthorizationAddresses) > 0 {
			txFieldsForHash["authorizationAddresses"] = signResult.Fields.AuthorizationAddresses
		}
		if len(signResult.Fields.AuthorizationAuthorities) > 0 {
			txFieldsForHash["authorizationAuthorities"] = signResult.Fields.AuthorizationAuthorities
		}
		hashInput := map[string]any{
			"activityType": activityType,
			"privateKeyId": req.PrivateKeyID,
			"txFields":     txFieldsForHash,
		}
		recomputedHash, hashErr := canonicaljson.SHA256Hex(hashInput)
		if hashErr != nil || recomputedHash != req.EvaluatedInputHash {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error":     "SIGNER_REQUEST_MISMATCH: evaluatedInputHash does not match",
				"errorCode": "SIGNER_REQUEST_MISMATCH",
			})
			return
		}
	}

	// Derive the public key from the EC key for the signer receipt.
	pubKeyHex := hex.EncodeToString(crypto.CompressPubkey(&ecKey.PublicKey))

	// Build signer receipt fields (hashes only — no key material).
	// Use SHA-256 of the unsigned tx bytes as the "payload hash" analogue.
	unsignedBytes := []byte(req.UnsignedTransaction)
	payloadHashBytes := sha256.Sum256(unsignedBytes)
	payloadHashHex := hex.EncodeToString(payloadHashBytes[:])

	// SignatureHash: sha256 of the signed tx bytes.
	signedBytes := []byte(signResult.SignedTransaction)
	sigHashBytes := sha256.Sum256(signedBytes)
	sigHashHex := hex.EncodeToString(sigHashBytes[:])

	// Map extracted fields to the response struct.
	fields := txFieldsResponse{
		ChainID:                  signResult.Fields.ChainID,
		To:                       signResult.Fields.To,
		Value:                    signResult.Fields.Value,
		Nonce:                    signResult.Fields.Nonce,
		Gas:                      signResult.Fields.Gas,
		MaxFeePerGas:             signResult.Fields.MaxFeePerGas,
		MaxPriorityFeePerGas:     signResult.Fields.MaxPriorityFeePerGas,
		GasPrice:                 signResult.Fields.GasPrice,
		Data:                     signResult.Fields.Data,
		MethodSelector:           signResult.Fields.MethodSelector,
		AuthorizationAddresses:   signResult.Fields.AuthorizationAddresses,
		AuthorizationAuthorities: signResult.Fields.AuthorizationAuthorities,
	}

	resp := signTransactionResponse{
		SignedTransaction: signResult.SignedTransaction,
		Fields:            fields,
		SignerReceipt: signerReceiptResponse{
			KeyID:         req.PrivateKeyID,
			PublicKey:     pubKeyHex,
			PayloadHash:   payloadHashHex,
			SignatureHash: sigHashHex,
			SignerBuildID: getBuildID(),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}
