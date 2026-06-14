package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"kryard/signer/internal/envelope"
	"kryard/signer/internal/keys"
)

// createKeyRequest is the request body for POST /internal/keys/create.
type createKeyRequest struct {
	OrganizationID      string `json:"organizationId"`
	PrivateKeyID        string `json:"privateKeyId"`
	Environment         string `json:"environment"`
	Name                string `json:"name"`
	ImportPrivateKeyHex string `json:"importPrivateKeyHex,omitempty"`
}

// createKeyResponse is the response body for POST /internal/keys/create.
// It MUST NOT contain any plaintext key material.
type createKeyResponse struct {
	PrivateKeyID        string            `json:"privateKeyId"`
	PublicKey           string            `json:"publicKey"`
	Addresses           []string          `json:"addresses"`
	Curve               string            `json:"curve"`
	EncryptedPrivateKey string            `json:"encryptedPrivateKey"` // base64(nonce||GCM(privKey)) under DEK
	EncryptedDataKey    string            `json:"encryptedDataKey"`    // base64(wrapped DEK)
	KMSProvider         string            `json:"kmsProvider"`
	KMSKeyID            string            `json:"kmsKeyId"`
	EncryptionContext   map[string]string `json:"encryptionContext"`
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req createKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	// Validate required fields.
	if req.OrganizationID == "" || req.PrivateKeyID == "" || req.Environment == "" || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "organizationId, privateKeyId, environment, and name are required",
		})
		return
	}

	// Gate key import behind ALLOW_KEY_IMPORT.
	if req.ImportPrivateKeyHex != "" && !s.deps.AllowImport {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "key import is disabled; set ALLOW_KEY_IMPORT=true to enable (security-sensitive)",
		})
		return
	}

	// Generate or import the secp256k1 key pair.
	var gen keys.Generated
	var err error
	if req.ImportPrivateKeyHex != "" {
		gen, err = keys.FromPrivateKeyHex(req.ImportPrivateKeyHex)
	} else {
		gen, err = keys.GenerateSecp256k1()
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "key generation failed: " + err.Error(),
		})
		return
	}

	// Build the encryption context per the architecture spec.
	encCtx := map[string]string{
		"organization_id": req.OrganizationID,
		"private_key_id":  req.PrivateKeyID,
		"environment":     req.Environment,
		"purpose":         "wallet-signing",
	}

	// Envelope-encrypt the private key under the KMS provider.
	// Use the request context so that cancellation/timeout propagates into KMS.
	enc, err := envelope.Encrypt(r.Context(), s.deps.KMSProvider, gen.PrivateKey, encCtx)

	// Zeroize the plaintext private key immediately after encryption, regardless
	// of whether encryption succeeded. The key must never linger in memory.
	zeroize(gen.PrivateKey)

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "envelope encryption failed: " + err.Error(),
		})
		return
	}

	resp := createKeyResponse{
		PrivateKeyID:        req.PrivateKeyID,
		PublicKey:           gen.PublicKey,
		Addresses:           []string{gen.Address},
		Curve:               "CURVE_SECP256K1",
		EncryptedPrivateKey: base64.StdEncoding.EncodeToString(enc.Ciphertext),
		EncryptedDataKey:    base64.StdEncoding.EncodeToString(enc.WrappedDEK),
		KMSProvider:         enc.KMSProvider,
		KMSKeyID:            enc.KMSKeyID,
		EncryptionContext:   encCtx,
	}
	writeJSON(w, http.StatusOK, resp)
}

// zeroize overwrites a byte slice to clear key material from memory.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
