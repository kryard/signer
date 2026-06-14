package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/crypto"

	"kryard/signer/internal/canonicaljson"
	"kryard/signer/internal/envelope"
	"kryard/signer/internal/keys"
)

// signRawPayloadRequest is the request body for POST /internal/sign/raw-payload.
// All ciphertext fields are base64-encoded, matching the shape stored in Postgres
// and forwarded by the API service.
type signRawPayloadRequest struct {
	OrganizationID      string            `json:"organizationId"`
	PrivateKeyID        string            `json:"privateKeyId"`
	Environment         string            `json:"environment"`
	EncryptedPrivateKey string            `json:"encryptedPrivateKey"` // base64
	EncryptedDataKey    string            `json:"encryptedDataKey"`    // base64
	KMSKeyID            string            `json:"kmsKeyId"`
	KMSProvider         string            `json:"kmsProvider"` // "local" | "aws"; forwarded from the key row
	EncryptionContext   map[string]string `json:"encryptionContext"`
	Payload             string            `json:"payload"`      // hex (with or without 0x prefix)
	HashFunction        string            `json:"hashFunction"` // HASH_FUNCTION_KECCAK256 | HASH_FUNCTION_NO_OP
	// EvaluatedInputHash is the hash the API computed when evaluating policy.
	// When non-empty, the signer re-computes it and refuses on mismatch (409).
	EvaluatedInputHash string `json:"evaluatedInputHash,omitempty"`
	// ActivityType is forwarded for the evaluatedInputHash re-check.
	ActivityType string `json:"activityType,omitempty"`
}

// signerReceiptResponse contains audit metadata about the signing operation.
// It intentionally omits all key material.
type signerReceiptResponse struct {
	KeyID         string `json:"keyId"`
	PublicKey     string `json:"publicKey"`
	PayloadHash   string `json:"payloadHash"`   // sha256(payload bytes) hex
	SignatureHash string `json:"signatureHash"` // sha256(r||s) hex
	SignerBuildID string `json:"signerBuildId"`
}

// signRawPayloadResponse is the response body for POST /internal/sign/raw-payload.
// It MUST NOT contain any plaintext key material.
type signRawPayloadResponse struct {
	R             string                `json:"r"` // 32-byte hex, no 0x
	S             string                `json:"s"` // 32-byte hex, no 0x
	V             string                `json:"v"` // "00" or "01"
	SignerReceipt signerReceiptResponse `json:"signerReceipt"`
}

// signerBuildID is set at build time via -ldflags. Falls back to the
// SIGNER_BUILD_ID environment variable or a "dev" default.
var signerBuildID = ""

func getBuildID() string {
	if signerBuildID != "" {
		return signerBuildID
	}
	if env := os.Getenv("SIGNER_BUILD_ID"); env != "" {
		return env
	}
	return "dev"
}

func (s *Server) handleSignRawPayload(w http.ResponseWriter, r *http.Request) {
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

	var req signRawPayloadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	// Validate required fields.
	if req.OrganizationID == "" || req.PrivateKeyID == "" || req.Environment == "" ||
		req.EncryptedPrivateKey == "" || req.EncryptedDataKey == "" ||
		req.Payload == "" || req.HashFunction == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "organizationId, privateKeyId, environment, encryptedPrivateKey, encryptedDataKey, payload, and hashFunction are required",
		})
		return
	}

	// Validate hashFunction.
	switch req.HashFunction {
	case "HASH_FUNCTION_KECCAK256", "HASH_FUNCTION_NO_OP":
		// valid
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unsupported hashFunction %q; use HASH_FUNCTION_KECCAK256 or HASH_FUNCTION_NO_OP", req.HashFunction),
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

	// Decrypt the private key inside the signer. The API service never decrypts.
	privKeyBytes, err := envelope.Decrypt(r.Context(), s.deps.KMSProvider, enc, req.EncryptionContext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "envelope decryption failed: " + err.Error(),
		})
		return
	}

	// Decode the payload hex (strip optional 0x prefix).
	payloadHex := req.Payload
	if len(payloadHex) >= 2 && (payloadHex[:2] == "0x" || payloadHex[:2] == "0X") {
		payloadHex = payloadHex[2:]
	}
	payloadBytes, err := hex.DecodeString(payloadHex)
	if err != nil {
		zeroize(privKeyBytes)
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "payload: invalid hex: " + err.Error(),
		})
		return
	}

	// Compute the digest per the requested hash function.
	var digest []byte
	switch req.HashFunction {
	case "HASH_FUNCTION_KECCAK256":
		digest = crypto.Keccak256(payloadBytes)
	case "HASH_FUNCTION_NO_OP":
		if len(payloadBytes) != 32 {
			zeroize(privKeyBytes)
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("HASH_FUNCTION_NO_OP requires a 32-byte payload, got %d bytes", len(payloadBytes)),
			})
			return
		}
		digest = payloadBytes
	}

	// EvaluatedInputHash re-check: if the API passed a hash, verify it matches
	// what the signer is about to sign. This is computed BEFORE signing so that
	// a mismatch prevents the signature from being produced.
	if req.EvaluatedInputHash != "" {
		activityType := req.ActivityType
		if activityType == "" {
			activityType = "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"
		}
		hashInput := map[string]any{
			"activityType": activityType,
			"privateKeyId": req.PrivateKeyID,
			"payload":      req.Payload,
		}
		recomputedHash, hashErr := canonicaljson.SHA256Hex(hashInput)
		if hashErr != nil || recomputedHash != req.EvaluatedInputHash {
			zeroize(privKeyBytes)
			writeJSON(w, http.StatusConflict, map[string]string{
				"error":     "SIGNER_REQUEST_MISMATCH: evaluatedInputHash does not match",
				"errorCode": "SIGNER_REQUEST_MISMATCH",
			})
			return
		}
	}

	// Sign the digest with the private key.
	r2, sigS, sigV, err := keys.SignDigest(privKeyBytes, digest)

	// ZEROIZE the private key immediately after signing, regardless of outcome.
	zeroize(privKeyBytes)

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "signing failed: " + err.Error(),
		})
		return
	}

	// Derive the public key from the private key for the receipt.
	// We re-derive from the hex fields in the request encryption context since
	// the key is already zeroized. However, we can use the encryptionContext
	// to identify the key; the publicKey comes from the stored row which the
	// API should provide. For now, derive from r/s/v + digest via SigToPub.
	rBytes, _ := hex.DecodeString(r2)
	sBytes, _ := hex.DecodeString(sigS)
	vByte := byte(0)
	if sigV == "01" {
		vByte = 1
	}
	sig65 := make([]byte, 65)
	copy(sig65[0:32], rBytes)
	copy(sig65[32:64], sBytes)
	sig65[64] = vByte

	recoveredPub, pubErr := crypto.SigToPub(digest, sig65)
	pubKeyHex := ""
	if pubErr == nil {
		pubKeyHex = hex.EncodeToString(crypto.CompressPubkey(recoveredPub))
	}

	// Build signer receipt fields (hashes only — no key material).
	payloadHashBytes := sha256.Sum256(payloadBytes)
	payloadHashHex := hex.EncodeToString(payloadHashBytes[:])

	sigHashBytes := sha256.Sum256(sig65[:64]) // hash of r||s
	sigHashHex := hex.EncodeToString(sigHashBytes[:])

	resp := signRawPayloadResponse{
		R: r2,
		S: sigS,
		V: sigV,
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
