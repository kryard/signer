package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

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
	// Curve of the key being signed with (default CURVE_SECP256K1). Forwarded
	// from the key row by the API service. Selects the signing algorithm and the
	// valid hash functions.
	Curve        string `json:"curve,omitempty"`
	Payload      string `json:"payload"`      // hex (with or without 0x prefix)
	HashFunction string `json:"hashFunction"` // curve-specific (KECCAK256/NO_OP/NOT_APPLICABLE)
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

	// Resolve the curve from the registry (default secp256k1). The curve owns
	// hashFunction validation in its Sign method; here we only ensure the curve
	// is known so an unsupported curve fails fast with 400.
	curveName := req.Curve
	if curveName == "" {
		curveName = keys.CurveSecp256k1
	}
	curve, ok := keys.Lookup(curveName)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unsupported curve %q; supported: %s", curveName, strings.Join(keys.RegisteredCurves(), ", ")),
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

	// Decode the payload hex (strips an optional 0x/0X prefix).
	payloadBytes, err := keys.DecodeHex(req.Payload)
	if err != nil {
		keys.Zeroize(privKeyBytes)
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "payload: invalid hex: " + err.Error(),
		})
		return
	}

	// EvaluatedInputHash re-check: if the API passed a hash, verify it matches
	// what the signer is about to sign. This is computed BEFORE signing so that
	// a mismatch prevents the signature from being produced. Curve-agnostic (it
	// hashes the request payload, not a curve-specific digest).
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
			keys.Zeroize(privKeyBytes)
			writeJSON(w, http.StatusConflict, map[string]string{
				"error":     "SIGNER_REQUEST_MISMATCH: evaluatedInputHash does not match",
				"errorCode": "SIGNER_REQUEST_MISMATCH",
			})
			return
		}
	}

	// Sign via the selected curve. The curve validates/applies hashFunction,
	// signs, and returns R/S/V plus the public key hex for the receipt. A bad
	// hashFunction or payload for the curve surfaces as an error → 400.
	sig, pubKeyHex, err := curve.Sign(privKeyBytes, payloadBytes, req.HashFunction)

	// ZEROIZE the private key immediately after signing, regardless of outcome.
	keys.Zeroize(privKeyBytes)

	if err != nil {
		// Curve-level errors are caller errors (bad hashFunction / payload size).
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "signing failed: " + err.Error(),
		})
		return
	}

	// Build sig64 = decode(R) || decode(S) for the signature-hash receipt field.
	rBytes, _ := hex.DecodeString(sig.R)
	sBytes, _ := hex.DecodeString(sig.S)
	sig64 := make([]byte, 0, len(rBytes)+len(sBytes))
	sig64 = append(sig64, rBytes...)
	sig64 = append(sig64, sBytes...)

	// Build signer receipt fields (hashes only — no key material).
	payloadHashBytes := sha256.Sum256(payloadBytes)
	payloadHashHex := hex.EncodeToString(payloadHashBytes[:])

	sigHashBytes := sha256.Sum256(sig64) // hash of r||s
	sigHashHex := hex.EncodeToString(sigHashBytes[:])

	resp := signRawPayloadResponse{
		R: sig.R,
		S: sig.S,
		V: sig.V,
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
