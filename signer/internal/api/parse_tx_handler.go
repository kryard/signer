package api

import (
	"encoding/json"
	"net/http"

	"kryard/signer/internal/evmtx"
)

// parseTxRequest is the request body for POST /internal/parse/transaction.
// No key material needed — this is a decode-only operation.
type parseTxRequest struct {
	UnsignedTransaction string `json:"unsignedTransaction"` // hex (with or without 0x)
}

// parseTxResponse carries the policy-relevant fields extracted from the decoded tx.
// Reuses txFieldsResponse (defined in sign_tx_handler.go).

func (s *Server) handleParseTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req parseTxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if req.UnsignedTransaction == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsignedTransaction is required"})
		return
	}

	// Parse (no signing, no key needed).
	fields, err := evmtx.ParseUnsignedTx(req.UnsignedTransaction)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "transaction parse failed: " + err.Error()})
		return
	}

	resp := txFieldsResponse{
		ChainID:                  fields.ChainID,
		To:                       fields.To,
		Value:                    fields.Value,
		Nonce:                    fields.Nonce,
		Gas:                      fields.Gas,
		MaxFeePerGas:             fields.MaxFeePerGas,
		MaxPriorityFeePerGas:     fields.MaxPriorityFeePerGas,
		GasPrice:                 fields.GasPrice,
		Data:                     fields.Data,
		MethodSelector:           fields.MethodSelector,
		AuthorizationAddresses:   fields.AuthorizationAddresses,
		AuthorizationAuthorities: fields.AuthorizationAuthorities,
	}
	writeJSON(w, http.StatusOK, resp)
}
