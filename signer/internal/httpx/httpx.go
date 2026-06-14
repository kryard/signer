// Package httpx is the shared, wallet-agnostic HTTP foundation for Kryard's
// internal services. It has NO dependency on wallet key material, KMS providers,
// or envelope code, so the wallet signer (cmd/signer) can import it without
// coupling the HTTP layer to its trust domain.
package httpx

import (
	"encoding/json"
	"net/http"
	"time"
)

// WriteJSON writes v as a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes a `{"error": message}` JSON body with the given status code.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}

// Health is the shared `/internal/health` handler.
func Health(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// NewHTTPServer builds an http.Server with conservative timeouts (Slowloris
// mitigation) for an internal private-network service. Callers run ListenAndServe.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
