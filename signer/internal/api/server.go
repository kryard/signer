package api

import (
	"net/http"

	"kryard/signer/internal/httpx"
	"kryard/signer/internal/kms"
)

// writeJSON delegates to the shared httpx package (single implementation;
// handlers in this package keep calling writeJSON unchanged). See ADR-006.
var writeJSON = httpx.WriteJSON

// Deps holds the external dependencies required by the signer API server.
type Deps struct {
	// KMSProvider is used to wrap/unwrap data-encryption keys. Required.
	KMSProvider kms.Provider
	// AllowImport gates the guarded key-import path. Set from ALLOW_KEY_IMPORT env.
	AllowImport bool
}

// Server is the signer's private internal API. It is NEVER exposed publicly; in
// production it runs on a private VM behind mTLS / a signed service token.
type Server struct {
	mux  *http.ServeMux
	deps Deps
}

// NewServer builds the internal API handler and wires all routes.
func NewServer(deps Deps) *Server {
	s := &Server{
		mux:  http.NewServeMux(),
		deps: deps,
	}
	s.mux.HandleFunc("GET /internal/health", httpx.Health)
	s.mux.HandleFunc("POST /internal/keys/create", s.handleCreateKey)
	s.mux.HandleFunc("POST /internal/parse/transaction", s.handleParseTransaction)
	s.mux.HandleFunc("POST /internal/sign/raw-payload", s.handleSignRawPayload)
	s.mux.HandleFunc("POST /internal/sign/transaction", s.handleSignTransaction)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }
