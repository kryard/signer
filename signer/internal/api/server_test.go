package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestServer creates a Server with a nil KMSProvider for health-only tests.
// Tests that exercise key operations use the external test in keys_handler_test.go.
func newTestServerInternal(t *testing.T) *Server {
	t.Helper()
	return NewServer(Deps{}) // KMSProvider nil; only health route is tested here
}

func TestHealth(t *testing.T) {
	srv := newTestServerInternal(t)
	req := httptest.NewRequest(http.MethodGet, "/internal/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("body = %q, want status ok", body)
	}
}
