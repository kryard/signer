package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]string{"a": "b"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"a":"b"}` {
		t.Fatalf("body = %q", body)
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "nope")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"nope"}` {
		t.Fatalf("body = %q", body)
	}
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	Health(rec, httptest.NewRequest(http.MethodGet, "/internal/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestNewHTTPServerHasTimeouts(t *testing.T) {
	s := NewHTTPServer(":0", http.NewServeMux())
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 {
		t.Fatal("expected non-zero timeouts")
	}
	if s.Addr != ":0" {
		t.Fatalf("addr = %q", s.Addr)
	}
}
