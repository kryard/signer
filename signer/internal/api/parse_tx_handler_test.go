package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// eip1559UnsignedTxHexInternal is the fixed EIP-1559 unsigned tx for Sepolia.
const eip1559UnsignedTxHexInternal = "0x02ea83aa36a780843b9aca00843b9aca0082520894000000000000000000000000000000000000dead8080c0"

// postJSONToServer sends a POST request with a JSON body to a *Server (internal package).
func postJSONToServer(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

type responseRecorder = httptest.ResponseRecorder

func TestParseTransactionEIP1559(t *testing.T) {
	srv := newTestServerInternal(t)

	rec := postJSONToServer(t, srv, "/internal/parse/transaction", map[string]string{
		"unsignedTransaction": eip1559UnsignedTxHexInternal,
	})
	if rec.Code != 200 {
		t.Fatalf("parse tx status = %d; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"chainId"`) {
		t.Errorf("expected chainId in response, got: %s", body)
	}
	if !strings.Contains(body, "0xaa36a7") {
		t.Errorf("expected Sepolia chainId 0xaa36a7 in response, got: %s", body)
	}
}

func TestParseTransactionMissingField(t *testing.T) {
	srv := newTestServerInternal(t)

	rec := postJSONToServer(t, srv, "/internal/parse/transaction", map[string]string{})
	if rec.Code != 400 {
		t.Fatalf("expected 400 for missing unsignedTransaction, got %d", rec.Code)
	}
}

func TestParseTransactionMalformed(t *testing.T) {
	srv := newTestServerInternal(t)

	rec := postJSONToServer(t, srv, "/internal/parse/transaction", map[string]string{
		"unsignedTransaction": "0xdeadbeef_not_valid!",
	})
	if rec.Code != 400 {
		t.Fatalf("expected 400 for malformed tx, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
