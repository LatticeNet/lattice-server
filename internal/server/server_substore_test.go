package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubStoreNativeRoutesAreAbsent(t *testing.T) {
	handler, _ := newTestServer(t)
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/substore/status?base_url=https://example.invalid/secret", ""},
		{http.MethodPost, "/api/substore/import", `{}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("native Sub-Store route %s %s still registered: status=%d", tc.method, tc.path, rec.Code)
		}
	}
}
