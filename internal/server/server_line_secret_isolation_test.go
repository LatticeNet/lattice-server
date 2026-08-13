package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenericKVRejectsReservedLineSecretBucketsForEveryMethod(t *testing.T) {
	srv := &Server{}
	for _, bucket := range []string{vpnCoreKVBucket, "managedline/def", "vpn_users", "vpn_user_secrets", "managed_line_secrets"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			req := httptest.NewRequest(method, "/api/kv?bucket="+bucket, nil)
			rec := httptest.NewRecorder()
			srv.handleKV(rec, req, principal{})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s bucket %q: got %d, want 403; body=%s", method, bucket, rec.Code, rec.Body.String())
			}
		}
	}
}

func TestGenericKVPostBodyCannotOverrideSafeQueryWithReservedBucket(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"kv:write", "kv:read"}, nil)
	for _, bucket := range []string{"vpn_user_secrets", vpnCoreKVBucket} {
		response := doBearerJSON(t, handler, http.MethodPost, "/api/kv?bucket=default", `{"bucket":"`+bucket+`","key":"canary","value":"credential-canary"}`, token)
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("reserved body bucket %q status=%d body=%s", bucket, response.StatusCode, body)
		}
		if _, ok := st.KVEntry(bucket, "canary"); ok {
			t.Fatalf("reserved body bucket %q mutated", bucket)
		}
	}
}
