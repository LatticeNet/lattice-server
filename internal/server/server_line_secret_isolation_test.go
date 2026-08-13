package server

import (
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
