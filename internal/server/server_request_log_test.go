package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	pathpkg "path"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

func TestRequestLogRedactsPublicSubscriptionAuthority(t *testing.T) {
	t.Setenv("LATTICE_ACCESS_LOG", "1")
	t.Setenv("LATTICE_SLOW_REQUEST_MS", "0")
	telemetry.ResetForTest()
	t.Cleanup(telemetry.ResetForTest)

	var output bytes.Buffer
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:                   st,
		AdminPassword:           testAdminPass,
		DisableRenewalScheduler: true,
		Logger:                  log.New(&output, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	output.Reset()

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{
			name:       "canonical",
			path:       "/sub/canonical-slug-canary/canonical-token-canary-0123456789",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "dot segments",
			path:       "/x/../sub/dot-slug-canary/dot-token-canary-012345678901234",
			wantStatus: http.StatusTemporaryRedirect,
		},
		{
			name:       "escaped segment before dot segments",
			path:       "/x%2Fy/../sub/escaped-slug-canary/escaped-token-canary-0123456789",
			wantStatus: http.StatusTemporaryRedirect,
		},
		{
			name:       "repeated slashes",
			path:       "//sub/slash-slug-canary/slash-token-canary-012345678901",
			wantStatus: http.StatusTemporaryRedirect,
		},
		{
			name:       "raw subscription path escapes cleaned subtree",
			path:       "/sub/../outside/raw-token-canary-012345678901234",
			wantStatus: http.StatusTemporaryRedirect,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusTemporaryRedirect && response.Header().Get("Location") != pathpkg.Clean(tc.path) {
				t.Fatalf("redirect location = %q, want %q", response.Header().Get("Location"), pathpkg.Clean(tc.path))
			}
		})
	}

	logged := output.String()
	for _, want := range []string{
		"GET " + redactedSubscriptionRequestLogPath + " -> 404",
		"GET " + redactedSubscriptionRequestLogPath + " -> 307",
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("request log lost observable method/path/status %q: %q", want, logged)
		}
	}
	metrics := telemetry.Prometheus()
	for _, canary := range []string{
		"canonical-slug-canary", "canonical-token-canary",
		"dot-slug-canary", "dot-token-canary",
		"escaped-slug-canary", "escaped-token-canary",
		"slash-slug-canary", "slash-token-canary",
		"raw-token-canary",
	} {
		if strings.Contains(logged, canary) {
			t.Fatalf("request log exposed public subscription authority %q: %q", canary, logged)
		}
		if strings.Contains(metrics, canary) {
			t.Fatalf("request telemetry exposed public subscription authority %q: %s", canary, metrics)
		}
	}
	for _, want := range []string{
		`lattice_http_requests_total{path="/sub/:token",status_class="3xx"} 4`,
		`lattice_http_requests_total{path="/sub/:token",status_class="4xx"} 1`,
		`lattice_http_slow_requests_total{path="/sub/:token"} 5`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("subscription telemetry lost route/status observation %q: %s", want, metrics)
		}
	}
}
