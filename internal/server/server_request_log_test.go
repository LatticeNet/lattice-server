package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

func TestRequestLogRedactsPublicSubscriptionAuthority(t *testing.T) {
	t.Setenv("LATTICE_ACCESS_LOG", "1")
	t.Setenv("LATTICE_SLOW_REQUEST_MS", "0")
	telemetry.ResetForTest()
	t.Cleanup(telemetry.ResetForTest)

	const (
		slugCanary   = "public-slug-authority-canary"
		pathToken    = "public-path-token-canary"
		bearerCanary = "public-bearer-token-canary"
	)
	var output bytes.Buffer
	srv := &Server{logger: log.New(&output, "", 0)}
	handler := srv.withRequestID(srv.withRequestLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))
	req := httptest.NewRequest(http.MethodGet, "/sub/"+slugCanary+"/"+pathToken+"/raw-authority", nil)
	req.Header.Set("Authorization", "Bearer "+bearerCanary)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	logged := output.String()
	if !strings.Contains(logged, "GET "+redactedSubscriptionRequestLogPath+" -> 418") {
		t.Fatalf("request log lost observable method/path/status: %q", logged)
	}
	for _, canary := range []string{slugCanary, pathToken, bearerCanary, "raw-authority"} {
		if strings.Contains(logged, canary) {
			t.Fatalf("request log exposed public subscription authority %q: %q", canary, logged)
		}
	}
	metrics := telemetry.Prometheus()
	if !strings.Contains(metrics, `path="/sub/:token",status_class="4xx"`) {
		t.Fatalf("subscription telemetry path was not normalized: %s", metrics)
	}
}
