package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

func TestMetricsExposeRuntimeCounters(t *testing.T) {
	handler, _, srv := newObservabilityTestServer(t, "metrics-secret")
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	telemetry.ResetForTest()

	health := doJSON(t, handler, http.MethodGet, "/api/health", "", nil, "")
	health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("health failed: %d", health.StatusCode)
	}
	metricsBody := `{"node_id":"node-a","version":"test","metrics":{"cpu_percent":12}}`
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics", metricsBody, nodeToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent metrics failed: %d (%s)", rec.Code, rec.Body.String())
	}
	srv.recordAudit(model.AuditEvent{ID: "audit_observe", Action: "observe.test", Decision: "allow"})

	resp := doMetrics(t, handler, "metrics-secret")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics failed: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("metrics content type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	for _, want := range []string{
		"lattice_process_uptime_seconds",
		`lattice_store_save_total{result="success"}`,
		`lattice_audit_append_total{result="success"}`,
		`lattice_http_requests_total{path="/api/health",status_class="2xx"} 1`,
		`lattice_agent_requests_total{path="/api/agent/metrics",status_class="2xx"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, text)
		}
	}
}

func TestMetricsRequiresConfiguredBearerToken(t *testing.T) {
	disabled, _, _ := newObservabilityTestServer(t, "")
	disabledResp := doMetrics(t, disabled, "metrics-secret")
	disabledResp.Body.Close()
	if disabledResp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled metrics status = %d, want 404", disabledResp.StatusCode)
	}

	enabled, _, _ := newObservabilityTestServer(t, "metrics-secret")
	unauthorized := doMetrics(t, enabled, "wrong")
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong metrics token status = %d, want 401", unauthorized.StatusCode)
	}
}

func TestReadyzReportsStoreAndAuditWALStatus(t *testing.T) {
	handler, _, _ := newObservabilityTestServer(t, "")
	resp := doJSON(t, handler, http.MethodGet, "/readyz", "", nil, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz failed: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	for _, want := range []string{`"status":"ok"`, `"store":"ok"`, `"audit_wal":"disabled"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("readyz output missing %q: %s", want, text)
		}
	}
}

func doMetrics(t *testing.T, handler http.Handler, token string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func newObservabilityTestServer(t *testing.T, metricsToken string) (http.Handler, *store.Store, *Server) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, MetricsToken: metricsToken})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), st, srv
}
