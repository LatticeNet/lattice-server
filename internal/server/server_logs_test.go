package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/logstore"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newLogServer(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	ls, err := logstore.Open(filepath.Join(t.TempDir(), "logs.db"), secret.Disabled(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ls.Close() })
	srv, err := New(Options{Store: st, LogStore: ls, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), st
}

func TestValidateLogPath(t *testing.T) {
	allow := []string{"/var/log/"}
	valid := []string{"/var/log/nginx/error.log", "/var/log/syslog"}
	for _, p := range valid {
		if err := validateLogPath(p, allow); err != nil {
			t.Fatalf("validateLogPath(%q) unexpected error: %v", p, err)
		}
	}
	invalid := []string{
		"",
		"relative/path.log",
		"/etc/shadow",               // not under allowlist
		"/var/log/../../etc/passwd", // .. (non-clean)
		"/proc/1/maps",              // deny prefix
		"/sys/kernel/x",             // deny prefix
		"/dev/sda",                  // deny prefix
		"/var/log/*.log",            // glob
		"/var/log/app.log\n",        // control char
		" /var/log/app.log",         // leading whitespace
		"/var/log/",                 // directory
	}
	for _, p := range invalid {
		if err := validateLogPath(p, allow); err == nil {
			t.Fatalf("validateLogPath(%q) expected error", p)
		}
	}
	// Operator-widened allowlist permits another prefix.
	if err := validateLogPath("/opt/app/logs/app.log", []string{"/var/log/", "/opt/app/logs/"}); err != nil {
		t.Fatalf("widened allowlist should permit /opt path: %v", err)
	}
}

func agentLogBody(t *testing.T, nodeID, token string, batch model.LogBatch) string {
	t.Helper()
	payload := struct {
		NodeID string         `json:"node_id"`
		Token  string         `json:"token"`
		Batch  model.LogBatch `json:"batch"`
	}{NodeID: nodeID, Token: token, Batch: batch}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestLogSourceCreateIngestQuery(t *testing.T) {
	handler, _ := newLogServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodPost, "/api/logs/sources",
		`{"name":"app","node_id":"`+nodeID+`","path":"/var/log/app.log"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create source: %d", res.StatusCode)
	}
	var src model.LogSource
	json.NewDecoder(res.Body).Decode(&src)
	res.Body.Close()
	if src.ID == "" || src.MaxLineBytes != defaultLogMaxLineBytes || !src.Enabled {
		t.Fatalf("unexpected source: %+v", src)
	}

	body := agentLogBody(t, nodeID, token, model.LogBatch{
		SourceID: src.ID, Path: "/var/log/app.log", RotID: "r1", LastOff: 30,
		Lines: []string{"ERROR boom", "info ok"},
	})
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/logs", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: %d (%s)", rec.Code, rec.Body.String())
	}

	q := doJSON(t, handler, http.MethodGet, "/api/logs/query?source_id="+src.ID+"&q=error", "", cookies, csrf)
	if q.StatusCode != http.StatusOK {
		t.Fatalf("query: %d", q.StatusCode)
	}
	var qr struct {
		Lines []model.LogLine `json:"lines"`
	}
	json.NewDecoder(q.Body).Decode(&qr)
	q.Body.Close()
	if len(qr.Lines) != 1 || qr.Lines[0].Line != "ERROR boom" || qr.Lines[0].NodeID != nodeID {
		t.Fatalf("unexpected query result: %+v", qr.Lines)
	}

	st := doJSON(t, handler, http.MethodGet, "/api/logs/stats?source_id="+src.ID, "", cookies, csrf)
	if st.StatusCode != http.StatusOK {
		t.Fatalf("stats: %d", st.StatusCode)
	}
	var sr struct {
		Stats []logSourceStatsView `json:"stats"`
	}
	json.NewDecoder(st.Body).Decode(&sr)
	st.Body.Close()
	if len(sr.Stats) != 1 || sr.Stats[0].Lines != 2 {
		t.Fatalf("unexpected stats: %+v", sr.Stats)
	}
}

func TestLogIngestCrossNodeRejected(t *testing.T) {
	handler, store := newLogServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)

	// A source that belongs to a DIFFERENT node.
	if err := store.UpsertLogSource(model.LogSource{ID: "other-src", NodeID: "other-node", Path: "/var/log/x.log", Enabled: true, MaxLineBytes: defaultLogMaxLineBytes, MaxBatchLines: defaultLogMaxBatchLines}); err != nil {
		t.Fatal(err)
	}
	body := agentLogBody(t, nodeID, token, model.LogBatch{SourceID: "other-src", Lines: []string{"x"}})
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/logs", body, token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-node ingest should be forbidden, got %d", rec.Code)
	}
	// Unknown source id is also rejected.
	body = agentLogBody(t, nodeID, token, model.LogBatch{SourceID: "nope", Lines: []string{"x"}})
	rec = doAgentRaw(t, handler, http.MethodPost, "/api/agent/logs", body, token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown source ingest should be forbidden, got %d", rec.Code)
	}
}

func TestLogSourcePathValidationRejectedAtCreate(t *testing.T) {
	handler, _ := newLogServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, _ := enrollNode(t, handler, cookies, csrf)
	bad := []string{"/etc/shadow", "/proc/1/maps", "relative.log", "/var/log/../etc/passwd"}
	for _, p := range bad {
		res := doJSON(t, handler, http.MethodPost, "/api/logs/sources",
			`{"name":"x","node_id":"`+nodeID+`","path":"`+p+`"}`, cookies, csrf)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("path %q should be rejected, got %d", p, res.StatusCode)
		}
		res.Body.Close()
	}
}

func TestLogIngestBudgetReturns429(t *testing.T) {
	handler, _ := newLogServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)
	res := doJSON(t, handler, http.MethodPost, "/api/logs/sources",
		`{"name":"chatty","node_id":"`+nodeID+`","path":"/var/log/chatty.log"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create source: %d", res.StatusCode)
	}
	var src model.LogSource
	json.NewDecoder(res.Body).Decode(&src)
	res.Body.Close()

	// A single batch larger than the per-source burst (10000 lines) can never
	// fit the token bucket, so it deterministically returns 429 + Retry-After.
	lines := make([]string, 11000)
	for i := range lines {
		lines[i] = "x"
	}
	body := agentLogBody(t, nodeID, token, model.LogBatch{SourceID: src.ID, Path: "/var/log/chatty.log", Lines: lines})
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/logs", body, token)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for an over-burst batch, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 must include Retry-After")
	}
}

func TestLogEndpointsDisabledWhenNoStore(t *testing.T) {
	// A server without a LogStore returns 503 on log endpoints.
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodGet, "/api/logs/sources", "", cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when log store disabled, got %d", res.StatusCode)
	}
}

func TestLogBatchCapArithmeticFitsDecodeLimit(t *testing.T) {
	// A legal maximum batch must fit the ingest decode cap with JSON overhead.
	if maxLogBatchPayload >= logBatchBodyLimit {
		t.Fatalf("payload cap %d must be below decode limit %d", maxLogBatchPayload, logBatchBodyLimit)
	}
	// The create handler enforces maxLineBytes*maxBatchLines <= maxLogBatchPayload.
	if defaultLogMaxLineBytes*defaultLogMaxBatchLines > maxLogBatchPayload {
		t.Fatal("default caps exceed the payload bound")
	}
	if strings.TrimSpace(logIngestRetryAfter) == "" {
		t.Fatal("retry-after must be set")
	}
}
