package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestNodeDebugPolicyDefaultsToCollectAndIngests(t *testing.T) {
	handler, _ := newLogServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/debug",
		`{"node_id":"`+nodeID+`","enabled":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enable debug: %d", res.StatusCode)
	}
	var node nodeView
	if err := json.NewDecoder(res.Body).Decode(&node); err != nil {
		t.Fatal(err)
	}
	if !node.AgentDebug.Enabled || !node.AgentDebug.Collect {
		t.Fatalf("debug should default to collect=true when enabled: %+v", node.AgentDebug)
	}

	cfgReq := httptest.NewRequest(http.MethodGet, "/api/agent/config?node_id="+nodeID, nil)
	cfgReq.Header.Set("Authorization", "Bearer "+token)
	cfgRec := serveReq(handler, cfgReq)
	if cfgRec.Code != http.StatusOK {
		t.Fatalf("agent config: %d (%s)", cfgRec.Code, cfgRec.Body.String())
	}
	var cfg model.AgentConfig
	if err := json.NewDecoder(cfgRec.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Debug.Enabled || !cfg.Debug.Collect || cfg.Debug.MaxLineBytes <= 0 || cfg.Debug.MaxBatchLines <= 0 {
		t.Fatalf("unexpected agent config: %+v", cfg)
	}

	body := string(mustJSON(t, map[string]any{
		"node_id": nodeID,
		"batch": model.AgentDebugBatch{
			NodeID: nodeID,
			Lines:  []string{"poll cycle complete", "agent post ok: path=/api/agent/metrics"},
		},
	}))
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/debug-events", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("debug ingest: %d (%s)", rec.Code, rec.Body.String())
	}
	var ingest struct {
		Accepted int    `json:"accepted"`
		SourceID string `json:"source_id"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&ingest); err != nil {
		t.Fatal(err)
	}
	if ingest.Accepted != 2 || ingest.SourceID != agentDebugSourceID(nodeID) {
		t.Fatalf("unexpected ingest result: %+v", ingest)
	}

	q := doJSON(t, handler, http.MethodGet, "/api/logs/query?source_id="+ingest.SourceID+"&q=poll", "", cookies, csrf)
	defer q.Body.Close()
	if q.StatusCode != http.StatusOK {
		t.Fatalf("query debug logs: %d", q.StatusCode)
	}
	var qr struct {
		Lines []model.LogLine `json:"lines"`
	}
	if err := json.NewDecoder(q.Body).Decode(&qr); err != nil {
		t.Fatal(err)
	}
	if len(qr.Lines) != 1 || qr.Lines[0].Path != agentDebugPathPrefix+nodeID || qr.Lines[0].Line != "poll cycle complete" {
		t.Fatalf("unexpected debug log query: %+v", qr.Lines)
	}
}

func TestNodeDebugPolicyCanKeepLocalOnly(t *testing.T) {
	handler, st := newLogServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodPost, "/api/nodes/debug",
		`{"node_id":"`+nodeID+`","enabled":true,"collect":false}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enable local-only debug: %d", res.StatusCode)
	}

	cfgReq := httptest.NewRequest(http.MethodGet, "/api/agent/config?node_id="+nodeID, nil)
	cfgReq.Header.Set("Authorization", "Bearer "+token)
	cfgRec := serveReq(handler, cfgReq)
	if cfgRec.Code != http.StatusOK {
		t.Fatalf("agent config: %d (%s)", cfgRec.Code, cfgRec.Body.String())
	}
	var cfg model.AgentConfig
	if err := json.NewDecoder(cfgRec.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Debug.Enabled || cfg.Debug.Collect {
		t.Fatalf("expected server debug enabled but collection disabled: %+v", cfg.Debug)
	}

	body := string(mustJSON(t, map[string]any{
		"node_id": nodeID,
		"batch": model.AgentDebugBatch{
			NodeID: nodeID,
			Lines:  []string{"local only"},
		},
	}))
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/debug-events", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("debug ingest with collection disabled: %d (%s)", rec.Code, rec.Body.String())
	}
	var ingest struct {
		Accepted int `json:"accepted"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&ingest); err != nil {
		t.Fatal(err)
	}
	if ingest.Accepted != 0 {
		t.Fatalf("collection disabled should accept no lines, got %+v", ingest)
	}
	if _, ok := st.LogSource(agentDebugSourceID(nodeID)); ok {
		t.Fatal("local-only debug must not create a managed server log source")
	}
}
