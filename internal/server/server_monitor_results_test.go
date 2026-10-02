package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func decodeIngest(t *testing.T, body []byte) agentMonitorResultsResponse {
	t.Helper()
	var out agentMonitorResultsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode ingest response %s: %v", body, err)
	}
	return out
}

func resultJSON(monitorID string, at time.Time, ok bool, errMsg string) string {
	return fmt.Sprintf(`{"monitor_id":%q,"at":%q,"success":%t,"latency_ms":12.5,"error":%q}`, monitorID, at.Format(time.RFC3339Nano), ok, errMsg)
}

// One batch carries several probes: new rows are accepted, a result the
// pair already holds is a duplicate, and refused results come back with
// their index and reason so the agent drops them instead of retrying.
func TestAgentMonitorResultsBatchAnswersPerResult(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	sent := captureTypedNotices(srv)
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-web", "tokyo-edge")
	enrollAndBeat(t, handler, cookies, csrf, "n-other", "osaka-edge")
	monID := createAllNodesMonitor(t, handler, cookies, csrf, "web")
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-elsewhere", Name: "elsewhere", Type: model.MonitorTypeTCP, Target: "x:1", NodeIDs: []string{"n-other"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	body := `{"node_id":"n-web","results":[` + strings.Join([]string{
		resultJSON(monID, now.Add(-20*time.Second), true, ""),
		resultJSON(monID, now.Add(-10*time.Second), false, "conn refused"),
		resultJSON("mon-elsewhere", now, true, ""),
		resultJSON("mon-missing", now, true, ""),
		resultJSON(monID, now, false, "conn refused"),
	}, ",") + `]}`
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-results", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch: %d %s", rec.Code, rec.Body.String())
	}
	got := decodeIngest(t, rec.Body.Bytes())
	if !got.OK || got.Accepted != 3 || got.Duplicates != 0 || len(got.Dropped) != 2 {
		t.Fatalf("batch response: %+v", got)
	}
	if got.Dropped[0] != (agentMonitorResultDrop{Index: 2, MonitorID: "mon-elsewhere", Reason: "not_assigned"}) ||
		got.Dropped[1] != (agentMonitorResultDrop{Index: 3, MonitorID: "mon-missing", Reason: "unknown_monitor"}) {
		t.Fatalf("dropped: %+v", got.Dropped)
	}
	// The two failures in a row inside one batch page once, by node name.
	notices := flushTake(srv, sent)
	if len(notices) != 1 || notices[0].eventType != EventMonitorDown || notices[0].title != "Monitor down: web on tokyo-edge" {
		t.Fatalf("notices after the batch: %+v", notices)
	}

	// Sent again after a lost response: all duplicates, no second page.
	rec = doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-results", body, token)
	again := decodeIngest(t, rec.Body.Bytes())
	if rec.Code != http.StatusOK || again.Accepted != 0 || again.Duplicates != 3 || len(again.Dropped) != 2 {
		t.Fatalf("retried batch: %d %+v", rec.Code, again)
	}
	if notices := flushTake(srv, sent); len(notices) != 0 {
		t.Fatalf("a retried batch paged again: %+v", notices)
	}
	rows := storedMonitorResults(t, st, monID)
	if len(rows) != 3 {
		t.Fatalf("stored rows = %d, want 3", len(rows))
	}
}

// The batch route refuses what it cannot judge before touching the store.
func TestAgentMonitorResultsBatchRefusals(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-web", "tokyo-edge")
	monID := createAllNodesMonitor(t, handler, cookies, csrf, "web")
	now := time.Now().UTC()

	tooMany := make([]string, maxAgentMonitorResultsBatch+1)
	for i := range tooMany {
		tooMany[i] = resultJSON(monID, now.Add(-time.Duration(i)*time.Second), true, "")
	}
	cases := []struct {
		name, method, body, token string
		want                      int
	}{
		{"empty", http.MethodPost, `{"node_id":"n-web","results":[]}`, token, http.StatusBadRequest},
		{"missing", http.MethodPost, `{"node_id":"n-web"}`, token, http.StatusBadRequest},
		{"too many", http.MethodPost, `{"node_id":"n-web","results":[` + strings.Join(tooMany, ",") + `]}`, token, http.StatusBadRequest},
		{"bad token", http.MethodPost, `{"node_id":"n-web","results":[` + resultJSON(monID, now, true, "") + `]}`, token + "x", http.StatusUnauthorized},
		{"wrong method", http.MethodGet, "", token, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doAgentRaw(t, handler, tc.method, "/api/agent/monitor-results", tc.body, tc.token)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
	if rows := storedMonitorResults(t, st, monID); len(rows) != 0 {
		t.Fatalf("a refused batch stored %d rows", len(rows))
	}
}

// The single route keeps its request shape and answers the batch body. A
// result for a monitor the node was not given is refused with 200, so an
// agent racing a delete does not log an error.
func TestAgentMonitorResultSingleRouteAnswersTheBatchBody(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	token := enrollAndBeat(t, handler, cookies, csrf, "n-web", "tokyo-edge")
	monID := createAllNodesMonitor(t, handler, cookies, csrf, "web")
	now := time.Now().UTC()

	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", `{"node_id":"n-web","result":`+resultJSON(monID, now, true, "")+`}`, token)
	if got := decodeIngest(t, rec.Body.Bytes()); rec.Code != http.StatusOK || !got.OK || got.Accepted != 1 {
		t.Fatalf("single result: %d %s", rec.Code, rec.Body.String())
	}
	rec = doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", `{"node_id":"n-web","result":{"monitor_id":"gone","success":true}}`, token)
	got := decodeIngest(t, rec.Body.Bytes())
	if rec.Code != http.StatusOK || got.Accepted != 0 || len(got.Dropped) != 1 || got.Dropped[0].Reason != "unknown_monitor" {
		t.Fatalf("result for an unknown monitor: %d %+v", rec.Code, got)
	}
	// The agent cannot speak for another node or for the server's tls watch.
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-tls", Name: "cert", Type: model.MonitorTypeTLS, Target: "x:443", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec = doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", `{"node_id":"n-web","result":{"monitor_id":"mon-tls","node_id":"","success":false}}`, token)
	if got := decodeIngest(t, rec.Body.Bytes()); len(got.Dropped) != 1 || got.Dropped[0].Reason != "server_evaluated" {
		t.Fatalf("agent result for a tls monitor: %+v", got)
	}
	rows := storedMonitorResults(t, st, monID)
	if len(rows) != 1 || rows[0].NodeID != "n-web" {
		t.Fatalf("rows: %+v", rows)
	}
}
