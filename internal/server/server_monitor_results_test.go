package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
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

type monitorListEntry struct {
	ID     string              `json:"id"`
	Latest []monitorLatestView `json:"latest"`
}

func listMonitors(t *testing.T, res *http.Response) map[string]monitorListEntry {
	t.Helper()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list monitors: %d", res.StatusCode)
	}
	var list []monitorListEntry
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	out := map[string]monitorListEntry{}
	for _, m := range list {
		out[m.ID] = m
	}
	return out
}

func postBatch(t *testing.T, handler http.Handler, nodeID, token string, results ...string) {
	t.Helper()
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-results", `{"node_id":"`+nodeID+`","results":[`+strings.Join(results, ",")+`]}`, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch for %s: %d %s", nodeID, rec.Code, rec.Body.String())
	}
	if got := decodeIngest(t, rec.Body.Bytes()); len(got.Dropped) != 0 {
		t.Fatalf("batch for %s dropped results: %+v", nodeID, got.Dropped)
	}
}

// GET /api/monitors carries each assigned node's newest result with its run,
// filtered to the nodes the caller may read, so the console reads one list
// instead of one history per monitor.
func TestMonitorsListCarriesEachNodesLatest(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	tokenA := enrollAndBeat(t, handler, cookies, csrf, "n-a", "alpha")
	tokenB := enrollAndBeat(t, handler, cookies, csrf, "n-b", "beta")
	res := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"web","type":"tcp","target":"x:443","node_ids":["n-a","n-b"]}`, cookies, csrf)
	var mon model.Monitor
	if err := json.NewDecoder(res.Body).Decode(&mon); err != nil || mon.ID == "" {
		t.Fatalf("create monitor: %v %+v", err, mon)
	}
	res.Body.Close()
	idle := createAllNodesMonitor(t, handler, cookies, csrf, "idle")

	now := time.Now().UTC().Truncate(time.Second)
	postBatch(t, handler, "n-a", tokenA,
		resultJSON(mon.ID, now.Add(-60*time.Second), true, ""),
		resultJSON(mon.ID, now.Add(-30*time.Second), false, "conn refused"),
		resultJSON(mon.ID, now, false, "conn refused"))
	postBatch(t, handler, "n-b", tokenB, resultJSON(mon.ID, now, true, ""))

	all := listMonitors(t, doJSON(t, handler, http.MethodGet, "/api/monitors", "", cookies, ""))
	latest := all[mon.ID].Latest
	if len(latest) != 2 || latest[0].NodeID != "n-a" || latest[1].NodeID != "n-b" {
		t.Fatalf("latest: %+v", latest)
	}
	a := latest[0]
	if a.Success || a.FailStreak != 2 || !a.Since.Equal(now.Add(-30*time.Second)) || !a.At.Equal(now) || a.Error != "conn refused" || a.ReceivedAt.IsZero() {
		t.Fatalf("n-a latest: %+v", a)
	}
	if b := latest[1]; !b.Success || b.FailStreak != 0 || b.LatencyMs != 12.5 {
		t.Fatalf("n-b latest: %+v", b)
	}
	if got, ok := all[idle]; !ok || got.Latest == nil || len(got.Latest) != 0 {
		t.Fatalf("a monitor with no results lists an empty latest: %+v", got)
	}

	// A token confined to n-a sees only n-a's reading.
	pat := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, []string{"n-a"})
	confined := listMonitors(t, doBearerJSON(t, handler, http.MethodGet, "/api/monitors", "", pat))
	if got := confined[mon.ID].Latest; len(got) != 1 || got[0].NodeID != "n-a" {
		t.Fatalf("confined latest: %+v", got)
	}

	// Taken off the monitor, n-b's last reading is no longer listed.
	mon.NodeIDs = []string{"n-a"}
	if err := st.UpsertMonitor(mon); err != nil {
		t.Fatal(err)
	}
	after := listMonitors(t, doJSON(t, handler, http.MethodGet, "/api/monitors", "", cookies, ""))
	if got := after[mon.ID].Latest; len(got) != 1 || got[0].NodeID != "n-a" {
		t.Fatalf("latest after unassigning n-b: %+v", got)
	}
}

// The results read returns the newest rows across nodes by default, one
// pair's with node_id, and never more than the limit allows.
func TestMonitorResultsReadIsBounded(t *testing.T) {
	_, handler, _ := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	tokens := map[string]string{
		"n-a": enrollAndBeat(t, handler, cookies, csrf, "n-a", "alpha"),
		"n-b": enrollAndBeat(t, handler, cookies, csrf, "n-b", "beta"),
	}
	monID := createAllNodesMonitor(t, handler, cookies, csrf, "web")
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for node, token := range tokens {
		batch := make([]string, 0, 30)
		for i := 0; i < 30; i++ {
			// n-a probes on the even seconds, n-b on the odd ones.
			offset := 2 * i
			if node == "n-b" {
				offset++
			}
			batch = append(batch, resultJSON(monID, base.Add(time.Duration(offset)*time.Second), true, ""))
		}
		postBatch(t, handler, node, token, batch...)
	}
	read := func(query string, auth func(path string) *http.Response) (int, []store.MonitorResultRecord) {
		t.Helper()
		res := auth("/api/monitors/results?monitor_id=" + monID + query)
		defer res.Body.Close()
		var rows []store.MonitorResultRecord
		if res.StatusCode == http.StatusOK {
			if err := json.NewDecoder(res.Body).Decode(&rows); err != nil {
				t.Fatal(err)
			}
		}
		return res.StatusCode, rows
	}
	admin := func(path string) *http.Response { return doJSON(t, handler, http.MethodGet, path, "", cookies, "") }

	if code, rows := read("", admin); code != http.StatusOK || len(rows) != 60 {
		t.Fatalf("default read: %d rows=%d", code, len(rows))
	}
	code, rows := read("&limit=10", admin)
	if code != http.StatusOK || len(rows) != 10 || !rows[9].At.Equal(base.Add(59*time.Second)) || !rows[0].At.Equal(base.Add(50*time.Second)) {
		t.Fatalf("limit=10: %d %+v", code, rows)
	}
	code, rows = read("&node_id=n-b&limit=5", admin)
	if code != http.StatusOK || len(rows) != 5 || rows[0].NodeID != "n-b" || !rows[4].At.Equal(base.Add(59*time.Second)) {
		t.Fatalf("one pair: %d %+v", code, rows)
	}
	for _, bad := range []string{"&limit=0", "&limit=abc", fmt.Sprintf("&limit=%d", maxMonitorResultsLimit+1)} {
		if code, _ := read(bad, admin); code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", bad, code)
		}
	}

	pat := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, []string{"n-a"})
	confined := func(path string) *http.Response { return doBearerJSON(t, handler, http.MethodGet, path, "", pat) }
	if code, _ := read("&node_id=n-b", confined); code != http.StatusForbidden {
		t.Fatalf("confined read of another node's pair: %d", code)
	}
	code, rows = read("&limit=100", confined)
	if code != http.StatusOK || len(rows) != 30 {
		t.Fatalf("confined read: %d rows=%d", code, len(rows))
	}
	for _, row := range rows {
		if row.NodeID != "n-a" {
			t.Fatalf("confined read returned %s's row", row.NodeID)
		}
	}
}
