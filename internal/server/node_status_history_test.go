package server

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestSummarizeNodeStatusArithmetic(t *testing.T) {
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	const week = 7 * 24 * time.Hour
	until := since.Add(week)
	at := func(d time.Duration) time.Time { return since.Add(d) }
	ev := func(d time.Duration, to, cause string) store.NodeStatusEvent {
		return store.NodeStatusEvent{At: at(d), To: to, Cause: cause}
	}
	const (
		on, off, unk = store.NodeStatusOnline, store.NodeStatusOffline, NodeStatusUnknown
		beat, sweep  = store.NodeStatusCauseBeat, store.NodeStatusCauseLivenessSweep
		stop, start  = store.NodeStatusCauseServerStop, store.NodeStatusCauseServerStart
		day          = 24 * time.Hour
	)
	restart := []store.NodeStatusEvent{ev(3*day, off, stop), ev(3*day+35*time.Second, on, start)}
	cases := []struct {
		name    string
		node    model.Node
		rows    []store.NodeStatusEvent
		control []store.NodeStatusEvent
		want    nodeStatusHistory
	}{
		{
			name:    "one gap and a restart",
			node:    model.Node{Online: true, OnlineSince: at(-day), LastSeen: until},
			rows:    []store.NodeStatusEvent{ev(day, off, sweep), ev(day+15*time.Minute, on, beat)},
			control: restart,
			want: nodeStatusHistory{
				Initial:        on,
				Events:         []store.NodeStatusEvent{ev(day, off, sweep), ev(day+15*time.Minute, on, beat), ev(3*day, unk, stop), ev(3*day+35*time.Second, on, start)},
				OnlineSeconds:  int64(week/time.Second) - 900 - 35,
				OfflineSeconds: 900, UnknownSeconds: 35, Episodes: 1, LongestOfflineSeconds: 900,
			},
		},
		{
			name: "no rows, came online inside the window",
			node: model.Node{Online: true, OnlineSince: at(2 * day), LastSeen: until},
			want: nodeStatusHistory{
				Initial: unk, Events: []store.NodeStatusEvent{ev(2*day, on, beat)},
				OnlineSeconds: int64(5 * day / time.Second), UnknownSeconds: int64(2 * day / time.Second),
			},
		},
		{
			name:    "offline across a restart is one episode",
			node:    model.Node{Online: false, OnlineSince: at(-day), LastSeen: at(day - 100*time.Second)},
			rows:    []store.NodeStatusEvent{ev(day, off, sweep)},
			control: []store.NodeStatusEvent{ev(2*day, off, stop), ev(2*day+35*time.Second, on, start)},
			want: nodeStatusHistory{
				Initial:        on,
				Events:         []store.NodeStatusEvent{ev(day, off, sweep), ev(2*day, unk, stop), ev(2*day+35*time.Second, off, start)},
				OnlineSeconds:  int64(day / time.Second),
				OfflineSeconds: int64(6*day/time.Second) - 35, UnknownSeconds: 35, Episodes: 1, LongestOfflineSeconds: int64(6*day/time.Second) - 35,
			},
		},
		{
			name: "record from before OnlineSince existed, never flapped",
			node: model.Node{Online: true, LastSeen: until},
			want: nodeStatusHistory{Initial: on, Events: []store.NodeStatusEvent{}, OnlineSeconds: int64(week / time.Second)},
		},
		{
			name: "window opens offline on a node with no rows",
			node: model.Node{Online: false, OnlineSince: at(-2 * day), LastSeen: at(-day)},
			want: nodeStatusHistory{
				Initial: off, Events: []store.NodeStatusEvent{},
				OfflineSeconds: int64(week / time.Second), Episodes: 1, LongestOfflineSeconds: int64(week / time.Second),
			},
		},
		{
			name: "never reported",
			node: model.Node{},
			want: nodeStatusHistory{Initial: unk, Events: []store.NodeStatusEvent{}, UnknownSeconds: int64(week / time.Second)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := summarizeNodeStatus(tc.node, tc.rows, tc.control, since, until)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("summary mismatch\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestNodeStatusHistoryEndpoint(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)

	const day = 24 * time.Hour
	for _, id := range []string{"node-a", "node-b"} {
		if err := st.UpsertNode(model.Node{ID: id, Name: id, Online: true, OnlineSince: now.Add(-10 * day), LastSeen: now}); err != nil {
			t.Fatal(err)
		}
	}
	appends := []struct {
		id string
		ev store.NodeStatusEvent
	}{
		{"node-a", store.NodeStatusEvent{At: now.Add(-2 * day), To: store.NodeStatusOffline, Cause: store.NodeStatusCauseLivenessSweep}},
		{"node-a", store.NodeStatusEvent{At: now.Add(-2*day + 10*time.Minute), To: store.NodeStatusOnline, Cause: store.NodeStatusCauseBeat}},
		{store.NodeStatusServerID, store.NodeStatusEvent{At: now.Add(-day), To: store.NodeStatusOffline, Cause: store.NodeStatusCauseServerStop}},
		{store.NodeStatusServerID, store.NodeStatusEvent{At: now.Add(-day + 35*time.Second), To: store.NodeStatusOnline, Cause: store.NodeStatusCauseServerStart}},
	}
	for _, a := range appends {
		if err := st.AppendNodeStatusEvent(a.id, a.ev); err != nil {
			t.Fatal(err)
		}
	}

	get := func(path string, token string) (int, nodeStatusHistoryResponse, string) {
		t.Helper()
		var res *http.Response
		if token != "" {
			res = doBearerJSON(t, handler, http.MethodGet, path, "", token)
		} else {
			res = doJSON(t, handler, http.MethodGet, path, "", cookies, csrf)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		var out nodeStatusHistoryResponse
		if res.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("decode %s: %v: %s", path, err, body)
			}
		}
		return res.StatusCode, out, string(body)
	}

	status, out, body := get("/api/nodes/status-history", "")
	if status != http.StatusOK {
		t.Fatalf("status-history: %d %s", status, body)
	}
	if !out.Since.Equal(now.Add(-7*day)) || !out.Until.Equal(now) || !out.ServerStartedAt.Equal(now.Add(-day+35*time.Second)) {
		t.Fatalf("window: since=%s until=%s started=%s", out.Since, out.Until, out.ServerStartedAt)
	}
	if len(out.Nodes) != 2 {
		t.Fatalf("expected both nodes, got %v", out.Nodes)
	}
	a := out.Nodes["node-a"]
	if a.Initial != store.NodeStatusOnline || len(a.Events) != 4 || a.OfflineSeconds != 600 || a.UnknownSeconds != 35 ||
		a.Episodes != 1 || a.LongestOfflineSeconds != 600 || a.OnlineSeconds != int64(7*day/time.Second)-635 {
		t.Fatalf("node-a summary: %+v", a)
	}
	if a.Events[2].To != NodeStatusUnknown || a.Events[2].Cause != store.NodeStatusCauseServerStop || a.Events[3].To != store.NodeStatusOnline {
		t.Fatalf("control-plane gap must appear as unknown in the node's events: %+v", a.Events)
	}
	b := out.Nodes["node-b"]
	if b.Initial != store.NodeStatusOnline || len(b.Events) != 2 || b.UnknownSeconds != 35 || b.Episodes != 0 {
		t.Fatalf("node-b summary: %+v", b)
	}

	status, out, body = get("/api/nodes/status-history?days=3&node_id=node-a", "")
	if status != http.StatusOK || len(out.Nodes) != 1 || !out.Since.Equal(now.Add(-3*day)) {
		t.Fatalf("node filter and days: %d %s", status, body)
	}
	for _, bad := range []string{"0", "31", "x"} {
		if status, _, _ := get("/api/nodes/status-history?days="+bad, ""); status != http.StatusBadRequest {
			t.Fatalf("days=%s: %d", bad, status)
		}
	}

	// The same reach as /api/nodes: a token confined to node-b sees node-b only.
	token := createPAT(t, handler, cookies, csrf, []string{"node:read"}, []string{"node-b"})
	status, out, body = get("/api/nodes/status-history", token)
	if status != http.StatusOK || len(out.Nodes) != 1 || out.Nodes["node-b"].Initial == "" {
		t.Fatalf("confined token: %d %s", status, body)
	}
	status, _, body = get("/api/nodes/status-history?node_id=node-a", token)
	if status == http.StatusOK || strings.Contains(body, "node-a") {
		t.Fatalf("confined token must not read node-a: %d %s", status, body)
	}
}

// The beat that registers a node and ends its offline episode writes one row
// and one node.online audit event; later beats on an online node write none.
func TestAgentBeatRecordsOnlineEdge(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)

	hello := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", `{"node_id":"`+nodeID+`","version":"test"}`, token)
	if hello.Code != http.StatusOK {
		t.Fatalf("hello: %d %s", hello.Code, hello.Body.String())
	}
	for i := 0; i < 2; i++ {
		beat := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics", `{"node_id":"`+nodeID+`","version":"test","metrics":{}}`, token)
		if beat.Code != http.StatusOK {
			t.Fatalf("metrics: %d %s", beat.Code, beat.Body.String())
		}
	}
	rows, err := st.NodeStatusEvents(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].To != store.NodeStatusOnline || rows[0].Cause != store.NodeStatusCauseBeat {
		t.Fatalf("hello plus two beats must leave one online row: %+v", rows)
	}
	online := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == "node.online" && ev.NodeID == nodeID {
			online++
		}
	}
	if online != 1 {
		t.Fatalf("expected one node.online audit event, got %d", online)
	}
}
