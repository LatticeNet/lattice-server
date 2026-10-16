package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// checksFleet is a server on a hot store with one agent of each age: one
// that runs icmp, one older agent that reports nothing (tcp and http only),
// one whose host refuses icmp, a target with a public TCP line, and a node
// with no public address.
func checksFleet(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	srv, handler, st := newPathsServer(t)
	upsertNodes(t, st,
		model.Node{ID: "node-new", Name: "new", PublicIP: "203.0.113.10", Online: true, ProbeMethods: []string{"http", "icmp", "tcp"}},
		model.Node{ID: "node-old", Name: "old", PublicIP: "203.0.113.11", Online: true},
		model.Node{ID: "node-ref", Name: "refused", PublicIP: "203.0.113.12", Online: true, ProbeMethods: []string{"http", "tcp"}, ProbeRefusals: map[string]string{"icmp": model.PathReasonICMPNotPermitted}},
		model.Node{ID: "node-tgt", Name: "tgt", PublicIP: "198.51.100.20", Online: true, Geo: &model.NodeGeo{Country: "JP"}},
		model.Node{ID: "node-nopub", Name: "nopub", InternalIP: "10.0.0.5", Online: true},
	)
	srv.singboxInvMu.Lock()
	if srv.singboxInv == nil {
		srv.singboxInv = map[string]model.SingBoxInventory{}
	}
	srv.singboxInv["node-tgt"] = model.SingBoxInventory{NodeID: "node-tgt", At: time.Now().UTC(), Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: "198.51.100.20"},
	}}
	srv.singboxInvMu.Unlock()
	return srv, handler, st
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// agentMonitorList is what an agent with token would be handed.
func agentMonitorList(t *testing.T, srv *Server, st *store.Store, nodeID string) []model.Monitor {
	t.Helper()
	n, ok := st.Node(nodeID)
	if !ok {
		t.Fatalf("no node %s", nodeID)
	}
	return srv.agentMonitorsFor(n, st.MonitorsForNode(nodeID), time.Now())
}

func monitorIDs(list []model.Monitor) []string {
	ids := make([]string, 0, len(list))
	for _, m := range list {
		ids = append(ids, m.ID)
	}
	return ids
}

// Every create rule of design 29 D1 for icmp, tcp, http and tls, one case
// each.
func TestMonitorCreateValidation(t *testing.T) {
	_, handler, _ := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	cases := []struct {
		name string
		body string
		code int
		want string // a substring of the answer
	}{
		{"icmp to a node resolves its public IPv4", `{"name":"p","type":"icmp","target_node":"node-tgt","node_ids":["node-new"]}`, 200, `"target":"198.51.100.20"`},
		{"icmp packets default to five", `{"name":"p","type":"icmp","target":"1.1.1.1","node_ids":["node-new"]}`, 200, `"packets":5`},
		{"icmp to a private literal", `{"name":"p","type":"icmp","target":"10.0.0.1","node_ids":["node-new"]}`, 400, "private"},
		{"icmp to the metadata service", `{"name":"p","type":"icmp","target":"169.254.169.254","node_ids":["node-new"]}`, 400, "metadata"},
		{"icmp to loopback", `{"name":"p","type":"icmp","target":"127.0.0.1","node_ids":["node-new"]}`, 400, "loopback"},
		{"icmp to multicast", `{"name":"p","type":"icmp","target":"224.0.0.1","node_ids":["node-new"]}`, 400, "multicast"},
		{"icmp to a carrier-grade NAT address", `{"name":"p","type":"icmp","target":"100.64.1.1","node_ids":["node-new"]}`, 400, "private"},
		{"icmp to a host name", `{"name":"p","type":"icmp","target":"example.com","node_ids":["node-new"]}`, 400, "IPv4"},
		{"icmp to IPv6", `{"name":"p","type":"icmp","target":"2606:4700:4700::1111","node_ids":["node-new"]}`, 400, "IPv4"},
		{"icmp to a node with no public address", `{"name":"p","type":"icmp","target_node":"node-nopub","node_ids":["node-new"]}`, 400, "cannot be pinged"},
		{"icmp to a node that does not exist", `{"name":"p","type":"icmp","target_node":"node-gone","node_ids":["node-new"]}`, 400, "no such node"},
		{"icmp packets above ten", `{"name":"p","type":"icmp","target":"1.1.1.1","packets":11,"node_ids":["node-new"]}`, 400, "packets must be 1 to 10"},
		{"icmp packets below one", `{"name":"p","type":"icmp","target":"1.1.1.1","packets":-1,"node_ids":["node-new"]}`, 400, "packets must be 1 to 10"},
		{"icmp run longer than the interval", `{"name":"p","type":"icmp","target":"1.1.1.1","packets":10,"interval_sec":10,"timeout_sec":9,"node_ids":["node-new"]}`, 400, "does not end before the next run"},
		{"icmp interval under the floor", `{"name":"p","type":"icmp","target":"1.1.1.1","interval_sec":5,"timeout_sec":2,"node_ids":["node-new"]}`, 400, "interval_sec must be 10"},
		{"icmp with expectations", `{"name":"p","type":"icmp","target":"1.1.1.1","expect_status":"200","node_ids":["node-new"]}`, 400, "http checks only"},
		{"tcp to a node resolves its line port", `{"name":"t","type":"tcp","target_node":"node-tgt","node_ids":["node-new"]}`, 200, `"target":"198.51.100.20:443"`},
		{"tcp to a node with no line", `{"name":"t","type":"tcp","target_node":"node-new","node_ids":["node-old"]}`, 400, "no public tcp line"},
		{"tcp to a name", `{"name":"t","type":"tcp","target":"example.com:443","node_ids":["node-new"]}`, 200, `"target":"example.com:443"`},
		{"tcp to loopback", `{"name":"t","type":"tcp","target":"127.0.0.1:22","node_ids":["node-new"]}`, 400, "loopback"},
		{"tcp to a private address", `{"name":"t","type":"tcp","target":"192.168.1.1:80","node_ids":["node-new"]}`, 400, "private"},
		{"tcp to localhost", `{"name":"t","type":"tcp","target":"localhost:80","node_ids":["node-new"]}`, 400, "loopback"},
		{"tcp to a mapped private address", `{"name":"t","type":"tcp","target":"[::ffff:10.0.0.1]:80","node_ids":["node-new"]}`, 400, "private"},
		{"tcp without a port", `{"name":"t","type":"tcp","target":"example.com","node_ids":["node-new"]}`, 400, "host:port"},
		{"tcp with packets", `{"name":"t","type":"tcp","target":"example.com:443","packets":3,"node_ids":["node-new"]}`, 400, "icmp checks only"},
		{"http with a status set", `{"name":"h","type":"http","target":"https://example.com/health","expect_status":"301, 200-299","node_ids":["node-new"]}`, 200, `"expect_status":"200-299,301"`},
		{"http with a bad status set", `{"name":"h","type":"http","target":"https://example.com/","expect_status":"2xx","node_ids":["node-new"]}`, 400, "three digits"},
		{"http to the metadata service", `{"name":"h","type":"http","target":"http://169.254.169.254/latest/meta-data","node_ids":["node-new"]}`, 400, "metadata"},
		{"http to localhost", `{"name":"h","type":"http","target":"http://localhost:8080/","node_ids":["node-new"]}`, 400, "loopback"},
		{"http to a private address", `{"name":"h","type":"http","target":"http://10.1.2.3/","node_ids":["node-new"]}`, 400, "private"},
		{"http with user info", `{"name":"h","type":"http","target":"https://user:pw@example.com/","node_ids":["node-new"]}`, 400, "user name or password"},
		{"http with another scheme", `{"name":"h","type":"http","target":"ftp://example.com/","node_ids":["node-new"]}`, 400, "http or https URL"},
		{"http that names a node", `{"name":"h","type":"http","target":"https://example.com/","target_node":"node-tgt","node_ids":["node-new"]}`, 400, "target_node applies"},
		{"http secrets over plain http", `{"name":"h","type":"http","target":"http://example.com/","headers":[{"name":"Authorization","value":"Bearer x","secret":true}],"node_ids":["node-new"]}`, 400, "must use https"},
		{"http with a Host header", `{"name":"h","type":"http","target":"https://example.com/","headers":[{"name":"host","value":"other.example"}],"node_ids":["node-new"]}`, 400, "cannot be set"},
		{"http with a header twice", `{"name":"h","type":"http","target":"https://example.com/","headers":[{"name":"X-A","value":"1"},{"name":"x-a","value":"2"}],"node_ids":["node-new"]}`, 400, "named twice"},
		{"http with a header injection", `{"name":"h","type":"http","target":"https://example.com/","headers":[{"name":"X-A","value":"1\r\nX-B: 2"}],"node_ids":["node-new"]}`, 400, "control character"},
		{"http with a secret and no value", `{"name":"h","type":"http","target":"https://example.com/","headers":[{"name":"X-Key","secret":true}],"node_ids":["node-new"]}`, 400, "needs a value"},
		{"http with nine headers", `{"name":"h","type":"http","target":"https://example.com/","headers":[` + strings.TrimSuffix(strings.Repeat(`{"name":"X-H","value":"v"},`, 9), ",") + `],"node_ids":["node-new"]}`, 400, "at most 8"},
		{"tls with packets", `{"name":"c","type":"tls","target":"example.com:443","packets":3}`, 400, "do not apply"},
		{"beacon is not created in M2a", `{"name":"b","type":"beacon","target_node":"node-tgt","node_ids":["node-new"]}`, 400, "only tcp, http, icmp and tls"},
	}
	for _, tc := range cases {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors", tc.body, cookies, csrf)
		body := readBody(t, res)
		if res.StatusCode != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("%s: %d %s; want %d containing %q", tc.name, res.StatusCode, body, tc.code, tc.want)
		}
	}
}

// A check that names a node needs read access to it, as its paths do.
func TestMonitorTargetNodeNeedsReadAccess(t *testing.T) {
	_, handler, _ := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"monitor:admin", "monitor:read"}, []string{"node-new"})
	res := doBearerJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"p","type":"icmp","target_node":"node-tgt","node_ids":["node-new"]}`, token)
	if body := readBody(t, res); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a token that cannot read the target created a check on it: %d %s", res.StatusCode, body)
	}
	// An admin's check on that target is hidden from the confined token.
	res = doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"p","type":"icmp","target_node":"node-tgt","node_ids":["node-new"]}`, cookies, csrf)
	if body := readBody(t, res); res.StatusCode != http.StatusOK {
		t.Fatalf("admin create = %d %s", res.StatusCode, body)
	}
	list := doBearerJSON(t, handler, http.MethodGet, "/api/monitors", "", token)
	if body := readBody(t, list); strings.Contains(body, "node-tgt") {
		t.Fatalf("a check on a node the token cannot read is listed: %s", body)
	}
}

// The packet budget counts every enabled multi-packet check from one source
// to one address, generated checks included.
func TestMonitorPacketBudget(t *testing.T) {
	_, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	create := func(body string) (int, string) {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors", body, cookies, csrf)
		return res.StatusCode, readBody(t, res)
	}
	heavy := `{"name":"p","type":"icmp","target":"198.51.100.20","packets":10,"interval_sec":10,"timeout_sec":5,"node_ids":["node-new"]}`
	if code, body := create(heavy); code != 200 {
		t.Fatalf("first heavy check = %d %s", code, body)
	}
	if code, body := create(heavy); code != 200 {
		t.Fatalf("second heavy check (2 packets a second) = %d %s", code, body)
	}
	// The same address named by its node counts against the same budget.
	if code, body := create(`{"name":"p","type":"icmp","target_node":"node-tgt","packets":1,"interval_sec":60,"node_ids":["node-new"]}`); code != 400 || !strings.Contains(body, "packets a second") {
		t.Fatalf("a third check over budget = %d %s", code, body)
	}
	// Another source has its own budget.
	if code, body := create(`{"name":"p","type":"icmp","target_node":"node-tgt","packets":10,"interval_sec":10,"timeout_sec":5,"node_ids":["node-old"]}`); code != 200 {
		t.Fatalf("another source = %d %s", code, body)
	}
	// The path set's generated icmp checks count too.
	cfg := `{"enabled":true,"interval_sec":10,"timeout_sec":5,"sources":["node-new"],"include_targets":["node-tgt"],"method":"icmp","version":0}`
	res := doJSON(t, handler, http.MethodPut, "/api/monitors/latency", cfg, cookies, csrf)
	if body := readBody(t, res); res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "packets a second") {
		t.Fatalf("a path set over budget = %d %s", res.StatusCode, body)
	}
	if mons := st.Monitors(); slices.ContainsFunc(mons, func(m model.Monitor) bool { return m.ID == latencyICMPMonitorID("node-tgt") }) {
		t.Fatal("a refused path set generated a check")
	}
}

// Secret header values are encrypted at rest, never returned by any read,
// never in an audit record, and reach only the agents assigned the check.
func TestMonitorSecretHeadersNeverLeave(t *testing.T) {
	srv, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	const secret = "Bearer s3cr3t-value"
	res := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"h","type":"http","target":"https://Example.com/health","headers":[{"name":"authorization","value":"`+secret+`","secret":true},{"name":"Accept","value":"application/json"}],"node_ids":["node-new"]}`, cookies, csrf)
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK || strings.Contains(body, "s3cr3t") {
		t.Fatalf("create = %d %s", res.StatusCode, body)
	}
	var created model.Monitor
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	if created.SecretsOrigin != "https://example.com:443" || len(created.Headers) != 2 ||
		created.Headers[0] != (model.MonitorHeader{Name: "Authorization", Secret: true, Set: true}) ||
		created.Headers[1] != (model.MonitorHeader{Name: "Accept", Value: "application/json"}) {
		t.Fatalf("created = %+v", created)
	}
	for _, path := range []string{"/api/monitors", "/api/monitors/paths?window=1h", "/api/monitors/results?monitor_id=" + created.ID} {
		read := doJSON(t, handler, http.MethodGet, path, "", cookies, "")
		if body := readBody(t, read); strings.Contains(body, "s3cr3t") {
			t.Fatalf("%s leaks the secret: %s", path, body)
		}
	}
	edit := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+created.ID+`","version":1,"headers":[{"name":"Authorization","op":"set","value":"Bearer n3w-s3cr3t","secret":true}]}`, cookies, csrf)
	if body := readBody(t, edit); edit.StatusCode != http.StatusOK || strings.Contains(body, "s3cr3t") {
		t.Fatalf("edit = %d %s", edit.StatusCode, body)
	}
	for _, ev := range st.AuditEvents() {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "s3cr3t") {
			t.Fatalf("audit record carries a secret: %s", raw)
		}
		if ev.Action == "monitor.update" && ev.Metadata["headers"] != "Authorization(secret),Accept" {
			t.Fatalf("the edit's audit names %q", ev.Metadata["headers"])
		}
	}
	assigned := agentMonitorList(t, srv, st, "node-new")
	if len(assigned) != 1 || assigned[0].Headers[0].Value != "Bearer n3w-s3cr3t" || assigned[0].SecretsOrigin != "https://example.com:443" {
		t.Fatalf("the assigned agent's list = %+v", assigned)
	}
	if other := agentMonitorList(t, srv, st, "node-old"); len(other) != 0 {
		t.Fatalf("an unassigned agent was handed %+v", other)
	}
}

// Header edits name each header keep, set or delete; an echoed read keeps
// every secret, and unnamed headers stay.
func TestMonitorHeaderEditOperations(t *testing.T) {
	srv, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"h","type":"http","target":"https://example.com/","headers":[{"name":"X-Key","value":"k1","secret":true},{"name":"X-Plain","value":"p"}],"node_ids":["node-new"]}`, cookies, csrf)
	var created model.Monitor
	if err := json.Unmarshal([]byte(readBody(t, res)), &created); err != nil || created.ID == "" {
		t.Fatalf("create: %v", err)
	}
	version := int64(1)
	edit := func(ops string) (int, string) {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+created.ID+`","version":`+itoa64(version)+`,"headers":`+ops+`}`, cookies, csrf)
		body := readBody(t, res)
		if res.StatusCode == http.StatusOK {
			version++
		}
		return res.StatusCode, body
	}
	headers := func() []model.MonitorHeader {
		mon, _ := st.Monitor(created.ID)
		return mon.Headers
	}
	// The console echoes what it read: keep for both.
	if code, body := edit(`[{"name":"X-Key","op":"keep"},{"name":"X-Plain","op":"keep"}]`); code != 200 {
		t.Fatalf("echo = %d %s", code, body)
	}
	if h := headers(); len(h) != 2 || h[0].Value != "k1" || !h[0].Secret {
		t.Fatalf("an echo changed the headers: %+v", h)
	}
	for _, tc := range []struct{ ops, want string }{
		{`[{"name":"X-Gone","op":"keep"}]`, "not on the check"},
		{`[{"name":"X-Key","op":"set","secret":true}]`, "needs a value"},
		{`[{"name":"X-Key","op":"keep"},{"name":"x-key","op":"delete"}]`, "named twice"},
		{`[{"name":"X-Key","op":"wipe"}]`, "op must be"},
		{`[{"name":"Host","op":"set","value":"other"}]`, "cannot be set"},
	} {
		if code, body := edit(tc.ops); code != 400 || !strings.Contains(body, tc.want) {
			t.Errorf("%s = %d %s; want 400 %q", tc.ops, code, body, tc.want)
		}
	}
	// Add one, delete the plain one, leave the secret unnamed.
	if code, body := edit(`[{"name":"X-Trace","op":"set","value":"on"},{"name":"X-Plain","op":"delete"},{"name":"X-Absent","op":"delete"}]`); code != 200 {
		t.Fatalf("set and delete = %d %s", code, body)
	}
	h := headers()
	if len(h) != 2 || h[0] != (model.MonitorHeader{Name: "X-Key", Value: "k1", Secret: true}) || h[1] != (model.MonitorHeader{Name: "X-Trace", Value: "on"}) {
		t.Fatalf("after set and delete: %+v", h)
	}
	// Turning the secret plain needs its value again.
	if code, body := edit(`[{"name":"X-Key","op":"set","value":"visible"}]`); code != 200 {
		t.Fatalf("make plain = %d %s", code, body)
	}
	if mon, _ := st.Monitor(created.ID); mon.SecretsOrigin != "" || model.MonitorHasSecrets(mon) {
		t.Fatalf("no secret left, but the check still binds an origin: %+v", mon)
	}
	if got := agentMonitorList(t, srv, st, "node-new"); len(got) != 1 || got[0].Headers[0].Value != "visible" {
		t.Fatalf("agent list after the edits = %+v", got)
	}
	// Expectations and headers are http's alone.
	icmp := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"p","type":"icmp","target":"1.1.1.1","node_ids":["node-new"]}`, cookies, csrf)
	var ping model.Monitor
	if err := json.Unmarshal([]byte(readBody(t, icmp)), &ping); err != nil {
		t.Fatal(err)
	}
	bad := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+ping.ID+`","version":1,"expect_status":"200"}`, cookies, csrf)
	if body := readBody(t, bad); bad.StatusCode != 400 || !strings.Contains(body, "http checks only") {
		t.Fatalf("expect_status on icmp = %d %s", bad.StatusCode, body)
	}
	moved := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+ping.ID+`","version":1,"target_node":"node-tgt"}`, cookies, csrf)
	if body := readBody(t, moved); moved.StatusCode != 400 || !strings.Contains(body, "cannot change") {
		t.Fatalf("a new target_node = %d %s", moved.StatusCode, body)
	}
	packets := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+ping.ID+`","version":1,"packets":3}`, cookies, csrf)
	if view := decodeMonitorView(t, packets); view.Packets != 3 || view.Version != 2 {
		t.Fatalf("packets edit = %+v", view)
	}
}

func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

// A source is handed only the kinds its agent runs; the others read
// unknown with why, never down.
func TestAgentMonitorGatingByProbeMethods(t *testing.T) {
	srv, _, st := checksFleet(t)
	for _, mon := range []model.Monitor{
		{ID: "mon-tcp", Name: "t", Type: model.MonitorTypeTCP, Target: "198.51.100.20:443", IntervalSec: 30, TimeoutSec: 5, AssignAll: true, Enabled: true},
		{ID: "mon-http", Name: "h", Type: model.MonitorTypeHTTP, Target: "https://example.com/", IntervalSec: 30, TimeoutSec: 5, AssignAll: true, Enabled: true},
		{ID: "mon-icmp", Name: "p", Type: model.MonitorTypeICMP, Target: "198.51.100.20", Packets: 5, IntervalSec: 30, TimeoutSec: 5, AssignAll: true, Enabled: true},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	for nodeID, want := range map[string][]string{
		"node-new": {"mon-http", "mon-icmp", "mon-tcp"},
		"node-old": {"mon-http", "mon-tcp"},
		"node-ref": {"mon-http", "mon-tcp"},
	} {
		if got := monitorIDs(agentMonitorList(t, srv, st, nodeID)); !slices.Equal(got, want) {
			t.Errorf("%s is handed %v, want %v", nodeID, got, want)
		}
	}
	matrix, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for source, reason := range map[string]string{"node-old": model.PathReasonAgentTooOld, "node-ref": model.PathReasonICMPNotPermitted} {
		cell := pathCellFor(t, matrix, source, "mon-icmp")
		if cell.State != model.PathStateUnknown || cell.Reason != reason || cell.TargetNode != "node-tgt" {
			t.Errorf("%s icmp path = %+v, want unknown %s", source, cell, reason)
		}
	}
	if cell := pathCellFor(t, matrix, "node-new", "mon-icmp"); cell.Reason == model.PathReasonAgentTooOld {
		t.Errorf("a source that runs icmp reads too old: %+v", cell)
	}
}

// The agent reports its methods on hello and on every beat; a report
// without them reads as an agent that runs tcp and http only.
func TestAgentProbeFactsFlowFromHelloAndHeartbeat(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)
	hello := `{"node_id":"` + nodeID + `","version":"0.4.0","probe_methods":["tcp","http","icmp","gopher"],"probe_refusals":{"beacon":"refused_by_node","icmp":"icmp_not_permitted","x":"y"}}`
	if rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/hello", hello, token); rec.Code != http.StatusOK {
		t.Fatalf("hello = %d %s", rec.Code, rec.Body.String())
	}
	n, _ := st.Node(nodeID)
	if !slices.Equal(n.ProbeMethods, []string{"http", "icmp", "tcp"}) || len(n.ProbeRefusals) != 1 || n.ProbeRefusals["beacon"] != "refused_by_node" {
		t.Fatalf("after hello: methods %v refusals %v", n.ProbeMethods, n.ProbeRefusals)
	}
	view := doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, "")
	if body := readBody(t, view); !strings.Contains(body, `"probe_methods":["http","icmp","tcp"]`) {
		t.Fatalf("node read lacks the methods: %s", body)
	}
	beat := `{"node_id":"` + nodeID + `","version":"0.3.9","metrics":{}}`
	if rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/metrics", beat, token); rec.Code != http.StatusOK {
		t.Fatalf("beat = %d %s", rec.Code, rec.Body.String())
	}
	n, _ = st.Node(nodeID)
	if n.ProbeMethods != nil || n.ProbeRefusals != nil {
		t.Fatalf("a beat without methods (an older agent) kept %v %v", n.ProbeMethods, n.ProbeRefusals)
	}
	view = doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, "")
	if body := readBody(t, view); !strings.Contains(body, `"probe_methods":["http","tcp"]`) {
		t.Fatalf("an older agent's node read: %s", body)
	}
}

// A check that names a node follows the node: a new public address reaches
// the agent's list and the reads without an edit, and a node that loses its
// address leaves the agent's list instead of being probed at a stale one.
func TestTargetNodeResolutionFollowsTheNode(t *testing.T) {
	srv, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	for _, body := range []string{
		`{"name":"p","type":"icmp","target_node":"node-tgt","node_ids":["node-new"]}`,
		`{"name":"t","type":"tcp","target_node":"node-tgt","node_ids":["node-new"]}`,
	} {
		if res := doJSON(t, handler, http.MethodPost, "/api/monitors", body, cookies, csrf); res.StatusCode != 200 {
			t.Fatalf("create = %d %s", res.StatusCode, readBody(t, res))
		}
	}
	targets := func() map[string]string {
		out := map[string]string{}
		for _, m := range agentMonitorList(t, srv, st, "node-new") {
			out[m.Type] = m.Target
		}
		return out
	}
	if got := targets(); got["icmp"] != "198.51.100.20" || got["tcp"] != "198.51.100.20:443" {
		t.Fatalf("resolved = %v", got)
	}
	n, _ := st.Node("node-tgt")
	n.PublicIP = "198.51.100.30"
	upsertNodes(t, st, n)
	srv.singboxInvMu.Lock()
	srv.singboxInv["node-tgt"] = model.SingBoxInventory{NodeID: "node-tgt", At: time.Now().UTC(), Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "vless-8443", Protocol: "vless", Network: "reality", Port: "8443", ListenHost: "::", Address: "198.51.100.30"},
	}}
	srv.singboxInvMu.Unlock()
	srv.monitorPaths.notePlan(srv.planLatencyProbes(time.Now()), time.Now())
	if got := targets(); got["icmp"] != "198.51.100.30" || got["tcp"] != "198.51.100.30:8443" {
		t.Fatalf("after the move = %v", got)
	}
	list := doJSON(t, handler, http.MethodGet, "/api/monitors", "", cookies, "")
	if body := readBody(t, list); !strings.Contains(body, `"target":"198.51.100.30"`) || strings.Contains(body, "198.51.100.20") {
		t.Fatalf("the reads still show the old address: %s", body)
	}
	n.PublicIP = ""
	upsertNodes(t, st, n)
	if got := targets(); got["icmp"] != "" {
		t.Fatalf("a node with no address is still pinged at %q", got["icmp"])
	}
}

// The path set probes with tcp unless told otherwise; icmp is opt-in, a pin
// never falls back, auto takes icmp where the source runs it, and a source
// pin overrides the set.
func TestLatencyPathSetMethods(t *testing.T) {
	srv, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	version := int64(0)
	save := func(extra string) model.LatencyProbePlan {
		t.Helper()
		body := `{"enabled":true,"interval_sec":60,"timeout_sec":5,"sources":["node-new","node-old","node-ref"],"include_targets":["node-tgt"],"version":` + itoa64(version) + extra + `}`
		res := doJSON(t, handler, http.MethodPut, "/api/monitors/latency", body, cookies, csrf)
		raw := readBody(t, res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("save %s = %d %s", extra, res.StatusCode, raw)
		}
		version++
		var plan model.LatencyProbePlan
		if err := json.Unmarshal([]byte(raw), &plan); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	pairOf := func(plan model.LatencyProbePlan, source string) model.LatencyProbePairState {
		for _, p := range plan.Pairs {
			if p.Source == source && p.Target == "node-tgt" {
				return p
			}
		}
		t.Fatalf("no pair from %s", source)
		return model.LatencyProbePairState{}
	}
	plan := save("")
	for _, source := range []string{"node-new", "node-old", "node-ref"} {
		if p := pairOf(plan, source); p.Method != "tcp" || !p.Active || p.MonitorID != "mon_lat_node-tgt" {
			t.Fatalf("default pair from %s = %+v", source, p)
		}
	}
	if _, ok := st.Monitor(latencyICMPMonitorID("node-tgt")); ok {
		t.Fatal("tcp by default created an icmp check")
	}
	plan = save(`,"method":"icmp"`)
	if p := pairOf(plan, "node-new"); p.Method != "icmp" || !p.Active || p.MonitorID != "mon_lati_node-tgt" {
		t.Fatalf("icmp from a new agent = %+v", p)
	}
	if p := pairOf(plan, "node-old"); p.Method != "icmp" || p.Active || p.Reason != model.PathReasonAgentTooOld {
		t.Fatalf("icmp pinned on an old agent = %+v", p)
	}
	if p := pairOf(plan, "node-ref"); p.Active || p.Reason != model.PathReasonICMPNotPermitted {
		t.Fatalf("icmp pinned on a refusing host = %+v", p)
	}
	icmp, ok := st.Monitor(latencyICMPMonitorID("node-tgt"))
	if !ok || icmp.Type != model.MonitorTypeICMP || icmp.Target != "198.51.100.20" || icmp.TargetNode != "node-tgt" || icmp.Packets != 5 ||
		!slices.Equal(icmp.NodeIDs, []string{"node-new"}) || len(icmp.Headers) != 0 {
		t.Fatalf("generated icmp check = %+v", icmp)
	}
	tcp, ok := st.Monitor(latencyMonitorID("node-tgt"))
	if !ok || tcp.Enabled || tcp.TargetNode != "node-tgt" {
		t.Fatalf("the tcp check with history must stay, paused: %+v %v", tcp, ok)
	}
	if got := monitorIDs(agentMonitorList(t, srv, st, "node-old")); slices.Contains(got, latencyICMPMonitorID("node-tgt")) {
		t.Fatalf("an old agent was handed the generated icmp check: %v", got)
	}
	plan = save(`,"method":"auto"`)
	for source, want := range map[string]string{"node-new": "icmp", "node-old": "tcp", "node-ref": "tcp"} {
		if p := pairOf(plan, source); p.Method != want || !p.Active {
			t.Errorf("auto from %s = %+v, want %s", source, p, want)
		}
	}
	plan = save(`,"method":"auto","source_methods":{"node-new":"tcp"}`)
	if p := pairOf(plan, "node-new"); p.Method != "tcp" || !p.Active {
		t.Fatalf("a source pinned to tcp = %+v", p)
	}
	tn := latencyNodeOf(t, plan, "node-tgt")
	if tn.ICMPTarget != "198.51.100.20" || tn.ICMPMonitorID != "mon_lati_node-tgt" || tn.MonitorID != "mon_lat_node-tgt" {
		t.Fatalf("plan node = %+v", tn)
	}
	// Only old agents and icmp pinned: nothing can probe, and the target says why.
	res := doJSON(t, handler, http.MethodPut, "/api/monitors/latency", `{"enabled":true,"interval_sec":60,"timeout_sec":5,"sources":["node-old"],"include_targets":["node-tgt"],"method":"icmp","version":`+itoa64(version)+`}`, cookies, csrf)
	var held model.LatencyProbePlan
	if err := json.Unmarshal([]byte(readBody(t, res)), &held); err != nil {
		t.Fatal(err)
	}
	version++
	if tn := latencyNodeOf(t, held, "node-tgt"); tn.Target != model.LatencyTargetPaused || tn.TargetReason != model.LatencyReasonSourceMethod {
		t.Fatalf("a target only old agents would ping = %+v", tn)
	}
	for _, body := range []string{
		`{"enabled":true,"sources":["node-new"],"method":"udp","version":` + itoa64(version) + `}`,
		`{"enabled":true,"sources":["node-new"],"source_methods":{"node-old":"icmp"},"version":` + itoa64(version) + `}`,
		`{"enabled":true,"sources":["node-new"],"source_methods":{"node-new":"beacon"},"version":` + itoa64(version) + `}`,
	} {
		res := doJSON(t, handler, http.MethodPut, "/api/monitors/latency", body, cookies, csrf)
		if raw := readBody(t, res); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d %s", body, res.StatusCode, raw)
		}
	}
}

// One path line crosses a switch from tcp to icmp: the series by (source,
// target node) joins both generated checks, marks the switch, and counts the
// icmp run's echoes in sent and lost.
func TestPathSeriesJoinsTCPAndICMPAcrossASwitch(t *testing.T) {
	_, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	save := func(method string, version int) {
		body := `{"enabled":true,"interval_sec":60,"timeout_sec":5,"sources":["node-new"],"include_targets":["node-tgt"],"method":"` + method + `","version":` + itoa64(int64(version)) + `}`
		if res := doJSON(t, handler, http.MethodPut, "/api/monitors/latency", body, cookies, csrf); res.StatusCode != 200 {
			t.Fatalf("save %s = %d %s", method, res.StatusCode, readBody(t, res))
		}
	}
	save("tcp", 0)
	now := time.Now().UTC()
	start := now.Add(-3 * time.Hour).Truncate(time.Hour)
	var tcp []model.MonitorResult
	for i := 0; i < 60; i++ {
		tcp = append(tcp, model.MonitorResult{MonitorID: "mon_lat_node-tgt", At: start.Add(time.Duration(i) * time.Minute), Success: true, LatencyMs: 40})
	}
	if _, err := st.IngestAgentMonitorResults("node-new", tcp, now); err != nil {
		t.Fatal(err)
	}
	save("icmp", 1)
	var icmp []model.MonitorResult
	for i := 0; i < 60; i++ {
		icmp = append(icmp, model.MonitorResult{MonitorID: "mon_lati_node-tgt", NodeID: "node-new", At: start.Add(time.Hour + time.Duration(i)*time.Minute),
			Sent: 5, Lost: 1, RTTsMs: []float64{30, 31, 32, 50}, Success: true, LatencyMs: 999})
	}
	out, err := st.IngestAgentMonitorResults("node-new", icmp, now)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Dropped != "" || out[0].Result.LatencyMs != 31.5 {
		t.Fatalf("an icmp result's latency is its median: %+v", out[0])
	}
	res := doJSON(t, handler, http.MethodGet, "/api/monitors/series?source=node-new&target_node=node-tgt&window=6h", "", cookies, "")
	var series model.PathSeries
	if err := json.Unmarshal([]byte(readBody(t, res)), &series); err != nil {
		t.Fatal(err)
	}
	if len(series.MethodChanges) != 2 || series.MethodChanges[0].Method != "tcp" || series.MethodChanges[1].Method != "icmp" {
		t.Fatalf("method changes = %+v", series.MethodChanges)
	}
	var tcpSent, icmpSent, icmpLost int
	for _, b := range series.Buckets {
		switch {
		case b.T.Before(start.Add(time.Hour)) && b.N > 0:
			tcpSent += b.Sent
			if b.Loss == nil || *b.Loss != 0 {
				t.Fatalf("a tcp bucket's loss = %v", b.Loss)
			}
		case b.N > 0:
			icmpSent += b.Sent
			icmpLost += b.Lost
			if b.Loss == nil || *b.Loss != 0.2 {
				t.Fatalf("an icmp bucket's loss is lost over sent: %+v", b)
			}
		}
	}
	if tcpSent != 60 || icmpSent != 300 || icmpLost != 60 {
		t.Fatalf("sent tcp %d, icmp %d lost %d", tcpSent, icmpSent, icmpLost)
	}
	if _, ok := st.Monitor("mon_lat_node-tgt"); !ok {
		t.Fatal("the tcp check and its history went with the switch")
	}
}

// An icmp path that has never had an echo back reads unknown (filtered) and
// pages nothing; once it has, all-loss runs read down and page.
func TestICMPAllLossFilteredUntilFirstEcho(t *testing.T) {
	srv, _, st := checksFleet(t)
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-ping", Name: "ping", Type: model.MonitorTypeICMP, Target: "198.51.100.20", TargetNode: "node-tgt", Packets: 5, IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-new"}, Enabled: true, AlertAfter: 2}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	allLoss := func(at time.Time) model.MonitorResult {
		return model.MonitorResult{MonitorID: "mon-ping", NodeID: "node-new", At: at, Sent: 5, Lost: 5, Error: "all 5 echoes lost"}
	}
	ingest := func(results ...model.MonitorResult) {
		t.Helper()
		if _, err := srv.ingestAgentMonitorResults("node-new", results); err != nil {
			t.Fatal(err)
		}
	}
	ingest(allLoss(now.Add(-3*time.Minute)), allLoss(now.Add(-150*time.Second)), allLoss(now.Add(-2*time.Minute)))
	state := func() model.PathCell {
		m, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return pathCellFor(t, m, "node-new", "mon-ping")
	}
	if c := state(); c.State != model.PathStateUnknown || c.Reason != model.PathReasonICMPFiltered {
		t.Fatalf("never answered = %+v", c)
	}
	if incs := st.Incidents(); len(incs) != 0 {
		t.Fatalf("a filtered path opened incidents: %+v", incs)
	}
	ingest(model.MonitorResult{MonitorID: "mon-ping", NodeID: "node-new", At: now.Add(-90 * time.Second), Sent: 5, Lost: 0, RTTsMs: []float64{20, 21, 22, 23, 24}})
	if c := state(); c.State != model.PathStateUp {
		t.Fatalf("after an echo = %+v", c)
	}
	ingest(allLoss(now.Add(-60*time.Second)), allLoss(now.Add(-30*time.Second)))
	if c := state(); c.State != model.PathStateDown {
		t.Fatalf("all loss after an echo = %+v", c)
	}
	if incs := st.Incidents(); len(incs) != 1 || incs[0].MonitorID != "mon-ping" {
		t.Fatalf("a real outage must open its incident: %+v", incs)
	}
}

// A run that measured nothing reads unknown with its reason and moves no
// streak.
func TestUnknownResultsReadUnknownAndKeepTheStreak(t *testing.T) {
	srv, _, st := checksFleet(t)
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-h", Name: "h", Type: model.MonitorTypeHTTP, Target: "https://internal.example/", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-new"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ingest := func(r model.MonitorResult) {
		t.Helper()
		r.MonitorID, r.NodeID = "mon-h", "node-new"
		out, err := srv.ingestAgentMonitorResults("node-new", []model.MonitorResult{r})
		if err != nil || out.Accepted != 1 {
			t.Fatalf("ingest %+v: %+v %v", r, out, err)
		}
	}
	ingest(model.MonitorResult{At: now.Add(-2 * time.Minute), Success: false, Error: "connection refused"})
	ingest(model.MonitorResult{At: now.Add(-time.Minute), Reason: model.PathReasonDestinationRefused, Success: true, LatencyMs: 3, Error: `Get "https://u:p@internal.example/?token=abc": refused`})
	latest, ok, err := st.MonitorLatest("mon-h", "node-new")
	if err != nil || !ok || latest.FailStreak != 1 || latest.Unknown == nil || latest.Unknown.Reason != model.PathReasonDestinationRefused {
		t.Fatalf("latest = %+v (%v %v)", latest, ok, err)
	}
	if latest.Unknown.Success || strings.Contains(latest.Unknown.Error, "token") || strings.Contains(latest.Unknown.Error, "u:p") {
		t.Fatalf("the unknown run was not normalized: %+v", latest.Unknown)
	}
	m, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c := pathCellFor(t, m, "node-new", "mon-h"); c.State != model.PathStateUnknown || c.Reason != model.PathReasonDestinationRefused || c.Samples != 1 {
		t.Fatalf("cell = %+v", c)
	}
	ingest(model.MonitorResult{At: now, Success: false, Error: "refused"})
	latest, _, _ = st.MonitorLatest("mon-h", "node-new")
	if latest.FailStreak != 2 || latest.Unknown != nil {
		t.Fatalf("the next real failure continues the streak: %+v", latest)
	}
}

// A token that may not read a check's target node can neither edit nor
// delete the check, even when it administers every source.
func TestMonitorTargetNodeGuardsEditAndDelete(t *testing.T) {
	_, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"p","type":"icmp","target_node":"node-tgt","node_ids":["node-new"]}`, cookies, csrf)
	var created model.Monitor
	if err := json.Unmarshal([]byte(readBody(t, res)), &created); err != nil || created.ID == "" {
		t.Fatalf("create: %v", err)
	}
	token := createPAT(t, handler, cookies, csrf, []string{"monitor:admin", "monitor:read"}, []string{"node-new"})
	edit := doBearerJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+created.ID+`","version":1,"name":"renamed"}`, token)
	if body := readBody(t, edit); edit.StatusCode != http.StatusForbidden || strings.Contains(body, "198.51.100.20") {
		t.Fatalf("edit by a token that cannot read the target = %d %s", edit.StatusCode, body)
	}
	del := doBearerJSON(t, handler, http.MethodPost, "/api/monitors/delete", `{"id":"`+created.ID+`"}`, token)
	if body := readBody(t, del); del.StatusCode != http.StatusForbidden {
		t.Fatalf("delete by a token that cannot read the target = %d %s", del.StatusCode, body)
	}
	if _, ok := st.Monitor(created.ID); !ok {
		t.Fatal("the check is gone")
	}
}

// Through the agent route: a node's token stores results only for checks
// assigned to that node and only under its own id; a result that names
// another node, or a check assigned elsewhere, is dropped with the reason.
func TestAgentIngestRefusesOtherNodesAndUnassignedChecks(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)
	upsertNodes(t, st, model.Node{ID: "node-other", Name: "other"})
	for _, mon := range []model.Monitor{
		{ID: "mon-mine", Name: "mine", Type: model.MonitorTypeTCP, Target: "example.com:443", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{nodeID}, Enabled: true},
		{ID: "mon-theirs", Name: "theirs", Type: model.MonitorTypeTCP, Target: "example.com:443", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-other"}, Enabled: true},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	body := `{"node_id":"` + nodeID + `","results":[` +
		`{"monitor_id":"mon-mine","node_id":"` + nodeID + `","at":"` + at + `","success":true,"latency_ms":5},` +
		`{"monitor_id":"mon-mine","node_id":"node-other","at":"` + at + `","success":false},` +
		`{"monitor_id":"mon-theirs","at":"` + at + `","success":false}]}`
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-results", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest = %d %s", rec.Code, rec.Body.String())
	}
	var resp agentMonitorResultsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Accepted != 1 || len(resp.Dropped) != 2 || resp.Dropped[0].Reason != store.MonitorResultDropWrongNode || resp.Dropped[1].Reason != store.MonitorResultDropNotAssigned {
		t.Fatalf("response = %+v", resp)
	}
	if rows, _ := st.MonitorPairResults("mon-mine", "node-other", 0); len(rows) != 0 {
		t.Fatalf("a result was stored under another node: %+v", rows)
	}
	if rows, _ := st.MonitorPairResults("mon-theirs", nodeID, 0); len(rows) != 0 {
		t.Fatalf("a result was stored for a check assigned elsewhere: %+v", rows)
	}
	// Another node's token cannot post as this node.
	other := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-results", strings.Replace(body, `"node_id":"`+nodeID+`","results"`, `"node_id":"node-other","results"`, 1), token)
	if other.Code != http.StatusUnauthorized {
		t.Fatalf("a token posting for another node = %d", other.Code)
	}
}

// An http check that uses a field older agents ignore (a status set other
// than the default, request headers) goes only to agents that report their
// methods; an older one would judge it by the old rule and send it without
// its headers, so its path reads too old instead of down. A default http
// check still reaches every agent.
func TestCurrentFieldsGateOlderAgents(t *testing.T) {
	srv, _, st := checksFleet(t)
	for _, mon := range []model.Monitor{
		{ID: "mon-plain", Name: "plain", Type: model.MonitorTypeHTTP, Target: "https://example.com/", ExpectStatus: "200-399", IntervalSec: 30, TimeoutSec: 5, AssignAll: true, Enabled: true},
		{ID: "mon-401", Name: "expects 401", Type: model.MonitorTypeHTTP, Target: "https://example.com/", ExpectStatus: "401", IntervalSec: 30, TimeoutSec: 5, AssignAll: true, Enabled: true},
		{ID: "mon-auth", Name: "auth", Type: model.MonitorTypeHTTP, Target: "https://example.com/", Headers: []model.MonitorHeader{{Name: "Authorization", Value: "Bearer old-agent-s3cr3t", Secret: true}}, SecretsOrigin: "https://example.com:443", IntervalSec: 30, TimeoutSec: 5, AssignAll: true, Enabled: true},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	if got := monitorIDs(agentMonitorList(t, srv, st, "node-old")); !slices.Equal(got, []string{"mon-plain"}) {
		t.Fatalf("an older agent is handed %v", got)
	}
	if got := monitorIDs(agentMonitorList(t, srv, st, "node-new")); !slices.Equal(got, []string{"mon-401", "mon-auth", "mon-plain"}) {
		t.Fatalf("a current agent is handed %v", got)
	}
	m, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"mon-401", "mon-auth"} {
		if c := pathCellFor(t, m, "node-old", id); c.State != model.PathStateUnknown || c.Reason != model.PathReasonAgentTooOld {
			t.Errorf("%s from an older agent = %+v", id, c)
		}
	}
}

// Numeric host forms some resolvers read as addresses, zones, and the
// reserved and transition ranges of the shared rule are refused on save.
func TestMonitorCreateRefusesNumericAndReservedHosts(t *testing.T) {
	_, handler, _ := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	for _, body := range []string{
		`{"name":"h","type":"http","target":"http://2130706433/","node_ids":["node-new"]}`,
		`{"name":"h","type":"http","target":"http://127.1/","node_ids":["node-new"]}`,
		`{"name":"h","type":"http","target":"http://0x7f.1/","node_ids":["node-new"]}`,
		`{"name":"h","type":"http","target":"http://0xa9fea9fe/","node_ids":["node-new"]}`,
		`{"name":"t","type":"tcp","target":"0:80","node_ids":["node-new"]}`,
		`{"name":"t","type":"tcp","target":"10.0.0.1.:80","node_ids":["node-new"]}`,
		`{"name":"t","type":"tcp","target":"[fe80::1%25eth0]:22","node_ids":["node-new"]}`,
		`{"name":"t","type":"tcp","target":"127.0.0.1%eth0:22","node_ids":["node-new"]}`,
		`{"name":"t","type":"tcp","target":"[64:ff9b::a00:1]:80","node_ids":["node-new"]}`,
		`{"name":"t","type":"tcp","target":"[2002:7f00:1::]:80","node_ids":["node-new"]}`,
		`{"name":"p","type":"icmp","target":"240.0.0.1","node_ids":["node-new"]}`,
		`{"name":"p","type":"icmp","target":"198.18.0.1","node_ids":["node-new"]}`,
	} {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors", body, cookies, csrf)
		if raw := readBody(t, res); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d %s", body, res.StatusCode, raw)
		}
	}
	for _, body := range []string{
		`{"name":"h","type":"http","target":"https://status.example.com/","node_ids":["node-new"]}`,
		`{"name":"h","type":"http","target":"https://host-2.example/","node_ids":["node-new"]}`,
		`{"name":"t","type":"tcp","target":"[2606:4700:4700::1111]:443","node_ids":["node-new"]}`,
	} {
		res := doJSON(t, handler, http.MethodPost, "/api/monitors", body, cookies, csrf)
		if raw := readBody(t, res); res.StatusCode != http.StatusOK {
			t.Errorf("%s = %d %s", body, res.StatusCode, raw)
		}
	}
}

// A check saved before the destination rules stays editable: an edit does
// not judge the stored target again (the agent refuses it at dial time).
// A headers-only edit does not report the status set as changed.
func TestEditOfAnOlderPrivateCheck(t *testing.T) {
	_, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-lan", Name: "lan", Type: model.MonitorTypeHTTP, Target: "http://10.1.2.3/health", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-new"}, Enabled: true, Version: 1}); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"mon-lan","version":1,"headers":[{"name":"X-Trace","op":"set","value":"1"}],"expect_status":""}`, cookies, csrf)
	if body := readBody(t, res); res.StatusCode != http.StatusOK {
		t.Fatalf("edit of an older private check = %d %s", res.StatusCode, body)
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action == "monitor.update" && ev.Metadata["changed"] != "headers" {
			t.Fatalf("changed = %q, want headers alone", ev.Metadata["changed"])
		}
	}
	tcp := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"t","type":"tcp","target":"example.com:443","node_ids":["node-new"]}`, cookies, csrf)
	var created model.Monitor
	if err := json.Unmarshal([]byte(readBody(t, tcp)), &created); err != nil {
		t.Fatal(err)
	}
	echo := doJSON(t, handler, http.MethodPost, "/api/monitors/update", `{"id":"`+created.ID+`","version":1,"expect_status":"","name":"t2"}`, cookies, csrf)
	if body := readBody(t, echo); echo.StatusCode != http.StatusOK {
		t.Fatalf("an echoed empty expect_status on tcp = %d %s", echo.StatusCode, body)
	}
}

// An incident of a check that names a node is hidden from a caller who may
// not read that node, as the check itself is.
func TestIncidentOfANodeTargetCheckIsScopedByTheTarget(t *testing.T) {
	srv, handler, st := checksFleet(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"to tgt","type":"tcp","target_node":"node-tgt","node_ids":["node-new"],"alert_after":1}`, cookies, csrf)
	var created model.Monitor
	if err := json.Unmarshal([]byte(readBody(t, res)), &created); err != nil || created.ID == "" {
		t.Fatalf("create: %v", err)
	}
	if _, err := srv.ingestAgentMonitorResults("node-new", []model.MonitorResult{{MonitorID: created.ID, At: time.Now().UTC(), Error: "dial tcp 198.51.100.20:443: refused"}}); err != nil {
		t.Fatal(err)
	}
	if len(st.Incidents()) == 0 {
		t.Fatal("no incident opened")
	}
	admin := doJSON(t, handler, http.MethodGet, "/api/incidents", "", cookies, "")
	if body := readBody(t, admin); !strings.Contains(body, created.ID) {
		t.Fatalf("the admin does not see the incident: %s", body)
	}
	token := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, []string{"node-new"})
	confined := doBearerJSON(t, handler, http.MethodGet, "/api/incidents", "", token)
	if body := readBody(t, confined); strings.Contains(body, created.ID) || strings.Contains(body, "198.51.100.20") {
		t.Fatalf("a token that cannot read the target sees its incident: %s", body)
	}
}

// An icmp run that failed before any echo left (a lookup error, a socket
// error other than permission) is an ordinary failed run: sent 0, an
// error, no reason. One malformed or out-of-bounds entry in a batch is
// dropped on its own and listed; the rest of the batch is stored, since an
// agent drops a whole batch on a 400.
func TestAgentBatchDropsBadEntriesOneByOne(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-ping", Name: "ping", Type: model.MonitorTypeICMP, Target: "198.51.100.20", Packets: 5, IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{nodeID}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Minute)
	at := func(i int) string { return base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano) }
	body := `{"node_id":"` + nodeID + `","results":[` +
		`{"monitor_id":"mon-ping","at":"` + at(0) + `","success":false,"error":"socket: too many open files"},` +
		`{"monitor_id":"mon-ping","at":"` + at(1) + `","sent":"five"},` +
		`{"monitor_id":"mon-ping","at":"` + at(2) + `","sent":11,"rtts_ms":[1,2,3,4,5,6,7,8,9,10,11]},` +
		`{"monitor_id":"mon-ping","at":"not a time","success":true},` +
		`{"monitor_id":"mon-ping","at":"` + at(4) + `","sent":5,"lost":1,"rtts_ms":[10,11,12,13],"success":true}]}`
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-results", body, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch = %d %s", rec.Code, rec.Body.String())
	}
	var resp agentMonitorResultsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Accepted != 2 || len(resp.Dropped) != 3 {
		t.Fatalf("response = %+v", resp)
	}
	for i, want := range []int{1, 2, 3} {
		if d := resp.Dropped[i]; d.Index != want || d.Reason != store.MonitorResultDropInvalid || d.MonitorID != "mon-ping" {
			t.Fatalf("drop %d = %+v, want index %d invalid", i, d, want)
		}
	}
	rows := storedMonitorResults(t, st, "mon-ping")
	if len(rows) != 2 || rows[0].Success || rows[0].Sent != 0 || rows[0].Reason != "" || rows[0].Error == "" || !rows[1].Success || rows[1].Sent != 5 {
		t.Fatalf("stored = %+v", rows)
	}
	latest, _, _ := st.MonitorLatest("mon-ping", nodeID)
	if latest.FailStreak != 0 || !latest.Success {
		t.Fatalf("latest = %+v", latest)
	}
	// A run with no packets counts as one probe lost.
	m := rowSummaryOf(t, st, "mon-ping", nodeID, base.Add(-time.Hour), time.Now().Add(time.Minute))
	if m.N != 2 || m.F != 1 || m.S != 6 || m.L != 2 {
		t.Fatalf("rollup = %+v", m)
	}
	// The single-result route drops an out-of-bounds entry the same way.
	one := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", `{"node_id":"`+nodeID+`","result":{"monitor_id":"mon-ping","at":"`+at(5)+`","sent":12,"rtts_ms":[]}}`, token)
	if one.Code != http.StatusOK || !strings.Contains(one.Body.String(), `"reason":"invalid"`) {
		t.Fatalf("single route = %d %s", one.Code, one.Body.String())
	}
}

// rowSummaryOf summarizes a pair's raw rows over a range.
func rowSummaryOf(t *testing.T, st *store.Store, monitorID, nodeID string, from, to time.Time) store.MonitorRollup {
	t.Helper()
	pair := store.MonitorPair{MonitorID: monitorID, NodeID: nodeID}
	sums, err := st.MonitorRowSummaries([]store.MonitorPair{pair}, from.Add(-time.Hour), from, to)
	if err != nil {
		t.Fatal(err)
	}
	return sums[pair].Cur
}

// A tcp result read no certificate, so no answer carries cert_not_after:
// not the stored rows, not the latest list, not the matrix.
func TestNoZeroCertificateOnTheWire(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, token := enrollNode(t, handler, cookies, csrf)
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-tcp", Name: "tcp", Type: model.MonitorTypeTCP, Target: "example.com:443", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{nodeID}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	body := `{"node_id":"` + nodeID + `","result":{"monitor_id":"mon-tcp","at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","success":true,"latency_ms":4}}`
	if rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", body, token); rec.Code != http.StatusOK {
		t.Fatalf("ingest = %d", rec.Code)
	}
	for _, path := range []string{"/api/monitors/results?monitor_id=mon-tcp", "/api/monitors", "/api/monitors/paths?window=1h", "/api/monitors/series?monitor=mon-tcp&source=" + nodeID + "&window=1h"} {
		res := doJSON(t, handler, http.MethodGet, path, "", cookies, "")
		if raw := readBody(t, res); res.StatusCode != http.StatusOK || strings.Contains(raw, "cert_not_after") || strings.Contains(raw, "0001-01-01") {
			t.Errorf("%s = %d %s", path, res.StatusCode, raw)
		}
	}
}

// A row stored before the expiry was omitted carries cert_not_after as year
// 1; it decodes to the zero time, and the server's answers leave it off.
func TestLegacyZeroCertificateRowsAreOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-tcp", Name: "tcp", Type: model.MonitorTypeTCP, Target: "example.com:443", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMonitorResult(model.MonitorResult{MonitorID: "mon-tcp", NodeID: "node-a", At: time.Now().UTC(), Success: true, LatencyMs: 4}); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(raw), `"latency_ms": 4,`, `"latency_ms": 4, "cert_not_after": "0001-01-01T00:00:00Z",`, 1)
	if legacy == string(raw) {
		t.Fatal("no stored row to age")
	}
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Close(context.Background())
		st.Close()
	})
	handler := srv.Handler()
	cookies, _ := loginSession(t, handler)
	for _, path := range []string{"/api/monitors/results?monitor_id=mon-tcp", "/api/monitors"} {
		res := doJSON(t, handler, http.MethodGet, path, "", cookies, "")
		body := readBody(t, res)
		if res.StatusCode != http.StatusOK || !strings.Contains(body, `"latency_ms":4`) || strings.Contains(body, "cert_not_after") || strings.Contains(body, "0001-01-01") {
			t.Errorf("%s = %d %s", path, res.StatusCode, body)
		}
	}
}
