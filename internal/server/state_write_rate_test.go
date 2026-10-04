package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

// fleetHarnessMaxPerMinute is the write rate a quiet fleet must stay under:
// generous against the one write per five minutes it should make, and far
// below the one per node per five minutes it used to.
const fleetHarnessMaxPerMinute = 1.0

// fleetHarnessNode is one simulated agent: its credentials, its address, and
// the facts it reports unchanged on every cycle, as a healthy node does.
type fleetHarnessNode struct {
	id, token string
	publicIP  string
	pid       int
	started   time.Time
	// edge is the provider edge name a node behind a provider declares, ""
	// for a direct node.
	edge string
}

// fleetShape is what the simulated fleet has besides its agents.
type fleetShape struct {
	// lines gives every node two discovered sing-box lines with share URLs
	// and port probes, so line identities, line metadata sync, client
	// templates, line chains and latency planning all run on real input.
	// Every fifth node sits behind a provider edge.
	lines bool
	// ddns adds a healthy DDNS profile and one whose provider keeps failing.
	ddns bool
}

// fleetHarnessResult is what one run measured.
type fleetHarnessResult struct {
	writes  int
	callers map[string]int
	// fixture says what the fleet had built by the end, so a quiet window
	// can be told apart from paths that never ran.
	fixture string
}

func (r fleetHarnessResult) breakdown() string {
	names := make([]string, 0, len(r.callers))
	for name := range r.callers {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if r.callers[names[i]] != r.callers[names[j]] {
			return r.callers[names[i]] > r.callers[names[j]]
		}
		return names[i] < names[j]
	})
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", name, r.callers[name]))
	}
	return strings.Join(parts, " ")
}

// TestFleetStateWriteRateHarness measures how often a quiet fleet rewrites
// state.json. It drives 34 agents (the production fleet in October 2026)
// against a disk-backed store with the runtime bolt hot store enabled, as
// production runs, with every background loop on. Each agent sends what a
// node-agent sends every ten seconds: the heartbeat, the config, sing-box
// inventory with its liveness probe, the task and monitor polls, the log
// sources and guard reality, all reporting facts that do not change.
// TestFleetStateWriteRateHarnessProductionShaped adds what production has
// besides agents (see fleetShape).
//
// It runs in real time, so it is opt-in: LATTICE_FLEET_HARNESS=<window
// seconds>, after a three minute warmup. Run one test alone, with -run: it counts writes through the
// process-wide store telemetry, so any test running beside it adds its own
// writes to the count. A window of at least 960 covers the 5 minute heartbeat
// and the 15 minute token and report clocks. Each fails above
// fleetHarnessMaxPerMinute and logs the writes by the store method that made
// them:
//
//	LATTICE_FLEET_HARNESS=960 go test ./internal/server/ -run 'TestFleetStateWriteRateHarness$' -v -timeout 30m
func TestFleetStateWriteRateHarness(t *testing.T) {
	runFleetHarnessTest(t, fleetShape{})
}

func TestFleetStateWriteRateHarnessProductionShaped(t *testing.T) {
	runFleetHarnessTest(t, fleetShape{lines: true, ddns: true})
}

func runFleetHarnessTest(t *testing.T, shape fleetShape) {
	raw := os.Getenv("LATTICE_FLEET_HARNESS")
	if raw == "" {
		t.Skip("set LATTICE_FLEET_HARNESS=<window seconds> to run the fleet write-rate harness")
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		t.Fatalf("LATTICE_FLEET_HARNESS=%q", raw)
	}
	window := time.Duration(secs) * time.Second
	const nodes = 34
	// The warmup outlasts the first DDNS sweep (1 min) and the first latency
	// probe sync (2 min), so writes that set things up once land before the
	// window and the window measures the steady state.
	got := runFleetHarness(t, nodes, shape, 10*time.Second, 3*time.Minute, window)
	perMinute := float64(got.writes) / window.Minutes()
	t.Logf("%d nodes, 10s cycle, %+v: %d state writes in %s = %.2f per minute; by caller: %s; fixture: %s",
		nodes, shape, got.writes, window, perMinute, got.breakdown(), got.fixture)
	if perMinute > fleetHarnessMaxPerMinute {
		t.Fatalf("a quiet fleet of %d nodes rewrote state.json %.2f times a minute, above %.0f", nodes, perMinute, fleetHarnessMaxPerMinute)
	}
}

// failingDDNSProvider is a provider that refuses every write, the way one
// with a revoked token does.
type failingDDNSProvider struct{}

func (failingDDNSProvider) Kind() string { return "failing" }
func (failingDDNSProvider) SetRecord(context.Context, ddns.Record) error {
	return errors.New("provider api error (status 403)")
}

// steadyDDNSProvider accepts every write.
type steadyDDNSProvider struct{}

func (steadyDDNSProvider) Kind() string                                 { return "steady" }
func (steadyDDNSProvider) SetRecord(context.Context, ddns.Record) error { return nil }

// runFleetHarness enrolls nodes agents, lets them report every cycle for
// warmup plus window, and returns the whole-state writes that landed inside
// the window, in total and by caller. It counts through the store telemetry,
// which every write reports, so it must not run beside other tests.
func runFleetHarness(t *testing.T, nodes int, shape fleetShape, cycle, warmup, window time.Duration) fleetHarnessResult {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Close(ctx)
	})
	// Edge names resolve to fixed public addresses, as a stable provider's do.
	srv.latencyEdges.mu.Lock()
	srv.latencyEdges.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		var n int
		if _, err := fmt.Sscanf(host, "edge-%d.example.net", &n); err != nil {
			return nil, err
		}
		return []net.IPAddr{{IP: net.IPv4(45, 77, byte(n), 20)}}, nil
	}
	srv.latencyEdges.mu.Unlock()
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	fleet := make([]fleetHarnessNode, nodes)
	for i := range fleet {
		nodeID := fmt.Sprintf("node-%02d", i)
		name := "fleet-" + nodeID
		if shape.lines && i == 0 {
			name = latencyDefaultSourceName // the default latency probe source
		}
		fleet[i] = fleetHarnessNode{
			id:       nodeID,
			token:    enrollNamedNodeToken(t, handler, cookies, csrf, nodeID, name),
			publicIP: fmt.Sprintf("45.76.%d.10", 10+i),
			pid:      1000 + i,
			started:  time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		}
		if shape.lines && i%5 == 4 {
			fleet[i].edge = fmt.Sprintf("edge-%d.example.net", i)
		}
	}
	for _, n := range fleet {
		body := `{"node_id":"` + n.id + `","version":"0.3.9","public_ip":"` + n.publicIP + `"}`
		if res := fleetAgentRequest(n, handler, http.MethodPost, "/api/agent/hello", body); res.Code != http.StatusOK {
			t.Fatalf("hello %s: %d %s", n.id, res.Code, res.Body.String())
		}
	}
	if shape.lines {
		// The default latency probe source is in mainland China and probes
		// every node outside it, so every other node gets a country there.
		countries := []string{"JP", "SG", "HK", "US", "DE"}
		for i, n := range fleet {
			country := countries[i%len(countries)]
			if i == 0 {
				country = "CN"
			}
			if _, _, err := st.UpdateNodeGeo(n.id, &model.NodeGeo{Country: country}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if shape.ddns {
		srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
			if p.ID == "ddns-failing" {
				return failingDDNSProvider{}, nil
			}
			return steadyDDNSProvider{}, nil
		}
		for _, p := range []model.DDNSProfile{
			{ID: "ddns-steady", Name: "steady", NodeID: fleet[1].id, Provider: "webhook", WebhookURL: "https://ddns.example.com/h", Domains: []string{"a.example.com"}, EnableIPv4: true},
			{ID: "ddns-failing", Name: "failing", NodeID: fleet[2].id, Provider: "webhook", WebhookURL: "https://ddns.example.com/h", Domains: []string{"b.example.com"}, EnableIPv4: true},
		} {
			if err := st.UpsertDDNSProfile(p); err != nil {
				t.Fatal(err)
			}
		}
	}

	callers := func() map[string]uint64 {
		out := map[string]uint64{}
		for caller, stats := range telemetry.CurrentSnapshot().StoreCallers {
			out[caller] = stats.Count
		}
		return out
	}
	measureFrom := time.Now().Add(warmup)
	end := measureFrom.Add(window)
	var wg sync.WaitGroup
	for i, n := range fleet {
		wg.Add(1)
		go func(i int, n fleetHarnessNode) {
			defer wg.Done()
			// Each node starts at its own offset in the cycle, as a fleet
			// that came up over time does.
			time.Sleep(time.Duration(i) * cycle / time.Duration(len(fleet)))
			for time.Now().Before(end) {
				fleetAgentCycle(t, handler, n, shape)
				time.Sleep(cycle)
			}
		}(i, n)
	}
	time.Sleep(time.Until(measureFrom))
	atStart := callers()
	wg.Wait()
	time.Sleep(time.Until(end))
	out := fleetHarnessResult{callers: map[string]int{}}
	linemeta := 0
	for _, ap := range st.Approvals() {
		if ap.Plugin == singBoxLineMetaPlugin {
			linemeta++
		}
	}
	latency := 0
	for _, mon := range st.Monitors() {
		if mon.ManagedBy == model.MonitorManagedLatency {
			latency++
		}
	}
	out.fixture = fmt.Sprintf("linemeta approvals=%d client templates=%d latency monitors=%d ddns profiles=%d",
		linemeta, len(st.LineClientTemplates()), latency, len(st.DDNSProfiles()))
	for caller, count := range callers() {
		if d := int(count - atStart[caller]); d > 0 {
			out.callers[caller] = d
			out.writes += d
		}
	}
	return out
}

// fleetLines is the sing-box inventory a node with lines reports: a VLESS
// REALITY line and a Trojan line, both with share URLs and bound ports.
func fleetLines(n fleetHarnessNode) []model.SingBoxNode {
	bound := true
	host, vlessPort, trojanPort := n.publicIP, "443", "8443"
	vlessPublic, trojanPublic := "", ""
	if n.edge != "" {
		host, vlessPublic, trojanPublic = n.edge, "50443", "58443"
	}
	dial := func(listen, public string) string {
		if public != "" {
			return public
		}
		return listen
	}
	vless := fmt.Sprintf("vless://3b5c8a0e-1f2d-4c3b-9a8e-%012d@%s:%s?encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#vless-reality",
		len(n.id), host, dial(vlessPort, vlessPublic))
	trojan := fmt.Sprintf("trojan://fleet-password@%s:%s?security=tls&sni=www.example.com&type=tcp#trojan", host, dial(trojanPort, trojanPublic))
	return []model.SingBoxNode{
		{Name: "vless-reality-443", Protocol: "vless", Network: "tcp", Address: n.publicIP, Port: vlessPort, PublicPort: vlessPublic, ListenHost: "::",
			OutboundRef: "direct", UserCount: 5, UserKnown: true, PortBound: &bound, PortBoundBy: "sing-box", ShareURL: vless},
		{Name: "trojan-8443", Protocol: "trojan", Network: "tcp", Address: n.publicIP, Port: trojanPort, PublicPort: trojanPublic, ListenHost: "::",
			OutboundRef: "direct", UserCount: 3, UserKnown: true, PortBound: &bound, PortBoundBy: "sing-box", ShareURL: trojan},
	}
}

// fleetAgentCycle sends one work loop's worth of agent requests.
func fleetAgentCycle(t *testing.T, handler http.Handler, n fleetHarnessNode, shape fleetShape) {
	now := time.Now().UTC()
	post := func(path string, body any) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Error(err)
			return
		}
		if res := fleetAgentRequest(n, handler, http.MethodPost, path, string(raw)); res.Code != http.StatusOK {
			t.Errorf("%s %s: %d %s", n.id, path, res.Code, res.Body.String())
		}
	}
	get := func(path string) {
		if res := fleetAgentRequest(n, handler, http.MethodGet, path+"?node_id="+n.id, ""); res.Code != http.StatusOK {
			t.Errorf("%s GET %s: %d %s", n.id, path, res.Code, res.Body.String())
		}
	}
	post("/api/agent/metrics", map[string]any{
		"node_id":   n.id,
		"version":   "0.3.9",
		"public_ip": n.publicIP,
		"metrics":   model.Metrics{CPUPercent: 3, MemoryUsed: 400, MemoryTotal: 1000, CollectedAt: now},
	})
	get("/api/agent/config")
	inventory := model.SingBoxInventory{
		At:     now,
		Status: "ok",
		Nodes:  []model.SingBoxNode{},
		Runtime: &model.SingBoxRuntime{
			Running: true, PID: n.pid, StartedAt: n.started,
			ActiveState: "active", SubState: "running", ProbedAt: now,
		},
	}
	if shape.lines {
		inventory.Nodes = fleetLines(n)
		inventory.Network = "direct"
		if n.edge != "" {
			inventory.Network, inventory.ProviderEdge = "nat", n.edge
		}
	}
	post("/api/agent/singbox-inventory", map[string]any{"node_id": n.id, "inventory": inventory})
	get("/api/agent/tasks")
	monitors := fleetAgentRequest(n, handler, http.MethodGet, "/api/agent/monitors?node_id="+n.id, "")
	if monitors.Code != http.StatusOK {
		t.Errorf("%s GET /api/agent/monitors: %d %s", n.id, monitors.Code, monitors.Body.String())
	}
	// The node runs what it was assigned and reports every result, as the
	// latency probe source does every cycle.
	var assigned []model.Monitor
	if err := json.Unmarshal(monitors.Body.Bytes(), &assigned); err != nil {
		t.Errorf("%s monitors: %v", n.id, err)
	}
	if len(assigned) > 0 {
		results := make([]model.MonitorResult, 0, len(assigned))
		for _, mon := range assigned {
			results = append(results, model.MonitorResult{MonitorID: mon.ID, NodeID: n.id, At: now, Success: true, LatencyMs: 42})
		}
		post("/api/agent/monitor-results", map[string]any{"node_id": n.id, "results": results})
	}
	get("/api/agent/log-sources")
	post("/api/agent/guard-reality", map[string]any{
		"node_id": n.id,
		"reality": model.GuardNodeReality{NodeID: n.id, NFTVersion: "1.0.9", CollectedAt: now},
	})
}

// fleetAgentRequest sends one agent request from the node's own address, so
// the per-address agent limiter sees a fleet rather than one noisy client.
func fleetAgentRequest(n fleetHarnessNode, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = n.publicIP + ":40000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.token)
	return serveReq(handler, req)
}
