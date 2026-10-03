package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
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
}

// TestFleetStateWriteRateHarness measures how often a quiet fleet rewrites
// state.json. It drives 34 agents (the production fleet in October 2026)
// against a disk-backed store with the runtime bolt hot store enabled, as
// production runs, with every background loop on. Each agent sends what a
// node-agent sends every ten seconds: the heartbeat, the config, sing-box
// inventory with its liveness probe, the task and monitor polls, the log
// sources and guard reality, all reporting facts that do not change.
//
// It runs in real time, so it is opt-in: LATTICE_FLEET_HARNESS=<window
// seconds>. Run it alone, with -run: it counts writes through the
// process-wide store telemetry, so any test running beside it adds its own
// writes to the count. A window of at least 960 covers the 5 minute heartbeat
// and the 15 minute token and report clocks. It fails above
// fleetHarnessMaxPerMinute; a quiet fleet writes about 0.2 a minute, and
// before the heartbeat clock was shared it wrote 8.5:
//
//	LATTICE_FLEET_HARNESS=960 go test ./internal/server/ -run TestFleetStateWriteRateHarness -v -timeout 30m
func TestFleetStateWriteRateHarness(t *testing.T) {
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
	writes := runFleetHarness(t, nodes, 10*time.Second, 30*time.Second, window)
	perMinute := float64(writes) / window.Minutes()
	t.Logf("%d nodes, 10s cycle: %d state writes in %s = %.2f per minute", nodes, writes, window, perMinute)
	if perMinute > fleetHarnessMaxPerMinute {
		t.Fatalf("a quiet fleet of %d nodes rewrote state.json %.2f times a minute, above %.0f", nodes, perMinute, fleetHarnessMaxPerMinute)
	}
}

// runFleetHarness enrolls nodes agents, lets them report every cycle for
// warmup plus window, and returns how many whole-state writes landed inside
// the window. It counts through the store telemetry, which every write
// reports, so it must not run beside other tests.
func runFleetHarness(t *testing.T, nodes int, cycle, warmup, window time.Duration) int {
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
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	fleet := make([]fleetHarnessNode, nodes)
	for i := range fleet {
		nodeID := fmt.Sprintf("node-%02d", i)
		fleet[i] = fleetHarnessNode{
			id:       nodeID,
			token:    enrollNamedNodeToken(t, handler, cookies, csrf, nodeID, "fleet-"+nodeID),
			publicIP: fmt.Sprintf("45.76.%d.10", 10+i),
			pid:      1000 + i,
			started:  time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		}
	}
	for _, n := range fleet {
		body := `{"node_id":"` + n.id + `","version":"0.3.9","public_ip":"` + n.publicIP + `"}`
		if res := fleetAgentRequest(n, handler, http.MethodPost, "/api/agent/hello", body); res.Code != http.StatusOK {
			t.Fatalf("hello %s: %d %s", n.id, res.Code, res.Body.String())
		}
	}

	saves := func() uint64 {
		snap := telemetry.CurrentSnapshot()
		return snap.Store["success"].Count + snap.Store["error"].Count
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
				fleetAgentCycle(t, handler, n)
				time.Sleep(cycle)
			}
		}(i, n)
	}
	time.Sleep(time.Until(measureFrom))
	atStart := saves()
	wg.Wait()
	time.Sleep(time.Until(end))
	return int(saves() - atStart)
}

// fleetAgentCycle sends one work loop's worth of agent requests.
func fleetAgentCycle(t *testing.T, handler http.Handler, n fleetHarnessNode) {
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
	post("/api/agent/singbox-inventory", map[string]any{
		"node_id": n.id,
		"inventory": model.SingBoxInventory{
			At:     now,
			Status: "ok",
			Nodes:  []model.SingBoxNode{},
			Runtime: &model.SingBoxRuntime{
				Running: true, PID: n.pid, StartedAt: n.started,
				ActiveState: "active", SubState: "running", ProbedAt: now,
			},
		},
	})
	get("/api/agent/tasks")
	get("/api/agent/monitors")
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
