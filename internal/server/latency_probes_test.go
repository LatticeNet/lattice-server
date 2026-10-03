package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func boolPtr(v bool) *bool { return &v }

// The port rule, one case per clause (latency_probes.go).
func TestLatencyPortRule(t *testing.T) {
	direct := model.Node{ID: "n", PublicIP: "203.0.113.10"}
	cases := []struct {
		name    string
		node    model.Node
		inv     model.SingBoxInventory
		refused []int
		edges   map[string][]string
		want    string
		note    string
	}{
		{
			name: "a reality line on the node's public address",
			node: direct,
			inv:  model.SingBoxInventory{Nodes: []model.SingBoxNode{{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: "203.0.113.10"}}},
			want: "203.0.113.10:443",
		},
		{
			name: "UDP lines only",
			node: direct,
			inv: model.SingBoxInventory{Nodes: []model.SingBoxNode{
				{Name: "hy2", Protocol: "hysteria2", Network: "hysteria2", Port: "8443", Address: "203.0.113.10"},
				{Name: "tuic", Protocol: "tuic", Network: "tuic", Port: "9443", Address: "203.0.113.10"},
				{Name: "vless-quic", Protocol: "vless", Network: "quic", Port: "7443", Address: "203.0.113.10"},
			}},
			note: model.LatencyEndpointUDPOnly,
		},
		{
			name: "only a TLS front on loopback, a relay, and SSH",
			node: direct,
			inv: model.SingBoxInventory{Nodes: []model.SingBoxNode{
				{Name: "vless-ws-example.com", Protocol: "vless", Network: "ws", Port: "443", ListenHost: "127.0.0.1", Address: "example.com"},
				{Name: "door", Protocol: "direct", Network: "direct", Port: "8080", Address: "203.0.113.10"},
				{Name: "socks", Protocol: "socks", Network: "socks", Port: "1080", Address: "203.0.113.10"},
				{Name: "trojan-on-ssh", Protocol: "trojan", Network: "trojan", Port: "22", Address: "203.0.113.10"},
			}},
			note: model.LatencyEndpointNoLine,
		},
		{
			name:    "a knock-gated port is refused even when a line claims it",
			node:    direct,
			refused: []int{8443},
			inv: model.SingBoxInventory{Nodes: []model.SingBoxNode{
				{Name: "gated", Protocol: "anytls", Network: "anytls", Port: "8443", Address: "203.0.113.10", PortBound: boolPtr(true)},
				{Name: "open", Protocol: "trojan", Network: "trojan", Port: "9443", Address: "203.0.113.10"},
			}},
			want: "203.0.113.10:9443",
		},
		{
			name:  "a NAT node is dialled at the address its provider edge resolved to, on the public port",
			node:  model.Node{ID: "n", PublicIP: "198.51.100.7"},
			edges: map[string][]string{"edge.provider.example": {"203.0.113.40", "203.0.113.50"}},
			inv: model.SingBoxInventory{Network: "nat", ProviderEdge: "Edge.Provider.Example", Nodes: []model.SingBoxNode{
				{Name: "vless-488", Protocol: "vless", Network: "reality", Port: "488", PublicPort: "50100", Address: "10.0.0.4"},
			}},
			want: "203.0.113.40:50100",
		},
		{
			name: "a provider edge name the control plane has not resolved to public addresses is not dialled",
			node: model.Node{ID: "n", PublicIP: "198.51.100.7"},
			inv: model.SingBoxInventory{Network: "nat", ProviderEdge: "edge.provider.example", Nodes: []model.SingBoxNode{
				{Name: "vless-488", Protocol: "vless", Network: "reality", Port: "488", PublicPort: "50100", Address: "198.51.100.7"},
			}},
			note: model.LatencyEndpointNoAddress,
		},
		{
			name: "a provider edge given as a public address literal is dialled as it is",
			node: model.Node{ID: "n", PublicIP: "198.51.100.7"},
			inv: model.SingBoxInventory{Network: "nat", ProviderEdge: "203.0.113.77", Nodes: []model.SingBoxNode{
				{Name: "vless-488", Protocol: "vless", Network: "reality", Port: "488", PublicPort: "50100"},
			}},
			want: "203.0.113.77:50100",
		},
		{
			name: "a line publishing an unrelated public address is dialled at the node's own",
			node: direct,
			inv: model.SingBoxInventory{Nodes: []model.SingBoxNode{
				{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443", Address: "8.8.8.8"},
			}},
			want: "203.0.113.10:443",
		},
		{
			name: "a NAT node's line that publishes another public address is not dialled",
			node: model.Node{ID: "n", PublicIP: "198.51.100.7"},
			inv: model.SingBoxInventory{Network: "nat", Nodes: []model.SingBoxNode{
				{Name: "vless", Protocol: "vless", Network: "reality", Port: "488", Address: "8.8.8.8"},
			}},
			note: model.LatencyEndpointNoAddress,
		},
		{
			name: "a NAT node's line that publishes the node's own address is dialled there",
			node: model.Node{ID: "n", PublicIP: "198.51.100.7"},
			inv: model.SingBoxInventory{Network: "nat", Nodes: []model.SingBoxNode{
				{Name: "vless", Protocol: "vless", Network: "reality", Port: "488", Address: "198.51.100.7"},
			}},
			want: "198.51.100.7:488",
		},
		{
			name: "a line's host name is never dialled, even with no other address",
			node: model.Node{ID: "n"},
			inv: model.SingBoxInventory{Nodes: []model.SingBoxNode{
				{Name: "anytls-host", Protocol: "anytls", Network: "anytls", Port: "443", Address: "internal.example.com"},
			}},
			note: model.LatencyEndpointNoAddress,
		},
		{
			name: "a NAT node with nothing public to dial",
			node: model.Node{ID: "n", PublicIP: "198.51.100.7"},
			inv: model.SingBoxInventory{Network: "nat", Nodes: []model.SingBoxNode{
				{Name: "vless", Protocol: "vless", Network: "reality", Port: "488", Address: "10.0.0.4"},
			}},
			note: model.LatencyEndpointNoAddress,
		},
		{
			name: "a direct node is dialled by address, not by the name a line publishes",
			node: direct,
			inv: model.SingBoxInventory{Nodes: []model.SingBoxNode{
				{Name: "anytls-host", Protocol: "anytls", Network: "anytls", Port: "443", Address: "jp.example.com"},
			}},
			want: "203.0.113.10:443",
		},
		{
			name: "held port first, then raw transport, then lowest port",
			node: direct,
			inv: model.SingBoxInventory{Nodes: []model.SingBoxNode{
				{Name: "a-not-listening", Protocol: "vless", Network: "reality", Port: "1000", Address: "203.0.113.10", PortBound: boolPtr(false)},
				{Name: "b-ws", Protocol: "vmess", Network: "ws", Port: "2000", Address: "203.0.113.10", PortBound: boolPtr(true)},
				{Name: "c-raw", Protocol: "trojan", Network: "trojan", Port: "3000", Address: "203.0.113.10", PortBound: boolPtr(true)},
			}},
			want: "203.0.113.10:3000",
		},
		{
			name: "no lines at all",
			node: direct,
			inv:  model.SingBoxInventory{},
			note: model.LatencyEndpointNoLine,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refused := map[int]bool{22: true}
			for _, port := range tc.refused {
				refused[port] = true
			}
			got, note := latencyEndpoints(tc.node, tc.inv, refused, tc.edges)
			if tc.want != "" {
				if len(got) == 0 || got[0].target != tc.want {
					t.Fatalf("endpoints = %+v note %q, want %s first", got, note, tc.want)
				}
				return
			}
			if len(got) != 0 || note != tc.note {
				t.Fatalf("endpoints = %+v note %q, want none with %q", got, note, tc.note)
			}
		})
	}
}

// latencyFleet seeds a source in Shanghai, three overseas targets (one with
// lines, one with only UDP lines, one NAT), one more mainland node and one
// with no country, and the targets' inventories.
func latencyFleet(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	srv, handler, st := newInventoryServer(t)
	srv.latencyEdges.lookup = fakeEdgeResolver(map[string][]string{"edge.example.net": {"203.0.113.50"}}).lookup
	nodes := []model.Node{
		{ID: "node-sh", Name: "cd-hs-sh", PublicIP: "203.0.113.1", Geo: &model.NodeGeo{Country: "CN"}},
		{ID: "node-bj", Name: "cd-bj", PublicIP: "203.0.113.2", Geo: &model.NodeGeo{Country: "cn"}},
		{ID: "node-jp", Name: "gomami-jp", PublicIP: "203.0.113.3", Geo: &model.NodeGeo{Country: "JP"}},
		{ID: "node-hk", Name: "hk-relay", PublicIP: "203.0.113.4", Geo: &model.NodeGeo{Country: "HK"}},
		{ID: "node-us", Name: "us-nat", PublicIP: "198.51.100.9", Geo: &model.NodeGeo{Country: "US"}},
		{ID: "node-xx", Name: "no-geo", PublicIP: "203.0.113.6"},
	}
	for _, n := range nodes {
		if err := st.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	srv.singboxInvMu.Lock()
	if srv.singboxInv == nil {
		srv.singboxInv = map[string]model.SingBoxInventory{}
	}
	srv.singboxInv["node-jp"] = model.SingBoxInventory{NodeID: "node-jp", At: now, Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "vless-reality-443", Protocol: "vless", Network: "reality", Port: "443", ListenHost: "::", Address: "203.0.113.3", PortBound: boolPtr(true)},
		{Name: "hy2", Protocol: "hysteria2", Network: "hysteria2", Port: "8443", Address: "203.0.113.3"},
	}}
	srv.singboxInv["node-hk"] = model.SingBoxInventory{NodeID: "node-hk", At: now, Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "hy2", Protocol: "hysteria2", Network: "hysteria2", Port: "8443", Address: "203.0.113.4"},
	}}
	srv.singboxInv["node-us"] = model.SingBoxInventory{NodeID: "node-us", At: now, Status: "ok", Network: "nat", ProviderEdge: "edge.example.net", Nodes: []model.SingBoxNode{
		{Name: "trojan-50100", Protocol: "trojan", Network: "trojan", Port: "488", PublicPort: "50100", Address: "10.1.2.3"},
	}}
	srv.singboxInvMu.Unlock()
	return srv, handler, st
}

func latencyNodeOf(t *testing.T, plan model.LatencyProbePlan, nodeID string) model.LatencyProbeNode {
	t.Helper()
	for _, n := range plan.Nodes {
		if n.NodeID == nodeID {
			return n
		}
	}
	t.Fatalf("plan has no node %s: %+v", nodeID, plan.Nodes)
	return model.LatencyProbeNode{}
}

// With nothing saved, the defaults probe from cd-hs-sh to every node outside
// mainland China, through monitors the source's agent receives like any
// other; a second sync changes nothing and writes nothing.
func TestLatencyDefaultsProbeFromShanghaiToOverseas(t *testing.T) {
	srv, _, st := latencyFleet(t)
	plan, changes, err := srv.syncLatencyProbes(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Stored || !plan.Config.Enabled || plan.Config.IntervalSec != 60 || !slices.Equal(plan.Config.Sources, []string{"node-sh"}) {
		t.Fatalf("defaults = %+v stored=%v", plan.Config, plan.Stored)
	}
	jp := latencyNodeOf(t, plan, "node-jp")
	if jp.Target != model.LatencyTargetProbed || jp.TargetReason != model.LatencyReasonAuto || jp.Endpoint != "203.0.113.3:443" || jp.Protocol != "vless" || jp.LineName != "vless-reality-443" {
		t.Fatalf("jp = %+v", jp)
	}
	if hk := latencyNodeOf(t, plan, "node-hk"); hk.Target != model.LatencyTargetNotProbeable || hk.EndpointNote != model.LatencyEndpointUDPOnly || hk.MonitorID != "" {
		t.Fatalf("hk = %+v", hk)
	}
	if us := latencyNodeOf(t, plan, "node-us"); us.Endpoint != "203.0.113.50:50100" {
		t.Fatalf("us = %+v", us)
	}
	if bj := latencyNodeOf(t, plan, "node-bj"); bj.Target != model.LatencyTargetNone || bj.TargetReason != model.LatencyReasonMainland || bj.Region != model.LatencyRegionMainland {
		t.Fatalf("bj = %+v", bj)
	}
	if xx := latencyNodeOf(t, plan, "node-xx"); xx.TargetReason != model.LatencyReasonRegionUnknown {
		t.Fatalf("no-geo = %+v", xx)
	}
	if sh := latencyNodeOf(t, plan, "node-sh"); !sh.Source || sh.Target != model.LatencyTargetNone {
		t.Fatalf("sh = %+v", sh)
	}
	if len(changes.Created) != 2 {
		t.Fatalf("created = %+v, want the jp and us monitors", changes)
	}
	mon, ok := st.Monitor(latencyMonitorID("node-jp"))
	if !ok || mon.Type != model.MonitorTypeTCP || mon.Target != "203.0.113.3:443" || !mon.Enabled || !slices.Equal(mon.NodeIDs, []string{"node-sh"}) || mon.ManagedBy != model.MonitorManagedLatency || mon.IntervalSec != 60 {
		t.Fatalf("generated monitor = %+v", mon)
	}
	assigned := st.MonitorsForNode("node-sh")
	if len(assigned) != 2 {
		t.Fatalf("the source's agent receives %d monitors, want 2", len(assigned))
	}
	if len(st.MonitorsForNode("node-jp")) != 0 {
		t.Fatal("a target was assigned its own probe")
	}
	if len(plan.Pairs) != 3 {
		t.Fatalf("pairs = %+v, want one per target", plan.Pairs)
	}
	again, changes, err := srv.syncLatencyProbes(time.Now())
	if err != nil || changes.Changed() {
		t.Fatalf("second sync = %+v %v", changes, err)
	}
	if latencyNodeOf(t, again, "node-jp").MonitorID != latencyMonitorID("node-jp") {
		t.Fatal("plan lost the monitor id")
	}
}

// A node whose inventory went stale keeps its endpoint; a better line does
// not move a probe that still passes the rule; losing the chosen line does.
func TestLatencyEndpointIsStickyAndSurvivesAStaleInventory(t *testing.T) {
	srv, _, st := latencyFleet(t)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	srv.removeSingBoxInventory("node-jp")
	plan, changes, err := srv.syncLatencyProbes(time.Now())
	if err != nil || changes.Changed() {
		t.Fatalf("stale inventory changed the monitors: %+v %v", changes, err)
	}
	jp := latencyNodeOf(t, plan, "node-jp")
	if jp.Target != model.LatencyTargetProbed || jp.EndpointNote != model.LatencyEndpointLastKnown || jp.Endpoint != "203.0.113.3:443" {
		t.Fatalf("offline target = %+v", jp)
	}

	srv.singboxInvMu.Lock()
	srv.singboxInv["node-jp"] = model.SingBoxInventory{NodeID: "node-jp", At: time.Now(), Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "aaa-trojan-80", Protocol: "trojan", Network: "trojan", Port: "80", Address: "203.0.113.3", PortBound: boolPtr(true)},
		{Name: "vless-reality-443", Protocol: "vless", Network: "reality", Port: "443", Address: "203.0.113.3", PortBound: boolPtr(true)},
	}}
	srv.singboxInvMu.Unlock()
	if _, changes, _ := srv.syncLatencyProbes(time.Now()); changes.Changed() {
		t.Fatalf("a better-ranked line moved a working probe: %+v", changes)
	}

	srv.singboxInvMu.Lock()
	inv := srv.singboxInv["node-jp"]
	inv.Nodes = inv.Nodes[:1]
	srv.singboxInv["node-jp"] = inv
	srv.singboxInvMu.Unlock()
	if _, changes, _ := srv.syncLatencyProbes(time.Now()); len(changes.Updated) != 1 {
		t.Fatalf("the chosen line went away and nothing moved: %+v", changes)
	}
	if mon, _ := st.Monitor(latencyMonitorID("node-jp")); mon.Target != "203.0.113.3:80" {
		t.Fatalf("moved to %s", mon.Target)
	}
}

func putLatencyConfig(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string, cfg model.LatencyProbeConfig) (int, model.LatencyProbePlan, string) {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	res := doJSON(t, handler, http.MethodPut, "/api/monitors/latency", string(raw), cookies, csrf)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var plan model.LatencyProbePlan
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &plan); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, plan, string(body)
}

// A save is validated, versioned, audited and applied at once: a disabled
// pair drops the source from the monitor, an excluded target keeps its
// monitor paused with its history, and a second source joins.
func TestLatencyConfigSave(t *testing.T) {
	srv, handler, st := latencyFleet(t)
	cookies, csrf := loginSession(t, handler)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}

	base := model.LatencyProbeConfig{Enabled: true, IntervalSec: 30, TimeoutSec: 5, AutoTargets: true, Sources: []string{"node-sh", "node-bj", "node-sh"}}
	if code, _, body := putLatencyConfig(t, handler, cookies, csrf, model.LatencyProbeConfig{Sources: []string{"node-gone"}}); code != http.StatusBadRequest || !strings.Contains(body, "not a node") {
		t.Fatalf("unknown node = %d %s", code, body)
	}
	if code, _, _ := putLatencyConfig(t, handler, cookies, csrf, model.LatencyProbeConfig{IntervalSec: 5}); code != http.StatusBadRequest {
		t.Fatalf("an interval under the floor = %d", code)
	}
	if code, _, _ := putLatencyConfig(t, handler, cookies, csrf, model.LatencyProbeConfig{IncludeTargets: []string{"node-jp"}, ExcludeTargets: []string{"node-jp"}}); code != http.StatusBadRequest {
		t.Fatalf("include and exclude one node = %d", code)
	}

	code, plan, body := putLatencyConfig(t, handler, cookies, csrf, base)
	if code != http.StatusOK {
		t.Fatalf("save = %d %s", code, body)
	}
	if !plan.Stored || plan.Config.Version != 1 || !slices.Equal(plan.Config.Sources, []string{"node-bj", "node-sh"}) {
		t.Fatalf("saved plan = %+v", plan.Config)
	}
	mon, _ := st.Monitor(latencyMonitorID("node-jp"))
	if mon.IntervalSec != 30 || !slices.Equal(mon.NodeIDs, []string{"node-bj", "node-sh"}) {
		t.Fatalf("monitor after the save = %+v", mon)
	}
	if code, _, _ := putLatencyConfig(t, handler, cookies, csrf, base); code != http.StatusConflict {
		t.Fatalf("a save from a stale version = %d, want 409", code)
	}

	now := time.Now().UTC()
	if _, err := st.IngestAgentMonitorResults("node-sh", []model.MonitorResult{{MonitorID: latencyMonitorID("node-jp"), At: now, Success: true, LatencyMs: 61}}, now); err != nil {
		t.Fatal(err)
	}
	next := base
	next.Version = 1
	next.DisabledPairs = []model.LatencyPair{{Source: "node-bj", Target: "node-us"}}
	next.ExcludeTargets = []string{"node-jp"}
	code, plan, body = putLatencyConfig(t, handler, cookies, csrf, next)
	if code != http.StatusOK {
		t.Fatalf("second save = %d %s", code, body)
	}
	if us, _ := st.Monitor(latencyMonitorID("node-us")); !slices.Equal(us.NodeIDs, []string{"node-sh"}) {
		t.Fatalf("a disabled pair still probes: %+v", us)
	}
	jp := latencyNodeOf(t, plan, "node-jp")
	paused, _ := st.Monitor(latencyMonitorID("node-jp"))
	if jp.Target != model.LatencyTargetNone || jp.TargetReason != model.LatencyReasonExcluded || jp.MonitorID == "" || paused.Enabled {
		t.Fatalf("excluded target = %+v monitor %+v", jp, paused)
	}
	if rows, _ := st.MonitorPairResults(paused.ID, "node-sh", 0); len(rows) != 1 {
		t.Fatalf("excluding a target dropped its history: %d rows", len(rows))
	}
	if len(st.MonitorsForNode("node-sh")) != 1 {
		t.Fatal("the paused monitor still reaches the source")
	}

	events := st.AuditEvents()
	saves, syncs := 0, 0
	for _, ev := range events {
		switch ev.Action {
		case "monitor.latency.config":
			saves++
			if ev.ActorID == "" || ev.Metadata["version"] == "" {
				t.Fatalf("config audit = %+v", ev)
			}
		case "monitor.latency.sync":
			syncs++
		case "monitor.result":
			t.Fatalf("a probe result was audited: %+v", ev)
		}
	}
	if saves != 2 || syncs < 2 {
		t.Fatalf("audit rows: %d saves, %d syncs", saves, syncs)
	}
}

// Only an unrestricted monitor:admin may save; monitor:read may read; a
// node-confined reader sees only its nodes.
func TestLatencyConfigScopes(t *testing.T) {
	srv, handler, _ := latencyFleet(t)
	cookies, csrf := loginSession(t, handler)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	reader := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, nil)
	confined := createPAT(t, handler, cookies, csrf, []string{"monitor:read", "monitor:admin"}, []string{"node-sh", "node-jp"})

	if res := doBearerJSON(t, handler, http.MethodPut, "/api/monitors/latency", `{"enabled":true}`, reader); res.StatusCode != http.StatusForbidden {
		t.Fatalf("monitor:read saved: %d", res.StatusCode)
	}
	if res := doBearerJSON(t, handler, http.MethodPut, "/api/monitors/latency", `{"enabled":true}`, confined); res.StatusCode != http.StatusForbidden {
		t.Fatalf("a node-confined admin saved fleet-wide probes: %d", res.StatusCode)
	}
	res := doBearerJSON(t, handler, http.MethodGet, "/api/monitors/latency", "", confined)
	defer res.Body.Close()
	var plan model.LatencyProbePlan
	if err := json.NewDecoder(res.Body).Decode(&plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Nodes) != 2 || len(plan.Pairs) != 1 || plan.Pairs[0].Target != "node-jp" {
		t.Fatalf("confined plan = %+v", plan)
	}
}

// A generated monitor is changed only through its configuration, and a
// client cannot forge one.
func TestLatencyMonitorsCannotBeDeletedOrForged(t *testing.T) {
	srv, handler, st := latencyFleet(t)
	cookies, csrf := loginSession(t, handler)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/monitors/delete", `{"id":"`+latencyMonitorID("node-jp")+`"}`, cookies, csrf)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("delete of a generated monitor = %d", res.StatusCode)
	}
	if _, ok := st.Monitor(latencyMonitorID("node-jp")); !ok {
		t.Fatal("the generated monitor was deleted")
	}
	res = doJSON(t, handler, http.MethodPost, "/api/monitors", `{"name":"x","type":"tcp","target":"a:1","assign_all":true,"managed_by":"latency"}`, cookies, csrf)
	defer res.Body.Close()
	var mon model.Monitor
	if err := json.NewDecoder(res.Body).Decode(&mon); err != nil {
		t.Fatal(err)
	}
	if stored, _ := st.Monitor(mon.ID); stored.ManagedBy != "" {
		t.Fatalf("a client marked its monitor as generated: %+v", stored)
	}

	// The list says which monitors are generated, so the console can keep
	// them out of the operator's list and its failing count.
	list := doJSON(t, handler, http.MethodGet, "/api/monitors", "", cookies, "")
	defer list.Body.Close()
	var views []map[string]any
	if err := json.NewDecoder(list.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	marked := map[string]any{}
	for _, view := range views {
		marked[view["id"].(string)] = view["managed_by"]
	}
	if marked[latencyMonitorID("node-jp")] != model.MonitorManagedLatency || marked[mon.ID] != nil {
		t.Fatalf("managed_by on the monitor list = %v", marked)
	}
}

// A latency pair failing twice does not page: degradation is judged on the
// rollups by the incident path, not result by result.
func TestLatencyProbeFailuresDoNotPage(t *testing.T) {
	srv, _, st := latencyFleet(t)
	sent := captureTypedNotices(srv)
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	monitorID := latencyMonitorID("node-jp")
	base := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 3; i++ {
		resp, err := srv.ingestAgentMonitorResults("node-sh", []model.MonitorResult{{MonitorID: monitorID, At: base.Add(time.Duration(i) * time.Second), Success: false, Error: "i/o timeout"}})
		if err != nil || resp.Accepted != 1 {
			t.Fatalf("ingest = %+v %v", resp, err)
		}
	}
	if got := flushTake(srv, sent); len(got) != 0 {
		t.Fatalf("latency failures paged: %+v", got)
	}
	if latest, _, _ := st.MonitorLatest(monitorID, "node-sh"); latest.FailStreak != 3 {
		t.Fatalf("the failures were not stored: %+v", latest)
	}
}

// The plan refuses a port the node's sshd reports, even when a line claims
// it, and a target left with only such a port is not probeable.
func TestLatencyPlanRefusesTheSSHPortGuardRealityReports(t *testing.T) {
	srv, _, st := latencyFleet(t)
	node, _ := st.Node("node-jp")
	node.LatticeIdentityUUID = "4b6f6a1e-6a55-4d6b-9a3e-2f1c0b7d9e10"
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, _, err := st.UpsertGuardRealitySnapshot(node.LatticeIdentityUUID, store.GuardRealitySnapshot{
		Reality:    model.GuardNodeReality{NodeID: "node-jp", CollectedAt: now, SSHD: &model.GuardSSHDFacts{Ports: []int{2222}, ObservedAt: now}},
		ReceivedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv["node-jp"] = model.SingBoxInventory{NodeID: "node-jp", At: now, Status: "ok", Nodes: []model.SingBoxNode{
		{Name: "aaa-on-ssh", Protocol: "vless", Network: "reality", Port: "2222", Address: "203.0.113.3", PortBound: boolPtr(true)},
		{Name: "vless-reality-8443", Protocol: "vless", Network: "reality", Port: "8443", Address: "203.0.113.3"},
	}}
	srv.singboxInvMu.Unlock()
	if jp := latencyNodeOf(t, srv.planLatencyProbes(now).plan, "node-jp"); jp.Endpoint != "203.0.113.3:8443" {
		t.Fatalf("a held line on the sshd port won over a public line: %+v", jp)
	}
	srv.singboxInvMu.Lock()
	inv := srv.singboxInv["node-jp"]
	inv.Nodes = inv.Nodes[:1]
	srv.singboxInv["node-jp"] = inv
	srv.singboxInvMu.Unlock()
	if jp := latencyNodeOf(t, srv.planLatencyProbes(now).plan, "node-jp"); jp.Target != model.LatencyTargetNotProbeable || jp.EndpointNote != model.LatencyEndpointNoLine {
		t.Fatalf("a target with only its sshd port = %+v", jp)
	}
}

// Close stops the latency sweep: Close returns with the loop gone, and no
// sync runs afterwards, so none writes the store or the audit log after
// shutdown.
func TestLatencyProbeSyncStopsOnClose(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	var syncs atomic.Int64
	srv.runLatencyProbeSync(time.Millisecond, func() { syncs.Add(1) })
	deadline := time.Now().Add(5 * time.Second)
	for syncs.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the sweep never ran")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("Close waited out its deadline instead of stopping the sweep")
	}
	stopped := syncs.Load()
	time.Sleep(50 * time.Millisecond)
	if got := syncs.Load(); got != stopped {
		t.Fatalf("the sweep ran %d more times after Close", got-stopped)
	}
}
