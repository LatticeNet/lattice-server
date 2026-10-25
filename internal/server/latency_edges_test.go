package server

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// edgeResolver answers edge name lookups from a table and counts them.
type edgeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	failing map[string]bool
	calls   int
}

func fakeEdgeResolver(answers map[string][]string) *edgeResolver {
	return &edgeResolver{answers: answers, failing: map[string]bool{}}
}

func (r *edgeResolver) set(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = addrs
	delete(r.failing, host)
}

func (r *edgeResolver) fail(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failing[host] = true
}

func (r *edgeResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *edgeResolver) lookup(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.failing[host] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	}
	addrs, ok := r.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

func ipAddrs(raw ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(raw))
	for _, a := range raw {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out
}

// A name is dialled only when every address it has is public; one internal
// address, IPv4 or IPv6, refuses it whole.
func TestLatencyEdgePublicAddrs(t *testing.T) {
	cases := []struct {
		name string
		ips  []net.IPAddr
		want []string
	}{
		{"public IPv4, sorted and deduplicated", ipAddrs("203.0.113.50", "203.0.113.40", "203.0.113.50"), []string{"203.0.113.40", "203.0.113.50"}},
		{"public IPv4 beside a public IPv6", ipAddrs("203.0.113.50", "2606:4700::1111"), []string{"203.0.113.50"}},
		{"one private IPv4", ipAddrs("203.0.113.50", "10.0.0.5"), nil},
		{"loopback", ipAddrs("127.0.0.1"), nil},
		{"CGNAT", ipAddrs("100.64.1.2"), nil},
		{"fake-ip answer", ipAddrs("198.18.0.7"), nil},
		{"link-local", ipAddrs("169.254.169.254"), nil},
		{"IPv6 loopback beside a public IPv4", ipAddrs("203.0.113.50", "::1"), nil},
		{"IPv6 unique local beside a public IPv4", ipAddrs("203.0.113.50", "fd00::5"), nil},
		{"IPv4-mapped private", ipAddrs("::ffff:192.168.1.1"), nil},
		{"public IPv6 only (probes dial IPv4)", ipAddrs("2606:4700::1111"), nil},
		{"no addresses", nil, nil},
	}
	for _, tc := range cases {
		if got := latencyEdgePublicAddrs(tc.ips); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A failed lookup keeps the last good answer for latencyEdgeStale, then the
// name is dropped; a name nobody declares any more is dropped at once.
func TestLatencyEdgeCacheKeepsTheLastGoodAnswerForAWhile(t *testing.T) {
	r := fakeEdgeResolver(map[string][]string{"edge.example.net": {"203.0.113.50"}, "other.example.net": {"203.0.113.60"}})
	c := &latencyEdgeCache{lookup: r.lookup}
	t0 := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	c.refresh([]string{"Edge.Example.Net", "other.example.net"}, t0)
	if got, asked := c.snapshot(); !asked["edge.example.net"] || !slices.Equal(got["edge.example.net"], []string{"203.0.113.50"}) || len(got) != 2 {
		t.Fatalf("first refresh = %v", got)
	}
	r.fail("edge.example.net")
	c.refresh([]string{"edge.example.net"}, t0.Add(latencyEdgeStale-time.Minute))
	got, _ := c.snapshot()
	if !slices.Equal(got["edge.example.net"], []string{"203.0.113.50"}) {
		t.Fatalf("a failed lookup dropped a fresh answer: %v", got)
	}
	if _, ok := got["other.example.net"]; ok {
		t.Fatalf("a name no inventory declares was kept: %v", got)
	}
	c.refresh([]string{"edge.example.net"}, t0.Add(latencyEdgeStale+time.Minute))
	if got, _ := c.snapshot(); len(got) != 0 {
		t.Fatalf("an answer older than latencyEdgeStale was kept: %v", got)
	}
}

// The probe of a NAT node dials the address the control plane resolved its
// edge name to, never the name, and stops dialling as soon as the name
// resolves to an internal address. Planning for a console read resolves
// nothing.
func TestLatencyEdgeNamesAreResolvedByTheControlPlane(t *testing.T) {
	srv, _, st := latencyFleet(t)
	r := fakeEdgeResolver(map[string][]string{"edge.example.net": {"203.0.113.50", "203.0.113.40"}})
	srv.latencyEdges.lookup = r.lookup
	monitorID := latencyMonitorID("node-us")
	probing := func(want string) {
		t.Helper()
		mon, ok := st.Monitor(monitorID)
		if !ok || !mon.Enabled || mon.Target != want || !slices.Equal(mon.NodeIDs, []string{"node-sh"}) {
			t.Fatalf("monitor = %+v, want %s probed from node-sh", mon, want)
		}
	}
	notDialled := func() {
		t.Helper()
		us := latencyNodeOf(t, srv.planLatencyProbes(time.Now()).plan, "node-us")
		if us.Target != model.LatencyTargetNotProbeable || us.EndpointNote != model.LatencyEndpointNoAddress {
			t.Fatalf("us = %+v, want not probeable with no_address", us)
		}
		if mon, _ := st.Monitor(monitorID); mon.Enabled {
			t.Fatalf("the probe still runs: %+v", mon)
		}
		for _, mon := range st.MonitorsForNode("node-sh") {
			if mon.ID == monitorID {
				t.Fatal("the source still receives the probe")
			}
		}
	}

	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	probing("203.0.113.40:50100")

	calls := r.count()
	srv.planLatencyProbes(time.Now())
	if r.count() != calls {
		t.Fatal("a plan for a read resolved a name")
	}

	r.set("edge.example.net", "203.0.113.50", "203.0.113.30", "203.0.113.40")
	if _, changes, _ := srv.syncLatencyProbes(time.Now()); changes.Changed() {
		t.Fatalf("a new record moved a probe whose address still resolves: %+v", changes)
	}
	r.fail("edge.example.net")
	if _, changes, _ := srv.syncLatencyProbes(time.Now()); changes.Changed() {
		t.Fatalf("a DNS failure paused the probe: %+v", changes)
	}
	probing("203.0.113.40:50100")

	r.set("edge.example.net", "10.0.0.5")
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	notDialled()

	r.set("edge.example.net", "203.0.113.40")
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	probing("203.0.113.40:50100")
	r.set("edge.example.net", "203.0.113.40", "127.0.0.1")
	if _, _, err := srv.syncLatencyProbes(time.Now()); err != nil {
		t.Fatal(err)
	}
	notDialled()
}

// A stored target that is a host name (one a build before the edge rule
// wrote) is not kept as the last known endpoint of an offline node.
func TestLatencyLastKnownEndpointMustBeAnAddress(t *testing.T) {
	srv, _, st := latencyFleet(t)
	now := time.Now().UTC()
	if _, err := st.SyncManagedMonitors(model.MonitorManagedLatency, []model.Monitor{{
		ID: latencyMonitorID("node-us"), Name: "Latency to us-nat", Type: model.MonitorTypeTCP,
		Target: "edge.example.net:50100", IntervalSec: 60, TimeoutSec: 5,
		NodeIDs: []string{"node-sh"}, Enabled: true, ManagedBy: model.MonitorManagedLatency,
	}}, now); err != nil {
		t.Fatal(err)
	}
	srv.removeSingBoxInventory("node-us")
	us := latencyNodeOf(t, srv.planLatencyProbes(now).plan, "node-us")
	if us.Target != model.LatencyTargetNotProbeable || us.EndpointNote != model.LatencyEndpointNoInventory {
		t.Fatalf("us = %+v, want not probeable with no_inventory", us)
	}
	if !latencyDialableTarget("203.0.113.3:443") || latencyDialableTarget("edge.example.net:50100") ||
		latencyDialableTarget("10.0.0.1:443") || latencyDialableTarget("203.0.113.3") {
		t.Fatal("latencyDialableTarget misjudged a target")
	}
}

// KI-34: only the sweep resolves edge names, and its first run waits one
// interval after a start, while agents report their inventories again within
// seconds. Until a sweep has looked up a node's edge name, a node whose lines
// sit behind it keeps the endpoint its checks dialled (an operator check that
// names the node, a check definition, an agent's pull) instead of reading as
// nothing to dial; once a sweep has looked the name up, the node is judged by
// the inventory and the edge's answer again.
func TestEdgeHostedEndpointStandsUntilASweepLooksUpTheEdge(t *testing.T) {
	srv, _, _ := latencyFleet(t)
	r := fakeEdgeResolver(map[string][]string{"edge.example.net": {"203.0.113.50"}})
	resolve := func(prior string) (string, string) {
		t.Helper()
		srv.monitorPaths.notePlan(latencyPlan{}, time.Time{})
		return srv.monitorTargetsAt(srv.now()).resolve(model.MonitorTypeTCP, "node-us", prior)
	}
	sweep := func() {
		t.Helper()
		if _, _, err := srv.syncLatencyProbes(srv.now()); err != nil {
			t.Fatal(err)
		}
	}
	setEdge := func(edge string) {
		srv.singboxInvMu.Lock()
		inv := srv.singboxInv["node-us"]
		inv.ProviderEdge, inv.At = edge, srv.now()
		srv.singboxInv["node-us"] = inv
		srv.singboxInvMu.Unlock()
	}

	// A start: nothing looked up yet, and node-us has reported its lines.
	srv.latencyEdges = latencyEdgeCache{lookup: r.lookup}
	if target, reason := resolve("203.0.113.50:50100"); target != "203.0.113.50:50100" || reason != "" {
		t.Fatalf("before the first sweep = %q %q, want the last known endpoint", target, reason)
	}
	r.set("edge.example.net", "203.0.113.51")
	sweep()
	if target, reason := resolve("203.0.113.50:50100"); target != "203.0.113.51:50100" || reason != "" {
		t.Fatalf("after the first sweep = %q %q, want the edge's new address", target, reason)
	}

	// A name no sweep has looked up yet (here a changed edge; equally an
	// agent that reports after the first sweep) waits for the next sweep.
	r.set("edge2.example.net", "203.0.113.52")
	setEdge("edge2.example.net")
	if target, reason := resolve("203.0.113.51:50100"); target != "203.0.113.51:50100" || reason != "" {
		t.Fatalf("a name not looked up yet = %q %q, want the last known endpoint", target, reason)
	}
	sweep()
	if target, reason := resolve("203.0.113.51:50100"); target != "203.0.113.52:50100" || reason != "" {
		t.Fatalf("after the sweep looked it up = %q %q, want its address", target, reason)
	}

	// A sweep that looks the name up and fails: the node is judged as
	// before, with nothing to dial, so a lasting DNS failure pins nothing.
	r.fail("edge2.example.net")
	srv.latencyEdges = latencyEdgeCache{lookup: r.lookup}
	sweep()
	if target, reason := resolve("203.0.113.52:50100"); target != "" || reason == "" {
		t.Fatalf("after a failed lookup = %q %q, want nothing to dial", target, reason)
	}
}

// An edge with no line published on it (no public port) never needed a
// lookup: such a node plans from its own address before any sweep.
func TestEdgeWithoutPublishedLinesIsNotPending(t *testing.T) {
	inv := model.SingBoxInventory{ProviderEdge: "edge.example.net", Nodes: []model.SingBoxNode{
		{Name: "vless-443", Protocol: "vless", Network: "reality", Port: "443"},
	}}
	if latencyEdgePending(inv, nil) {
		t.Fatal("an edge with no published line is pending")
	}
	inv.Nodes = append(inv.Nodes, model.SingBoxNode{Name: "trojan", Protocol: "trojan", Port: "488", PublicPort: "50100"})
	if !latencyEdgePending(inv, nil) || latencyEdgePending(inv, map[string]bool{"edge.example.net": true}) {
		t.Fatal("pending misjudged a published edge line")
	}
	if inv.ProviderEdge = "203.0.113.50"; latencyEdgePending(inv, nil) {
		t.Fatal("an address edge needs no lookup")
	}
}
