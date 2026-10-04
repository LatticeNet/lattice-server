package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/netguard"
)

// ephemeralTestInventory is a sing-box node with a TCP line, a hysteria2 line
// on 50000 (a real UDP service inside the ephemeral range), and a NAT line
// published at 50100.
func ephemeralTestInventory(at time.Time) model.SingBoxInventory {
	return model.SingBoxInventory{
		NodeID: "node-a",
		At:     at,
		Status: "ok",
		Nodes: []model.SingBoxNode{
			{Name: "vless-443", Protocol: "vless", Port: "443"},
			{Name: "hy2-50000", Protocol: "hysteria2", Port: "50000"},
			{Name: "nat-488", Protocol: "vless", Port: "488", PublicPort: "50100"},
		},
	}
}

func setTestInventory(srv *Server, inv *model.SingBoxInventory) {
	srv.singboxInvMu.Lock()
	defer srv.singboxInvMu.Unlock()
	srv.singboxInv = map[string]model.SingBoxInventory{}
	if inv != nil {
		srv.singboxInv[inv.NodeID] = *inv
	}
}

func singBoxUDP(port int) model.GuardListener {
	return model.GuardListener{Protocol: "udp", Port: port, Address: "::", Process: "sing-box"}
}

func TestSplitEphemeralSocketsRule(t *testing.T) {
	now := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	srv, _, st, _, _ := newGuardRealityServerForTest(t, newGuardRealityTestClock(now))
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "Node A"}); err != nil {
		t.Fatal(err)
	}

	client := []model.GuardListener{
		singBoxUDP(46779),
		singBoxUDP(32768), // first port of the range
		singBoxUDP(60999), // last port of the range
	}
	facts := []model.GuardListener{
		{Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "sshd"},
		singBoxUDP(32767), // below the range
		singBoxUDP(61000), // above the range
		singBoxUDP(50000), // the hysteria2 inbound
		singBoxUDP(50100), // a line's public port
		{Protocol: "tcp", Port: 46780, Address: "::", Process: "sing-box"},
		{Protocol: "udp", Port: 46781, Address: "::", Process: "xray"},
		{Protocol: "udp", Port: 51820, Address: "0.0.0.0"}, // kernel WireGuard: no process
		{Protocol: "udp", Port: 41641, Address: "::", Process: "tailscaled"},
	}
	report := append(append([]model.GuardListener(nil), facts...), client...)

	inv := ephemeralTestInventory(now)
	setTestInventory(srv, &inv)
	gotFacts, gotClient := srv.splitEphemeralSockets("node-a", report, now)
	if !reflect.DeepEqual(gotFacts, facts) || !reflect.DeepEqual(gotClient, client) {
		t.Fatalf("split:\n facts  %+v\n client %+v\nwant\n facts  %+v\n client %+v", gotFacts, gotClient, facts, client)
	}

	// Every case where the server cannot vouch for the node's inbounds keeps
	// every socket a fact.
	stale := ephemeralTestInventory(now.Add(-nodeOfflineThreshold - time.Second))
	failed := ephemeralTestInventory(now)
	failed.Status, failed.Nodes = "error", []model.SingBoxNode{}
	ranged := ephemeralTestInventory(now)
	ranged.Nodes = append(ranged.Nodes, model.SingBoxNode{Name: "hop", Protocol: "hysteria2", Port: "40000-40100"})
	portless := ephemeralTestInventory(now)
	portless.Nodes = append(portless.Nodes, model.SingBoxNode{Name: "no-port", Protocol: "tuic"})
	for name, inv := range map[string]*model.SingBoxInventory{
		"no inventory":        nil,
		"stale inventory":     &stale,
		"failed discovery":    &failed,
		"a port range":        &ranged,
		"a line with no port": &portless,
	} {
		setTestInventory(srv, inv)
		gotFacts, gotClient := srv.splitEphemeralSockets("node-a", report, now)
		if gotClient != nil || !reflect.DeepEqual(gotFacts, report) {
			t.Fatalf("%s: split off %+v, want every socket kept as a fact", name, gotClient)
		}
	}

	// An inbound the central proxy model renders onto the node is an inbound
	// even when on-box discovery does not list it.
	if err := st.UpsertProxyInbound(model.ProxyInbound{ID: "in-tuic", Name: "tuic", Core: model.ProxyCoreSingbox, Protocol: "tuic", Port: 46779}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProxyNodeProfile(model.ProxyNodeProfile{NodeID: "node-a", Core: model.ProxyCoreSingbox, InboundIDs: []string{"in-tuic"}}); err != nil {
		t.Fatal(err)
	}
	inv = ephemeralTestInventory(now)
	setTestInventory(srv, &inv)
	gotFacts, gotClient = srv.splitEphemeralSockets("node-a", report, now)
	if len(gotClient) != 2 || !reflect.DeepEqual(gotFacts[len(gotFacts)-1], singBoxUDP(46779)) {
		t.Fatalf("a rendered inbound on 46779: facts %+v client %+v", gotFacts, gotClient)
	}
}

// ephemeralTestReporter drives one agent through the guard reality and
// inventory routes on a clock the test moves.
type ephemeralTestReporter struct {
	t       *testing.T
	handler http.Handler
	token   string
	clock   *guardRealityTestClock
	at      time.Time
}

func (r *ephemeralTestReporter) report(listeners []model.GuardListener) {
	r.t.Helper()
	r.at = r.at.Add(10 * time.Second)
	r.clock.Set(r.at)
	inv, err := json.Marshal(map[string]any{"node_id": "node-a", "inventory": ephemeralTestInventory(r.at)})
	if err != nil {
		r.t.Fatal(err)
	}
	if rec := doAgentRaw(r.t, r.handler, http.MethodPost, "/api/agent/singbox-inventory", string(inv), r.token); rec.Code != http.StatusOK {
		r.t.Fatalf("inventory: %d %s", rec.Code, rec.Body.String())
	}
	reality := model.GuardNodeReality{
		NodeID:      "node-a",
		Listeners:   listeners,
		Interfaces:  []model.GuardInterface{{Name: "eth0", Addresses: []string{"203.0.113.10/24"}, Up: true}},
		NFTVersion:  "nftables v1.0.9",
		CollectedAt: r.at,
	}
	if res := postGuardRealityForTest(r.t, r.handler, r.token, "node-a", reality); res.code != http.StatusOK {
		r.t.Fatalf("guard reality: %d %s", res.code, res.body)
	}
}

// churningClientSockets is three sing-box client sockets whose ports move
// with every report, as production's did.
func churningClientSockets(i int) []model.GuardListener {
	return []model.GuardListener{
		singBoxUDP(32768 + (i*7919)%28000),
		singBoxUDP(32768 + (i*7919+9001)%28000),
		singBoxUDP(32768 + (i*7919+18002)%28000),
	}
}

func withSockets(listeners []model.GuardListener, more ...model.GuardListener) []model.GuardListener {
	return append(append([]model.GuardListener(nil), listeners...), more...)
}

func TestEphemeralClientSocketChurnDoesNotWriteState(t *testing.T) {
	f := openIngestFixture(t, t.TempDir())
	defer f.st.Close()
	clock := newGuardRealityTestClock(time.Now().UTC().Truncate(time.Second))
	f.srv.now = clock.Now
	cookies, csrf := loginSession(t, f.handler)
	token := enrollNamedNodeToken(t, f.handler, cookies, csrf, "node-a", "Node A")
	if rec := doAgentRaw(t, f.handler, http.MethodPost, "/api/agent/hello", `{"node_id":"node-a","version":"0.3.10"}`, token); rec.Code != http.StatusOK {
		t.Fatalf("hello: %d %s", rec.Code, rec.Body.String())
	}
	r := &ephemeralTestReporter{t: t, handler: f.handler, token: token, clock: clock, at: clock.Now()}
	services := []model.GuardListener{
		{Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "sshd"},
		{Protocol: "tcp", Port: 443, Address: "::", Process: "sing-box"},
	}
	r.report(withSockets(services, churningClientSockets(0)...))

	writes := watchStateFile(t, f.statePath())
	for i := 1; i <= 30; i++ {
		sockets := churningClientSockets(i)
		if i%5 == 0 {
			sockets = nil // the core closed every client socket
		}
		r.report(withSockets(services, sockets...))
		writes.check()
	}
	if n := writes.take(); n != 0 {
		t.Fatalf("30 reports that moved only sing-box client sockets rewrote state %d times, want 0", n)
	}

	// Real changes still write at once.
	steps := []struct {
		name      string
		listeners []model.GuardListener
	}{
		{"a new listener", withSockets(services, model.GuardListener{Protocol: "tcp", Port: 8080, Address: "0.0.0.0", Process: "nginx"})},
		{"the hysteria2 inbound starts", withSockets(services, model.GuardListener{Protocol: "tcp", Port: 8080, Address: "0.0.0.0", Process: "nginx"}, singBoxUDP(50000))},
		{"the hysteria2 inbound stops", withSockets(services, model.GuardListener{Protocol: "tcp", Port: 8080, Address: "0.0.0.0", Process: "nginx"})},
		{"a UDP service in the range that is not sing-box", withSockets(services, model.GuardListener{Protocol: "tcp", Port: 8080, Address: "0.0.0.0", Process: "nginx"}, model.GuardListener{Protocol: "udp", Port: 41641, Address: "::", Process: "tailscaled"})},
	}
	for i, step := range steps {
		r.report(withSockets(step.listeners, churningClientSockets(100+i)...))
		if n := writes.take(); n != 1 {
			t.Fatalf("%s rewrote state %d times, want 1", step.name, n)
		}
	}
}

// The detail and the roster are what the console and the NetGuard plugin
// read: the plugin's open and unexplained ports come from reality.listeners.
// Real listeners are all there, the hysteria2 inbound inside the range among
// them, and the client sockets are listed beside them rather than dropped.
// The review's suggestions, the server's own exposure check, agree.
func TestRealityAPIServesEphemeralSocketsBesideListeners(t *testing.T) {
	clock := newGuardRealityTestClock(time.Now().UTC().Truncate(time.Second))
	_, handler, _, cookies, csrf := newGuardRealityServerForTest(t, clock)
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	r := &ephemeralTestReporter{t: t, handler: handler, token: token, clock: clock, at: clock.Now()}
	services := []model.GuardListener{
		{Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "sshd"},
		{Protocol: "tcp", Port: 443, Address: "::", Process: "sing-box"},
		singBoxUDP(50000),
	}
	client := []model.GuardListener{singBoxUDP(39727), singBoxUDP(56107)}
	r.report(withSockets(services, client...))

	res := doJSON(t, handler, http.MethodGet, "/api/netguard/reality?node_id=node-a", "", cookies, csrf)
	defer res.Body.Close()
	var detail struct {
		Node struct {
			Reality          *model.GuardNodeReality `json:"reality"`
			EphemeralSockets []model.GuardListener   `json:"ephemeral_sockets"`
		} `json:"node"`
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("detail: %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Node.Reality == nil {
		t.Fatal("detail has no reality")
	}
	wantListeners := []model.GuardListener{services[0], services[1], services[2]}
	if !reflect.DeepEqual(detail.Node.Reality.Listeners, wantListeners) {
		t.Fatalf("reality.listeners = %+v, want the services %+v", detail.Node.Reality.Listeners, wantListeners)
	}
	if !reflect.DeepEqual(detail.Node.EphemeralSockets, client) {
		t.Fatalf("ephemeral_sockets = %+v, want %+v", detail.Node.EphemeralSockets, client)
	}

	roster := doJSON(t, handler, http.MethodGet, "/api/netguard/reality", "", cookies, csrf)
	defer roster.Body.Close()
	var list struct {
		Nodes []struct {
			NodeID               string `json:"node_id"`
			ListenerCount        *int   `json:"listener_count"`
			EphemeralSocketCount *int   `json:"ephemeral_socket_count"`
		} `json:"nodes"`
	}
	if err := json.NewDecoder(roster.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Nodes) != 1 || list.Nodes[0].ListenerCount == nil || *list.Nodes[0].ListenerCount != 3 ||
		list.Nodes[0].EphemeralSocketCount == nil || *list.Nodes[0].EphemeralSocketCount != 2 {
		t.Fatalf("roster = %+v, want 3 listeners and 2 ephemeral sockets", list.Nodes)
	}

	review := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=node-a", "", cookies, csrf)
	defer review.Body.Close()
	var out netGuardReviewResponse
	if err := json.NewDecoder(review.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	missing := map[string]bool{}
	for _, s := range out.Review.Suggestions {
		if s.Code == netguard.SuggestionListenerMissingAllow {
			missing[fmt.Sprintf("%s/%d", s.Protocol, s.Port)] = true
		}
	}
	want := map[string]bool{"tcp/22": true, "tcp/443": true, "udp/50000": true}
	if !reflect.DeepEqual(missing, want) {
		t.Fatalf("listeners missing an allow = %v, want %v", missing, want)
	}
}

// observeEvery feeds the tracker one report every ten seconds from start to
// end, each listing sockets(at), and returns what came due and when.
func observeEvery(tr *ephemeralSocketTracker, start, end time.Time, sockets func(at time.Time) []model.GuardListener) (due []persistentEphemeralSocket, at []time.Time) {
	for now := start; !now.After(end); now = now.Add(10 * time.Second) {
		for _, d := range tr.observe("node-a", sockets(now), now) {
			due = append(due, d)
			at = append(at, now)
		}
	}
	return due, at
}

func TestEphemeralSocketTrackerAuditsOncePerEpisode(t *testing.T) {
	t0 := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	persistent := singBoxUDP(45678)
	churn := func(at time.Time) []model.GuardListener {
		return churningClientSockets(int(at.Sub(t0) / (10 * time.Second)))
	}

	t.Run("a socket bound past the threshold audits once", func(t *testing.T) {
		var tr ephemeralSocketTracker
		due, at := observeEvery(&tr, t0, t0.Add(2*time.Hour), func(now time.Time) []model.GuardListener {
			return withSockets(churn(now), persistent)
		})
		if len(due) != 1 || due[0].socket != persistent || !due[0].firstSeen.Equal(t0) || !at[0].Equal(t0.Add(ephemeralPersistAfter)) {
			t.Fatalf("due = %+v at %v, want one audit of %+v at %s", due, at, persistent, t0.Add(ephemeralPersistAfter))
		}
	})

	t.Run("churning sockets never audit", func(t *testing.T) {
		var tr ephemeralSocketTracker
		if due, _ := observeEvery(&tr, t0, t0.Add(4*time.Hour), churn); len(due) != 0 {
			t.Fatalf("churn came due: %+v", due)
		}
	})

	t.Run("a gap starts a new episode", func(t *testing.T) {
		var tr ephemeralSocketTracker
		gapAt := t0.Add(20 * time.Minute)
		backAt := gapAt.Add(10 * time.Second)
		closedAt := backAt.Add(ephemeralPersistAfter + 5*time.Minute)
		reopenAt := closedAt.Add(10 * time.Second)
		due, at := observeEvery(&tr, t0, reopenAt.Add(ephemeralPersistAfter), func(now time.Time) []model.GuardListener {
			if now.Equal(gapAt) || now.Equal(closedAt) {
				return churn(now)
			}
			return withSockets(churn(now), persistent)
		})
		want := []time.Time{backAt.Add(ephemeralPersistAfter), reopenAt.Add(ephemeralPersistAfter)}
		if !reflect.DeepEqual(at, want) || !due[0].firstSeen.Equal(backAt) || !due[1].firstSeen.Equal(reopenAt) {
			t.Fatalf("due at %v (%+v), want %v", at, due, want)
		}
	})

	t.Run("a report that reads the socket as a fact ends the episode", func(t *testing.T) {
		var tr ephemeralSocketTracker
		tr.observe("node-a", []model.GuardListener{persistent}, t0)
		tr.observe("node-a", nil, t0.Add(10*time.Second))
		if due := tr.observe("node-a", []model.GuardListener{persistent}, t0.Add(ephemeralPersistAfter)); len(due) != 0 {
			t.Fatalf("an interrupted episode came due: %+v", due)
		}
	})

	t.Run("the cap holds and keeps followed sockets", func(t *testing.T) {
		var tr ephemeralSocketTracker
		var first []model.GuardListener
		for port := 40000; port < 40000+ephemeralTrackCap; port++ {
			first = append(first, singBoxUDP(port))
		}
		tr.observe("node-a", first, t0)
		// 100 new sockets sort ahead of the followed ones.
		var burst []model.GuardListener
		for port := 33000; port < 33100; port++ {
			burst = append(burst, singBoxUDP(port))
		}
		tr.observe("node-a", append(burst, first...), t0.Add(10*time.Second))
		nodes := tr.nodes["node-a"]
		if len(nodes) != ephemeralTrackCap {
			t.Fatalf("followed %d sockets, want the cap %d", len(nodes), ephemeralTrackCap)
		}
		if _, ok := nodes[ephemeralSocketKey{protocol: "udp", port: 33000, address: "::"}]; ok {
			t.Fatal("a new socket took the place of a followed one")
		}
		due := tr.observe("node-a", first, t0.Add(ephemeralPersistAfter))
		if len(due) != ephemeralTrackCap {
			t.Fatalf("%d followed sockets came due, want %d", len(due), ephemeralTrackCap)
		}
	})

	t.Run("node delete forgets", func(t *testing.T) {
		srv, _, _, _, _ := newGuardRealityServerForTest(t, newGuardRealityTestClock(t0))
		srv.ephemeralSockets.observe("node-a", []model.GuardListener{persistent}, t0)
		srv.removeGuardRealityAudit("node-a")
		if due := srv.ephemeralSockets.observe("node-a", []model.GuardListener{persistent}, t0.Add(ephemeralPersistAfter)); len(due) != 0 {
			t.Fatalf("an episode survived node delete: %+v", due)
		}
	})
}

// The persistence audit runs on the production storage layout: one event for
// a client socket that stays bound, none for churn, and no state write from
// the report that records it.
func TestPersistentEphemeralSocketAuditsWithoutWritingState(t *testing.T) {
	f := openIngestFixture(t, t.TempDir())
	defer f.st.Close()
	clock := newGuardRealityTestClock(time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC))
	f.srv.now = clock.Now
	cookies, csrf := loginSession(t, f.handler)
	token := enrollNamedNodeToken(t, f.handler, cookies, csrf, "node-a", "Node A")
	r := &ephemeralTestReporter{t: t, handler: f.handler, token: token, clock: clock, at: clock.Now()}
	services := []model.GuardListener{{Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "sshd"}}
	persistent := singBoxUDP(45678)
	persistentAudits := func() []model.AuditEvent {
		var out []model.AuditEvent
		for _, ev := range f.st.AuditEvents() {
			if ev.Action == auditActionEphemeralSocketPersistent {
				out = append(out, ev)
			}
		}
		return out
	}

	writes := watchStateFile(t, f.statePath())
	var firstSeen time.Time
	auditedAt := -1
	// 45 minutes of reports; the persistent socket binds five minutes in, so
	// its audit lands at 35 minutes, clear of the 15 minute clock flushes.
	for i := 1; i <= 270; i++ {
		sockets := churningClientSockets(i)
		if i >= 30 {
			sockets = append(sockets, persistent)
		}
		r.report(withSockets(services, sockets...))
		if i == 30 {
			firstSeen = r.at
		}
		wrote := writes.check()
		if n := len(persistentAudits()); n == 1 && auditedAt < 0 {
			auditedAt = i
			if wrote {
				t.Fatalf("the report that recorded the audit rewrote state")
			}
		} else if n > 1 {
			t.Fatalf("report %d: %d persistence audits, want 1", i, n)
		}
	}
	if auditedAt != 30+int(ephemeralPersistAfter/(10*time.Second)) {
		t.Fatalf("audit recorded at report %d, want report %d", auditedAt, 30+int(ephemeralPersistAfter/(10*time.Second)))
	}
	ev := persistentAudits()[0]
	want := map[string]string{
		"protocol":   "udp",
		"port":       "45678",
		"address":    "::",
		"process":    "sing-box",
		"first_seen": firstSeen.UTC().Format(time.RFC3339),
	}
	for k, v := range want {
		if ev.Metadata[k] != v {
			t.Fatalf("audit metadata %s = %q, want %q (event %+v)", k, ev.Metadata[k], v, ev)
		}
	}
	if ev.NodeID != "node-a" || ev.Decision != "observe" {
		t.Fatalf("audit = %+v", ev)
	}
}
