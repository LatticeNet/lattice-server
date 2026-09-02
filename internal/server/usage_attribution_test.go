package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The attribution order is fixed: named > credential > binding > substore >
// none, first match wins, and every row says which rule fired and whether it
// proves or infers.
func TestUsageAttributionOrder(t *testing.T) {
	ctx := &usageAttributionContext{nodeName: map[string]string{"n": "N"}, users: map[string]VpnUser{
		"alice": {ID: "alice", Email: "alice@example.com"}, "bob": {ID: "bob", Email: "bob@example.com"}, "carol": {ID: "carol"},
	}}
	line := Line{NodeID: "n", LineHashID: "line_x", Tag: "in-x"}
	inbound := usageCounter{Uplink: 100, Downlink: 200}
	cases := []struct {
		name        string
		facts       *usageLineFacts
		named       map[string]usageCounter
		attribution string
		proof       string
		user        string
		counted     bool
		rows        int
		candidates  []string
	}{
		{name: "named wins and the remainder stays unattributed",
			facts:       &usageLineFacts{Line: line, Named: map[string]string{"u_a": "alice"}, CredentialUser: "bob", Bound: []string{"bob"}},
			named:       map[string]usageCounter{"alice": {Uplink: 40, Downlink: 50}},
			attribution: usageAttributionNamed, proof: usageProofProof, user: "alice", counted: true, rows: 2, candidates: []string{"alice"}},
		{name: "credential beats binding",
			facts:       &usageLineFacts{Line: line, Named: map[string]string{}, CredentialUser: "bob", CredentialReason: "inbound vless uuid is this user's credential", Bound: []string{"alice"}},
			attribution: usageAttributionCredential, proof: usageProofProof, user: "bob", counted: true, rows: 1},
		{name: "single binding is inferred",
			facts:       &usageLineFacts{Line: line, Named: map[string]string{}, Bound: []string{"alice"}, SubStore: []usageSubStoreRef{{RecordID: "r1", IdentityID: "carol"}}},
			attribution: usageAttributionBinding, proof: usageProofInferred, user: "alice", counted: true, rows: 1},
		{name: "two bindings fall through to substore",
			facts:       &usageLineFacts{Line: line, Named: map[string]string{}, Bound: []string{"alice", "bob"}, SubStore: []usageSubStoreRef{{RecordID: "r1", IdentityID: "carol"}}},
			attribution: usageAttributionSubstore, proof: usageProofInferred, user: "carol", counted: false, rows: 1},
		{name: "nothing decides: none with candidates",
			facts:       &usageLineFacts{Line: line, Named: map[string]string{}, Bound: []string{"alice", "bob"}, SubStore: []usageSubStoreRef{{RecordID: "r1", IdentityID: "carol"}, {RecordID: "r2", IdentityID: "bob"}}},
			attribution: usageAttributionNone, proof: "", user: "", counted: false, rows: 1, candidates: []string{"alice", "bob", "carol"}},
		{name: "no line at all is unknown_line, never dropped",
			facts:       nil,
			attribution: usageAttributionUnknownLine, rows: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := ctx.attributeLine("n", "in-x", tc.facts, usageLineTraffic{Inbound: inbound, Named: tc.named})
			if len(rows) != tc.rows {
				t.Fatalf("rows = %d, want %d: %+v", len(rows), tc.rows, rows)
			}
			first := rows[0]
			if first.Attribution != tc.attribution || first.AttributionProof != tc.proof || first.UserID != tc.user || first.Counted != tc.counted {
				t.Fatalf("first row: %+v", first)
			}
			total := usageCounter{}
			for _, row := range rows {
				total.add(usageCounter{Uplink: row.Uplink, Downlink: row.Downlink})
				if row.UsedBytes != row.Uplink+row.Downlink {
					t.Fatalf("used_bytes must stay the sum: %+v", row)
				}
			}
			if total != inbound {
				t.Fatalf("rows must account for every inbound byte: %+v vs %+v", total, inbound)
			}
			last := rows[len(rows)-1]
			if tc.candidates != nil && strings.Join(last.Candidates, ",") != strings.Join(tc.candidates, ",") {
				t.Fatalf("candidates = %v, want %v", last.Candidates, tc.candidates)
			}
			if tc.facts != nil && tc.named != nil && (last.Attribution != usageAttributionNone || last.Counted) {
				t.Fatalf("named remainder must be none and uncounted: %+v", last)
			}
		})
	}
}

func TestUsageLineRoleTable(t *testing.T) {
	cases := []struct {
		source, target, direct bool
		want                   string
	}{
		{false, false, false, usageRoleDirect},
		{false, false, true, usageRoleDirect},
		{true, false, true, usageRoleEntry},
		{true, true, true, usageRoleRelay},
		{false, true, false, usageRoleExit},
		{false, true, true, usageRoleShared},
	}
	for _, tc := range cases {
		if got := usageLineRole(tc.source, tc.target, tc.direct); got != tc.want {
			t.Fatalf("role(source=%v target=%v direct=%v) = %q, want %q", tc.source, tc.target, tc.direct, got, tc.want)
		}
	}
}

// A chain target's bytes beyond the upstream relay counters are the direct
// portion; the rest carries counted_at and is excluded from user totals.
func TestUsageChainExclusionAndEstimate(t *testing.T) {
	ctx := &usageAttributionContext{nodeName: map[string]string{}, users: map[string]VpnUser{"dave": {ID: "dave"}}}
	exit := &usageLineFacts{Line: Line{NodeID: "b", LineHashID: "line_exit", Tag: "exit"}, Role: usageRoleShared, Upstream: []string{"line_hub"}, Named: map[string]string{}, Bound: []string{"dave"}}
	upstream := usageCounter{Uplink: 500, Downlink: 600}
	rows := ctx.attributeLine("b", "exit", exit, usageLineTraffic{Inbound: usageCounter{Uplink: 600, Downlink: 700}, Upstream: &upstream})
	if len(rows) != 2 {
		t.Fatalf("rows: %+v", rows)
	}
	relayed, direct := rows[0], rows[1]
	if relayed.CountedAt != "line_hub" || relayed.Uplink != 500 || relayed.Downlink != 600 || relayed.Counted || relayed.Estimate {
		t.Fatalf("relayed row: %+v", relayed)
	}
	if !direct.Estimate || direct.Uplink != 100 || direct.Downlink != 100 || direct.Attribution != usageAttributionBinding || direct.UserID != "dave" || direct.Counted {
		t.Fatalf("direct estimate row: %+v", direct)
	}
	// Upstream larger than the exit floors the direct portion at zero.
	big := usageCounter{Uplink: 9000, Downlink: 9000}
	rows = ctx.attributeLine("b", "exit", exit, usageLineTraffic{Inbound: usageCounter{Uplink: 600, Downlink: 700}, Upstream: &big})
	if len(rows) != 1 || rows[0].CountedAt != "line_hub" || rows[0].UsedBytes != 1300 {
		t.Fatalf("floored: %+v", rows)
	}
	// Without an aligned upstream (one node's ingestion) everything non-named
	// on a target is relayed and nothing is estimated.
	rows = ctx.attributeLine("b", "exit", exit, usageLineTraffic{Inbound: usageCounter{Uplink: 600, Downlink: 700}})
	if len(rows) != 1 || rows[0].CountedAt != "line_hub" || rows[0].Estimate {
		t.Fatalf("unaligned: %+v", rows)
	}
}

func TestShareURLCredential(t *testing.T) {
	uuid := "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
	vmess := "vmess://" + base64Std(`{"v":"2","ps":"x","add":"h","port":"1","id":"`+uuid+`","aid":"0"}`)
	cases := []struct{ raw, uuid, password string }{
		{"vless://" + uuid + "@203.0.113.5:443?security=reality#hub", uuid, ""},
		{"VLESS://" + strings.ToUpper(uuid) + "@h:1", uuid, ""},
		{"trojan://s3cret@h:443?sni=x#t", "", "s3cret"},
		{"hysteria2://pw%40word@h:8443/?sni=x", "", "pw@word"},
		{"tuic://" + uuid + ":pass@h:443", uuid, "pass"},
		{"ss://" + base64Std("aes-128-gcm:sspass") + "@h:8388#s", "", "sspass"},
		{"ss://" + base64Std("aes-128-gcm:sspass2@h:8388"), "", "sspass2"},
		{vmess, uuid, ""},
		{"socks://user:pw@h:1080", "", "pw"},
		{"not a url", "", ""},
		{"vmess://%%%", "", ""},
	}
	for _, tc := range cases {
		gotUUID, gotPassword := shareURLCredential(tc.raw)
		if gotUUID != tc.uuid || gotPassword != tc.password {
			t.Fatalf("%s: got (%q, %q), want (%q, %q)", tc.raw, gotUUID, gotPassword, tc.uuid, tc.password)
		}
	}
}

func base64Std(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	b := []byte(s)
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		v := uint(chunk[0])<<16 | uint(chunk[1])<<8 | uint(chunk[2])
		out.WriteByte(alphabet[v>>18&63])
		out.WriteByte(alphabet[v>>12&63])
		if n > 1 {
			out.WriteByte(alphabet[v>>6&63])
		} else {
			out.WriteByte('=')
		}
		if n > 2 {
			out.WriteByte(alphabet[v&63])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

// usageFleet is the fixture the end-to-end tests share: node-a with an entry
// line relaying to node-b, a second relay to a shared exit, a direct line
// with one binding, a single-credential line, and node-b with the two chain
// targets. Users: alice named on hub-a, bob bound to direct-a, carol holding
// cred-a's credential, dave bound to shared-b.
type usageFleet struct {
	hub, hub2, direct, cred, exit, shared Line
	alice, bob, carol, dave               VpnUser
	aliceName                             string
}

func seedUsageFleet(t *testing.T, srv *Server) usageFleet {
	t.Helper()
	carolUUID := "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", LatticeIdentityUUID: "node-uuid-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertNode(model.Node{ID: "node-b", Name: "Node B", PublicIP: "198.51.100.9"}); err != nil {
		t.Fatal(err)
	}
	for _, nodeID := range []string{"node-a", "node-b"} {
		if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{ID: "prof-" + nodeID, NodeID: nodeID, Core: "sing-box"}); err != nil {
			t.Fatal(err)
		}
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "hub-a", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "443", OutboundRef: "exit-b", OutboundServer: "198.51.100.9", OutboundPort: "8443"},
			{Name: "hub2-a", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "444", OutboundRef: "shared-b", OutboundServer: "198.51.100.9", OutboundPort: "9443"},
			{Name: "direct-a", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "80", OutboundRef: "direct"},
			{Name: "cred-a", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "8081", OutboundRef: "direct", UserKnown: true, UserCount: 1, ShareURL: "vless://" + carolUUID + "@203.0.113.5:8081?security=reality#cred-a"},
		}},
		"node-b": {NodeID: "node-b", At: srv.now(), Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "exit-b-in", Protocol: "vless", Network: "tcp", Address: "198.51.100.9", Port: "8443", OutboundRef: "direct"},
			{Name: "shared-b", Protocol: "vless", Network: "tcp", Address: "198.51.100.9", Port: "9443", OutboundRef: "direct"},
		}},
	}
	srv.singboxInvMu.Unlock()
	groups := srv.buildLineGroups()
	f := usageFleet{
		hub: findLine(t, groups, "node-a", "hub-a"), hub2: findLine(t, groups, "node-a", "hub2-a"),
		direct: findLine(t, groups, "node-a", "direct-a"), cred: findLine(t, groups, "node-a", "cred-a"),
		exit: findLine(t, groups, "node-b", "exit-b-in"), shared: findLine(t, groups, "node-b", "shared-b"),
	}
	if len(f.hub.JumpEdges) != 1 || f.hub.JumpEdges[0] != f.exit.LineHashID || len(f.hub2.JumpEdges) != 1 || f.hub2.JumpEdges[0] != f.shared.LineHashID {
		t.Fatalf("fixture edges: hub=%v hub2=%v", f.hub.JumpEdges, f.hub2.JumpEdges)
	}
	f.alice = VpnUser{ID: "vpnuser_alice", Email: "alice@example.com", Enabled: true, Credentials: []VpnCredential{{Protocol: "vless", UUID: "1b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}},
		Bindings: []LineBinding{{LineHashID: f.hub.LineHashID, Enabled: true}}}
	f.bob = VpnUser{ID: "vpnuser_bob", Email: "bob@example.com", Enabled: true, Credentials: []VpnCredential{{Protocol: "vless", UUID: "2b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}},
		Bindings: []LineBinding{{LineHashID: f.direct.LineHashID, Enabled: true}}}
	f.carol = VpnUser{ID: "vpnuser_carol", Email: "carol@example.com", Enabled: true, Credentials: []VpnCredential{{Protocol: "vless", UUID: carolUUID}}}
	f.dave = VpnUser{ID: "vpnuser_dave", Email: "dave@example.com", Enabled: true, Credentials: []VpnCredential{{Protocol: "vless", UUID: "4b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}},
		Bindings: []LineBinding{{LineHashID: f.shared.LineHashID, Enabled: true}}}
	for _, u := range []VpnUser{f.alice, f.bob, f.carol, f.dave} {
		if err := srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}
	f.aliceName = userLineName(f.alice.ID, f.hub.LineUUID)
	return f
}

func counter(up, down int64) model.ProxyTrafficCounter {
	return model.ProxyTrafficCounter{Uplink: up, Downlink: down}
}

func mustApplyUsage(t *testing.T, srv *Server, snap model.ProxyUsageSnapshot) proxyUsageApplyResult {
	t.Helper()
	if snap.At.IsZero() {
		snap.At = srv.now()
	}
	result, err := srv.applyProxyUsageSnapshot(snap)
	if err != nil {
		t.Fatalf("apply %s: %v", snap.NodeID, err)
	}
	return result
}

// reportUsageFleet sends the baseline and one delta report for both nodes.
func reportUsageFleet(t *testing.T, srv *Server, f usageFleet) proxyUsageApplyResult {
	t.Helper()
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 100,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(1000, 2000), "hub2-a": counter(100, 100), "direct-a": counter(10, 20), "cred-a": counter(5, 5), "ghost": counter(1, 1)},
		UserTraffic:    map[string]model.ProxyTrafficCounter{f.aliceName: counter(300, 600), "u_unknown1234567": counter(9, 9)},
	})
	result := mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CoreUptimeSec: 200,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(1500, 2600), "hub2-a": counter(200, 300), "direct-a": counter(40, 70), "cred-a": counter(15, 25), "ghost": counter(3, 4)},
		UserTraffic:    map[string]model.ProxyTrafficCounter{f.aliceName: counter(400, 800), "u_unknown1234567": counter(19, 19)},
	})
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-b", CoreUptimeSec: 50,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"exit-b-in": counter(100, 100), "shared-b": counter(50, 50)}})
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-b", CoreUptimeSec: 60,
		InboundTraffic: map[string]model.ProxyTrafficCounter{"exit-b-in": counter(700, 800), "shared-b": counter(250, 350)}})
	return result
}

func usageTestServer(t *testing.T, now time.Time) *Server {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	srv.now = func() time.Time { return now }
	return srv
}

// One report end to end: the per-line join by (node, tag), the ordered rules,
// unknown tags kept, named remainder unattributed, cumulative totals fed by
// named and by credential/binding, and the day rows both ways.
func TestUsageIngestAttributesLinesAndWritesDayRows(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	result := reportUsageFleet(t, srv, f)
	if result.UnknownLines != 1 || result.UsersIgnored != 1 {
		t.Fatalf("result: %+v", result)
	}
	// alice: named (100+200 through the u_ counter); bob: binding on direct-a
	// (30+50); carol: credential on cred-a (10+20). dave sits on a chain
	// target and gets nothing counted at ingestion.
	for _, tc := range []struct {
		id   string
		used int64
	}{{f.alice.ID, 300}, {f.bob.ID, 80}, {f.carol.ID, 30}} {
		pu, ok := srv.store.ProxyUser(tc.id)
		if !ok || pu.UsedBytes != tc.used {
			t.Fatalf("%s UsedBytes = %d ok=%v, want %d", tc.id, pu.UsedBytes, ok, tc.used)
		}
	}
	if _, ok := srv.store.ProxyUser(f.dave.ID); ok {
		t.Fatal("dave must not gain a projection from relayed bytes")
	}
	day := store.UsageDay(now)
	nodes, err := srv.store.UsageDayNodeRows("node-a", day, day)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("node-a day rows: %v %+v", err, nodes)
	}
	lines := nodes[0].Lines
	if hub := lines["hub-a"]; hub.Uplink != 500 || hub.Downlink != 600 || hub.LineHashID != f.hub.LineHashID || hub.Users[f.alice.ID] != (store.UsageDayBytes{Uplink: 100, Downlink: 200}) {
		t.Fatalf("hub-a day row: %+v", hub)
	}
	if direct := lines["direct-a"]; direct.Users[f.bob.ID] != (store.UsageDayBytes{Uplink: 30, Downlink: 50}) {
		t.Fatalf("direct-a day row: %+v", direct)
	}
	if cred := lines["cred-a"]; cred.Users[f.carol.ID] != (store.UsageDayBytes{Uplink: 10, Downlink: 20}) {
		t.Fatalf("cred-a day row: %+v", cred)
	}
	if ghost := lines["ghost"]; ghost.Uplink != 2 || ghost.Downlink != 3 || ghost.LineHashID != "" || len(ghost.Users) != 0 {
		t.Fatalf("unknown tag must keep its bytes: %+v", ghost)
	}
	users, err := srv.store.UsageDayUserRows(f.alice.ID, day, day)
	if err != nil || len(users) != 1 || users[0].Uplink != 100 || users[0].Downlink != 200 || users[0].ByLine[f.hub.LineHashID].Uplink != 100 || !users[0].LastSeenAt.Equal(now) {
		t.Fatalf("alice day row: %v %+v", err, users)
	}
	if rows, _ := srv.store.UsageDayUserRows(f.dave.ID, day, day); len(rows) != 0 {
		t.Fatalf("dave must have no counted bytes: %+v", rows)
	}
	// The stored snapshot never carries an unmatched user counter name.
	snap, _ := srv.store.ProxyUsageSnapshot("node-a")
	if _, leaked := snap.UserTraffic["u_unknown1234567"]; leaked || snap.UserTraffic[f.aliceName].Uplink != 400 {
		t.Fatalf("stored user_traffic: %+v", snap.UserTraffic)
	}
	if snap.UserBytes[f.alice.ID] != 1200 {
		t.Fatalf("folded user_bytes: %+v", snap.UserBytes)
	}
}

// The read model over the day: roles, the relayed portion carrying
// counted_at, the shared line's direct estimate, and the fleet double-count
// figure.
func TestUsageLinesReadModelChainRoles(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	reportUsageFleet(t, srv, f)
	window, _ := parseUsagePeriod("today", now)
	report, _ := srv.buildUsageLines(srv.usageAttributionContext(), window)
	byKey := map[string][]usageLineRow{}
	for _, row := range report.Rows {
		byKey[row.NodeID+"/"+row.Tag] = append(byKey[row.NodeID+"/"+row.Tag], row)
	}
	hub := byKey["node-a/hub-a"]
	if len(hub) != 2 || hub[0].Role != usageRoleEntry || hub[0].Attribution != usageAttributionNamed || hub[0].UserID != f.alice.ID || !hub[0].Counted ||
		hub[1].Attribution != usageAttributionNone || hub[1].Uplink != 400 || hub[1].Downlink != 400 || hub[1].Counted {
		t.Fatalf("hub-a rows: %+v", hub)
	}
	exit := byKey["node-b/exit-b-in"]
	if len(exit) != 2 || exit[0].Role != usageRoleExit || exit[0].CountedAt != f.hub.LineHashID || exit[0].Uplink != 500 || exit[0].Downlink != 600 || exit[0].Counted ||
		!exit[1].Estimate || exit[1].Uplink != 100 || exit[1].Downlink != 100 || exit[1].Attribution != usageAttributionNone {
		t.Fatalf("exit rows: %+v", exit)
	}
	shared := byKey["node-b/shared-b"]
	if len(shared) != 2 || shared[0].Role != usageRoleShared || shared[0].CountedAt != f.hub2.LineHashID || shared[0].UsedBytes != 300 ||
		!shared[1].Estimate || shared[1].Attribution != usageAttributionBinding || shared[1].UserID != f.dave.ID || shared[1].Counted || shared[1].Uplink != 100 || shared[1].Downlink != 100 {
		t.Fatalf("shared rows: %+v", shared)
	}
	if got := byKey["node-a/direct-a"]; len(got) != 1 || got[0].Role != usageRoleDirect || got[0].Attribution != usageAttributionBinding || got[0].AttributionProof != usageProofInferred || !got[0].Counted {
		t.Fatalf("direct-a rows: %+v", got)
	}
	if got := byKey["node-a/cred-a"]; len(got) != 1 || got[0].Attribution != usageAttributionCredential || got[0].AttributionProof != usageProofProof || got[0].UserID != f.carol.ID {
		t.Fatalf("cred-a rows: %+v", got)
	}
	if got := byKey["node-a/ghost"]; len(got) != 1 || got[0].Attribution != usageAttributionUnknownLine || got[0].UsedBytes != 5 {
		t.Fatalf("ghost rows: %+v", got)
	}
	if report.DoubleCountedViaChainsBytes != 1100+300 {
		t.Fatalf("double counted = %d", report.DoubleCountedViaChainsBytes)
	}
	// Node totals count every inbound: the legacy by_node view is untouched by
	// the chain policy, and the collectors list carries every profiled node.
	_, _, _, collectors, _ := srv.buildUsage()
	states := map[string]string{}
	for _, c := range collectors {
		states[c.NodeID] = c.Status
	}
	if states["node-a"] != usageCollectorStateNoCollector || states["node-b"] != usageCollectorStateNoCollector {
		t.Fatalf("collector states: %+v", states)
	}
}

// stats_off is a collector state of its own: accepted, stored on the profile,
// never a baseline, and surfaced beside ok, error and no_collector.
func TestUsageCollectorStatsOff(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	seedUsageFleet(t, srv)
	result := mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "node-a", CollectorSource: "singbox-stats", CollectorStatus: "stats_off"})
	if result.CollectorStatus != "stats_off" {
		t.Fatalf("result: %+v", result)
	}
	profile, _ := srv.store.ProxyNodeProfile("node-a")
	if usageCollectorState(profile) != usageCollectorStateStatsOff || !strings.Contains(profile.UsageCollectorLastError, "v2ray_api") {
		t.Fatalf("profile: %+v", profile)
	}
	if _, ok := srv.store.ProxyUsageSnapshot("node-a"); ok {
		t.Fatal("stats_off must not store a baseline")
	}
	if _, err := srv.applyProxyUsageSnapshot(model.ProxyUsageSnapshot{NodeID: "node-a", At: now, CollectorStatus: "stats_off",
		InboundTraffic: map[string]model.ProxyTrafficCounter{"hub-a": counter(1, 1)}}); err == nil {
		t.Fatal("stats_off with counters must be rejected")
	}
	_, _, _, collectors, _ := srv.buildUsage()
	found := false
	for _, c := range collectors {
		found = found || (c.NodeID == "node-a" && c.Status == "stats_off")
	}
	if !found {
		t.Fatalf("collectors: %+v", collectors)
	}
	if got := usageCollectorState(model.ProxyNodeProfile{}); got != usageCollectorStateNoCollector {
		t.Fatalf("empty profile state = %q", got)
	}
	if got := usageCollectorState(model.ProxyNodeProfile{UsageCollectorStatus: "error"}); got != usageCollectorStateError {
		t.Fatalf("error state = %q", got)
	}
}

// The wire shapes: the usage RPC's lines, the HTTP surface, and the users
// list fields.
func TestUsageWireShapes(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	f := seedUsageFleet(t, srv)
	reportUsageFleet(t, srv, f)

	raw, err := srv.vpnCoreUsageRPC(context.Background(), "query", []byte(`{"period":"7d"}`))
	if err != nil {
		t.Fatal(err)
	}
	var usage map[string]json.RawMessage
	if err := json.Unmarshal(raw, &usage); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"by_user", "by_node", "rows", "collectors", "per_line", "lines", "double_counted_via_chains_bytes", "period", "from", "to"} {
		if _, ok := usage[key]; !ok {
			t.Fatalf("usage query missing %q: %s", key, raw)
		}
	}
	var lines []map[string]any
	if err := json.Unmarshal(usage["lines"], &lines); err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 {
		t.Fatal("no lines")
	}
	for _, key := range []string{"node_id", "line_hash_id", "tag", "role", "uplink", "downlink", "used_bytes", "attribution", "counted"} {
		if _, ok := lines[0][key]; !ok {
			t.Fatalf("line row missing %q: %+v", key, lines[0])
		}
	}
	if string(usage["period"]) != `"7d"` {
		t.Fatalf("period: %s", usage["period"])
	}
	if _, err := srv.vpnCoreUsageRPC(context.Background(), "query", []byte(`{"period":"yesterday"}`)); err == nil {
		t.Fatal("unknown period must error")
	}

	raw, err = srv.vpnCoreUsersRPC(context.Background(), "list", nil)
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Users []vpnUserUsageView `json:"users"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	views := map[string]vpnUserUsageView{}
	for _, v := range list.Users {
		views[v.ID] = v
	}
	alice := views[f.alice.ID]
	if alice.UsedTotalBytes != 300 || alice.UsedPeriodBytes != 300 || len(alice.Last7d) != 7 || alice.Last7d[6] != 300 || alice.LastSeenAt == "" || alice.PeriodStart != "" {
		t.Fatalf("alice view: %+v", alice)
	}
	if len(alice.AllocatedNodes) != 2 {
		t.Fatalf("alice allocated nodes: %+v", alice.AllocatedNodes)
	}
	nodeA, nodeB := alice.AllocatedNodes[0], alice.AllocatedNodes[1]
	if nodeA.NodeID != "node-a" || nodeA.CollectorState != usageCollectorStateNoCollector || len(nodeA.Lines) != 1 ||
		nodeA.Lines[0].LineHashID != f.hub.LineHashID || nodeA.Lines[0].Role != usageRoleEntry || nodeA.Lines[0].Allocation != "binding" ||
		nodeA.Lines[0].PeriodUplink != 100 || nodeA.Lines[0].PeriodDownlink != 200 || !nodeA.Lines[0].Counted || nodeA.Lines[0].LastSeenAt == "" {
		t.Fatalf("alice node-a: %+v", nodeA)
	}
	if nodeB.NodeID != "node-b" || len(nodeB.Lines) != 1 || !nodeB.Lines[0].ViaRelay || nodeB.Lines[0].Counted || nodeB.Lines[0].Role != usageRoleExit || nodeB.Lines[0].PeriodUplink != 0 {
		t.Fatalf("alice node-b via relay: %+v", nodeB)
	}
	dave := views[f.dave.ID]
	if len(dave.AllocatedNodes) != 1 || len(dave.AllocatedNodes[0].Lines) != 1 {
		t.Fatalf("dave allocated: %+v", dave.AllocatedNodes)
	}
	if line := dave.AllocatedNodes[0].Lines[0]; line.Role != usageRoleShared || !line.Estimate || line.Counted || line.PeriodUplink != 100 || line.PeriodDownlink != 100 {
		t.Fatalf("dave shared line: %+v", line)
	}
	if carol := views[f.carol.ID]; carol.UsedTotalBytes != 30 || len(carol.AllocatedNodes) != 0 {
		t.Fatalf("carol view: %+v", carol)
	}

	// usage_query: one scope at a time, node:read re-checked in the method.
	reader := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"node:read"}}}
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, reader)
	raw, err = srv.vpnCoreUsersAdminRPC(ctx, "usage_query", []byte(`{"user_id":"`+f.alice.ID+`","period":"today"}`))
	if err != nil {
		t.Fatal(err)
	}
	var q usageQueryResponse
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	if q.Scope["user_id"] != f.alice.ID || q.Uplink != 100 || q.Downlink != 200 || q.UsedBytes != 300 || len(q.Days) != 1 || len(q.Lines) != 1 || q.Lines[0].LineHashID != f.hub.LineHashID || q.Lines[0].Attribution != usageAttributionNamed {
		t.Fatalf("user query: %+v", q)
	}
	raw, err = srv.vpnCoreUsersAdminRPC(ctx, "usage_query", []byte(`{"line_hash_id":"`+f.shared.LineHashID+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	if q.Scope["line_hash_id"] != f.shared.LineHashID || q.UsedBytes != 500 || q.DoubleCountedViaChainsBytes != 300 || len(q.Lines) != 2 {
		t.Fatalf("line query: %+v", q)
	}
	raw, err = srv.vpnCoreUsersAdminRPC(ctx, "usage_query", []byte(`{"node_id":"node-a"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	if q.Scope["node_id"] != "node-a" || q.UsedBytes != 1100+300+80+30+5 || len(q.Lines) < 5 {
		t.Fatalf("node query: %+v", q)
	}
	for _, bad := range []string{`{}`, `{"user_id":"x","node_id":"node-a"}`, `{"user_id":"nobody"}`, `{"line_hash_id":"line_nope"}`} {
		if _, err := srv.vpnCoreUsersAdminRPC(ctx, "usage_query", []byte(bad)); err == nil {
			t.Fatalf("%s must error", bad)
		}
	}
	limited := principal{Principal: rbac.Principal{ActorID: "op2", Scopes: []string{"vpncore:admin"}}}
	if _, err := srv.vpnCoreUsersAdminRPC(context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, limited), "usage_query", []byte(`{"node_id":"node-a"}`)); err == nil {
		t.Fatal("usage_query without node:read must be denied")
	}
}
