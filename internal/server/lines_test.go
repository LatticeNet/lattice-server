package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newLinesTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// seedLinesFixture sets up one node with a managed inbound (vless:443, applied),
// one eligible user, and a discovered inventory containing a NEW line (hy2:8443)
// plus a DUPLICATE of the managed line (vless:443) that must be deduped away.
func seedLinesFixture(t *testing.T, srv *Server) {
	t.Helper()
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyInbound(model.ProxyInbound{
		ID: "in-1", Name: "reality-443", Core: "sing-box", Protocol: "vless",
		Listen: "0.0.0.0", Port: 443, Security: "reality", SNI: "www.example.com", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{
		ID: "prof-a", NodeID: "node-a", Core: "sing-box", InboundIDs: []string{"in-1"},
		AppliedSHA256: "deadbeef",
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyUser(model.ProxyUser{ID: "u-1", Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {
			NodeID: "node-a", At: srv.now(), Status: "ok",
			Nodes: []model.SingBoxNode{
				{Name: "hy2-8443", Protocol: "hysteria2", Network: "udp", Address: "203.0.113.5", Port: "8443", ShareURL: "hysteria2://x"},
				{Name: "vless-443", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "443", ShareURL: "vless://y"},
			},
		},
	}
	srv.singboxInvMu.Unlock()
}

func TestBuildLineGroupsMergesAndDedups(t *testing.T) {
	srv := newLinesTestServer(t)
	seedLinesFixture(t, srv)

	groups := srv.buildLineGroups()
	if len(groups) != 1 {
		t.Fatalf("want 1 node group, got %d", len(groups))
	}
	g := groups[0]
	if g.NodeID != "node-a" || g.NodeName != "Node A" {
		t.Fatalf("group identity: %+v", g)
	}
	// managed vless:443 + discovered hy2:8443; discovered vless:443 deduped away.
	if len(g.Lines) != 2 {
		t.Fatalf("want 2 lines (dup removed), got %d: %+v", len(g.Lines), g.Lines)
	}

	var managed, discovered *Line
	for i := range g.Lines {
		switch g.Lines[i].Source {
		case "managed":
			managed = &g.Lines[i]
		case "discovered":
			discovered = &g.Lines[i]
		}
	}
	if managed == nil || discovered == nil {
		t.Fatalf("expected one managed + one discovered line: %+v", g.Lines)
	}

	if !managed.Managed || managed.Type != "vless" || managed.ListenPort != 443 ||
		managed.OutboundRef != "direct" || managed.Domain != "www.example.com" ||
		managed.PublicHost != "203.0.113.5" || managed.Status != "ok" {
		t.Fatalf("managed line wrong: %+v", managed)
	}
	if managed.UserCount != 1 || !managed.UserKnown {
		t.Fatalf("managed user_count: want 1 known, got %d known=%v", managed.UserCount, managed.UserKnown)
	}
	if managed.LineHashID == "" || managed.ID != managed.LineHashID {
		t.Fatalf("managed line hash unset: %+v", managed)
	}

	if discovered.Managed || discovered.Type != "hysteria2" || discovered.ListenPort != 8443 || discovered.UserKnown {
		t.Fatalf("discovered line wrong: %+v", discovered)
	}
}

func TestLineHashStableAndDistinct(t *testing.T) {
	a := lineHash("node-a", "sing-box", "vless", "0.0.0.0", 443, "in-1", "direct")
	b := lineHash("node-a", "sing-box", "vless", "0.0.0.0", 443, "in-1", "direct")
	if a != b {
		t.Fatalf("lineHash not stable: %q vs %q", a, b)
	}
	if a == lineHash("node-a", "sing-box", "vless", "0.0.0.0", 8443, "in-1", "direct") {
		t.Fatal("lineHash should differ when the port differs")
	}
}

func TestVPNCoreLinesRPC(t *testing.T) {
	srv := newLinesTestServer(t)
	seedLinesFixture(t, srv)
	ctx := context.Background()

	// list
	raw, err := srv.vpnCoreLinesRPC(ctx, "list", nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listed struct {
		Groups []LineGroup `json:"groups"`
		Count  int         `json:"count"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if listed.Count != 2 || len(listed.Groups) != 1 {
		t.Fatalf("list: want count 2 / 1 group, got %d / %d", listed.Count, len(listed.Groups))
	}

	// get a known line by hash
	target := listed.Groups[0].Lines[0].LineHashID
	raw, err = srv.vpnCoreLinesRPC(ctx, "get", []byte(`{"line_hash_id":"`+target+`"}`))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var got struct {
		Line Line `json:"line"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("get decode: %v", err)
	}
	if got.Line.LineHashID != target {
		t.Fatalf("get returned wrong line: %+v", got.Line)
	}

	// get unknown -> error; bad method -> error; empty id -> error
	if _, err := srv.vpnCoreLinesRPC(ctx, "get", []byte(`{"line_hash_id":"nope"}`)); err == nil {
		t.Fatal("get unknown: want error")
	}
	if _, err := srv.vpnCoreLinesRPC(ctx, "get", []byte(`{}`)); err == nil {
		t.Fatal("get empty id: want error")
	}
	if _, err := srv.vpnCoreLinesRPC(ctx, "bogus", nil); err == nil {
		t.Fatal("bogus method: want error")
	}
}
