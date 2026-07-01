package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestVPNCoreUsageRPC(t *testing.T) {
	srv := newLinesTestServer(t)
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A"}); err != nil {
		t.Fatal(err)
	}
	// legacy proxy user with accumulated total + a per-node snapshot
	if err := srv.store.UpsertProxyUser(model.ProxyUser{
		ID: "pu-1", Name: "alice@example.com", Enabled: true, UsedBytes: 5000,
		TrafficLimitBytes: 100000, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyUsageSnapshot(model.ProxyUsageSnapshot{
		NodeID: "node-a", At: srv.now(), UserBytes: map[string]int64{"pu-1": 3200},
		LineUserBytes:   map[string]map[string]int64{"line-a": {"pu-1": 3200}},
		CollectorSource: "file", CollectorStatus: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	srv.migrateProxyUsersToVpnUsers() // so usage maps to the VpnUser identity

	raw, err := srv.vpnCoreUsageRPC(context.Background(), "query", nil)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var out struct {
		ByUser     []UsageByUser    `json:"by_user"`
		ByNode     []UsageByNode    `json:"by_node"`
		Rows       []UsageRow       `json:"rows"`
		Collectors []UsageCollector `json:"collectors"`
		PerLine    bool             `json:"per_line"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.ByUser) != 1 || out.ByUser[0].UsedBytes != 5000 || out.ByUser[0].Email != "alice@example.com" {
		t.Fatalf("by_user wrong: %+v", out.ByUser)
	}
	if out.ByUser[0].UserID != "vu_pu-1" {
		t.Fatalf("usage should map to the migrated VpnUser identity, got %q", out.ByUser[0].UserID)
	}
	if len(out.ByNode) != 1 || out.ByNode[0].UsedBytes != 3200 || out.ByNode[0].UserCount != 1 {
		t.Fatalf("by_node wrong: %+v", out.ByNode)
	}
	if len(out.Rows) != 1 || out.Rows[0].Bytes != 3200 || out.Rows[0].Email != "alice@example.com" || out.Rows[0].LineHashID != "line-a" {
		t.Fatalf("rows wrong: %+v", out.Rows)
	}
	if len(out.Collectors) != 1 || out.Collectors[0].Status != "ok" {
		t.Fatalf("collectors wrong: %+v", out.Collectors)
	}
	if !out.PerLine {
		t.Fatal("per_line should be true when line_user_bytes are present")
	}
	if _, err := srv.vpnCoreUsageRPC(context.Background(), "bogus", nil); err == nil {
		t.Fatal("bogus method should error")
	}
}
