package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestSingBoxDiscoverReportAndList(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	// Agent reports an inventory of 2 on-box nodes; body node_id is spoofed and
	// must be overridden by the authenticated node id.
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/singbox-inventory", `{
		"node_id":"node-a",
		"inventory":{"node_id":"SPOOFED","core_version":"1.12.12","status":"ok","nodes":[
			{"name":"VLESS-REALITY-17891.json","protocol":"vless","network":"reality","port":"17891","share_url":"vless://x@h:17891"},
			{"name":"Hysteria2-17892.json","protocol":"hysteria2","port":"17892","share_url":"hysteria2://y@h:17892"}
		]}
	}`, nodeToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("report: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Wrong token is rejected.
	bad := doAgentRaw(t, handler, http.MethodPost, "/api/agent/singbox-inventory",
		`{"node_id":"node-a","inventory":{"nodes":[]}}`, "wrong-token")
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401, got %d", bad.Code)
	}

	// Operator lists discovered inventories.
	resp := doJSON(t, handler, http.MethodGet, "/api/proxy/discovered", "", cookies, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovered: want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out struct {
		Inventories []model.SingBoxInventory `json:"inventories"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if len(out.Inventories) != 1 {
		t.Fatalf("want 1 inventory, got %d", len(out.Inventories))
	}
	inv := out.Inventories[0]
	if inv.NodeID != "node-a" {
		t.Fatalf("node id not forced from auth: got %q (spoof must be ignored)", inv.NodeID)
	}
	if inv.CoreVersion != "1.12.12" || len(inv.Nodes) != 2 {
		t.Fatalf("unexpected inventory: %+v", inv)
	}
	if inv.Nodes[0].Name != "VLESS-REALITY-17891.json" || inv.Nodes[0].Network != "reality" {
		t.Fatalf("node 0 wrong: %+v", inv.Nodes[0])
	}
}
