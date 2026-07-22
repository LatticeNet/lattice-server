package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// activateCorePlugin marks a plugin active so its services are servable. A service is
// only served while its owning plugin is active, whether the engine behind it lives in
// core or in the plugin's artifact — so even an in-core provider needs its plugin
// installed and active, exactly as in a real deployment.
func activateCorePlugin(t *testing.T, st *store.Store, pluginID string) {
	t.Helper()
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: pluginID, Name: pluginID, Type: "system", Status: model.PluginStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVPNCoreExportIncludesDiscoveredNodes(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	activateCorePlugin(t, st, vpnCorePluginID)
	// The nodes must exist (the export filters discovery to live nodes), as they
	// would when a real agent reports.
	for _, id := range []string{"node-a", "node-b"} {
		if err := st.UpsertNode(model.Node{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	// Inject a discovered inventory (as the agent report would).
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {NodeID: "node-a", Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "VLESS-REALITY-17891.json", ShareURL: "vless://a@h:17891#n1"},
			{Name: "Hysteria2-17892.json", ShareURL: "hysteria2://b@h:17892#n2"},
		}},
		// A node reporting a discovery error contributes a warning, no links.
		"node-b": {NodeID: "node-b", Status: "error", Error: "sb not found"},
	}
	srv.singboxInvMu.Unlock()

	call := func(body string) struct {
		Links    []string `json:"links"`
		Count    int      `json:"count"`
		Warnings []string `json:"warnings"`
	} {
		raw, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "export", []byte(body))
		if err != nil {
			t.Fatalf("export(%s): %v", body, err)
		}
		var out struct {
			Links    []string `json:"links"`
			Count    int      `json:"count"`
			Warnings []string `json:"warnings"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	// Default (no body) includes discovered nodes.
	def := call("")
	if def.Count != 2 || len(def.Links) != 2 {
		t.Fatalf("default export should include 2 discovered links, got %+v", def)
	}
	hasWarn := false
	for _, w := range def.Warnings {
		if w != "" {
			hasWarn = true
		}
	}
	if !hasWarn {
		t.Fatalf("expected a discovery-error warning for node-b, got %+v", def.Warnings)
	}

	// include_discovered=false excludes them (empty managed store -> 0).
	off := call(`{"include_discovered":false}`)
	if off.Count != 0 {
		t.Fatalf("include_discovered=false should yield 0 links, got %+v", off)
	}

	// A user_id filter scopes to managed subscribers only (no discovered nodes);
	// unknown user errors rather than silently returning discovered links.
	if _, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "export", []byte(`{"user_id":"nope"}`)); err == nil {
		t.Fatalf("expected error for unknown user_id")
	}
}

func TestVPNCoreNodesRPCRegisteredAndExports(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	activateCorePlugin(t, st, vpnCorePluginID)

	// The in-core vpn-core/nodes service is registered with the export + list
	// methods (list backs the design-10 plugin-contributed Nodes table; Services()
	// returns methods sorted, so the expected slice is ["export","list"]).
	var found bool
	for _, d := range srv.pluginRPC.Services() {
		if d.Service == vpnCoreNodesService {
			found = true
			if len(d.Methods) != 2 || d.Methods[0] != "export" || d.Methods[1] != "list" {
				t.Fatalf("unexpected methods: %+v", d.Methods)
			}
			if d.Owner != vpnCorePluginID {
				t.Fatalf("unexpected owner: %s", d.Owner)
			}
		}
	}
	if !found {
		t.Fatalf("vpn-core/nodes not registered: %+v", srv.pluginRPC.Services())
	}

	// Owner self-call export on an empty store -> empty, valid JSON envelope.
	out, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "export", nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var resp struct {
		Links []string `json:"links"`
		Count int      `json:"count"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if resp.Count != 0 || len(resp.Links) != 0 {
		t.Fatalf("expected empty export, got %+v", resp)
	}

	// list (the design-10 table data source) returns a valid, empty envelope on
	// an empty store — rows is a non-nil [] so the dashboard table renders cleanly.
	listOut, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "list", nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var listResp struct {
		Rows  []map[string]any `json:"rows"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal(listOut, &listResp); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if listResp.Rows == nil {
		t.Fatalf("list rows must be non-nil JSON array, got null")
	}
	if listResp.Count != 0 || len(listResp.Rows) != 0 {
		t.Fatalf("expected empty list, got %+v", listResp)
	}

	// Unknown method is rejected by the handler.
	if _, err := srv.pluginRPC.Call(context.Background(), vpnCorePluginID, vpnCoreNodesService, "nope", nil); err == nil {
		t.Fatalf("expected unknown-method error")
	}

	// The registry is wired into the broker host services so plugins can reach it.
	if srv.pluginHostServices().RPC == nil {
		t.Fatalf("HostServices.RPC not wired")
	}
}

func TestVPNCoreDesign15MutationMethodsRegisteredAndReachable(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	activateCorePlugin(t, st, vpnCorePluginID)
	line, user := seedLineUserFixture(t, srv)
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, lineUserTestPrincipal())

	var methods []string
	for _, service := range srv.pluginRPC.Services() {
		if service.Service == vpnCoreUsersAdminService {
			methods = service.Methods
		}
	}
	for _, want := range []string{"plan_add", "plan_update", "plan_remove", "rotate"} {
		if !containsString(methods, want) {
			t.Fatalf("users-admin method %q not registered: %v", want, methods)
		}
	}
	request := mustJSON(t, map[string]string{"user_id": user.ID, "line_hash_id": line.LineHashID})
	for _, method := range []string{"plan_update", "plan_remove"} {
		if _, err := srv.pluginRPC.Call(ctx, vpnCorePluginID, vpnCoreUsersAdminService, method, request); err != nil {
			t.Fatalf("%s unreachable: %v", method, err)
		}
	}
	user.Bindings = nil
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.pluginRPC.Call(ctx, vpnCorePluginID, vpnCoreUsersAdminService, "plan_add", request); err != nil {
		t.Fatalf("plan_add unreachable: %v", err)
	}
	if _, err := srv.pluginRPC.Call(ctx, vpnCorePluginID, vpnCoreUsersAdminService, "rotate",
		mustJSON(t, map[string]string{"user_id": user.ID, "protocol": "trojan"})); err != nil {
		t.Fatalf("rotate unreachable: %v", err)
	}
	if _, err := srv.pluginRPC.Call(ctx, vpnCorePluginID, vpnCoreLinesService, "sync_metadata",
		mustJSON(t, map[string]string{"node_id": line.NodeID})); err != nil {
		t.Fatalf("lines.sync_metadata unreachable: %v", err)
	}
}

func TestVPNCoreLinesReattachAuditsAndRejectsCollisions(t *testing.T) {
	st, _ := store.Open("")
	srv := newLinemetaTestServer(t, st)
	seedLinemetaNodes(t, srv)
	line := findLine(t, srv.buildLineGroups(), "node-a", "hub-a")
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, lineUserTestPrincipal())
	want := "44444444-4444-4444-8444-444444444444"
	out, err := srv.vpnCoreLinesRPC(ctx, "reattach", mustJSON(t, map[string]string{
		"line_hash_id": line.LineHashID, "line_uuid": want,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), want) {
		t.Fatalf("reattach response: %s", out)
	}
	entry, ok := st.KVEntry(lineUUIDKVBucket, line.LineHashID)
	if !ok || entry.Value != want {
		t.Fatalf("reattach mapping: %+v ok=%v", entry, ok)
	}
	if !auditMetadataSeen(st, "line.uuid.reattach", "line_uuid", want) {
		t.Fatalf("reattach audit missing: %+v", st.AuditEvents())
	}
	if _, err := srv.vpnCoreLinesRPC(ctx, "reattach", mustJSON(t, map[string]string{
		"line_hash_id": line.LineHashID, "line_uuid": "not-v4",
	})); err == nil {
		t.Fatal("invalid reattach UUID must fail")
	}
	if err := st.PutKV(model.KVEntry{Bucket: lineUUIDKVBucket, Key: "line_other", Value: "55555555-5555-4555-8555-555555555555"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.vpnCoreLinesRPC(ctx, "reattach", mustJSON(t, map[string]string{
		"line_hash_id": line.LineHashID, "line_uuid": "55555555-5555-4555-8555-555555555555",
	})); err == nil {
		t.Fatal("colliding reattach UUID must fail")
	}
}
