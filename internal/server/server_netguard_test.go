package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type netGuardGroupsResponse struct {
	Groups []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Source string `json:"source"`
		NodeID string `json:"node_id"`
		Rules  []struct {
			ID       string `json:"id"`
			Action   string `json:"action"`
			Protocol string `json:"protocol"`
			Ports    []struct {
				From int `json:"from"`
				To   int `json:"to"`
			} `json:"ports"`
			Remote struct {
				Kind   string `json:"kind"`
				ZoneID string `json:"zone_id"`
			} `json:"remote"`
		} `json:"rules"`
	} `json:"groups"`
}

type netGuardNodesResponse struct {
	Nodes []struct {
		NodeID   string `json:"node_id"`
		NodeName string `json:"node_name"`
		Source   string `json:"source"`
		Binding  struct {
			Managed  bool     `json:"managed"`
			GroupIDs []string `json:"group_ids"`
			ZoneIDs  []string `json:"zone_ids"`
		} `json:"binding"`
		Zones []struct {
			ID         string   `json:"id"`
			Builtin    bool     `json:"builtin"`
			Interfaces []string `json:"interfaces"`
			CIDRs      []string `json:"cidrs"`
		} `json:"zones"`
	} `json:"nodes"`
}

func TestNetGuardLegacyReadOnlyViews(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"node-a",
		"interface_name":"ens3",
		"wireguard_cidr":"10.66.0.0/24",
		"public_tcp":[22,9009,9010,9011,9012,9013],
		"public_udp":[51820]
	}`, cookies, csrf)
	defer save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}

	nodesRes := doJSON(t, handler, http.MethodGet, "/api/netguard/nodes", "", cookies, csrf)
	defer nodesRes.Body.Close()
	if nodesRes.StatusCode != http.StatusOK {
		t.Fatalf("netguard nodes failed: %d", nodesRes.StatusCode)
	}
	var nodes netGuardNodesResponse
	if err := json.NewDecoder(nodesRes.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes.Nodes) != 1 {
		t.Fatalf("want 1 node view, got %d", len(nodes.Nodes))
	}
	node := nodes.Nodes[0]
	if node.NodeID != "node-a" || node.NodeName != "Node A" || node.Source != "legacy" {
		t.Fatalf("bad node view: %+v", node)
	}
	if node.Binding.Managed {
		t.Fatal("legacy view must be observe-only")
	}
	if len(node.Binding.GroupIDs) != 1 || node.Binding.GroupIDs[0] != "sg-legacy-node-a" {
		t.Fatalf("bad binding groups: %v", node.Binding.GroupIDs)
	}
	if len(node.Binding.ZoneIDs) != 0 {
		t.Fatalf("legacy binding must not trust zones: %v", node.Binding.ZoneIDs)
	}
	zoneIfaces := map[string][]string{}
	zoneCIDRs := map[string][]string{}
	for _, z := range node.Zones {
		zoneIfaces[z.ID] = z.Interfaces
		zoneCIDRs[z.ID] = z.CIDRs
	}
	if got := zoneIfaces["public"]; len(got) != 1 || got[0] != "ens3" {
		t.Fatalf("public zone interfaces = %v", got)
	}
	if got := zoneCIDRs["wireguard"]; len(got) != 1 || got[0] != "10.66.0.0/24" {
		t.Fatalf("wireguard zone cidrs = %v", got)
	}

	groupsRes := doJSON(t, handler, http.MethodGet, "/api/netguard/groups", "", cookies, csrf)
	defer groupsRes.Body.Close()
	if groupsRes.StatusCode != http.StatusOK {
		t.Fatalf("netguard groups failed: %d", groupsRes.StatusCode)
	}
	var groups netGuardGroupsResponse
	if err := json.NewDecoder(groupsRes.Body).Decode(&groups); err != nil {
		t.Fatal(err)
	}
	if len(groups.Groups) != 1 {
		t.Fatalf("want 1 legacy group, got %d", len(groups.Groups))
	}
	group := groups.Groups[0]
	if group.ID != "sg-legacy-node-a" || group.Source != "legacy" || group.NodeID != "node-a" {
		t.Fatalf("bad group view: %+v", group)
	}
	if len(group.Rules) != 2 {
		t.Fatalf("want tcp+udp rules, got %d", len(group.Rules))
	}
	tcp := group.Rules[0]
	if tcp.Protocol != "tcp" || tcp.Remote.Kind != "zone" || tcp.Remote.ZoneID != "public" {
		t.Fatalf("bad tcp rule: %+v", tcp)
	}
	// 22 stays single, 9009-9013 collapses into one reviewable range.
	if len(tcp.Ports) != 2 || tcp.Ports[0].From != 22 || tcp.Ports[0].To != 22 ||
		tcp.Ports[1].From != 9009 || tcp.Ports[1].To != 9013 {
		t.Fatalf("bad tcp ranges: %+v", tcp.Ports)
	}

	// The legacy view must not have persisted anything.
	if _, ok := st.SecurityGroup("sg-legacy-node-a"); ok {
		t.Fatal("legacy conversion must not write to the store")
	}
	if _, ok := st.NodeGuardBinding("node-a"); ok {
		t.Fatal("legacy conversion must not persist bindings")
	}

	zonesRes := doJSON(t, handler, http.MethodGet, "/api/netguard/zones", "", cookies, csrf)
	defer zonesRes.Body.Close()
	if zonesRes.StatusCode != http.StatusOK {
		t.Fatalf("netguard zones failed: %d", zonesRes.StatusCode)
	}
	var zones struct {
		Zones []struct {
			ID      string `json:"id"`
			Builtin bool   `json:"builtin"`
		} `json:"zones"`
	}
	if err := json.NewDecoder(zonesRes.Body).Decode(&zones); err != nil {
		t.Fatal(err)
	}
	builtins := map[string]bool{}
	for _, z := range zones.Zones {
		if z.Builtin {
			builtins[z.ID] = true
		}
	}
	for _, want := range []string{"public", "loopback", "wireguard", "tailscale"} {
		if !builtins[want] {
			t.Fatalf("builtin zone %q missing from %+v", want, zones.Zones)
		}
	}
}

func TestNetGuardStoredBindingSupersedesLegacyView(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[22]}`, cookies, csrf)
	defer save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}

	group, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-web", Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{
		NodeID:   "node-a",
		GroupIDs: []string{group.ID},
		Managed:  true,
	}); err != nil {
		t.Fatal(err)
	}

	nodesRes := doJSON(t, handler, http.MethodGet, "/api/netguard/nodes", "", cookies, csrf)
	defer nodesRes.Body.Close()
	var nodes netGuardNodesResponse
	if err := json.NewDecoder(nodesRes.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes.Nodes) != 1 {
		t.Fatalf("stored binding must supersede the legacy view, got %d views", len(nodes.Nodes))
	}
	if nodes.Nodes[0].Source != "stored" || !nodes.Nodes[0].Binding.Managed {
		t.Fatalf("bad stored view: %+v", nodes.Nodes[0])
	}
}

func TestNetGuardGlobalCatalogRejectsRestrictedToken(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	for _, nodeID := range []string{"node-a", "node-b"} {
		save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
			`{"node_id":"`+nodeID+`","public_tcp":[22]}`, cookies, csrf)
		save.Body.Close()
		if save.StatusCode != http.StatusOK {
			t.Fatalf("save nft inputs for %s failed: %d", nodeID, save.StatusCode)
		}
	}

	token := createPAT(t, handler, cookies, csrf,
		[]string{"netguard:read", "netguard:admin", "network:plan"},
		[]string{"node-a"})

	nodesRes := doBearerJSON(t, handler, http.MethodGet, "/api/netguard/nodes", "", token)
	defer nodesRes.Body.Close()
	if nodesRes.StatusCode != http.StatusOK {
		t.Fatalf("restricted node view = %d, want 200", nodesRes.StatusCode)
	}
	var nodes netGuardNodesResponse
	if err := json.NewDecoder(nodesRes.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes.Nodes) != 1 || nodes.Nodes[0].NodeID != "node-a" {
		t.Fatalf("restricted node view leaked nodes: %+v", nodes.Nodes)
	}

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "list groups", method: http.MethodGet, path: "/api/netguard/groups"},
		{name: "create group", method: http.MethodPost, path: "/api/netguard/groups", body: `{"id":"sg-a","name":"a"}`},
		{name: "list zones", method: http.MethodGet, path: "/api/netguard/zones"},
		{name: "create zone", method: http.MethodPost, path: "/api/netguard/zones", body: `{"id":"tail","name":"tail","interfaces":["tailscale0"]}`},
	} {
		res := doBearerJSON(t, handler, tc.method, tc.path, tc.body, token)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s with restricted token = %d, want 403", tc.name, res.StatusCode)
		}
	}

	adoptA := doBearerJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, token)
	defer adoptA.Body.Close()
	if adoptA.StatusCode != http.StatusOK {
		t.Fatalf("restricted token should adopt node-a, got %d", adoptA.StatusCode)
	}
	adoptB := doBearerJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-b"}`, token)
	defer adoptB.Body.Close()
	if adoptB.StatusCode != http.StatusForbidden {
		t.Fatalf("restricted token must not adopt node-b, got %d", adoptB.StatusCode)
	}
}

// End-to-end G2: adopt a legacy node, then plan from the new model. The plan
// must be a lattice_guard ruleset carried by an `nft` approval so it rides the
// existing rollback-protected apply script unchanged.
func TestNetGuardAdoptThenPlan(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"node-a","interface_name":"ens3","public_tcp":[22,443]
	}`, cookies, csrf)
	defer save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save inputs: %d", save.StatusCode)
	}

	// Planning before adoption is refused: converted views are observe-only.
	early := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer early.Body.Close()
	if early.StatusCode != http.StatusBadRequest {
		t.Fatalf("plan before adopt = %d, want 400", early.StatusCode)
	}

	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()
	if adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopt failed: %d", adopt.StatusCode)
	}
	binding, ok := st.NodeGuardBinding("node-a")
	if !ok || !binding.Managed {
		t.Fatalf("adopt must persist a managed binding, got %+v", binding)
	}
	if _, ok := st.SecurityGroup("sg-legacy-node-a"); !ok {
		t.Fatal("adopt must persist the converted group")
	}

	// Adopting twice is a conflict, not a silent re-materialization.
	again := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer again.Body.Close()
	if again.StatusCode != http.StatusConflict {
		t.Fatalf("re-adopt = %d, want 409", again.StatusCode)
	}

	plan := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("netguard plan failed: %d", plan.StatusCode)
	}
	var planRes struct {
		Approval model.Approval `json:"approval"`
		Findings []struct {
			Code string `json:"code"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(plan.Body).Decode(&planRes); err != nil {
		t.Fatal(err)
	}
	if planRes.Approval.Plugin != "nft" || planRes.Approval.Action != "apply-ruleset" {
		t.Fatalf("plan must ride the existing nft apply path: %+v", planRes.Approval)
	}
	for _, want := range []string{
		`destroy table inet lattice_guard`,
		`iifname "ens3" tcp dport { 22, 443 }`,
		`counter drop`,
	} {
		if !strings.Contains(planRes.Approval.Plan, want) {
			t.Fatalf("plan missing %q:\n%s", want, planRes.Approval.Plan)
		}
	}
	if len(planRes.Findings) != 0 {
		t.Fatalf("a plan allowing tcp/22 with a public url must be clean: %+v", planRes.Findings)
	}
}

// The dmit-eb-wee guard: a plan with no management-port accept is refused
// before it can ever reach a node, and only an explicit, audited override
// lets it through.
func TestNetGuardPlanBlocksLockoutRisk(t *testing.T) {
	handler, _ := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	// A baseline with the real incident's shape: services, but no SSH.
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[7443,7500]}`, cookies, csrf)
	defer save.Body.Close()
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()
	if adopt.StatusCode != http.StatusOK {
		t.Fatalf("adopt: %d", adopt.StatusCode)
	}

	blocked := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer blocked.Body.Close()
	if blocked.StatusCode != http.StatusConflict {
		t.Fatalf("lockout plan = %d, want 409", blocked.StatusCode)
	}
	var blockedRes struct {
		Findings []struct {
			Code     string `json:"code"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(blocked.Body).Decode(&blockedRes); err != nil {
		t.Fatal(err)
	}
	if len(blockedRes.Findings) == 0 || blockedRes.Findings[0].Code != "lockout_risk_ssh" ||
		blockedRes.Findings[0].Severity != "block" {
		t.Fatalf("findings = %+v", blockedRes.Findings)
	}

	forced := doJSON(t, handler, http.MethodPost, "/api/netguard/plan",
		`{"node_id":"node-a","accept_lockout_risk":true}`, cookies, csrf)
	defer forced.Body.Close()
	if forced.StatusCode != http.StatusOK {
		t.Fatalf("explicit override = %d, want 200", forced.StatusCode)
	}
}

// A trusted overlay zone is the safe remedy for the lockout case: the node
// keeps its tailscale path and the plan stops blocking.
func TestNetGuardTrustedZoneClearsLockoutAndRendersIifname(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[7443]}`, cookies, csrf)
	defer save.Body.Close()
	adopt := doJSON(t, handler, http.MethodPost, "/api/netguard/nodes/adopt", `{"node_id":"node-a"}`, cookies, csrf)
	defer adopt.Body.Close()

	zone := doJSON(t, handler, http.MethodPost, "/api/netguard/zones",
		`{"id":"tailscale","name":"tailscale","interfaces":["tailscale0"]}`, cookies, csrf)
	defer zone.Body.Close()
	if zone.StatusCode != http.StatusOK {
		t.Fatalf("create zone: %d", zone.StatusCode)
	}

	binding, _ := st.NodeGuardBinding("node-a")
	body := `{"node_id":"node-a","managed":true,"version":` +
		strconv.FormatInt(binding.Version, 10) +
		`,"group_ids":["sg-legacy-node-a"],"zone_ids":["tailscale"]}`
	bind := doJSON(t, handler, http.MethodPost, "/api/netguard/bindings", body, cookies, csrf)
	defer bind.Body.Close()
	if bind.StatusCode != http.StatusOK {
		t.Fatalf("bind zone: %d", bind.StatusCode)
	}

	plan := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan with trusted zone = %d, want 200 (lockout lint satisfied)", plan.StatusCode)
	}
	var planRes struct {
		Approval model.Approval `json:"approval"`
	}
	if err := json.NewDecoder(plan.Body).Decode(&planRes); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(planRes.Approval.Plan, `iifname "tailscale0" accept comment "trusted zone tailscale"`) {
		t.Fatalf("trusted zone accept missing:\n%s", planRes.Approval.Plan)
	}

	// A zone still trusted by a node cannot be deleted out from under it.
	del := doJSON(t, handler, http.MethodPost, "/api/netguard/zones/delete", `{"id":"tailscale"}`, cookies, csrf)
	defer del.Body.Close()
	if del.StatusCode != http.StatusConflict {
		t.Fatalf("delete in-use zone = %d, want 409", del.StatusCode)
	}
}

func TestNetGuardWriteValidationAndConflicts(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	// An unrenderable rule must be rejected at write time, never stored.
	bad := doJSON(t, handler, http.MethodPost, "/api/netguard/groups", `{
		"id":"sg-bad","name":"bad","rules":[{"id":"r","action":"allow","direction":"ingress",
		"protocol":"icmp","remote":{"kind":"zone","zone_id":"public"}}]}`, cookies, csrf)
	defer bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("icmp rule = %d, want 400", bad.StatusCode)
	}

	good := doJSON(t, handler, http.MethodPost, "/api/netguard/groups", `{
		"id":"sg-web","name":"web","rules":[{"id":"https","action":"allow","direction":"ingress",
		"protocol":"tcp","ports":[{"from":443,"to":443}],"remote":{"kind":"zone","zone_id":"public"}}]}`, cookies, csrf)
	defer good.Body.Close()
	if good.StatusCode != http.StatusOK {
		t.Fatalf("valid group = %d, want 200", good.StatusCode)
	}

	// Stale version write is a 409, not a silent clobber.
	stale := doJSON(t, handler, http.MethodPost, "/api/netguard/groups",
		`{"id":"sg-web","name":"clobber","version":0}`, cookies, csrf)
	defer stale.Body.Close()
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("stale group write = %d, want 409", stale.StatusCode)
	}

	// Reserved legacy id space cannot be squatted.
	squat := doJSON(t, handler, http.MethodPost, "/api/netguard/groups",
		`{"id":"sg-legacy-node-a","name":"squat"}`, cookies, csrf)
	defer squat.Body.Close()
	if squat.StatusCode != http.StatusBadRequest {
		t.Fatalf("legacy id squat = %d, want 400", squat.StatusCode)
	}

	// A group attached to a node cannot be deleted.
	bind := doJSON(t, handler, http.MethodPost, "/api/netguard/bindings",
		`{"node_id":"node-a","managed":true,"group_ids":["sg-web"]}`, cookies, csrf)
	defer bind.Body.Close()
	if bind.StatusCode != http.StatusOK {
		t.Fatalf("bind: %d", bind.StatusCode)
	}
	del := doJSON(t, handler, http.MethodPost, "/api/netguard/groups/delete", `{"id":"sg-web"}`, cookies, csrf)
	defer del.Body.Close()
	if del.StatusCode != http.StatusConflict {
		t.Fatalf("delete attached group = %d, want 409", del.StatusCode)
	}

	// The loopback zone is not editable.
	lo := doJSON(t, handler, http.MethodPost, "/api/netguard/zones",
		`{"id":"loopback","name":"lo","interfaces":["lo"]}`, cookies, csrf)
	defer lo.Body.Close()
	if lo.StatusCode != http.StatusBadRequest {
		t.Fatalf("edit loopback zone = %d, want 400", lo.StatusCode)
	}
}

func TestNetGuardStoreVersionConflicts(t *testing.T) {
	_, st := newTestServer(t)

	created, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-a", Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 {
		t.Fatalf("first upsert version = %d, want 1", created.Version)
	}

	// Stale write (echoes version 0 after the record moved to 1) must fail.
	if _, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-a", Name: "clobber"}); !errors.Is(err, store.ErrGuardVersionConflict) {
		t.Fatalf("stale group upsert error = %v, want ErrGuardVersionConflict", err)
	}
	updated, err := st.UpsertSecurityGroup(model.SecurityGroup{ID: "sg-a", Name: "a2", Version: created.Version})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || updated.Name != "a2" {
		t.Fatalf("bad updated group: %+v", updated)
	}

	binding, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a", Managed: true})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Version != 1 {
		t.Fatalf("first binding version = %d, want 1", binding.Version)
	}
	if _, err := st.UpsertNodeGuardBinding(model.NodeGuardBinding{NodeID: "node-a"}); !errors.Is(err, store.ErrGuardVersionConflict) {
		t.Fatalf("stale binding upsert error = %v, want ErrGuardVersionConflict", err)
	}
}
