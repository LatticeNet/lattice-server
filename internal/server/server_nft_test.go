package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func enrollNamedNode(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID, name string) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"`+nodeID+`","name":"`+name+`"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll %s failed: %d", nodeID, res.StatusCode)
	}
}

func TestNFTInputsPersistAndPlanFromStoredState(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"node-a",
		"interface_name":"ens3",
		"wireguard_cidr":"10.66.0.9/24",
		"public_tcp":[443,80,443],
		"public_udp":[53],
		"wireguard_tcp":[9100,22],
		"wireguard_udp":[51820]
	}`, cookies, csrf)
	defer save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}
	var view struct {
		NodeID        string `json:"node_id"`
		NodeName      string `json:"node_name"`
		InterfaceName string `json:"interface_name"`
		WireGuardCIDR string `json:"wireguard_cidr"`
		PublicTCP     []int  `json:"public_tcp"`
		PublicUDP     []int  `json:"public_udp"`
	}
	if err := json.NewDecoder(save.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.NodeID != "node-a" || view.NodeName != "Node A" || view.InterfaceName != "ens3" {
		t.Fatalf("bad view: %+v", view)
	}
	if view.WireGuardCIDR != "10.66.0.0/24" || strings.Join(intsToStrings(view.PublicTCP), ",") != "80,443" || strings.Join(intsToStrings(view.PublicUDP), ",") != "53" {
		t.Fatalf("inputs were not normalized: %+v", view)
	}

	stored, ok := st.NFTInputs("node-a")
	if !ok {
		t.Fatal("stored nft inputs missing")
	}
	if stored.ID != "node-a" || stored.InterfaceName != "ens3" || stored.WireGuardCIDR != "10.66.0.0/24" {
		t.Fatalf("bad stored inputs: %+v", stored)
	}

	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan from stored inputs failed: %d", plan.StatusCode)
	}
	var approval model.Approval
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`destroy table inet lattice_guard`,
		`iifname "ens3" tcp dport { 80, 443 }`,
		`iifname "ens3" udp dport { 53 }`,
		`elements = { 10.66.0.0/24 }`,
	} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("plan missing %q:\n%s", want, approval.Plan)
		}
	}
}

func TestNFTPlanComposesIngressNetPolicyIntoGuard(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")
	setNodeIP(t, st, "node-a", "10.66.0.1/32", "203.0.113.10")
	setNodeIP(t, st, "node-b", "10.66.0.2/32", "198.51.100.2")

	save := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"node-a",
		"wireguard_cidr":"10.66.0.0/24",
		"wireguard_tcp":[1234]
	}`, cookies, csrf)
	save.Body.Close()
	if save.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", save.StatusCode)
	}
	policy := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"id":"deny-db",
			"action":"deny",
			"direction":"ingress",
			"protocol":"tcp",
			"ports":[1234],
			"remote":{"kind":"node","node_id":"node-b"}
		}]
	}`, cookies, csrf)
	policy.Body.Close()
	if policy.StatusCode != http.StatusOK {
		t.Fatalf("create ingress policy failed: %d", policy.StatusCode)
	}

	planRes := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", planRes.StatusCode)
	}
	var approval model.Approval
	if err := json.NewDecoder(planRes.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	if approval.Plugin != "nft" || !strings.Contains(approval.Plan, "table inet lattice_guard") || strings.Contains(approval.Plan, "table inet lattice_policy") {
		t.Fatalf("bad guard approval: %+v", approval)
	}
	deny := `ip saddr { 10.66.0.2, 198.51.100.2 } tcp dport { 1234 } drop comment "lattice rule deny-db"`
	allow := `ip saddr @wg_peers4 tcp dport { 1234 } accept comment "wg tcp services"`
	if !strings.Contains(approval.Plan, deny) || !strings.Contains(approval.Plan, allow) {
		t.Fatalf("guard plan missing deny or broad allow:\n%s", approval.Plan)
	}
	if strings.Index(approval.Plan, deny) > strings.Index(approval.Plan, allow) {
		t.Fatalf("ingress deny must precede broad allow:\n%s", approval.Plan)
	}
	if !auditMetadataSeen(st, "network.nft.plan", "ingress_rules", "1") {
		t.Fatalf("missing ingress_rules audit metadata: %+v", st.AuditEvents())
	}

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve failed: %d", approve.StatusCode)
	}
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("expected one queued guard task, got %+v", tasks)
	}
	task := tasks[0]
	if task.TimeoutSec != networkApplyTaskTimeoutSec {
		t.Fatalf("guard apply timeout = %d, want %d", task.TimeoutSec, networkApplyTaskTimeoutSec)
	}
	for _, needle := range []string{
		"guard.rollback.nft",
		"nft -f \"$CANDIDATE\"",
		"{ echo 'flush ruleset'; nft list ruleset; } > \"$ROLLBACK\"",
		"WATCHDOG_FIRED=/tmp/lattice-nft-watchdog.$$",
		"setsid sh -c",
		"assert_watchdog_clean",
		"refusing to mark apply verified",
		"--selfcheck-controlplane -server 'https://203.0.113.99'",
	} {
		if !strings.Contains(task.Script, needle) {
			t.Fatalf("guard apply script missing %q:\n%s", needle, task.Script)
		}
	}
	if strings.Contains(task.Script, "nft list ruleset > \"$ROLLBACK\"") {
		t.Fatalf("guard rollback snapshot must flush before replay:\n%s", task.Script)
	}
}

func TestNFTPlanRequiresNetPolicyReadWhenIngressIsComposed(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")
	setNodeIP(t, st, "node-a", "10.66.0.1/32", "203.0.113.10")
	setNodeIP(t, st, "node-b", "10.66.0.2/32", "198.51.100.2")
	policy := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"id":"deny-db",
			"action":"deny",
			"direction":"ingress",
			"protocol":"tcp",
			"ports":[1234],
			"remote":{"kind":"node","node_id":"node-b"}
		}]
	}`, cookies, csrf)
	policy.Body.Close()
	if policy.StatusCode != http.StatusOK {
		t.Fatalf("create ingress policy failed: %d", policy.StatusCode)
	}

	networkOnly := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, networkOnly)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("network-only token must not create policy-omitting guard plan, got %d", denied.StatusCode)
	}

	withRead := createPAT(t, handler, cookies, csrf, []string{"network:plan", "netpolicy:read"}, []string{"node-a"})
	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, withRead)
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("token with netpolicy:read should plan composed guard, got %d", allowed.StatusCode)
	}
}

func TestNFTInputsAllowlistEnforced(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	token := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-a"})
	deniedSave := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-b","public_tcp":[443]}`, token)
	defer deniedSave.Body.Close()
	if deniedSave.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not save node-b inputs, got %d", deniedSave.StatusCode)
	}

	allowedSave := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/inputs",
		`{"node_id":"node-a","public_tcp":[443]}`, token)
	defer allowedSave.Body.Close()
	if allowedSave.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted token should save node-a inputs, got %d", allowedSave.StatusCode)
	}

	list := doBearerJSON(t, handler, http.MethodGet, "/api/network/nft/inputs", `{}`, token)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list failed: %d", list.StatusCode)
	}
	var out struct {
		Inputs []struct {
			NodeID string `json:"node_id"`
		} `json:"inputs"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Inputs) != 1 || out.Inputs[0].NodeID != "node-a" {
		t.Fatalf("list did not filter by node allowlist: %+v", out.Inputs)
	}
}

func auditMetadataSeen(st interface{ AuditEvents() []model.AuditEvent }, action, key, value string) bool {
	for _, ev := range st.AuditEvents() {
		if ev.Action == action && ev.Metadata[key] == value {
			return true
		}
	}
	return false
}

func intsToStrings(values []int) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strconv.Itoa(v))
	}
	return out
}
