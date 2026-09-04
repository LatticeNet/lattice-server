package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/netguard"
)

// nftPlanResponse is the shape /api/network/nft/plan returns since the lockout
// lint was wired in: the approval plus the lint findings the operator has to
// read before approving a default-drop ruleset.
type nftPlanResponse struct {
	Approval model.Approval     `json:"approval"`
	Findings []netguard.Finding `json:"findings"`
}

// decodeNFTPlan unwraps a successful plan response. Tests that are not about
// lockout still have to pass the lint, so they either keep the node's
// management port in the plan or send accept_lockout_risk.
func decodeNFTPlan(t *testing.T, res *http.Response) model.Approval {
	t.Helper()
	var out nftPlanResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Approval
}

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

	// No accept_lockout_risk here on purpose: the stored inputs above list
	// tcp/22 in wireguard_tcp and the node reports ens3, so the composed chain
	// still has a path to the shell and this plan clears the lockout lint on
	// its own merits.
	seedNodeReality(t, st, "node-a", 22, "ens3")
	plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan from stored inputs failed: %d", plan.StatusCode)
	}
	approval := decodeNFTPlan(t, plan)
	for _, want := range []string{
		`delete table inet lattice_guard`,
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

	// The stored inputs above open tcp/1234 to the wireguard peers and nothing
	// else, so this really is a plan that would cut the node's shell. The test
	// is about ingress composition, not about lockout, so it accepts the risk
	// explicitly rather than pretending the plan is safe.
	planRes := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan",
		`{"node_id":"node-a","accept_lockout_risk":true}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", planRes.StatusCode)
	}
	approval := decodeNFTPlan(t, planRes)
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
		"{ echo 'add table inet lattice_guard'; echo 'delete table inet lattice_guard'; nft list table inet lattice_guard 2>/dev/null || true; } > \"$ROLLBACK\"",
		"WATCHDOG_FIRED=/tmp/lattice-nft-watchdog.$$",
		"setsid sh -c",
		"assert_watchdog_clean",
		"refusing to mark apply verified",
		"--selfcheck-controlplane -server 'https://203.0.113.99'",
		// A reboot used to drop the table while the store still said applied:
		// the committed file must be reloaded at boot, before the uplink is up
		// and after Debian's nftables.service has done its flush ruleset.
		"cat > /etc/systemd/system/lattice-guard-firewall.service <<'LATTICE_GUARD_UNIT_",
		"DefaultDependencies=no\nAfter=nftables.service\nWants=network-pre.target\nBefore=network-pre.target shutdown.target\n",
		"Type=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f /etc/lattice/guard.nft\n",
		"systemctl enable lattice-guard-firewall.service",
	} {
		if !strings.Contains(task.Script, needle) {
			t.Fatalf("guard apply script missing %q:\n%s", needle, task.Script)
		}
	}
	// The unit is installed only once the ruleset is committed and the file
	// is in place; enabling it before that would persist a candidate.
	if strings.Index(task.Script, "mv \"$CANDIDATE\" \"$ACTIVE\"") > strings.Index(task.Script, "systemctl enable lattice-guard-firewall.service") {
		t.Fatalf("boot unit must be installed after the ruleset is committed:\n%s", task.Script)
	}
	// Five fleet nodes carry Docker's iptables-nft tables and seven carry
	// lattice_knock; a rollback that flushes the ruleset takes them all down.
	if strings.Contains(task.Script, "flush ruleset") || strings.Contains(task.Script, "nft list ruleset") {
		t.Fatalf("guard rollback must touch only table inet lattice_guard:\n%s", task.Script)
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

	// This assertion used to grant netpolicy:read with the allowlist pinned to
	// node-a and expect 200. That encoded the target-only rule, which is the
	// defect: the policy's one rule names node-b as its remote, and compiling
	// it writes node-b's WireGuard IP and public IP into the ruleset this
	// endpoint returns. Reading node-a is not authority over node-b's
	// addresses. The assertion is corrected rather than the check relaxed, and
	// the target-only case is now asserted as a refusal directly below.
	readTargetOnly := createPAT(t, handler, cookies, csrf, []string{"network:plan", "netpolicy:read"}, []string{"node-a"})
	refused := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a"}`, readTargetOnly)
	refusedBody, _ := io.ReadAll(refused.Body)
	refused.Body.Close()
	if refused.StatusCode != http.StatusForbidden {
		t.Fatalf("netpolicy:read on the target alone must not compile a rule naming node-b, got %d", refused.StatusCode)
	}
	if strings.Contains(string(refusedBody), "node-b") {
		t.Fatalf("the refusal must report a count, never the node it protects: %s", refusedBody)
	}

	// accept_lockout_risk only on the case that has to reach 200: this node has
	// no stored inputs, so the composed chain accepts nothing. The two refusals
	// above deliberately omit it, which also pins the order: authorization is
	// decided before the lint, so a caller who may not read node-b gets 403
	// rather than a 409 that would leak that the plan compiled at all.
	withRead := createPAT(t, handler, cookies, csrf, []string{"network:plan", "netpolicy:read"}, []string{"node-a", "node-b"})
	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/network/nft/plan", `{"node_id":"node-a","accept_lockout_risk":true}`, withRead)
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("token that may read every node the rules name should plan composed guard, got %d", allowed.StatusCode)
	}
}

// This endpoint replaces the node's entire lattice_guard input chain, and that
// chain is policy drop, so whatever the plan does not accept is dropped. A
// caller-supplied ruleset that lists tcp/443 and nothing else severs the
// operator's shell the moment it is approved, and nothing downstream notices:
// the node-side apply verifies with an outbound control-plane selfcheck, which
// a default-drop input ruleset still permits, so the selfcheck passes, the
// dead-man watchdog is disarmed, and the ruleset commits permanently. The lint
// is the only check that catches it, and the port it protects comes from the
// node's reported reality, which is why sshd here is on 2222: a check pinned to
// tcp/22 would wave this plan through and lock the node out for good.
func TestNFTPlanBlocksLockoutRiskFromReportedReality(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	seedNodeShellReality(t, st, "node-a", 2222)

	res := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan",
		`{"node_id":"node-a","interface_name":"ens3","public_tcp":[443]}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("lockout-risk nft plan should be refused, got %d", res.StatusCode)
	}
	var out struct {
		Error    string             `json:"error"`
		Findings []netguard.Finding `json:"findings"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	var blocked *netguard.Finding
	for i, f := range out.Findings {
		if f.Code == netguard.FindingLockoutRiskSSH {
			blocked = &out.Findings[i]
		}
	}
	if blocked == nil {
		t.Fatalf("expected a %s finding, got %+v", netguard.FindingLockoutRiskSSH, out.Findings)
	}
	if blocked.Severity != netguard.SeverityBlock {
		t.Fatalf("lockout finding severity = %q want %q", blocked.Severity, netguard.SeverityBlock)
	}
	if !strings.Contains(blocked.Message, "tcp/2222") {
		t.Fatalf("finding should name the reported shell port, got %q", blocked.Message)
	}
	// A refused plan must not leave a pending approval behind for someone to
	// approve later.
	for _, a := range st.Approvals() {
		if a.Plugin == "nft" {
			t.Fatalf("refused nft plan still created approval %+v", a)
		}
	}
}

// The block is an override, not a wall: an operator who knows the node is
// reachable another way can still plan, and the override is audited so the
// decision is attributable afterwards.
func TestNFTPlanLockoutRiskOverrideIsAudited(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	seedNodeShellReality(t, st, "node-a", 2222)

	res := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan",
		`{"node_id":"node-a","interface_name":"ens3","public_tcp":[443],"accept_lockout_risk":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("accepted lockout risk should still plan, got %d", res.StatusCode)
	}
	var out nftPlanResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Approval.ID == "" || out.Approval.Action != "apply-ruleset" {
		t.Fatalf("expected an apply-ruleset approval, got %+v", out.Approval)
	}
	// The findings ride along with the approval so the reviewer reads the same
	// risk the planner accepted.
	if len(out.Findings) == 0 {
		t.Fatalf("accepted plan should still report its findings")
	}
	if !auditMetadataSeen(st, "network.nft.lockout_risk.accepted", "approval_id", out.Approval.ID) {
		t.Fatalf("override should be audited: %+v", st.AuditEvents())
	}
	if !auditMetadataSeen(st, "network.nft.plan", "lockout_risk_accepted", "true") {
		t.Fatalf("network.nft.plan audit should record the override: %+v", st.AuditEvents())
	}
}

// The question this path raises that the Network Guard path does not: here the
// caller supplies the ruleset rather than deriving it from a stored baseline.
// The lint still reads the management port from the node's reported reality,
// never from the plan's provenance, so a request that opens the port the node
// actually runs sshd on plans with no override at all. Without this the gate
// would be a toll booth every raw caller learns to pay, which is worse than no
// gate.
func TestNFTPlanAcceptsCallerSuppliedManagementPort(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	seedNodeReality(t, st, "node-a", 2222, "ens3")

	res := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan",
		`{"node_id":"node-a","interface_name":"ens3","public_tcp":[443,2222]}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("plan that keeps the reported shell port open should not be refused, got %d", res.StatusCode)
	}
	var out nftPlanResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, f := range out.Findings {
		if f.Code == netguard.FindingLockoutRiskSSH {
			t.Fatalf("tcp/2222 is open in this plan, lockout must not fire: %+v", f)
		}
		if f.Code == netguard.FindingManagementPortAssumed {
			t.Fatalf("the node reported sshd on 2222, the port must not be assumed: %+v", f)
		}
	}
	if auditMetadataSeen(st, "network.nft.plan", "lockout_risk_accepted", "true") {
		t.Fatalf("a plan that passed the lint must not be audited as an override: %+v", st.AuditEvents())
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
