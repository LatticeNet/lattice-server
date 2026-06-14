package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/netpolicy"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestNetPolicyCRUDAndGraph(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	create := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"comment":"deny db\ncontrol",
			"action":"deny",
			"direction":"egress",
			"protocol":"tcp",
			"ports":[1234,22,1234],
			"remote":{"kind":"node","node_id":"node-b"}
		}]
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create policy failed: %d", create.StatusCode)
	}
	var view struct {
		TargetNodeID   string          `json:"target_node_id"`
		TargetNodeName string          `json:"target_node_name"`
		Rules          []model.NetRule `json:"rules"`
	}
	if err := json.NewDecoder(create.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.TargetNodeID != "node-a" || view.TargetNodeName != "Node A" || len(view.Rules) != 1 {
		t.Fatalf("bad view: %+v", view)
	}
	if strings.Contains(view.Rules[0].Comment, "\n") || len(view.Rules[0].Ports) != 2 || view.Rules[0].Ports[0] != 22 || view.Rules[0].Ports[1] != 1234 {
		t.Fatalf("rule was not normalized: %+v", view.Rules[0])
	}
	if stored, ok := st.NetPolicy("node-a"); !ok || stored.ID != "node-a" || stored.Rules[0].Remote.NodeID != "node-b" {
		t.Fatalf("policy not stored: ok=%v stored=%+v", ok, stored)
	}

	graphRes := doJSON(t, handler, http.MethodGet, "/api/netpolicy/graph", "", cookies, "")
	defer graphRes.Body.Close()
	if graphRes.StatusCode != http.StatusOK {
		t.Fatalf("graph failed: %d", graphRes.StatusCode)
	}
	var graph netpolicy.Graph
	if err := json.NewDecoder(graphRes.Body).Decode(&graph); err != nil {
		t.Fatal(err)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].From != "node-a" || graph.Edges[0].To != "node-b" || graph.Edges[0].Action != model.NetRuleDeny {
		t.Fatalf("bad graph edges: %+v", graph.Edges)
	}

	del := doJSON(t, handler, http.MethodPost, "/api/netpolicy/delete", `{"target_node_id":"node-a"}`, cookies, csrf)
	defer del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete failed: %d", del.StatusCode)
	}
	if _, ok := st.NetPolicy("node-a"); ok {
		t.Fatal("policy should be deleted")
	}
}

func TestNetPolicyRejectsInvalidRule(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	res := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"action":"deny",
			"direction":"egress",
			"protocol":"any",
			"ports":[53],
			"remote":{"kind":"cidr","cidr":"2001:db8::/32"}
		}]
	}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid policy should be rejected, got %d", res.StatusCode)
	}
}

func TestNetPolicyAllowlistEnforced(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	adminA := createPAT(t, handler, cookies, csrf, []string{"netpolicy:read", "netpolicy:admin"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-b",
		"enabled":true,
		"rules":[{"action":"deny","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"any"}}]
	}`, adminA)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not write node-b policy, got %d", denied.StatusCode)
	}

	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{"action":"deny","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"any"}}]
	}`, adminA)
	defer allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted token should write node-a policy, got %d", allowed.StatusCode)
	}

	list := doBearerJSON(t, handler, http.MethodGet, "/api/netpolicy", "", adminA)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list failed: %d", list.StatusCode)
	}
	var out struct {
		Policies []struct {
			TargetNodeID string `json:"target_node_id"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) != 1 || out.Policies[0].TargetNodeID != "node-a" {
		t.Fatalf("list did not filter by allowlist: %+v", out.Policies)
	}
}

func TestNetPolicyPlanApproveAndResultUpdatesPolicy(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	nodeAToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")
	setNodeIP(t, st, "node-a", "10.66.0.1/32", "203.0.113.10")
	setNodeIP(t, st, "node-b", "10.66.0.2/32", "198.51.100.2")

	create := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"id":"deny-db",
			"action":"deny",
			"direction":"egress",
			"protocol":"tcp",
			"ports":[1234],
			"remote":{"kind":"node","node_id":"node-b"}
		}]
	}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create policy failed: %d", create.StatusCode)
	}

	planRes := doJSON(t, handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", planRes.StatusCode)
	}
	var approval approvalView
	if err := json.NewDecoder(planRes.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	if approval.Plugin != "nftpolicy" || approval.Action != "apply-ruleset" || !strings.Contains(approval.Plan, "table inet lattice_policy") {
		t.Fatalf("bad approval: %+v", approval)
	}
	sum := sha256.Sum256([]byte(approval.Plan))
	planSHA := hex.EncodeToString(sum[:])
	storedPolicy, ok := st.NetPolicy("node-a")
	if !ok || storedPolicy.LastPlanSHA != planSHA {
		t.Fatalf("LastPlanSHA not stored: ok=%v policy=%+v want=%s", ok, storedPolicy, planSHA)
	}

	approveBody := `{"approval_id":"` + approval.ID + `","queue_apply":true,"plan_sha256":"` + planSHA + `"}`
	approveRes := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve", approveBody, cookies, csrf)
	approveRes.Body.Close()
	if approveRes.StatusCode != http.StatusOK {
		t.Fatalf("approve failed: %d", approveRes.StatusCode)
	}
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("expected one queued task, got %+v", tasks)
	}
	task := tasks[0]
	if task.ApprovalID != approval.ID || len(task.Targets) != 1 || task.Targets[0] != "node-a" {
		t.Fatalf("task not linked to approval: %+v", task)
	}
	for _, needle := range []string{"policy.rollback.nft", "--selfcheck-controlplane", "https://203.0.113.99"} {
		if !strings.Contains(task.Script, needle) {
			t.Fatalf("apply script missing %q:\n%s", needle, task.Script)
		}
	}
	for _, needle := range []string{
		"systemctl disable --now lattice-nftpolicy-domain-refresh.timer",
		"/etc/cron.d/lattice-nftpolicy-domain-refresh",
		"rm -f /etc/lattice/nftpolicy-domain-refresh.sh",
	} {
		if !strings.Contains(task.Script, needle) {
			t.Fatalf("IPv4 apply script should clean stale domain refresher, missing %q:\n%s", needle, task.Script)
		}
	}
	if strings.Contains(task.Script, "--update-nft-domain-set") {
		t.Fatalf("IPv4 apply script must not install domain set updater:\n%s", task.Script)
	}
	if strings.Contains(strings.ToLower(task.Script), "bearer") {
		t.Fatalf("apply script must not embed bearer-token logic:\n%s", task.Script)
	}

	leaseReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id=node-a", nil)
	leaseReq.Header.Set("Authorization", "Bearer "+nodeAToken)
	leaseRec := serveReq(handler, leaseReq)
	if leaseRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d %s", leaseRec.Code, leaseRec.Body.String())
	}
	var leased []map[string]any
	if err := json.NewDecoder(leaseRec.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 {
		t.Fatalf("expected one leased task, got %+v", leased)
	}
	taskID, _ := leased[0]["id"].(string)
	leaseID, _ := leased[0]["lease_id"].(string)
	report := `{"node_id":"node-a","result":{"task_id":"` + taskID + `","lease_id":"` + leaseID + `","exit_code":0,"stdout":"applied"}}`
	resultRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", report, nodeAToken)
	if resultRec.Code != http.StatusOK {
		t.Fatalf("task result failed: %d %s", resultRec.Code, resultRec.Body.String())
	}
	appliedApproval, ok := st.Approval(approval.ID)
	if !ok || appliedApproval.Status != model.ApprovalApplied {
		t.Fatalf("approval not marked applied: ok=%v approval=%+v", ok, appliedApproval)
	}
	appliedPolicy, ok := st.NetPolicy("node-a")
	if !ok || appliedPolicy.LastAppliedAt.IsZero() || appliedPolicy.LastError != "" {
		t.Fatalf("policy not marked applied: ok=%v policy=%+v", ok, appliedPolicy)
	}
	if !auditActionSeen(st, "network.policy.applied") {
		t.Fatalf("missing network.policy.applied audit event: %+v", st.AuditEvents())
	}
}

func TestNetPolicyStalePlanCannotApproveOrMarkCurrentPolicyApplied(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	nodeAToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	createNetPolicy(t, handler, cookies, csrf, 22)
	planRes := doJSON(t, handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", planRes.StatusCode)
	}
	var staleApproval approvalView
	if err := json.NewDecoder(planRes.Body).Decode(&staleApproval); err != nil {
		t.Fatal(err)
	}
	staleSHA := sha256.Sum256([]byte(staleApproval.Plan))

	createNetPolicy(t, handler, cookies, csrf, 2222)
	changed, ok := st.NetPolicy("node-a")
	if !ok || changed.LastPlanSHA != "" || !strings.Contains(changed.LastError, "policy changed") {
		t.Fatalf("policy change should clear current plan hash: ok=%v policy=%+v", ok, changed)
	}
	approveOld := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+staleApproval.ID+`","queue_apply":true,"plan_sha256":"`+hex.EncodeToString(staleSHA[:])+`"}`, cookies, csrf)
	approveOld.Body.Close()
	if approveOld.StatusCode != http.StatusConflict {
		t.Fatalf("stale approval should be rejected, got %d", approveOld.StatusCode)
	}

	freshPlanRes := doJSON(t, handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer freshPlanRes.Body.Close()
	if freshPlanRes.StatusCode != http.StatusOK {
		t.Fatalf("fresh plan failed: %d", freshPlanRes.StatusCode)
	}
	var freshApproval approvalView
	if err := json.NewDecoder(freshPlanRes.Body).Decode(&freshApproval); err != nil {
		t.Fatal(err)
	}
	freshSHA := sha256.Sum256([]byte(freshApproval.Plan))
	approveFresh := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		`{"approval_id":"`+freshApproval.ID+`","queue_apply":true,"plan_sha256":"`+hex.EncodeToString(freshSHA[:])+`"}`, cookies, csrf)
	approveFresh.Body.Close()
	if approveFresh.StatusCode != http.StatusOK {
		t.Fatalf("fresh approve failed: %d", approveFresh.StatusCode)
	}

	createNetPolicy(t, handler, cookies, csrf, 3333)
	leaseReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id=node-a", nil)
	leaseReq.Header.Set("Authorization", "Bearer "+nodeAToken)
	leaseRec := serveReq(handler, leaseReq)
	if leaseRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d %s", leaseRec.Code, leaseRec.Body.String())
	}
	var leased []map[string]any
	if err := json.NewDecoder(leaseRec.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	taskID, _ := leased[0]["id"].(string)
	leaseID, _ := leased[0]["lease_id"].(string)
	report := `{"node_id":"node-a","result":{"task_id":"` + taskID + `","lease_id":"` + leaseID + `","exit_code":0,"stdout":"applied old plan"}}`
	resultRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", report, nodeAToken)
	if resultRec.Code != http.StatusOK {
		t.Fatalf("task result failed: %d %s", resultRec.Code, resultRec.Body.String())
	}
	appliedApproval, ok := st.Approval(freshApproval.ID)
	if !ok || appliedApproval.Status == model.ApprovalApplied {
		t.Fatalf("stale task result must not mark approval applied: ok=%v approval=%+v", ok, appliedApproval)
	}
	current, ok := st.NetPolicy("node-a")
	if !ok || current.LastAppliedAt.IsZero() == false || !strings.Contains(current.LastError, "stale netpolicy plan") {
		t.Fatalf("stale task result must not mark current policy applied: ok=%v policy=%+v", ok, current)
	}
}

func TestNetPolicyPlanRejectsIngressAndAcceptsHTTPSDomainPublicURL(t *testing.T) {
	handler, _ := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	create := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{"id":"ssh","action":"allow","direction":"ingress","protocol":"tcp","ports":[22],"remote":{"kind":"any"}}]
	}`, cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create ingress placeholder failed: %d", create.StatusCode)
	}
	plan := doJSON(t, handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, cookies, csrf)
	plan.Body.Close()
	if plan.StatusCode != http.StatusBadRequest {
		t.Fatalf("ingress policy should be rejected at plan time, got %d", plan.StatusCode)
	}

	domainHandler, domainStore := newTestServerWithPublicURL(t, "https://lattice.example.com")
	domainCookies, domainCSRF := loginSession(t, domainHandler)
	enrollNamedNodeToken(t, domainHandler, domainCookies, domainCSRF, "node-a", "Node A")
	domainCreate := doJSON(t, domainHandler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{"id":"deny","action":"deny","direction":"egress","protocol":"tcp","ports":[22],"remote":{"kind":"any"}}]
	}`, domainCookies, domainCSRF)
	domainCreate.Body.Close()
	if domainCreate.StatusCode != http.StatusOK {
		t.Fatalf("create domain policy failed: %d", domainCreate.StatusCode)
	}
	domainPlan := doJSON(t, domainHandler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, domainCookies, domainCSRF)
	defer domainPlan.Body.Close()
	if domainPlan.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS domain public_url should be accepted, got %d", domainPlan.StatusCode)
	}
	var domainApproval approvalView
	if err := json.NewDecoder(domainPlan.Body).Decode(&domainApproval); err != nil {
		t.Fatal(err)
	}
	if domainApproval.Plugin != "nftpolicy" || domainApproval.Action != "apply-ruleset" {
		t.Fatalf("bad domain approval: %+v", domainApproval)
	}
	storedBeforeApprove, ok := domainStore.Approval(domainApproval.ID)
	if !ok {
		t.Fatalf("stored domain approval missing")
	}
	if storedBeforeApprove.Action == domainApproval.Action || !strings.HasPrefix(storedBeforeApprove.Action, nftPolicyApplyActionPrefix) {
		t.Fatalf("stored approval action should bind public_url while view stays stable: stored=%q view=%q", storedBeforeApprove.Action, domainApproval.Action)
	}
	for _, needle := range []string{
		"set lattice_control4",
		"set lattice_control6",
		"ip daddr @lattice_control4 tcp dport 443 accept comment \"lattice control-plane domain\"",
		"ip6 daddr @lattice_control6 tcp dport 443 accept comment \"lattice control-plane domain6\"",
		"udp dport 53 accept comment \"lattice dns udp\"",
		"tcp dport 53 accept comment \"lattice dns tcp\"",
	} {
		if !strings.Contains(domainApproval.Plan, needle) {
			t.Fatalf("domain plan missing %q:\n%s", needle, domainApproval.Plan)
		}
	}
	if strings.Contains(domainApproval.Plan, "ip daddr lattice.example.com") {
		t.Fatalf("domain plan must not render hostname as an nft address literal:\n%s", domainApproval.Plan)
	}
	approveDomain := doJSON(t, domainHandler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{
			"approval_id": domainApproval.ID,
			"queue_apply": true,
			"plan_sha256": planSHA256(domainApproval.Plan),
		})), domainCookies, domainCSRF)
	approveDomain.Body.Close()
	if approveDomain.StatusCode != http.StatusOK {
		t.Fatalf("approve domain plan failed: %d", approveDomain.StatusCode)
	}
	scriptFromChangedServerURL := applyScriptForWithServer(storedBeforeApprove, "https://203.0.113.99")
	if !strings.Contains(scriptFromChangedServerURL, "--update-nft-domain-set -host 'lattice.example.com' -family inet -table lattice_policy -set lattice_control4 -set6 lattice_control6") ||
		!strings.Contains(scriptFromChangedServerURL, "--selfcheck-controlplane -server 'https://lattice.example.com'") {
		t.Fatalf("nftpolicy apply script must use the plan-bound public_url, not the current server setting:\n%s", scriptFromChangedServerURL)
	}
	domainTasks := domainStore.Tasks()
	if len(domainTasks) != 1 {
		t.Fatalf("expected one queued domain apply task, got %+v", domainTasks)
	}
	for _, needle := range []string{
		"AGENT_BIN=${LATTICE_AGENT_BIN:-lattice-agent}",
		"--update-nft-domain-set -host 'lattice.example.com' -family inet -table lattice_policy -set lattice_control4 -set6 lattice_control6",
		"--selfcheck-controlplane -server 'https://lattice.example.com'",
		"/etc/lattice/nftpolicy-domain-refresh.sh",
		"lattice-nftpolicy-domain-refresh.service",
		"lattice-nftpolicy-domain-refresh.timer",
		"/run/systemd/system",
		"OnUnitActiveSec=60s",
		"chmod 0700 '/etc/lattice/nftpolicy-domain-refresh.sh'",
		"chmod 0644 '/etc/systemd/system/lattice-nftpolicy-domain-refresh.service' '/etc/systemd/system/lattice-nftpolicy-domain-refresh.timer'",
		"systemctl enable --now lattice-nftpolicy-domain-refresh.timer",
		"/etc/cron.d/lattice-nftpolicy-domain-refresh",
		"* * * * * root /etc/lattice/nftpolicy-domain-refresh.sh >/dev/null 2>&1",
		"chmod 0644 '/etc/cron.d/lattice-nftpolicy-domain-refresh'",
		"periodic domain refresh cron installed",
		"no systemd runtime or /etc/cron.d; periodic domain refresh scheduler skipped",
	} {
		if !strings.Contains(domainTasks[0].Script, needle) {
			t.Fatalf("domain apply script missing %q:\n%s", needle, domainTasks[0].Script)
		}
	}
	for _, forbidden := range []string{"getent", "awk", "CONTROL4="} {
		if strings.Contains(domainTasks[0].Script, forbidden) {
			t.Fatalf("domain apply script must not use shell DNS pipeline %q:\n%s", forbidden, domainTasks[0].Script)
		}
	}

	httpHandler, _ := newTestServerWithPublicURL(t, "http://203.0.113.99")
	httpCookies, httpCSRF := loginSession(t, httpHandler)
	enrollNamedNodeToken(t, httpHandler, httpCookies, httpCSRF, "node-a", "Node A")
	createNetPolicy(t, httpHandler, httpCookies, httpCSRF, 22)
	httpPlan := doJSON(t, httpHandler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, httpCookies, httpCSRF)
	httpPlan.Body.Close()
	if httpPlan.StatusCode != http.StatusBadRequest {
		t.Fatalf("remote cleartext public_url should be rejected for MVP, got %d", httpPlan.StatusCode)
	}

	httpDomainHandler, _ := newTestServerWithPublicURL(t, "http://lattice.example.com")
	httpDomainCookies, httpDomainCSRF := loginSession(t, httpDomainHandler)
	enrollNamedNodeToken(t, httpDomainHandler, httpDomainCookies, httpDomainCSRF, "node-a", "Node A")
	createNetPolicy(t, httpDomainHandler, httpDomainCookies, httpDomainCSRF, 22)
	httpDomainPlan := doJSON(t, httpDomainHandler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, httpDomainCookies, httpDomainCSRF)
	httpDomainPlan.Body.Close()
	if httpDomainPlan.StatusCode != http.StatusBadRequest {
		t.Fatalf("HTTP domain public_url should be rejected, got %d", httpDomainPlan.StatusCode)
	}

	ipv6Handler, ipv6Store := newTestServerWithPublicURL(t, "https://[2001:db8::99]:8443")
	ipv6Cookies, ipv6CSRF := loginSession(t, ipv6Handler)
	enrollNamedNodeToken(t, ipv6Handler, ipv6Cookies, ipv6CSRF, "node-a", "Node A")
	createNetPolicy(t, ipv6Handler, ipv6Cookies, ipv6CSRF, 22)
	ipv6Plan := doJSON(t, ipv6Handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, ipv6Cookies, ipv6CSRF)
	defer ipv6Plan.Body.Close()
	if ipv6Plan.StatusCode != http.StatusOK {
		t.Fatalf("IPv6 literal public_url should be accepted, got %d", ipv6Plan.StatusCode)
	}
	var ipv6Approval approvalView
	if err := json.NewDecoder(ipv6Plan.Body).Decode(&ipv6Approval); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipv6Approval.Plan, "ip6 daddr 2001:db8::99 tcp dport 8443 accept comment \"lattice control-plane\"") {
		t.Fatalf("IPv6 literal plan missing ip6 control-plane allow:\n%s", ipv6Approval.Plan)
	}
	storedIPv6Approval, ok := ipv6Store.Approval(ipv6Approval.ID)
	if !ok {
		t.Fatalf("stored IPv6 approval missing")
	}
	ipv6Script := applyScriptForWithServer(storedIPv6Approval, "https://203.0.113.99")
	if !strings.Contains(ipv6Script, "--selfcheck-controlplane -server 'https://[2001:db8::99]:8443'") {
		t.Fatalf("IPv6 apply script must use plan-bound public_url:\n%s", ipv6Script)
	}
	if strings.Contains(ipv6Script, "--update-nft-domain-set") {
		t.Fatalf("IPv6 literal apply script must not install domain updater:\n%s", ipv6Script)
	}

	httpIPv6Handler, _ := newTestServerWithPublicURL(t, "http://[2001:db8::99]")
	httpIPv6Cookies, httpIPv6CSRF := loginSession(t, httpIPv6Handler)
	enrollNamedNodeToken(t, httpIPv6Handler, httpIPv6Cookies, httpIPv6CSRF, "node-a", "Node A")
	createNetPolicy(t, httpIPv6Handler, httpIPv6Cookies, httpIPv6CSRF, 22)
	httpIPv6Plan := doJSON(t, httpIPv6Handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, httpIPv6Cookies, httpIPv6CSRF)
	httpIPv6Plan.Body.Close()
	if httpIPv6Plan.StatusCode != http.StatusBadRequest {
		t.Fatalf("remote cleartext IPv6 public_url should be rejected, got %d", httpIPv6Plan.StatusCode)
	}
}

func TestNetPolicyPlanBindsOperatorDomainRemoteSets(t *testing.T) {
	handler, st := newTestServerWithPublicURL(t, "https://203.0.113.99")
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	create := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"id":"allow-api",
			"action":"allow",
			"direction":"egress",
			"protocol":"tcp",
			"ports":[443],
			"remote":{"kind":"domain","domain":"API.Example.COM."}
		}]
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create domain remote policy failed: %d", create.StatusCode)
	}
	var policyView netPolicyView
	if err := json.NewDecoder(create.Body).Decode(&policyView); err != nil {
		t.Fatal(err)
	}
	if got := policyView.Rules[0].Remote.Domain; got != "api.example.com" {
		t.Fatalf("domain remote not normalized: %q", got)
	}
	planRes := doJSON(t, handler, http.MethodPost, "/api/netpolicy/plan", `{"node_id":"node-a"}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("plan domain remote policy failed: %d", planRes.StatusCode)
	}
	var approval approvalView
	if err := json.NewDecoder(planRes.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	stored, ok := st.Approval(approval.ID)
	if !ok {
		t.Fatal("stored approval missing")
	}
	payload, err := nftPolicyApprovalPayload(stored, "")
	if err != nil {
		t.Fatal(err)
	}
	if payload.PublicURL != "https://203.0.113.99" || len(payload.DomainSets) != 1 || payload.DomainSets[0].Host != "api.example.com" {
		t.Fatalf("bad action payload: %+v", payload)
	}
	set := payload.DomainSets[0]
	for _, needle := range []string{
		"set " + set.Set4,
		"set " + set.Set6,
		"ip daddr @" + set.Set4 + " tcp dport 443 accept comment \"lattice rule allow-api\"",
		"ip6 daddr @" + set.Set6 + " tcp dport 443 accept comment \"lattice rule allow-api\"",
	} {
		if !strings.Contains(approval.Plan, needle) {
			t.Fatalf("domain remote plan missing %q:\n%s", needle, approval.Plan)
		}
	}
	if strings.Contains(approval.Plan, "API.Example.COM") || strings.Contains(approval.Plan, "api.example.com tcp dport") {
		t.Fatalf("domain remote plan must not render hostname as an nft address literal:\n%s", approval.Plan)
	}
	script := applyScriptForWithServer(stored, "https://198.51.100.1")
	for _, needle := range []string{
		"--update-nft-domain-set -host 'api.example.com' -family inet -table lattice_policy -set " + set.Set4 + " -set6 " + set.Set6,
		"--selfcheck-controlplane -server 'https://203.0.113.99'",
		"/etc/lattice/nftpolicy-domain-refresh.sh",
		"lattice-nftpolicy-domain-refresh.timer",
		"/etc/cron.d/lattice-nftpolicy-domain-refresh",
		"periodic domain refresh cron installed",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("domain remote apply script missing %q:\n%s", needle, script)
		}
	}
	if strings.Contains(script, "lattice_control4") || strings.Contains(script, "lattice_control6") {
		t.Fatalf("IPv4 control-plane plus operator domain remote should not install control-plane domain sets:\n%s", script)
	}
}

func newTestServerWithPublicURL(t *testing.T, publicURL string) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, PublicURL: publicURL})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler(), st
}

func enrollNamedNodeToken(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID, name string) string {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/enroll-token",
		`{"node_id":"`+nodeID+`","name":"`+name+`"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enroll %s failed: %d", nodeID, res.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" {
		t.Fatal("expected node token")
	}
	return out.Token
}

func createNetPolicy(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string, port int) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/netpolicy", `{
		"target_node_id":"node-a",
		"enabled":true,
		"rules":[{
			"id":"deny",
			"action":"deny",
			"direction":"egress",
			"protocol":"tcp",
			"ports":[`+strconv.Itoa(port)+`],
			"remote":{"kind":"any"}
		}]
	}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create policy on port %d failed: %d", port, res.StatusCode)
	}
}

func setNodeIP(t *testing.T, st *store.Store, nodeID, wgIP, publicIP string) {
	t.Helper()
	node, ok := st.Node(nodeID)
	if !ok {
		t.Fatalf("missing node %s", nodeID)
	}
	node.WireGuardIP = wgIP
	node.PublicIP = publicIP
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
}

func auditActionSeen(st *store.Store, action string) bool {
	for _, ev := range st.AuditEvents() {
		if ev.Action == action {
			return true
		}
	}
	return false
}
