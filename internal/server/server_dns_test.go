package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newDNSServer(t *testing.T) (*Server, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "n1", Name: "tokyo-1", WireGuardIP: "10.66.0.1/32", PublicIP: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNode(model.Node{ID: "n2", Name: "la-1", WireGuardIP: "10.66.0.2/32", PublicIP: "198.51.100.9"}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), st
}

func TestDNSDeploymentCreateListHidesSecret(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"n1.dns.example.com",
		"cf_api_token":"super-secret-dns-token",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1","1.1.1.1"]}]
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", create.StatusCode)
	}
	var created map[string]any
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created["cf_api_token"] != nil {
		t.Fatalf("create response leaked token field: %+v", created)
	}
	if created["has_credential"] != true {
		t.Fatalf("create response should expose only has_credential: %+v", created)
	}
	if created["listen_port"].(float64) != 53 || created["exposure"] != model.DNSExposureMesh || created["status"] != model.DNSStatusPending {
		t.Fatalf("expected safe defaults in view: %+v", created)
	}

	id := created["id"].(string)
	stored, ok := st.DNSDeployment(id)
	if !ok || stored.CFAPIToken != "super-secret-dns-token" {
		t.Fatalf("token should persist server-side only: ok=%v dep=%+v", ok, stored)
	}
	if len(stored.Zones) != 1 || len(stored.Zones[0].Upstreams) != 1 || stored.Zones[0].Suffix != "." {
		t.Fatalf("zone should be normalized/de-duplicated: %+v", stored.Zones)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/dns/deployments", "", cookies, "")
	defer list.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(list.Body)
	if bytes.Contains(buf.Bytes(), []byte("super-secret-dns-token")) || bytes.Contains(buf.Bytes(), []byte("cf_api_token")) {
		t.Fatalf("dns deployment list leaked credential: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"has_credential":true`)) {
		t.Fatalf("expected has_credential flag: %s", buf.String())
	}
}

func TestDNSDeploymentValidatesConfig(t *testing.T) {
	_, handler, _ := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown engine",
			body: `{"name":"x","node_id":"n1","engine":"bind","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`,
		},
		{
			name: "bad upstream injection",
			body: `{"name":"x","node_id":"n1","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1\nmalicious"]}]}`,
		},
		{
			name: "public hostname without credential",
			body: `{"name":"x","node_id":"n1","hostname":"n1.dns.example.com","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`,
		},
		{
			name: "invalid static record",
			body: `{"name":"x","node_id":"n1","zones":[{"suffix":"mesh.local","mode":"static","records":[{"name":"gw.mesh.local","type":"A","value":"not-ip"}]}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", tc.body, cookies, csrf)
			defer res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", res.StatusCode)
			}
		})
	}
}

func TestDNSDeploymentUpdatePreservesSecret(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"n1.dns.example.com",
		"cf_api_token":"keep-me",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&created)
	create.Body.Close()
	update := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"id":"`+created.ID+`",
		"name":"renamed dns",
		"node_id":"n1",
		"hostname":"n1.dns.example.com",
		"zones":[{"suffix":".","mode":"forward","upstreams":["9.9.9.9"]}]
	}`, cookies, csrf)
	defer update.Body.Close()
	if update.StatusCode != http.StatusOK {
		t.Fatalf("update failed: %d", update.StatusCode)
	}
	stored, ok := st.DNSDeployment(created.ID)
	if !ok || stored.CFAPIToken != "keep-me" || stored.Name != "renamed dns" {
		t.Fatalf("update should preserve write-only token: ok=%v dep=%+v", ok, stored)
	}
}

func TestDNSDeploymentRequiresScopeAndAllowlist(t *testing.T) {
	_, handler, _ := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	mk := doJSON(t, handler, http.MethodPost, "/api/tokens", `{"name":"dns-n1","scopes":["dns:admin"],"server_allowlist":["n1"]}`, cookies, csrf)
	var tok struct {
		Token string `json:"token"`
	}
	json.NewDecoder(mk.Body).Decode(&tok)
	mk.Body.Close()

	body := `{"name":"private dns","node_id":"n2","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/dns/deployments", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must be forbidden on n2, got %d", rec.Result().StatusCode)
	}

	okBody := `{"name":"private dns","node_id":" n1 ","zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]}`
	okReq := httptest.NewRequest(http.MethodPost, "/api/dns/deployments", bytes.NewBufferString(okBody))
	okReq.Header.Set("Authorization", "Bearer "+tok.Token)
	okReq.Header.Set("Content-Type", "application/json")
	okRec := httptest.NewRecorder()
	handler.ServeHTTP(okRec, okReq)
	if okRec.Result().StatusCode != http.StatusOK {
		t.Fatalf("allowlisted token should accept trimmed n1, got %d", okRec.Result().StatusCode)
	}
}

func TestDNSDeploymentDelete(t *testing.T) {
	_, handler, _ := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&created)
	create.Body.Close()

	del := doJSON(t, handler, http.MethodPost, "/api/dns/deployments/delete", `{"id":"`+created.ID+`"}`, cookies, csrf)
	del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete failed: %d", del.StatusCode)
	}
	list := doJSON(t, handler, http.MethodGet, "/api/dns/deployments", "", cookies, "")
	defer list.Body.Close()
	var out struct {
		Deployments []map[string]any `json:"deployments"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Deployments) != 0 {
		t.Fatalf("expected no deployments after delete: %+v", out)
	}
}

func TestDNSPlanCreatesSecretFreeReviewApproval(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	saveInputs := doJSON(t, handler, http.MethodPost, "/api/network/nft/inputs", `{
		"node_id":"n1",
		"interface_name":"ens3",
		"wireguard_cidr":"10.66.0.0/24",
		"public_tcp":[443]
	}`, cookies, csrf)
	saveInputs.Body.Close()
	if saveInputs.StatusCode != http.StatusOK {
		t.Fatalf("save nft inputs failed: %d", saveInputs.StatusCode)
	}
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"n1.dns.example.com",
		"cf_api_token":"super-secret-dns-token",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1","9.9.9.9"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	create.Body.Close()

	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`"}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("dns plan failed: %d", planRes.StatusCode)
	}
	var approval model.Approval
	if err := json.NewDecoder(planRes.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	if approval.Plugin != "selfdns" || selfDNSApprovalDisplayAction(approval.Action) != selfDNSApplyAction || approval.NodeID != "n1" {
		t.Fatalf("bad approval: %+v", approval)
	}
	for _, want := range []string{
		"# Lattice Self-host DNS plan",
		"node_name: tokyo-1",
		"credential=true",
		"bind 10.66.0.1",
		"forward . 1.1.1.1 9.9.9.9",
		"nft inputs source: stored",
		`iifname "ens3" tcp dport { 443 }`,
		`ip saddr @wg_peers4 udp dport { 53 }`,
		`ip saddr @wg_peers4 tcp dport { 53 }`,
		"publish n1.dns.example.com",
	} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("approval plan missing %q:\n%s", want, approval.Plan)
		}
	}
	if strings.Contains(approval.Plan, "super-secret-dns-token") || strings.Contains(approval.Plan, "cf_api_token") {
		t.Fatalf("approval plan leaked secret material:\n%s", approval.Plan)
	}
	if !auditMetadataSeen(st, "dns.plan", "approval_id", approval.ID) {
		t.Fatalf("missing dns.plan audit metadata: %+v", st.AuditEvents())
	}

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("selfdns queue_apply failed: %d", approve.StatusCode)
	}
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("selfdns approval should queue one task: %+v", tasks)
	}
	task := tasks[0]
	if task.ApprovalID != approval.ID || len(task.Targets) != 1 || task.Targets[0] != "n1" {
		t.Fatalf("bad queued task: %+v", task)
	}
	queuedDep, ok := st.DNSDeployment(created.ID)
	if !ok || queuedDep.Status != model.DNSStatusApplying {
		t.Fatalf("deployment should be marked applying after queue: ok=%v dep=%+v", ok, queuedDep)
	}
	for _, want := range []string{
		"command -v coredns",
		"nft -c -f \"$NFT_CANDIDATE\"",
		"nft -f \"$NFT_CANDIDATE\"",
		"CONFIG_BACKUP=/etc/lattice/selfdns.rollback.$$",
		"lattice-selfdns.service",
		"systemctl is-active --quiet lattice-selfdns.service",
	} {
		if !strings.Contains(task.Script, want) {
			t.Fatalf("queued selfdns script missing %q:\n%s", want, task.Script)
		}
	}
}

func TestDNSPlanRequiresNetworkPlanScope(t *testing.T) {
	_, handler, _ := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(create.Body).Decode(&created)
	create.Body.Close()

	dnsOnly := createPAT(t, handler, cookies, csrf, []string{"dns:admin"}, []string{"n1"})
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`"}`, dnsOnly)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("dns-only token must not view firewall-bearing plan, got %d", denied.StatusCode)
	}

	withNetwork := createPAT(t, handler, cookies, csrf, []string{"dns:admin", "network:plan"}, []string{"n1"})
	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`"}`, withNetwork)
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("dns+network token should create plan, got %d", allowed.StatusCode)
	}
}

func TestDNSApplyResultUpdatesDeploymentStatus(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID, nodeToken := enrollNode(t, handler, cookies, csrf)
	node, ok := st.Node(nodeID)
	if !ok {
		t.Fatal("missing enrolled node")
	}
	node.Name = "tokyo-apply"
	node.WireGuardIP = "10.66.0.9/32"
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"`+nodeID+`",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	create.Body.Close()
	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`"}`, cookies, csrf)
	var approval model.Approval
	if err := json.NewDecoder(planRes.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	planRes.Body.Close()
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve failed: %d", approve.StatusCode)
	}
	applyingDep, ok := st.DNSDeployment(created.ID)
	if !ok || applyingDep.Status != model.DNSStatusApplying {
		t.Fatalf("deployment should be applying after queued approval: ok=%v dep=%+v", ok, applyingDep)
	}

	tasksReq := httptest.NewRequest(http.MethodGet, "/api/agent/tasks?node_id="+nodeID, nil)
	tasksReq.Header.Set("Authorization", "Bearer "+nodeToken)
	tasksRec := serveReq(handler, tasksReq)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d", tasksRec.Code)
	}
	var leased []map[string]any
	if err := json.NewDecoder(tasksRec.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 {
		t.Fatalf("expected one leased task, got %+v", leased)
	}
	taskID, _ := leased[0]["id"].(string)
	leaseID, _ := leased[0]["lease_id"].(string)
	result := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result",
		`{"node_id":"`+nodeID+`","result":{"task_id":"`+taskID+`","lease_id":"`+leaseID+`","exit_code":0,"stdout":"ok"}}`, nodeToken)
	if result.Code != http.StatusOK {
		t.Fatalf("task result failed: %d (%s)", result.Code, result.Body.String())
	}
	dep, ok := st.DNSDeployment(created.ID)
	if !ok {
		t.Fatal("dns deployment missing after apply")
	}
	if dep.Status != model.DNSStatusRunning || dep.LastAppliedAt.IsZero() || dep.LastError != "" {
		t.Fatalf("deployment not marked running: %+v", dep)
	}
	appliedApproval, ok := st.Approval(approval.ID)
	if !ok || appliedApproval.Status != model.ApprovalApplied {
		t.Fatalf("approval not marked applied: ok=%v approval=%+v", ok, appliedApproval)
	}
	if !auditMetadataSeen(st, "dns.apply.applied", "dns_id", created.ID) {
		t.Fatalf("missing dns.apply.applied audit: %+v", st.AuditEvents())
	}
}
