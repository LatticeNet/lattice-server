package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/netguard"
	"github.com/LatticeNet/lattice-server/internal/selfdns"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type captureDNSProvider struct {
	ch chan ddns.Record
}

func (p *captureDNSProvider) Kind() string { return "capture" }

func (p *captureDNSProvider) SetRecord(ctx context.Context, r ddns.Record) error {
	select {
	case p.ch <- r:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newDNSServer(t *testing.T) (*Server, http.Handler, *store.Store) {
	return newDNSServerWithOptions(t, Options{})
}

func newDNSServerWithOptions(t *testing.T, opts Options) (*Server, http.Handler, *store.Store) {
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
	opts.Store = st
	opts.AdminPassword = testAdminPass
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), st
}

// dnsPlanResponse is the shape /api/dns/plan returns since the lockout lint was
// wired in: the approval plus the lint findings the operator has to read.
type dnsPlanResponse struct {
	Approval model.Approval     `json:"approval"`
	Findings []netguard.Finding `json:"findings"`
}

// decodeDNSPlan unwraps a successful plan response. Tests that are not about
// lockout still have to pass the lint, so they either seed a baseline that
// keeps the management port open or send accept_lockout_risk.
func decodeDNSPlan(t *testing.T, res *http.Response) model.Approval {
	t.Helper()
	var out dnsPlanResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Approval
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

func TestDNSDeploymentRequiresCloudflareDDNSProfile(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertDDNSProfile(model.DDNSProfile{
		ID:         "ddns_webhook",
		Name:       "webhook",
		NodeID:     "n1",
		Provider:   model.DDNSProviderWebhook,
		Domains:    []string{"old.example.com"},
		WebhookURL: "https://example.com/hook",
		EnableIPv4: true,
	}); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"n1.dns.example.com",
		"ddns_profile_id":"ddns_webhook",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-cloudflare profile must be rejected for dns publish, got %d", res.StatusCode)
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
		"public_tcp":[22,443]
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

	// No accept_lockout_risk here on purpose: the seeded baseline keeps tcp/22
	// open, so this plan has to clear the lockout lint on its own merits.
	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`"}`, cookies, csrf)
	defer planRes.Body.Close()
	if planRes.StatusCode != http.StatusOK {
		t.Fatalf("dns plan failed: %d", planRes.StatusCode)
	}
	approval := decodeDNSPlan(t, planRes)
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
		`iifname "ens3" tcp dport { 22, 443 }`,
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
	if task.TimeoutSec != networkApplyTaskTimeoutSec {
		t.Fatalf("selfdns apply timeout = %d, want %d", task.TimeoutSec, networkApplyTaskTimeoutSec)
	}
	queuedDep, ok := st.DNSDeployment(created.ID)
	if !ok || queuedDep.Status != model.DNSStatusApplying {
		t.Fatalf("deployment should be marked applying after queue: ok=%v dep=%+v", ok, queuedDep)
	}
	for _, want := range []string{
		"command -v coredns",
		"nft -c -f \"$NFT_CANDIDATE\"",
		"{ echo 'flush ruleset'; nft list ruleset; } > \"$NFT_ROLLBACK\"",
		"nft -f \"$NFT_CANDIDATE\"",
		"CONFIG_BACKUP=/etc/lattice/selfdns.rollback.$$",
		"WATCHDOG_FIRED=/tmp/lattice-selfdns-watchdog.$$",
		"setsid sh -c",
		"assert_watchdog_clean",
		"refusing to mark apply verified",
		"lattice-selfdns.service",
		"systemctl is-active --quiet lattice-selfdns.service",
	} {
		if !strings.Contains(task.Script, want) {
			t.Fatalf("queued selfdns script missing %q:\n%s", want, task.Script)
		}
	}
	if strings.Contains(task.Script, "nft list ruleset > \"$NFT_ROLLBACK\"") {
		t.Fatalf("selfdns rollback snapshot must flush before replay:\n%s", task.Script)
	}
}

func TestDNSPlanBindsPinnedCoreDNSBinaryIntoReviewedPlan(t *testing.T) {
	_, handler, st := newDNSServerWithOptions(t, Options{CoreDNSBinary: selfdns.CoreDNSBinarySource{
		Version: "1.12.4",
		URL:     "https://downloads.example.com/coredns-1.12.4-linux-amd64",
		SHA256:  strings.Repeat("b", 64),
	}})
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", create.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	plan := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`","accept_lockout_risk":true}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", plan.StatusCode)
	}
	approval := decodeDNSPlan(t, plan)
	for _, want := range []string{
		"## CoreDNS binary",
		"version: 1.12.4",
		"url: https://downloads.example.com/coredns-1.12.4-linux-amd64",
		"sha256: " + strings.Repeat("b", 64),
	} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("approval plan missing pinned coredns metadata %q:\n%s", want, approval.Plan)
		}
	}
	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("selfdns queue_apply failed: %d", approve.StatusCode)
	}
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("expected one selfdns task, got %+v", tasks)
	}
	for _, want := range []string{
		"COREDNS_URL='https://downloads.example.com/coredns-1.12.4-linux-amd64'",
		"COREDNS_SHA256='" + strings.Repeat("b", 64) + "'",
		"ExecStart=/usr/local/bin/coredns -conf /etc/lattice/selfdns/Corefile",
	} {
		if !strings.Contains(tasks[0].Script, want) {
			t.Fatalf("queued selfdns script missing pinned coredns install %q:\n%s", want, tasks[0].Script)
		}
	}
}

func TestDNSApproveRejectsStaleDeletedDeployment(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", create.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	plan := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`","accept_lockout_risk":true}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("plan failed: %d", plan.StatusCode)
	}
	approval := decodeDNSPlan(t, plan)
	if err := st.DeleteDNSDeployment(created.ID); err != nil {
		t.Fatal(err)
	}

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	if approve.StatusCode != http.StatusConflict {
		approve.Body.Close()
		t.Fatalf("stale selfdns approval should be rejected, got %d", approve.StatusCode)
	}
	approveErr := errorBodyFromResponse(t, approve)
	if approveErr.Error.Code != model.APIErrorApprovalStale {
		t.Fatalf("stale selfdns approval code = %q want %q", approveErr.Error.Code, model.APIErrorApprovalStale)
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
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`","accept_lockout_risk":true}`, dnsOnly)
	denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("dns-only token must not view firewall-bearing plan, got %d", denied.StatusCode)
	}

	withNetwork := createPAT(t, handler, cookies, csrf, []string{"dns:admin", "network:plan"}, []string{"n1"})
	allowed := doBearerJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`","accept_lockout_risk":true}`, withNetwork)
	allowed.Body.Close()
	if allowed.StatusCode != http.StatusOK {
		t.Fatalf("dns+network token should create plan, got %d", allowed.StatusCode)
	}
}

func TestDNSPublishUsesDDNSProviderAndRecordsStatus(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	fp := &fakeProvider{}
	var seen model.DDNSProfile
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		seen = p
		return fp, nil
	}
	node, ok := st.Node("n1")
	if !ok {
		t.Fatal("missing node")
	}
	node.PublicIP = "203.0.113.77"
	node.PublicIPv6 = "2001:db8::77"
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"gmami-jp1.dns.roobli.org",
		"cf_api_token":"super-secret-dns-token",
		"publish_ipv4":true,
		"publish_ipv6":true,
		"record_ttl":120,
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	create.Body.Close()

	publish := doJSON(t, handler, http.MethodPost, "/api/dns/publish", `{"id":"`+created.ID+`"}`, cookies, csrf)
	defer publish.Body.Close()
	body := new(bytes.Buffer)
	body.ReadFrom(publish.Body)
	if publish.StatusCode != http.StatusOK {
		t.Fatalf("publish failed: %d %s", publish.StatusCode, body.String())
	}
	if strings.Contains(body.String(), "super-secret-dns-token") || strings.Contains(body.String(), "cf_api_token") {
		t.Fatalf("publish response leaked secret: %s", body.String())
	}
	if seen.Provider != model.DDNSProviderCloudflare || seen.CFAPIToken != "super-secret-dns-token" ||
		len(seen.Domains) != 1 || seen.Domains[0] != "gmami-jp1.dns.roobli.org" || seen.TTL != 120 {
		t.Fatalf("bad publish profile: %+v", seen)
	}
	if len(fp.records) != 2 {
		t.Fatalf("expected A+AAAA publish records, got %+v", fp.records)
	}
	if fp.records[0].Name != "gmami-jp1.dns.roobli.org" || fp.records[0].TTL != 120 {
		t.Fatalf("bad record metadata: %+v", fp.records)
	}
	dep, ok := st.DNSDeployment(created.ID)
	if !ok {
		t.Fatal("stored deployment missing")
	}
	if dep.LastIPv4 != "203.0.113.77" || dep.LastIPv6 != "2001:db8::77" || dep.LastPublishError != "" || dep.LastPublishedAt.IsZero() {
		t.Fatalf("publish status not recorded: %+v", dep)
	}
	if !dep.LastAppliedAt.IsZero() || dep.LastError != "" {
		t.Fatalf("publish must not mutate service apply status: %+v", dep)
	}
	assertResponseAuditCorrelation(t, st, publish, "dns.publish", "dns:admin")
}

func TestDNSPublishReusesCloudflareDDNSProfileCredential(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	fp := &fakeProvider{}
	var seen model.DDNSProfile
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		seen = p
		return fp, nil
	}
	if err := st.UpsertDDNSProfile(model.DDNSProfile{
		ID:         "ddns_cf",
		Name:       "shared cf",
		NodeID:     "n1",
		Provider:   model.DDNSProviderCloudflare,
		Domains:    []string{"old.example.com"},
		CFAPIToken: "shared-token",
		EnableIPv4: true,
		EnableIPv6: true,
		MaxRetries: 3,
		TTL:        300,
		LastRunAt:  time.Now().UTC(),
		LastIPv4:   "198.51.100.1",
		LastIPv6:   "2001:db8::1",
		LastError:  "old",
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	node, _ := st.Node("n1")
	node.PublicIP = "203.0.113.88"
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"profile.dns.roobli.org",
		"ddns_profile_id":"ddns_cf",
		"publish_ipv4":true,
		"publish_ipv6":false,
		"record_ttl":60,
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	create.Body.Close()

	publish := doJSON(t, handler, http.MethodPost, "/api/dns/publish", `{"id":"`+created.ID+`"}`, cookies, csrf)
	publish.Body.Close()
	if publish.StatusCode != http.StatusOK {
		t.Fatalf("publish with profile failed: %d", publish.StatusCode)
	}
	if seen.CFAPIToken != "shared-token" || seen.Domains[0] != "profile.dns.roobli.org" || seen.TTL != 60 || seen.MaxRetries != 3 {
		t.Fatalf("dns publish did not build the expected profile: %+v", seen)
	}
	if len(fp.records) != 1 || fp.records[0].Type != "A" || fp.records[0].IP != "203.0.113.88" {
		t.Fatalf("bad publish records: %+v", fp.records)
	}
	shared, ok := st.DDNSProfile("ddns_cf")
	if !ok || shared.LastError != "old" || shared.LastIPv4 != "198.51.100.1" {
		t.Fatalf("dns publish must not mutate reusable ddns profile status: ok=%v profile=%+v", ok, shared)
	}
}

func TestDNSPublishFailureIsAuditedAndRecorded(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		t.Fatal("provider must not be constructed when no publishable IP exists")
		return nil, nil
	}
	node, _ := st.Node("n1")
	node.PublicIP = ""
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"hostname":"missing-ip.dns.roobli.org",
		"cf_api_token":"super-secret-dns-token",
		"publish_ipv4":true,
		"publish_ipv6":false,
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	create.Body.Close()

	publish := doJSON(t, handler, http.MethodPost, "/api/dns/publish", `{"id":"`+created.ID+`"}`, cookies, csrf)
	publish.Body.Close()
	if publish.StatusCode != http.StatusBadGateway {
		t.Fatalf("publish without node IPv4 should fail as upstream error, got %d", publish.StatusCode)
	}
	dep, ok := st.DNSDeployment(created.ID)
	if !ok || dep.LastPublishError == "" || dep.LastPublishedAt.IsZero() {
		t.Fatalf("publish failure should be recorded: ok=%v dep=%+v", ok, dep)
	}
	if dep.LastError != "" || !dep.LastAppliedAt.IsZero() {
		t.Fatalf("publish failure must not mutate service apply status: %+v", dep)
	}
	if !auditMetadataSeen(st, "dns.publish", "ok", "false") {
		t.Fatalf("publish failure should be audited: %+v", st.AuditEvents())
	}
}

func TestDNSPublishRunsOnNodeIPChange(t *testing.T) {
	srv, _, st := newDNSServer(t)
	cap := &captureDNSProvider{ch: make(chan ddns.Record, 1)}
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		return cap, nil
	}
	if err := st.UpsertDNSDeployment(model.DNSDeployment{
		ID:          "dns_auto",
		Name:        "auto dns",
		NodeID:      "n1",
		Engine:      model.DNSEngineCoreDNS,
		ListenPort:  53,
		EnableUDP:   true,
		EnableTCP:   true,
		Exposure:    model.DNSExposureMesh,
		Zones:       []model.DNSZone{{Suffix: ".", Mode: model.DNSZoneForward, Upstreams: []string{"1.1.1.1"}}},
		Hostname:    "auto.dns.roobli.org",
		PublishIPv4: true,
		CFAPIToken:  "auto-token",
		Status:      model.DNSStatusRunning,
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	srv.maybeTriggerDDNS("n1", "203.0.113.1", "", "203.0.113.99", "")
	select {
	case rec := <-cap.ch:
		if rec.Type != "A" || rec.Name != "auto.dns.roobli.org" || rec.IP != "203.0.113.99" {
			t.Fatalf("unexpected auto publish record: %+v", rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for automatic dns publish")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		dep, ok := st.DNSDeployment("dns_auto")
		if ok && dep.LastIPv4 == "203.0.113.99" && dep.LastPublishError == "" && !dep.LastPublishedAt.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("auto publish status not persisted: ok=%v dep=%+v", ok, dep)
		}
		time.Sleep(10 * time.Millisecond)
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
	planRes := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created.ID+`","accept_lockout_risk":true}`, cookies, csrf)
	approval := decodeDNSPlan(t, planRes)
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

// A DNS plan commits the node's whole lattice_guard input chain, and that chain
// is policy drop. On a node with no stored Network Guard baseline the composed
// ruleset accepts the DNS listener and nothing else, so approving it would cut
// the operator's shell, the resolver's own DoH listener, and every other
// service on the box. The node-side apply cannot notice: its post-commit
// selfcheck is an outbound connection, which a default-drop input ruleset still
// permits. The lint is the only thing that catches it, so the plan path has to
// run it. Reality drives the port, which is why sshd here is on 2222: a check
// hardcoded to tcp/22 would pass this plan and lock the node out for good.
func TestDNSPlanBlocksLockoutRiskFromReportedReality(t *testing.T) {
	_, handler, st := newDNSServer(t)
	seedNodeShellReality(t, st, "n1", 2222)
	cookies, csrf := loginSession(t, handler)
	created := createDNSDeployment(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created+`"}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("lockout-risk dns plan should be refused, got %d", res.StatusCode)
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
		if a.Plugin == "selfdns" {
			t.Fatalf("refused dns plan still created approval %+v", a)
		}
	}
}

// The block is an override, not a wall: an operator who knows the node is
// reachable another way can still plan, and the override is audited so the
// decision is attributable afterwards.
func TestDNSPlanLockoutRiskOverrideIsAudited(t *testing.T) {
	_, handler, st := newDNSServer(t)
	seedNodeShellReality(t, st, "n1", 2222)
	cookies, csrf := loginSession(t, handler)
	created := createDNSDeployment(t, handler, cookies, csrf)

	res := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+created+`","accept_lockout_risk":true}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("accepted lockout risk should still plan, got %d", res.StatusCode)
	}
	var out dnsPlanResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Approval.ID == "" {
		t.Fatalf("expected an approval, got %+v", out)
	}
	// The findings ride along with the approval so the reviewer reads the same
	// risk the planner accepted.
	if len(out.Findings) == 0 {
		t.Fatalf("accepted plan should still report its findings")
	}
	if !auditMetadataSeen(st, "dns.lockout_risk.accepted", "approval_id", out.Approval.ID) {
		t.Fatalf("override should be audited: %+v", st.AuditEvents())
	}
	if !auditMetadataSeen(st, "dns.plan", "lockout_risk_accepted", "true") {
		t.Fatalf("dns.plan audit should record the override: %+v", st.AuditEvents())
	}
}

// seedNodeShellReality gives a node a reported firewall reality whose only
// shell daemon listens on shellPort, so the lockout lint has evidence instead
// of the tcp/22 fallback. Shared with the raw nft plan tests: the lint reads
// the same node-scoped reality whatever endpoint composed the plan.
func seedNodeShellReality(t *testing.T, st *store.Store, nodeID string, shellPort int) {
	t.Helper()
	now := time.Now().UTC()
	// The store binds a reality snapshot to the node's enrolment identity, so
	// the seed reads it rather than assuming the node has none.
	node, ok := st.Node(nodeID)
	if !ok {
		t.Fatalf("seed reality: missing node %s", nodeID)
	}
	if _, _, err := st.UpsertGuardRealitySnapshot(node.LatticeIdentityUUID, store.GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID: nodeID,
			Listeners: []model.GuardListener{
				{Protocol: "tcp", Port: shellPort, Address: "0.0.0.0", Process: "sshd"},
			},
			CollectedAt: now,
		},
		ReceivedAt: now,
	}); err != nil {
		t.Fatalf("seed reality: %v", err)
	}
}

// createDNSDeployment creates a minimal mesh deployment on n1 and returns its id.
func createDNSDeployment(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) string {
	t.Helper()
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns",
		"node_id":"n1",
		"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	defer create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create deployment failed: %d", create.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	return created.ID
}
