package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestProxyInboundAndUserViewsHideSecrets(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	createInbound := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", `{
		"id":"in-reality-443",
		"name":"VLESS Reality 443",
		"core":"sing-box",
		"protocol":"vless",
		"listen":"::",
		"port":443,
		"transport":"tcp",
		"security":"reality",
		"sni":"Cdn.Example.COM",
		"alpn":["h2","http/1.1","h2"],
		"reality_private_key":"super-secret-reality-private-key",
		"reality_public_key":"public-reality-key-123456",
		"reality_short_ids":["AA","aa","0123456789abcdef"],
		"reality_dest":"www.microsoft.com:443",
		"enabled":true
	}`, cookies, csrf)
	defer createInbound.Body.Close()
	if createInbound.StatusCode != http.StatusOK {
		t.Fatalf("create inbound failed: %d", createInbound.StatusCode)
	}
	inBody := new(bytes.Buffer)
	inBody.ReadFrom(createInbound.Body)
	if bytes.Contains(inBody.Bytes(), []byte("super-secret-reality-private-key")) || bytes.Contains(inBody.Bytes(), []byte(`"reality_private_key"`)) {
		t.Fatalf("inbound view leaked private key: %s", inBody.String())
	}
	if !bytes.Contains(inBody.Bytes(), []byte(`"has_reality_private_key":true`)) {
		t.Fatalf("inbound view should expose only has_reality_private_key: %s", inBody.String())
	}
	if !bytes.Contains(inBody.Bytes(), []byte(`"sni":"cdn.example.com"`)) {
		t.Fatalf("sni should be normalized: %s", inBody.String())
	}
	if stored, ok := st.ProxyInbound("in-reality-443"); !ok || stored.RealityPrivateKey != "super-secret-reality-private-key" || len(stored.ALPN) != 2 || stored.RealityShortIDs[0] != "aa" {
		t.Fatalf("secret should persist server-side only and lists should normalize: ok=%v inbound=%+v", ok, stored)
	}

	createUser := doJSON(t, handler, http.MethodPost, "/api/proxy/users", `{
		"id":"alice",
		"name":"Alice",
		"enabled":true,
		"uuid":"11111111-1111-4111-8111-111111111111",
		"password":"proxy-password-secret",
		"sub_token":"sub-token-secret-abcdefghijklmnopqrstuvwxyz",
		"inbound_ids":["in-reality-443","in-reality-443"],
		"traffic_limit_bytes":12345
	}`, cookies, csrf)
	defer createUser.Body.Close()
	if createUser.StatusCode != http.StatusOK {
		t.Fatalf("create user failed: %d", createUser.StatusCode)
	}
	userBody := new(bytes.Buffer)
	userBody.ReadFrom(createUser.Body)
	for _, leak := range []string{"11111111-1111-4111-8111-111111111111", "proxy-password-secret", "sub-token-secret-abcdefghijklmnopqrstuvwxyz", `"uuid"`, `"password"`, `"sub_token"`} {
		if bytes.Contains(userBody.Bytes(), []byte(leak)) {
			t.Fatalf("user view leaked secret %q: %s", leak, userBody.String())
		}
	}
	for _, field := range []string{`"has_uuid":true`, `"has_password":true`, `"has_sub_token":true`} {
		if !bytes.Contains(userBody.Bytes(), []byte(field)) {
			t.Fatalf("user view missing %s: %s", field, userBody.String())
		}
	}
	if stored, ok := st.ProxyUser("alice"); !ok || stored.UUID != "11111111-1111-4111-8111-111111111111" || stored.Password != "proxy-password-secret" || stored.SubToken == "" || len(stored.InboundIDs) != 1 {
		t.Fatalf("user secrets should persist server-side only: ok=%v user=%+v", ok, stored)
	}

	listUsers := doJSON(t, handler, http.MethodGet, "/api/proxy/users", "", cookies, "")
	defer listUsers.Body.Close()
	listBody := new(bytes.Buffer)
	listBody.ReadFrom(listUsers.Body)
	for _, leak := range []string{"11111111-1111-4111-8111-111111111111", "proxy-password-secret", "sub-token-secret-abcdefghijklmnopqrstuvwxyz"} {
		if bytes.Contains(listBody.Bytes(), []byte(leak)) {
			t.Fatalf("user list leaked secret %q: %s", leak, listBody.String())
		}
	}
}

func TestProxyUpdatePreservesWriteOnlySecrets(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	create := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", proxyInboundBody("in-a", "First"), cookies, csrf)
	create.Body.Close()
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create inbound failed: %d", create.StatusCode)
	}
	update := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", `{
		"id":"in-a",
		"name":"Renamed",
		"core":"sing-box",
		"protocol":"vless",
		"port":8443,
		"transport":"tcp",
		"security":"reality",
		"reality_public_key":"public-reality-key-123456",
		"reality_short_ids":["bb"],
		"reality_dest":"www.microsoft.com:443",
		"enabled":true
	}`, cookies, csrf)
	defer update.Body.Close()
	if update.StatusCode != http.StatusOK {
		t.Fatalf("update inbound failed: %d", update.StatusCode)
	}
	if stored, ok := st.ProxyInbound("in-a"); !ok || stored.RealityPrivateKey != "super-secret-reality-private-key" || stored.Name != "Renamed" || stored.Port != 8443 {
		t.Fatalf("update should preserve write-only private key: ok=%v inbound=%+v", ok, stored)
	}

	bad := doJSON(t, handler, http.MethodPost, "/api/proxy/profiles", `{
		"node_id":"node-a",
		"core":"sing-box",
		"inbound_ids":["in-a"],
		"config_path":"/etc/sing-box/config.json;touch /tmp/pwn"
	}`, cookies, csrf)
	defer bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsafe profile path should be rejected, got %d", bad.StatusCode)
	}
}

func TestProxyProfilesRespectNodeAllowlist(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNode(t, handler, cookies, csrf, "node-b", "Node B")

	createInbound := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", proxyInboundBody("in-a", "Inbound A"), cookies, csrf)
	createInbound.Body.Close()
	if createInbound.StatusCode != http.StatusOK {
		t.Fatalf("create inbound failed: %d", createInbound.StatusCode)
	}

	tokenA := createPAT(t, handler, cookies, csrf, []string{"proxy:read", "proxy:admin"}, []string{"node-a"})
	deniedGlobal := doBearerJSON(t, handler, http.MethodGet, "/api/proxy/inbounds", "", tokenA)
	deniedGlobal.Body.Close()
	if deniedGlobal.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not read global inbounds, got %d", deniedGlobal.StatusCode)
	}

	deniedProfile := doBearerJSON(t, handler, http.MethodPost, "/api/proxy/profiles", `{
		"node_id":"node-b",
		"core":"sing-box",
		"inbound_ids":["in-a"]
	}`, tokenA)
	deniedProfile.Body.Close()
	if deniedProfile.StatusCode != http.StatusForbidden {
		t.Fatalf("allowlisted token must not write node-b profile, got %d", deniedProfile.StatusCode)
	}

	allowedProfile := doBearerJSON(t, handler, http.MethodPost, "/api/proxy/profiles", `{
		"node_id":"node-a",
		"core":"sing-box",
		"inbound_ids":["in-a"],
		"hostname":"Node-A.Dns.Example.COM",
		"listen_ip":"10.66.0.1",
		"config_path":"/etc/sing-box/config.json",
		"stats_api":"127.0.0.1:9090"
	}`, tokenA)
	defer allowedProfile.Body.Close()
	if allowedProfile.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted token should write node-a profile, got %d", allowedProfile.StatusCode)
	}
	var profile proxyNodeProfileView
	if err := json.NewDecoder(allowedProfile.Body).Decode(&profile); err != nil {
		t.Fatal(err)
	}
	if profile.NodeID != "node-a" || profile.NodeName != "Node A" || profile.Hostname != "node-a.dns.example.com" {
		t.Fatalf("bad profile view: %+v", profile)
	}

	adminProfile := doJSON(t, handler, http.MethodPost, "/api/proxy/profiles", `{
		"node_id":"node-b",
		"core":"sing-box",
		"inbound_ids":["in-a"]
	}`, cookies, csrf)
	adminProfile.Body.Close()
	if adminProfile.StatusCode != http.StatusOK {
		t.Fatalf("admin should write node-b profile, got %d", adminProfile.StatusCode)
	}

	list := doBearerJSON(t, handler, http.MethodGet, "/api/proxy/profiles", "", tokenA)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		t.Fatalf("profile list failed: %d", list.StatusCode)
	}
	var out struct {
		Profiles []proxyNodeProfileView `json:"profiles"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Profiles) != 1 || out.Profiles[0].NodeID != "node-a" {
		t.Fatalf("profile list did not filter by allowlist: %+v", out.Profiles)
	}
}

func TestProxyInboundDeleteRejectsReferencedInbound(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")

	createInbound := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", proxyInboundBody("in-a", "Inbound A"), cookies, csrf)
	createInbound.Body.Close()
	if createInbound.StatusCode != http.StatusOK {
		t.Fatalf("create inbound failed: %d", createInbound.StatusCode)
	}
	createProfile := doJSON(t, handler, http.MethodPost, "/api/proxy/profiles", `{
		"node_id":"node-a",
		"core":"sing-box",
		"inbound_ids":["in-a"]
	}`, cookies, csrf)
	createProfile.Body.Close()
	if createProfile.StatusCode != http.StatusOK {
		t.Fatalf("create profile failed: %d", createProfile.StatusCode)
	}

	rejected := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds/delete", `{"id":"in-a"}`, cookies, csrf)
	rejected.Body.Close()
	if rejected.StatusCode != http.StatusConflict {
		t.Fatalf("referenced inbound delete should conflict, got %d", rejected.StatusCode)
	}
	forced := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds/delete", `{"id":"in-a","force":true}`, cookies, csrf)
	forced.Body.Close()
	if forced.StatusCode != http.StatusOK {
		t.Fatalf("forced delete failed: %d", forced.StatusCode)
	}
}

func TestProxyPlanCreatesSecretFreeApproval(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	plan := doJSON(t, handler, http.MethodPost, "/api/proxy/nodes/node-a/plan", `{}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("proxy plan failed: %d", plan.StatusCode)
	}
	var approval approvalView
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	if approval.Plugin != proxyCorePlugin || approval.Action != proxyCoreApplyAction || approval.NodeID != "node-a" {
		t.Fatalf("bad proxy approval view: %+v", approval)
	}
	for _, leak := range []string{
		"super-secret-reality-private-key",
		"11111111-1111-4111-8111-111111111111",
		"proxy-password-secret",
		"sub-token-secret-abcdefghijklmnopqrstuvwxyz",
		`"private_key": "super-secret-reality-private-key"`,
		`"uuid": "11111111-1111-4111-8111-111111111111"`,
	} {
		if strings.Contains(approval.Plan, leak) {
			t.Fatalf("proxy plan leaked secret %q:\n%s", leak, approval.Plan)
		}
	}
	for _, want := range []string{
		"artifact_sha256:",
		"secret_handling:",
		`"private_key": "<redacted>"`,
		`"uuid": "<redacted>"`,
		`"type": "vless"`,
	} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("proxy plan missing %q:\n%s", want, approval.Plan)
		}
	}
	stored, ok := st.Approval(approval.ID)
	if !ok {
		t.Fatalf("stored approval not found")
	}
	configSHA, err := proxyCoreApprovalConfigSHA(stored)
	if err != nil {
		t.Fatal(err)
	}
	if configSHA == "" || !strings.Contains(approval.Plan, configSHA) {
		t.Fatalf("approval did not bind config sha: action=%q plan=\n%s", stored.Action, approval.Plan)
	}

	approveQueue := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	defer approveQueue.Body.Close()
	if approveQueue.StatusCode != http.StatusOK {
		t.Fatalf("proxycore queue_apply failed: %d", approveQueue.StatusCode)
	}
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("proxycore queue_apply should create one task: %+v", tasks)
	}
	task := tasks[0]
	if task.ApprovalID != approval.ID || len(task.Targets) != 1 || task.Targets[0] != "node-a" {
		t.Fatalf("bad proxycore task: %+v", task)
	}
	for _, want := range []string{
		"cat > '/etc/sing-box/config.json.lattice-new'",
		"BACKUP='/etc/sing-box/config.json.lattice-prev'",
		"restore_target()",
		"restart_after_restore()",
		"trap 'cleanup_candidate; restore_target; restart_after_restore' ERR",
		"sing-box check -c \"$CANDIDATE\"",
		"cp -p \"$TARGET\" \"$BACKUP\"",
		"mv -f \"$CANDIDATE\" \"$TARGET\"",
		"systemctl reload sing-box",
		"service sing-box reload",
		"no supported service manager found",
		"super-secret-reality-private-key",
		"11111111-1111-4111-8111-111111111111",
	} {
		if !strings.Contains(task.Script, want) {
			t.Fatalf("proxycore task script missing %q:\n%s", want, task.Script)
		}
	}
	for _, bad := range []string{"apply support is not implemented", "restart sing-box manually", "cat > $CANDIDATE"} {
		if strings.Contains(task.Script, bad) {
			t.Fatalf("proxycore task script contains unsafe/stale fragment %q:\n%s", bad, task.Script)
		}
	}

	listTasks := doJSON(t, handler, http.MethodGet, "/api/tasks", "", cookies, "")
	defer listTasks.Body.Close()
	if listTasks.StatusCode != http.StatusOK {
		t.Fatalf("task list failed: %d", listTasks.StatusCode)
	}
	var visible []map[string]any
	if err := json.NewDecoder(listTasks.Body).Decode(&visible); err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 {
		t.Fatalf("expected one visible task, got %+v", visible)
	}
	if _, leaked := visible[0]["script"]; leaked {
		t.Fatalf("control-plane task view leaked script: %+v", visible[0])
	}

	tasksRec := doAgentRaw(t, handler, http.MethodGet, "/api/agent/tasks?node_id=node-a", "", nodeToken)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d (%s)", tasksRec.Code, tasksRec.Body.String())
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
	if taskID == "" || leaseID == "" {
		t.Fatalf("leased task missing id/lease: %+v", leased[0])
	}
	result := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result",
		`{"node_id":"node-a","result":{"task_id":"`+taskID+`","lease_id":"`+leaseID+`","exit_code":0,"stdout":"ok"}}`, nodeToken)
	if result.Code != http.StatusOK {
		t.Fatalf("task result failed: %d (%s)", result.Code, result.Body.String())
	}
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok || profile.AppliedSHA256 != configSHA || profile.LastApplyAt.IsZero() || profile.LastError != "" {
		t.Fatalf("proxy profile not marked applied: ok=%v profile=%+v want_sha=%s", ok, profile, configSHA)
	}
	appliedApproval, ok := st.Approval(approval.ID)
	if !ok || appliedApproval.Status != model.ApprovalApplied {
		t.Fatalf("approval not marked applied: ok=%v approval=%+v", ok, appliedApproval)
	}
	if !auditMetadataSeen(st, "proxy.apply.applied", "config_sha", configSHA) {
		t.Fatalf("missing proxy.apply.applied audit: %+v", st.AuditEvents())
	}
}

func TestProxyPlanRequiresGlobalProxyRead(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")

	tokenA := createPAT(t, handler, cookies, csrf, []string{"network:plan", "proxy:read"}, []string{"node-a"})
	denied := doBearerJSON(t, handler, http.MethodPost, "/api/proxy/nodes/node-a/plan", `{}`, tokenA)
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("node-allowlisted PAT must not plan proxycore without global proxy read, got %d", denied.StatusCode)
	}
}

func TestProxyApproveRejectsStalePlan(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")

	plan := doJSON(t, handler, http.MethodPost, "/api/proxy/nodes/node-a/plan", `{}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("proxy plan failed: %d", plan.StatusCode)
	}
	var approval approvalView
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}

	updateInbound := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", `{
		"id":"in-reality-443",
		"name":"VLESS Reality 8443",
		"core":"sing-box",
		"protocol":"vless",
		"port":8443,
		"transport":"tcp",
		"security":"reality",
		"sni":"cdn.example.com",
		"alpn":["h2","http/1.1"],
		"reality_public_key":"public-reality-key-123456",
		"reality_short_ids":["aa"],
		"reality_dest":"www.microsoft.com:443",
		"enabled":true
	}`, cookies, csrf)
	updateInbound.Body.Close()
	if updateInbound.StatusCode != http.StatusOK {
		t.Fatalf("update inbound failed: %d", updateInbound.StatusCode)
	}

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	defer approve.Body.Close()
	if approve.StatusCode != http.StatusConflict {
		t.Fatalf("stale proxycore plan should be rejected, got %d", approve.StatusCode)
	}
}

func TestProxyRejectsInvalidMVPInput(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", `{
		"id":"in-ws",
		"name":"WS",
		"core":"sing-box",
		"protocol":"vless",
		"port":443,
		"transport":"ws",
		"path":"/ws",
		"security":"reality",
		"reality_private_key":"super-secret-reality-private-key",
		"reality_short_ids":["aa"],
		"reality_dest":"www.microsoft.com:443",
		"enabled":true
	}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsupported transport should be rejected, got %d", res.StatusCode)
	}

	servicePort := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", `{
		"id":"in-service-port",
		"name":"Service Port",
		"core":"sing-box",
		"protocol":"vless",
		"port":443,
		"transport":"tcp",
		"security":"reality",
		"reality_private_key":"super-secret-reality-private-key",
		"reality_short_ids":["aa"],
		"reality_dest":"www.microsoft.com:https",
		"enabled":true
	}`, cookies, csrf)
	defer servicePort.Body.Close()
	if servicePort.StatusCode != http.StatusBadRequest {
		t.Fatalf("service-name ports must be rejected for deterministic rendering, got %d", servicePort.StatusCode)
	}
}

func createProxyPlanFixtures(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) {
	t.Helper()
	createInbound := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", proxyInboundBody("in-reality-443", "Inbound A"), cookies, csrf)
	createInbound.Body.Close()
	if createInbound.StatusCode != http.StatusOK {
		t.Fatalf("create inbound failed: %d", createInbound.StatusCode)
	}
	createUser := doJSON(t, handler, http.MethodPost, "/api/proxy/users", `{
		"id":"alice",
		"name":"Alice",
		"enabled":true,
		"uuid":"11111111-1111-4111-8111-111111111111",
		"password":"proxy-password-secret",
		"sub_token":"sub-token-secret-abcdefghijklmnopqrstuvwxyz",
		"inbound_ids":["in-reality-443"]
	}`, cookies, csrf)
	createUser.Body.Close()
	if createUser.StatusCode != http.StatusOK {
		t.Fatalf("create user failed: %d", createUser.StatusCode)
	}
	createProfile := doJSON(t, handler, http.MethodPost, "/api/proxy/profiles", `{
		"node_id":"`+nodeID+`",
		"core":"sing-box",
		"inbound_ids":["in-reality-443"],
		"hostname":"node-a.dns.example.com",
		"config_path":"/etc/sing-box/config.json",
		"stats_api":"127.0.0.1:9090"
	}`, cookies, csrf)
	createProfile.Body.Close()
	if createProfile.StatusCode != http.StatusOK {
		t.Fatalf("create profile failed: %d", createProfile.StatusCode)
	}
}

func proxyInboundBody(id, name string) string {
	return `{
		"id":"` + id + `",
		"name":"` + name + `",
		"core":"sing-box",
		"protocol":"vless",
		"port":443,
		"transport":"tcp",
		"security":"reality",
		"sni":"cdn.example.com",
		"alpn":["h2","http/1.1"],
		"reality_private_key":"super-secret-reality-private-key",
		"reality_public_key":"public-reality-key-123456",
		"reality_short_ids":["aa"],
		"reality_dest":"www.microsoft.com:443",
		"enabled":true
	}`
}
