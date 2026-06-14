package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		"fingerprint":"firefox",
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
	if !bytes.Contains(inBody.Bytes(), []byte(`"fingerprint":"firefox"`)) {
		t.Fatalf("fingerprint should be preserved in the non-secret view: %s", inBody.String())
	}
	if stored, ok := st.ProxyInbound("in-reality-443"); !ok || stored.RealityPrivateKey != "super-secret-reality-private-key" || stored.Fingerprint != "firefox" || len(stored.ALPN) != 2 || stored.RealityShortIDs[0] != "aa" {
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

	badFingerprint := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", `{
		"id":"in-bad-fp",
		"name":"Bad Fingerprint",
		"core":"sing-box",
		"protocol":"vless",
		"port":443,
		"transport":"tcp",
		"security":"reality",
		"fingerprint":"chrome beta",
		"reality_private_key":"super-secret-reality-private-key",
		"reality_public_key":"public-reality-key-123456",
		"reality_short_ids":["aa"],
		"reality_dest":"www.microsoft.com:443",
		"enabled":true
	}`, cookies, csrf)
	defer badFingerprint.Body.Close()
	if badFingerprint.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsafe fingerprint should be rejected, got %d", badFingerprint.StatusCode)
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

func TestProxyPlanSupportsXrayApplyScript(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-x", "Xray Node")

	createProxyPlanFixturesForCore(t, handler, cookies, csrf, "node-x", model.ProxyCoreXray, "/usr/local/etc/xray/config.json")
	plan := doJSON(t, handler, http.MethodPost, "/api/proxy/nodes/node-x/plan", `{}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusOK {
		t.Fatalf("xray proxy plan failed: %d", plan.StatusCode)
	}
	var approval approvalView
	if err := json.NewDecoder(plan.Body).Decode(&approval); err != nil {
		t.Fatal(err)
	}
	if approval.Plugin != proxyCorePlugin || approval.Action != proxyCoreApplyAction || approval.NodeID != "node-x" {
		t.Fatalf("bad xray proxy approval view: %+v", approval)
	}
	for _, leak := range []string{
		"super-secret-reality-private-key",
		"11111111-1111-4111-8111-111111111111",
		`"privateKey": "super-secret-reality-private-key"`,
		`"id": "11111111-1111-4111-8111-111111111111"`,
	} {
		if strings.Contains(approval.Plan, leak) {
			t.Fatalf("xray proxy plan leaked secret %q:\n%s", leak, approval.Plan)
		}
	}
	for _, want := range []string{
		"core: xray",
		"config_path: /usr/local/etc/xray/config.json",
		"## redacted xray config",
		`"privateKey": "<redacted>"`,
		`"id": "<redacted>"`,
		`"protocol": "vless"`,
		`"streamSettings": {`,
		`"realitySettings": {`,
	} {
		if !strings.Contains(approval.Plan, want) {
			t.Fatalf("xray proxy plan missing %q:\n%s", want, approval.Plan)
		}
	}
	stored, ok := st.Approval(approval.ID)
	if !ok {
		t.Fatalf("stored xray approval not found")
	}
	configSHA, err := proxyCoreApprovalConfigSHA(stored)
	if err != nil {
		t.Fatal(err)
	}
	if configSHA == "" || !strings.Contains(approval.Plan, configSHA) {
		t.Fatalf("xray approval did not bind config sha: action=%q plan=\n%s", stored.Action, approval.Plan)
	}

	approveQueue := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": approval.ID, "queue_apply": true, "plan_sha256": planSHA256(approval.Plan)})), cookies, csrf)
	defer approveQueue.Body.Close()
	if approveQueue.StatusCode != http.StatusOK {
		t.Fatalf("xray proxycore queue_apply failed: %d", approveQueue.StatusCode)
	}
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("xray proxycore queue_apply should create one task: %+v", tasks)
	}
	task := tasks[0]
	for _, want := range []string{
		"cat > '/usr/local/etc/xray/config.json.lattice-new'",
		"BACKUP='/usr/local/etc/xray/config.json.lattice-prev'",
		"xray test -c \"$CANDIDATE\"",
		"systemctl reload xray",
		"service xray reload",
		"no supported service manager found for xray reload/restart",
		"super-secret-reality-private-key",
		"11111111-1111-4111-8111-111111111111",
	} {
		if !strings.Contains(task.Script, want) {
			t.Fatalf("xray proxycore task script missing %q:\n%s", want, task.Script)
		}
	}
	for _, bad := range []string{"sing-box check", "systemctl reload sing-box", "service sing-box reload", "cat > $CANDIDATE"} {
		if strings.Contains(task.Script, bad) {
			t.Fatalf("xray proxycore task script contains wrong fragment %q:\n%s", bad, task.Script)
		}
	}
}

func TestProxySubscriptionServesPlainAndBase64(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("proxy node profile not found")
	}
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	profile.LastError = ""
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}

	const token = "sub-token-secret-abcdefghijklmnopqrstuvwxyz"
	plain := doJSON(t, handler, http.MethodGet, "/sub/"+token+"?format=plain", "", nil, "")
	defer plain.Body.Close()
	if plain.StatusCode != http.StatusOK {
		t.Fatalf("plain subscription failed: %d", plain.StatusCode)
	}
	if got := plain.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := plain.Header.Get("Subscription-Userinfo"); !strings.Contains(got, "upload=0; download=0; total=0; expire=0") {
		t.Fatalf("Subscription-Userinfo = %q", got)
	}
	plainBody := new(bytes.Buffer)
	plainBody.ReadFrom(plain.Body)
	body := plainBody.String()
	for _, want := range []string{
		"vless://11111111-1111-4111-8111-111111111111@node-a.dns.example.com:443?",
		"pbk=public-reality-key-123456",
		"sid=aa",
		"sni=cdn.example.com",
		"security=reality",
		"type=tcp",
		"#Node%20A%20-%20Inbound%20A",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("plain subscription missing %q:\n%s", want, body)
		}
	}
	for _, leak := range []string{"super-secret-reality-private-key", "proxy-password-secret", token, `"sub_token"`} {
		if strings.Contains(body, leak) {
			t.Fatalf("subscription leaked %q:\n%s", leak, body)
		}
	}

	encoded := doJSON(t, handler, http.MethodGet, "/sub/"+token, "", nil, "")
	defer encoded.Body.Close()
	if encoded.StatusCode != http.StatusOK {
		t.Fatalf("base64 subscription failed: %d", encoded.StatusCode)
	}
	encodedBody := new(bytes.Buffer)
	encodedBody.ReadFrom(encoded.Body)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedBody.String()))
	if err != nil {
		t.Fatalf("base64 subscription did not decode: %v; body=%q", err, encodedBody.String())
	}
	if string(decoded) != body {
		t.Fatalf("base64 decoded body mismatch:\ngot  %q\nwant %q", decoded, body)
	}

	singBox := doJSON(t, handler, http.MethodGet, "/sub/"+token+"?format=sing-box", "", nil, "")
	defer singBox.Body.Close()
	if singBox.StatusCode != http.StatusOK {
		t.Fatalf("sing-box subscription failed: %d", singBox.StatusCode)
	}
	if got := singBox.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("sing-box Content-Type = %q", got)
	}
	var singBoxOut struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			UUID       string `json:"uuid"`
			TLS        struct {
				Reality struct {
					PublicKey string `json:"public_key"`
					ShortID   string `json:"short_id"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if err := json.NewDecoder(singBox.Body).Decode(&singBoxOut); err != nil {
		t.Fatalf("sing-box subscription JSON decode failed: %v", err)
	}
	if len(singBoxOut.Outbounds) != 1 || singBoxOut.Outbounds[0].Type != "vless" || singBoxOut.Outbounds[0].Server != "node-a.dns.example.com" || singBoxOut.Outbounds[0].ServerPort != 443 {
		t.Fatalf("unexpected sing-box subscription: %+v", singBoxOut)
	}
	if singBoxOut.Outbounds[0].UUID != "11111111-1111-4111-8111-111111111111" || singBoxOut.Outbounds[0].TLS.Reality.PublicKey != "public-reality-key-123456" || singBoxOut.Outbounds[0].TLS.Reality.ShortID != "aa" {
		t.Fatalf("unexpected sing-box credentials: %+v", singBoxOut.Outbounds[0])
	}

	clash := doJSON(t, handler, http.MethodGet, "/sub/"+token+"?format=clash-meta", "", nil, "")
	defer clash.Body.Close()
	if clash.StatusCode != http.StatusOK {
		t.Fatalf("clash subscription failed: %d", clash.StatusCode)
	}
	if got := clash.Header.Get("Content-Type"); !strings.Contains(got, "text/yaml") {
		t.Fatalf("clash Content-Type = %q", got)
	}
	clashBody := new(bytes.Buffer)
	clashBody.ReadFrom(clash.Body)
	for _, want := range []string{
		`proxies:`,
		`type: vless`,
		`server: "node-a.dns.example.com"`,
		`port: 443`,
		`uuid: "11111111-1111-4111-8111-111111111111"`,
		`packet-encoding: xudp`,
		`encryption: ""`,
		`reality-opts:`,
		`public-key: "public-reality-key-123456"`,
		`short-id: "aa"`,
	} {
		if !strings.Contains(clashBody.String(), want) {
			t.Fatalf("clash subscription missing %q:\n%s", want, clashBody.String())
		}
	}
	for _, leak := range []string{"super-secret-reality-private-key", "proxy-password-secret", token, `"sub_token"`} {
		if strings.Contains(clashBody.String(), leak) {
			t.Fatalf("clash subscription leaked %q:\n%s", leak, clashBody.String())
		}
	}

	hash := proxySubTokenAuditHash(token)
	if !auditMetadataSeen(st, "proxy.subscription.fetch", "token_sha256", hash) {
		t.Fatalf("subscription fetch audit missing token hash: %+v", st.AuditEvents())
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action != "proxy.subscription.fetch" {
			continue
		}
		if ev.Reason == token {
			t.Fatalf("raw token leaked into audit reason: %+v", ev)
		}
		for key, value := range ev.Metadata {
			if strings.Contains(key, token) || strings.Contains(value, token) {
				t.Fatalf("raw token leaked into audit metadata: %+v", ev.Metadata)
			}
		}
	}
}

func TestProxySubscriptionRejectsUnknownMethodsFormatsAndDuplicateTokens(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("proxy node profile not found")
	}
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}

	const token = "sub-token-secret-abcdefghijklmnopqrstuvwxyz"
	unknown := doJSON(t, handler, http.MethodGet, "/sub/unknown-token-secret-abcdefghijklmnopqrstuvwxyz", "", nil, "")
	unknown.Body.Close()
	if unknown.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown token should 404, got %d", unknown.StatusCode)
	}
	post := doJSON(t, handler, http.MethodPost, "/sub/"+token, "", nil, "")
	post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("subscription POST should 405, got %d", post.StatusCode)
	}
	badFormat := doJSON(t, handler, http.MethodGet, "/sub/"+token+"?format=xml", "", nil, "")
	badFormat.Body.Close()
	if badFormat.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad subscription format should 400, got %d", badFormat.StatusCode)
	}

	sameUserUpdate := doJSON(t, handler, http.MethodPost, "/api/proxy/users", `{
		"id":"alice",
		"name":"Alice",
		"enabled":true,
		"uuid":"11111111-1111-4111-8111-111111111111",
		"sub_token":"sub-token-secret-abcdefghijklmnopqrstuvwxyz",
		"inbound_ids":["in-reality-443"]
	}`, cookies, csrf)
	sameUserUpdate.Body.Close()
	if sameUserUpdate.StatusCode != http.StatusOK {
		t.Fatalf("same user should be able to keep existing sub_token, got %d", sameUserUpdate.StatusCode)
	}
	duplicate := doJSON(t, handler, http.MethodPost, "/api/proxy/users", `{
		"id":"bob",
		"name":"Bob",
		"enabled":true,
		"uuid":"22222222-2222-4222-8222-222222222222",
		"sub_token":"sub-token-secret-abcdefghijklmnopqrstuvwxyz",
		"inbound_ids":["in-reality-443"]
	}`, cookies, csrf)
	duplicate.Body.Close()
	if duplicate.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate sub_token should 400, got %d", duplicate.StatusCode)
	}

	alice, ok := st.ProxyUser("alice")
	if !ok {
		t.Fatal("alice not found")
	}
	dirtyDuplicate := alice
	dirtyDuplicate.ID = "bob"
	dirtyDuplicate.UUID = "22222222-2222-4222-8222-222222222222"
	if err := st.UpsertProxyUser(dirtyDuplicate); err != nil {
		t.Fatal(err)
	}
	failClosed := doJSON(t, handler, http.MethodGet, "/sub/"+token+"?format=plain", "", nil, "")
	failClosed.Body.Close()
	if failClosed.StatusCode != http.StatusNotFound {
		t.Fatalf("dirty duplicate token should fail closed with 404, got %d", failClosed.StatusCode)
	}
}

func TestProxySubscriptionOmitsInactiveUsersAndUnappliedProfiles(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")

	const token = "sub-token-secret-abcdefghijklmnopqrstuvwxyz"
	inactive := doJSON(t, handler, http.MethodGet, "/sub/"+token+"?format=plain", "", nil, "")
	defer inactive.Body.Close()
	if inactive.StatusCode != http.StatusOK {
		t.Fatalf("unapplied profile should still return an empty subscription, got %d", inactive.StatusCode)
	}
	body := new(bytes.Buffer)
	body.ReadFrom(inactive.Body)
	if body.Len() != 0 {
		t.Fatalf("unapplied profile should return an empty body, got %q", body.String())
	}

	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("proxy node profile not found")
	}
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}
	alice, ok := st.ProxyUser("alice")
	if !ok {
		t.Fatal("alice not found")
	}
	alice.Enabled = false
	alice.Status = model.ProxyUserStatusDisabled
	if err := st.UpsertProxyUser(alice); err != nil {
		t.Fatal(err)
	}
	disabled := doJSON(t, handler, http.MethodGet, "/sub/"+token+"?format=plain", "", nil, "")
	defer disabled.Body.Close()
	if disabled.StatusCode != http.StatusOK {
		t.Fatalf("disabled user should still return an empty subscription, got %d", disabled.StatusCode)
	}
	body.Reset()
	body.ReadFrom(disabled.Body)
	if body.Len() != 0 {
		t.Fatalf("disabled user should return an empty body, got %q", body.String())
	}
}

func TestProxyRotateSubscriptionTokenReturnsURLAndInvalidatesOldToken(t *testing.T) {
	const publicURL = "https://lattice.example.test"
	handler, st := newTestServerWithPublicURL(t, publicURL)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("proxy node profile not found")
	}
	profile.AppliedSHA256 = strings.Repeat("a", 64)
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}

	const oldToken = "sub-token-secret-abcdefghijklmnopqrstuvwxyz"
	oldSub := doJSON(t, handler, http.MethodGet, "/sub/"+oldToken+"?format=plain", "", nil, "")
	oldSub.Body.Close()
	if oldSub.StatusCode != http.StatusOK {
		t.Fatalf("old token should be valid before rotation, got %d", oldSub.StatusCode)
	}

	rotate := doJSON(t, handler, http.MethodPost, "/api/proxy/users/rotate-sub-token", `{"id":"alice"}`, cookies, csrf)
	defer rotate.Body.Close()
	if rotate.StatusCode != http.StatusOK {
		t.Fatalf("rotate failed: %d", rotate.StatusCode)
	}
	var out struct {
		User            proxyUserView `json:"user"`
		SubscriptionURL string        `json:"subscription_url"`
		TokenSHA256     string        `json:"token_sha256"`
	}
	if err := json.NewDecoder(rotate.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.User.ID != "alice" || !out.User.HasSubToken {
		t.Fatalf("bad rotated user view: %+v", out.User)
	}
	if out.SubscriptionURL == "" || !strings.HasPrefix(out.SubscriptionURL, publicURL+"/sub/") {
		t.Fatalf("bad subscription url: %q", out.SubscriptionURL)
	}
	if strings.Contains(out.SubscriptionURL, oldToken) {
		t.Fatalf("rotated subscription url reused old token: %q", out.SubscriptionURL)
	}
	newToken := strings.TrimPrefix(out.SubscriptionURL, publicURL+"/sub/")
	if !proxySubTokenRe.MatchString(newToken) {
		t.Fatalf("new token has unexpected shape: %q", newToken)
	}
	if out.TokenSHA256 != proxySubTokenAuditHash(newToken) {
		t.Fatalf("token hash mismatch: got %s want %s", out.TokenSHA256, proxySubTokenAuditHash(newToken))
	}
	if stored, ok := st.ProxyUser("alice"); !ok || stored.SubToken != newToken || stored.SubToken == oldToken {
		t.Fatalf("stored token did not rotate: ok=%v user=%+v", ok, stored)
	}

	oldAgain := doJSON(t, handler, http.MethodGet, "/sub/"+oldToken+"?format=plain", "", nil, "")
	oldAgain.Body.Close()
	if oldAgain.StatusCode != http.StatusNotFound {
		t.Fatalf("old token should be invalid after rotation, got %d", oldAgain.StatusCode)
	}
	newSub := doJSON(t, handler, http.MethodGet, "/sub/"+newToken+"?format=plain", "", nil, "")
	newSub.Body.Close()
	if newSub.StatusCode != http.StatusOK {
		t.Fatalf("new token should fetch subscription, got %d", newSub.StatusCode)
	}

	list := doJSON(t, handler, http.MethodGet, "/api/proxy/users", "", cookies, "")
	defer list.Body.Close()
	listBody := new(bytes.Buffer)
	listBody.ReadFrom(list.Body)
	if strings.Contains(listBody.String(), oldToken) || strings.Contains(listBody.String(), newToken) {
		t.Fatalf("proxy user list leaked subscription token: %s", listBody.String())
	}
	if !auditMetadataSeen(st, "proxy.user.rotate_sub_token", "new_token_sha256", proxySubTokenAuditHash(newToken)) {
		t.Fatalf("missing token rotate audit: %+v", st.AuditEvents())
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action != "proxy.user.rotate_sub_token" {
			continue
		}
		for key, value := range ev.Metadata {
			if strings.Contains(key, oldToken) || strings.Contains(key, newToken) || strings.Contains(value, oldToken) || strings.Contains(value, newToken) {
				t.Fatalf("raw token leaked into rotate audit metadata: %+v", ev.Metadata)
			}
		}
	}
}

func TestProxyRotateSubscriptionTokenWithoutPublicURLReturnsRelativePath(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNode(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")

	req := httptest.NewRequest(http.MethodPost, "/api/proxy/users/rotate-sub-token", strings.NewReader(`{"id":"alice"}`))
	req.Host = "attacker.example"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Lattice-CSRF", csrf)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate failed: %d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		SubscriptionURL string `json:"subscription_url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.SubscriptionURL, "/sub/") {
		t.Fatalf("expected relative subscription path without public URL, got %q", out.SubscriptionURL)
	}
	if strings.Contains(out.SubscriptionURL, "attacker.example") {
		t.Fatalf("subscription URL reflected request host: %q", out.SubscriptionURL)
	}
}

func TestProxyUsageReportBaselinesAndRollsForward(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	alice, ok := st.ProxyUser("alice")
	if !ok {
		t.Fatal("proxy user alice not found")
	}
	alice.TrafficLimitBytes = 170
	if err := st.UpsertProxyUser(alice); err != nil {
		t.Fatal(err)
	}

	first := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":100,"user_bytes":{"alice":100,"unknown":999}}
	}`, nodeToken)
	if first.Code != http.StatusOK {
		t.Fatalf("first usage report failed: %d %s", first.Code, first.Body.String())
	}
	var firstOut proxyUsageApplyResult
	if err := json.NewDecoder(first.Body).Decode(&firstOut); err != nil {
		t.Fatal(err)
	}
	if firstOut.BytesDelta != 0 || firstOut.UsersUpdated != 1 || firstOut.UsersIgnored != 1 {
		t.Fatalf("first snapshot should baseline only and ignore unknown user: %+v", firstOut)
	}
	if user, _ := st.ProxyUser("alice"); user.UsedBytes != 0 || user.LastSeenAt.IsZero() {
		t.Fatalf("baseline should not import historical bytes but should mark seen: %+v", user)
	}

	second := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":120,"user_bytes":{"alice":250}}
	}`, nodeToken)
	if second.Code != http.StatusOK {
		t.Fatalf("second usage report failed: %d %s", second.Code, second.Body.String())
	}
	var secondOut proxyUsageApplyResult
	if err := json.NewDecoder(second.Body).Decode(&secondOut); err != nil {
		t.Fatal(err)
	}
	if secondOut.BytesDelta != 150 || secondOut.UsersUpdated != 1 {
		t.Fatalf("second snapshot should advance by monotonic delta: %+v", secondOut)
	}
	if user, _ := st.ProxyUser("alice"); user.UsedBytes != 150 || user.Status != model.ProxyUserStatusActive {
		t.Fatalf("unexpected user after monotonic delta: %+v", user)
	}

	reset := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":5,"user_bytes":{"alice":25}}
	}`, nodeToken)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset usage report failed: %d %s", reset.Code, reset.Body.String())
	}
	var resetOut proxyUsageApplyResult
	if err := json.NewDecoder(reset.Body).Decode(&resetOut); err != nil {
		t.Fatal(err)
	}
	if resetOut.BytesDelta != 25 {
		t.Fatalf("counter reset should add current post-reset bytes, got %+v", resetOut)
	}
	if user, _ := st.ProxyUser("alice"); user.UsedBytes != 175 || user.Status != model.ProxyUserStatusOverQuota {
		t.Fatalf("usage should roll up and derive over-quota status: %+v", user)
	}

	decrease := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":6,"user_bytes":{"alice":10}}
	}`, nodeToken)
	if decrease.Code != http.StatusOK {
		t.Fatalf("decreased counter report should reset baseline without adding bytes: %d %s", decrease.Code, decrease.Body.String())
	}
	if user, _ := st.ProxyUser("alice"); user.UsedBytes != 175 {
		t.Fatalf("decreased counter without uptime reset should not advance usage: %+v", user)
	}

	usage := doJSON(t, handler, http.MethodGet, "/api/proxy/usage", "", cookies, "")
	defer usage.Body.Close()
	if usage.StatusCode != http.StatusOK {
		t.Fatalf("usage query failed: %d", usage.StatusCode)
	}
	body := new(bytes.Buffer)
	body.ReadFrom(usage.Body)
	for _, want := range []string{`"node_id":"node-a"`, `"id":"alice"`, `"used_bytes":175`, `"status":"over_quota"`} {
		if !strings.Contains(body.String(), want) {
			t.Fatalf("usage response missing %s: %s", want, body.String())
		}
	}
	if strings.Contains(body.String(), "unknown") {
		t.Fatalf("usage response should not persist unknown reported users: %s", body.String())
	}

	negative := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":7,"user_bytes":{"alice":-1}}
	}`, nodeToken)
	if negative.Code != http.StatusBadRequest {
		t.Fatalf("negative usage should be rejected, got %d", negative.Code)
	}
}

func TestProxyUsageCollectorHealthDoesNotOverwriteAccountingBaseline(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")

	failed := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{
			"collector_source":"http",
			"collector_status":"error",
			"collector_error":"dial tcp 127.0.0.1:9090: connection refused",
			"collector_checked_at":"2026-06-14T10:00:00Z"
		}
	}`, nodeToken)
	if failed.Code != http.StatusOK {
		t.Fatalf("collector error health report failed: %d %s", failed.Code, failed.Body.String())
	}
	var failedOut proxyUsageApplyResult
	if err := json.NewDecoder(failed.Body).Decode(&failedOut); err != nil {
		t.Fatal(err)
	}
	if failedOut.CollectorStatus != model.ProxyUsageCollectorStatusError || failedOut.UsersUpdated != 0 || failedOut.BytesDelta != 0 {
		t.Fatalf("collector error should update health only: %+v", failedOut)
	}
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("proxy profile missing")
	}
	if profile.UsageCollectorStatus != model.ProxyUsageCollectorStatusError ||
		profile.UsageCollectorSource != "http" ||
		!strings.Contains(profile.UsageCollectorLastError, "connection refused") ||
		profile.UsageCollectorLastErrorAt.IsZero() {
		t.Fatalf("collector error not persisted on profile: %+v", profile)
	}
	if _, ok := st.ProxyUsageSnapshot("node-a"); ok {
		t.Fatalf("collector error must not create an accounting baseline")
	}
	profilesAfterError := doJSON(t, handler, http.MethodGet, "/api/proxy/profiles", "", cookies, "")
	defer profilesAfterError.Body.Close()
	errorBody := new(bytes.Buffer)
	errorBody.ReadFrom(profilesAfterError.Body)
	if !strings.Contains(errorBody.String(), `"usage_collector_status":"error"`) ||
		!strings.Contains(errorBody.String(), `"usage_collector_last_error":"dial tcp 127.0.0.1:9090: connection refused"`) {
		t.Fatalf("profile view missing collector error health: %s", errorBody.String())
	}

	badOK := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{
			"user_bytes":{"bad id":1},
			"collector_source":"http",
			"collector_status":"ok",
			"collector_checked_at":"2026-06-14T10:00:30Z"
		}
	}`, nodeToken)
	if badOK.Code != http.StatusBadRequest {
		t.Fatalf("malformed ok usage report should be rejected, got %d", badOK.Code)
	}
	profile, _ = st.ProxyNodeProfile("node-a")
	if profile.UsageCollectorStatus != model.ProxyUsageCollectorStatusError {
		t.Fatalf("rejected ok report must not overwrite collector health: %+v", profile)
	}

	success := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{
			"core_uptime_sec":100,
			"user_bytes":{"alice":100},
			"collector_source":"http",
			"collector_status":"ok",
			"collector_checked_at":"2026-06-14T10:01:00Z"
		}
	}`, nodeToken)
	if success.Code != http.StatusOK {
		t.Fatalf("collector success report failed: %d %s", success.Code, success.Body.String())
	}
	var successOut proxyUsageApplyResult
	if err := json.NewDecoder(success.Body).Decode(&successOut); err != nil {
		t.Fatal(err)
	}
	if successOut.CollectorStatus != model.ProxyUsageCollectorStatusOK || successOut.BytesDelta != 0 || successOut.UsersUpdated != 1 {
		t.Fatalf("first success after error should baseline only: %+v", successOut)
	}
	profile, _ = st.ProxyNodeProfile("node-a")
	if profile.UsageCollectorStatus != model.ProxyUsageCollectorStatusOK || profile.UsageCollectorLastOKAt.IsZero() {
		t.Fatalf("collector ok not persisted on profile: %+v", profile)
	}
	if usage, ok := st.ProxyUsageSnapshot("node-a"); !ok || usage.UserBytes["alice"] != 100 {
		t.Fatalf("success report should create accounting baseline: ok=%v usage=%+v", ok, usage)
	}
	profilesAfterOK := doJSON(t, handler, http.MethodGet, "/api/proxy/profiles", "", cookies, "")
	defer profilesAfterOK.Body.Close()
	okBody := new(bytes.Buffer)
	okBody.ReadFrom(profilesAfterOK.Body)
	if !strings.Contains(okBody.String(), `"usage_collector_status":"ok"`) ||
		!strings.Contains(okBody.String(), `"usage_collector_last_ok_at":"2026-06-14T10:01:00Z"`) {
		t.Fatalf("profile view missing collector ok health: %s", okBody.String())
	}
}

func TestProxyUsageNotificationsFireOncePerQuotaThreshold(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cap := &captureNotify{}
	srv.emitNotify = cap.hook()
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	createProxyPlanFixtures(t, handler, cookies, csrf, "node-a")
	alice, ok := st.ProxyUser("alice")
	if !ok {
		t.Fatal("proxy user alice not found")
	}
	alice.TrafficLimitBytes = 200
	if err := st.UpsertProxyUser(alice); err != nil {
		t.Fatal(err)
	}

	first := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":100,"user_bytes":{"alice":100}}
	}`, nodeToken)
	if first.Code != http.StatusOK {
		t.Fatalf("first usage report failed: %d %s", first.Code, first.Body.String())
	}
	var firstOut proxyUsageApplyResult
	if err := json.NewDecoder(first.Body).Decode(&firstOut); err != nil {
		t.Fatal(err)
	}
	if firstOut.AlertsFired != 0 {
		t.Fatalf("baseline must not fire quota alerts: %+v", firstOut)
	}

	second := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":120,"user_bytes":{"alice":260}}
	}`, nodeToken)
	if second.Code != http.StatusOK {
		t.Fatalf("second usage report failed: %d %s", second.Code, second.Body.String())
	}
	var secondOut proxyUsageApplyResult
	if err := json.NewDecoder(second.Body).Decode(&secondOut); err != nil {
		t.Fatal(err)
	}
	if secondOut.BytesDelta != 160 || secondOut.AlertsFired != 1 {
		t.Fatalf("80%% threshold should fire once: %+v", secondOut)
	}

	repeat := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":121,"user_bytes":{"alice":260}}
	}`, nodeToken)
	if repeat.Code != http.StatusOK {
		t.Fatalf("repeat usage report failed: %d %s", repeat.Code, repeat.Body.String())
	}
	var repeatOut proxyUsageApplyResult
	if err := json.NewDecoder(repeat.Body).Decode(&repeatOut); err != nil {
		t.Fatal(err)
	}
	if repeatOut.AlertsFired != 0 {
		t.Fatalf("same threshold must not repeat: %+v", repeatOut)
	}

	third := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", `{
		"node_id":"node-a",
		"snapshot":{"core_uptime_sec":122,"user_bytes":{"alice":300}}
	}`, nodeToken)
	if third.Code != http.StatusOK {
		t.Fatalf("third usage report failed: %d %s", third.Code, third.Body.String())
	}
	var thirdOut proxyUsageApplyResult
	if err := json.NewDecoder(third.Body).Decode(&thirdOut); err != nil {
		t.Fatal(err)
	}
	if thirdOut.BytesDelta != 40 || thirdOut.AlertsFired != 1 {
		t.Fatalf("100%% threshold should fire once after 80%%: %+v", thirdOut)
	}

	if len(cap.titles) != 2 || !strings.Contains(cap.titles[0], "80%") || !strings.Contains(cap.titles[1], "100%") {
		t.Fatalf("unexpected quota notifications: %+v", cap.titles)
	}
	stored, _ := st.ProxyUser("alice")
	if stored.LastQuotaNotifiedKey != "quota:200:100" {
		t.Fatalf("quota cursor not persisted: %+v", stored)
	}
	if !auditMetadataSeen(st, "proxy.user.notify", "kind", proxyUserAlertQuota) {
		t.Fatalf("proxy quota notification audit missing: %+v", st.AuditEvents())
	}
}

func TestProxyExpiryNotificationsAdvanceAndDoNotRepeat(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	cap := &captureNotify{}
	srv.emitNotify = cap.hook()
	expires := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if err := st.UpsertProxyUser(model.ProxyUser{
		ID: "alice", Name: "Alice", Enabled: true, ExpiresAt: expires, Status: model.ProxyUserStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	fired, err := srv.evaluateProxyUserNotifications(time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].Kind != proxyUserAlertExpiry || fired[0].ExpiryOffsetDays != 7 {
		t.Fatalf("expected 7-day expiry warning: %+v", fired)
	}
	again, err := srv.evaluateProxyUserNotifications(time.Date(2026, 6, 24, 13, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("same expiry warning should not repeat: %+v", again)
	}
	oneDay, err := srv.evaluateProxyUserNotifications(time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(oneDay) != 1 || oneDay[0].ExpiryOffsetDays != 1 {
		t.Fatalf("expected 1-day expiry warning: %+v", oneDay)
	}
	expired, err := srv.evaluateProxyUserNotifications(time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].ExpiryOffsetDays != -1 {
		t.Fatalf("expected expired warning: %+v", expired)
	}
	if len(cap.titles) != 3 || !strings.Contains(cap.titles[0], "7d") || !strings.Contains(cap.titles[1], "1d") || !strings.Contains(cap.titles[2], "expired") {
		t.Fatalf("unexpected expiry notifications: %+v", cap.titles)
	}
	stored, _ := st.ProxyUser("alice")
	if stored.LastExpiryNotifiedKey != "expiry:2026-07-01:expired" || stored.Status != model.ProxyUserStatusExpired {
		t.Fatalf("expiry cursor/status not persisted: %+v", stored)
	}
}

func TestProxyUserRejectsClientManagedNotificationCursors(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/proxy/users", `{
		"id":"alice",
		"name":"Alice",
		"last_quota_notified_key":"quota:100:80"
	}`, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("client-managed proxy notification cursor should be rejected, got %d", res.StatusCode)
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
	createProxyPlanFixturesForCore(t, handler, cookies, csrf, nodeID, model.ProxyCoreSingbox, "/etc/sing-box/config.json")
}

func createProxyPlanFixturesForCore(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID, core, configPath string) {
	t.Helper()
	createInbound := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", proxyInboundBodyForCore("in-reality-443", "Inbound A", core), cookies, csrf)
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
		"core":"`+core+`",
		"inbound_ids":["in-reality-443"],
		"hostname":"node-a.dns.example.com",
		"config_path":"`+configPath+`",
		"stats_api":"127.0.0.1:9090"
	}`, cookies, csrf)
	createProfile.Body.Close()
	if createProfile.StatusCode != http.StatusOK {
		t.Fatalf("create profile failed: %d", createProfile.StatusCode)
	}
}

func proxyInboundBody(id, name string) string {
	return proxyInboundBodyForCore(id, name, model.ProxyCoreSingbox)
}

func proxyInboundBodyForCore(id, name, core string) string {
	return `{
		"id":"` + id + `",
		"name":"` + name + `",
		"core":"` + core + `",
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
