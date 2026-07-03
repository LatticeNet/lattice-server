package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestValidateNodeIPConfig(t *testing.T) {
	cases := []struct {
		name         string
		mode, v4, v6 string
		resolvers    []string
		script       string
		wantErr      bool
		wantNil      bool
	}{
		{"empty clears", "", "", "", nil, "", false, true},
		{"auto ok", "auto", "", "", nil, "", false, false},
		{"static needs an ip", "static", "", "", nil, "", true, false},
		{"static v4 ok", "static", "203.0.113.7", "", nil, "", false, false},
		{"unknown mode", "bogus", "", "", nil, "", true, false},
		{"bad v4", "auto", "not-an-ip", "", nil, "", true, false},
		{"v6 in the v4 slot", "auto", "2001:db8::1", "", nil, "", true, false},
		{"static v6 ok", "static", "", "2001:db8::1", nil, "", false, false},
		{"resolver must be a url", "resolver", "", "", []string{"1.1.1.1"}, "", true, false},
		{"resolver url ok", "resolver", "", "", []string{"https://api.ipify.org"}, "", false, false},
		{"script needs body", "script", "", "", nil, "", true, false},
		{"script ok", "script", "", "", nil, "echo 8.8.8.8", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := validateNodeIPConfig(c.mode, c.v4, c.v6, c.resolvers, c.script, nil)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && (cfg == nil) != c.wantNil {
				t.Fatalf("cfg nil=%v wantNil=%v", cfg == nil, c.wantNil)
			}
		})
	}
}

// TestNodeIPConfigHTTP exercises setting, rejecting, and clearing a per-node IP
// override through the endpoint, asserting it is persisted on the node.
func TestNodeIPConfigHTTP(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	set := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"static","static_ipv4":"203.0.113.7","resolvers":["https://api.ipify.org"]}`,
		cookies, csrf)
	set.Body.Close()
	if set.StatusCode != http.StatusOK {
		t.Fatalf("set ip-config failed: %d", set.StatusCode)
	}
	n, _ := st.Node("node-a")
	if n.IPConfig == nil || n.IPConfig.Mode != model.NodeIPModeStatic || n.IPConfig.StaticIPv4 != "203.0.113.7" {
		t.Fatalf("ip-config not stored: %+v", n.IPConfig)
	}
	if len(n.IPConfig.Resolvers) != 1 || n.IPConfig.Resolvers[0] != "https://api.ipify.org" {
		t.Fatalf("resolvers not stored: %+v", n.IPConfig.Resolvers)
	}

	script := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"script","script":"echo 8.8.8.8"}`,
		cookies, csrf)
	defer script.Body.Close()
	if script.StatusCode != http.StatusOK {
		t.Fatalf("set script ip-config failed: %d", script.StatusCode)
	}
	var scriptView struct {
		IPConfig *model.NodeIPConfig `json:"ip_config"`
	}
	if err := json.NewDecoder(script.Body).Decode(&scriptView); err != nil {
		t.Fatal(err)
	}
	if scriptView.IPConfig == nil || scriptView.IPConfig.Mode != model.NodeIPModeScript {
		t.Fatalf("script ip-config not returned: %+v", scriptView.IPConfig)
	}
	if scriptView.IPConfig.Script != "" {
		t.Fatalf("script body leaked in node view: %q", scriptView.IPConfig.Script)
	}
	if scriptView.IPConfig.ScriptSHA256 == "" {
		t.Fatalf("script hash missing in node view: %+v", scriptView.IPConfig)
	}
	n, _ = st.Node("node-a")
	if n.IPConfig == nil || n.IPConfig.Script != "echo 8.8.8.8" {
		t.Fatalf("stored script missing: %+v", n.IPConfig)
	}
	if !auditMetadataSeen(st, "node.ip.config", "script_sha256", n.IPConfig.ScriptSHA256) {
		t.Fatalf("script update audit missing script hash: %+v", st.AuditEvents())
	}
	if !auditMetadataSeen(st, "node.ip.config", "script_size_bytes", "12") {
		t.Fatalf("script update audit missing script size: %+v", st.AuditEvents())
	}

	preserve := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"script"}`,
		cookies, csrf)
	preserve.Body.Close()
	if preserve.StatusCode != http.StatusOK {
		t.Fatalf("preserve script failed: %d", preserve.StatusCode)
	}
	n, _ = st.Node("node-a")
	if n.IPConfig == nil || n.IPConfig.Script != "echo 8.8.8.8" {
		t.Fatalf("empty script should preserve existing script: %+v", n.IPConfig)
	}

	bad := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"static"}`, cookies, csrf)
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("static without an ip should be 400, got %d", bad.StatusCode)
	}

	clr := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":""}`, cookies, csrf)
	clr.Body.Close()
	if clr.StatusCode != http.StatusOK {
		t.Fatalf("clear failed: %d", clr.StatusCode)
	}
	if n2, _ := st.Node("node-a"); n2.IPConfig != nil {
		t.Fatalf("override not cleared: %+v", n2.IPConfig)
	}
}

func TestNodeIPConfigScriptObeysTaskExecutionKillSwitch(t *testing.T) {
	handler, st := newTaskExecutionDisabledTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	script := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"script","script":"echo 8.8.8.8"}`,
		cookies, csrf)
	defer script.Body.Close()
	if script.StatusCode != http.StatusConflict {
		t.Fatalf("script ip-config under kill switch status = %d, want 409", script.StatusCode)
	}
	if code := errorCodeFromHTTPResponse(t, script); code != apiErrorTaskExecutionDisabled {
		t.Fatalf("script ip-config under kill switch code = %q", code)
	}
	if n, _ := st.Node("node-a"); n.IPConfig != nil {
		t.Fatalf("kill switch must not store script ip-config: %+v", n.IPConfig)
	}
	if !auditMetadataSeen(st, "node.ip.config", "script_sha256", shortSHA256("echo 8.8.8.8")) {
		t.Fatalf("denied script update audit missing script hash: %+v", st.AuditEvents())
	}

	static := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"static","static_ipv4":"203.0.113.7"}`,
		cookies, csrf)
	defer static.Body.Close()
	if static.StatusCode != http.StatusOK {
		t.Fatalf("static ip-config should remain allowed under kill switch: %d", static.StatusCode)
	}
	if n, _ := st.Node("node-a"); n.IPConfig == nil || n.IPConfig.Mode != model.NodeIPModeStatic {
		t.Fatalf("static ip-config not stored under kill switch: %+v", n.IPConfig)
	}
}

func TestNodeIPConfigScriptRequiresNetworkPlanScope(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	nodeAdmin := createPAT(t, handler, cookies, csrf, []string{"node:admin"}, []string{"node-a"})
	static := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"static","static_ipv4":"203.0.113.7"}`, nodeAdmin)
	static.Body.Close()
	if static.StatusCode != http.StatusOK {
		t.Fatalf("node:admin should set static ip-config, got %d", static.StatusCode)
	}

	scriptDenied := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"script","script":"echo 8.8.8.8"}`, nodeAdmin)
	scriptDenied.Body.Close()
	if scriptDenied.StatusCode != http.StatusForbidden {
		t.Fatalf("node:admin-only script ip-config status = %d, want 403", scriptDenied.StatusCode)
	}
	if n, _ := st.Node("node-a"); n.IPConfig == nil || n.IPConfig.Mode != model.NodeIPModeStatic {
		t.Fatalf("denied script update should leave static config intact: %+v", n.IPConfig)
	}

	withNetworkPlan := createPAT(t, handler, cookies, csrf, []string{"node:admin", "network:plan"}, []string{"node-a"})
	scriptAllowed := doBearerJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"script","script":"echo 8.8.4.4"}`, withNetworkPlan)
	scriptAllowed.Body.Close()
	if scriptAllowed.StatusCode != http.StatusOK {
		t.Fatalf("node:admin + network:plan should set script ip-config, got %d", scriptAllowed.StatusCode)
	}
	if n, _ := st.Node("node-a"); n.IPConfig == nil || n.IPConfig.Mode != model.NodeIPModeScript || n.IPConfig.Script != "echo 8.8.4.4" {
		t.Fatalf("script config not stored with network:plan: %+v", n.IPConfig)
	}
}

func TestAgentConfigSuppressesScriptIPConfigWhenTaskExecutionDisabled(t *testing.T) {
	handler, st := newTaskExecutionDisabledTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	node, ok := st.Node("node-a")
	if !ok {
		t.Fatal("node not enrolled")
	}
	node.IPConfig = &model.NodeIPConfig{
		Mode:         model.NodeIPModeScript,
		Script:       "echo 8.8.8.8",
		ScriptSHA256: shortSHA256("echo 8.8.8.8"),
	}
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/agent/config?node_id=node-a", nil)
	req.Header.Set("Authorization", "Bearer "+nodeToken)
	rec := serveReq(handler, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent config failed: %d (%s)", rec.Code, rec.Body.String())
	}
	var cfg model.AgentConfig
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.IPConfig != nil {
		t.Fatalf("kill switch must suppress script ip-config in agent config: %+v", cfg.IPConfig)
	}

	node.IPConfig = &model.NodeIPConfig{Mode: model.NodeIPModeStatic, StaticIPv4: "203.0.113.7"}
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	rec = serveReq(handler, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent config for static failed: %d (%s)", rec.Code, rec.Body.String())
	}
	cfg = model.AgentConfig{}
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.IPConfig == nil || cfg.IPConfig.Mode != model.NodeIPModeStatic || cfg.IPConfig.StaticIPv4 != "203.0.113.7" {
		t.Fatalf("kill switch should still return non-script ip-config: %+v", cfg.IPConfig)
	}
}
