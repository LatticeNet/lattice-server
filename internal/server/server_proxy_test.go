package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
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
