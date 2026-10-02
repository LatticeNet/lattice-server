package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// Read scopes reached credentials two ways: /api/proxy/discovered returned
// each adopted line's share_url, the full client URI with the line owner's
// credential, to proxy:read; and vpn-core's subscription-sources compose,
// declared at vpncore:read, returned the identity's VLESS uuid inside every
// composed entry to any operator who called it through the plugin gateway.
// Admin callers keep receiving exactly what they did.

const (
	readScopeVLESSUUID  = "6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e"
	readScopeVMessUUID  = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
	readScopeTrojanPass = "trojan-owner-secret"
)

// forkShareURLs are the share_url shapes the fork's script emits
// (src/core.sh, one per protocol), each mapped to the string that carries its
// secret: the uuid inside a vmess document, and the userinfo for the rest.
func forkShareURLs() map[string]string {
	vmessJSON := `{"v":"2","ps":"hub-vmess","add":"203.0.113.5","port":"443","id":"` + readScopeVMessUUID + `","aid":"0","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls"}`
	return map[string]string{
		"vless://" + readScopeVLESSUUID + "@203.0.113.5:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=www.example.com&pbk=pk&fp=chrome#hub": readScopeVLESSUUID,
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON)):                                                                                             readScopeVMessUUID,
		"ss://" + base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:c3MtcGFzc3dvcmQtc2VjcmV0")) + "@203.0.113.5:8388#hub":                             base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:c3MtcGFzc3dvcmQtc2VjcmV0")),
		"trojan://" + readScopeTrojanPass + "@203.0.113.5:8443?type=tcp&security=tls&insecure=1#hub":                                                                  readScopeTrojanPass,
		"hysteria2://hy2-owner-secret@203.0.113.5:9443?alpn=h3&insecure=1#hub":                                                                                        "hy2-owner-secret",
		"tuic://8b9c0d1e-2f3a-4b4c-8d5e-6f7a8b9c0d1e:tuic-owner-secret@203.0.113.5:10443?alpn=h3#hub":                                                                 "8b9c0d1e-2f3a-4b4c-8d5e-6f7a8b9c0d1e",
		"anytls://anytls-owner-secret@203.0.113.5:11443?insecure=1#hub":                                                                                               "anytls-owner-secret",
		"socks://" + base64.StdEncoding.EncodeToString([]byte("owner:socks-owner-secret")) + "@203.0.113.5:1080#hub":                                                  base64.StdEncoding.EncodeToString([]byte("owner:socks-owner-secret")),
	}
}

func TestRedactLinkCredentialCoversEveryForkShareURL(t *testing.T) {
	for link, secret := range forkShareURLs() {
		redacted, ok := redactLinkCredential(link)
		if !ok {
			t.Fatalf("%s: a share URL the fork emits must redact, not drop", link)
		}
		if strings.Contains(redacted, secret) || strings.Contains(redacted, "tuic-owner-secret") {
			t.Fatalf("redacted link still carries the secret:\n%s", redacted)
		}
		if strings.HasPrefix(link, "vmess://") {
			payload, ok := decodeLooseBase64(strings.TrimPrefix(redacted, "vmess://"))
			var doc map[string]any
			if !ok || json.Unmarshal(payload, &doc) != nil || doc["id"] != vpnCoreRedactedCredential || doc["add"] != "203.0.113.5" || doc["port"] != "443" {
				t.Fatalf("vmess must keep its endpoint and carry the redacted marker as its id: %s (%v)", redacted, doc)
			}
			continue
		}
		if !strings.Contains(redacted, vpnCoreRedactedCredential+"@203.0.113.5:") {
			t.Fatalf("the endpoint must survive with the marker in place of the userinfo: %s", redacted)
		}
	}
	// The legacy shadowsocks form encodes method:password@host:port as the
	// host itself; there is no userinfo to replace, so it is dropped.
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:legacy-secret@203.0.113.5:8388"))
	if redacted, ok := redactLinkCredential(legacy); ok {
		t.Fatalf("a legacy shadowsocks link must be dropped, got %s", redacted)
	}
	if _, ok := redactLinkCredential("vmess://not-base64-json!"); ok {
		t.Fatal("an undecodable vmess link must be dropped")
	}
}

func discoveredFixture(t *testing.T) *Server {
	t.Helper()
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	for _, id := range []string{"node-a", "node-b"} {
		if err := srv.store.UpsertNode(model.Node{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	var nodes []model.SingBoxNode
	i := 0
	for link := range forkShareURLs() {
		i++
		nodes = append(nodes, model.SingBoxNode{Name: "line-" + string(rune('a'+i)), Protocol: strings.SplitN(link, ":", 2)[0], Port: "443", ShareURL: link})
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok", Nodes: nodes},
		"node-b": {NodeID: "node-b", At: srv.now(), Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "b-vless", Protocol: "vless", Port: "443", ShareURL: "vless://" + readScopeVLESSUUID + "@198.51.100.9:443?security=reality#b"},
		}},
	}
	srv.singboxInvMu.Unlock()
	return srv
}

func getDiscovered(t *testing.T, srv *Server, p principal) string {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handleProxyDiscovered(rec, httptest.NewRequest(http.MethodGet, "/api/proxy/discovered", nil), p)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovered: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestProxyDiscoveredRedactsShareURLsBelowProxyAdmin(t *testing.T) {
	srv := discoveredFixture(t)
	secrets := forkShareURLs()

	shareURLs := func(t *testing.T, body string) []string {
		t.Helper()
		var decoded struct {
			Inventories []model.SingBoxInventory `json:"inventories"`
		}
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, inv := range decoded.Inventories {
			for _, n := range inv.Nodes {
				out = append(out, n.ShareURL)
			}
		}
		return out
	}
	for _, scopes := range [][]string{{"proxy:read"}, {"vpncore:read"}} {
		body := getDiscovered(t, srv, principal{Principal: rbac.Principal{ActorID: "reader", Scopes: scopes}})
		urls := shareURLs(t, body)
		if len(urls) != len(secrets)+1 {
			t.Fatalf("%v: want every line listed, got %d share URLs", scopes, len(urls))
		}
		for _, got := range urls {
			for _, secret := range secrets {
				if strings.Contains(got, secret) || strings.Contains(got, "tuic-owner-secret") {
					t.Fatalf("%v: the discovered inventory leaked an owner credential: %s", scopes, got)
				}
			}
			if !strings.Contains(got, vpnCoreRedactedCredential+"@") && !strings.HasPrefix(got, "vmess://") {
				t.Fatalf("%v: want the redacted marker in place of the credential: %s", scopes, got)
			}
		}
		if strings.Contains(body, readScopeVLESSUUID) || strings.Contains(body, readScopeVMessUUID) {
			t.Fatalf("%v: a credential survived somewhere in the body:\n%s", scopes, body)
		}
	}

	// Admin callers receive what they always did, byte for byte.
	for _, scopes := range [][]string{{"proxy:read", "proxy:admin"}, {"vpncore:read", "vpncore:admin"}, {"*"}} {
		body := getDiscovered(t, srv, principal{Principal: rbac.Principal{ActorID: "admin", Scopes: scopes}})
		var decoded struct {
			Inventories []model.SingBoxInventory `json:"inventories"`
		}
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, inv := range decoded.Inventories {
			for _, n := range inv.Nodes {
				if _, ok := secrets[n.ShareURL]; ok || strings.HasPrefix(n.ShareURL, "vless://"+readScopeVLESSUUID+"@198.51.100.9") {
					seen++
				}
			}
		}
		if seen != len(secrets)+1 {
			t.Fatalf("%v: an admin must get every share_url unchanged, %d of %d matched:\n%s", scopes, seen, len(secrets)+1, body)
		}
	}

	// An admin confined to node-b sees node-b's link whole and nothing of
	// node-a: the allowlist bounds the read before the admin check runs.
	confined := principal{Principal: rbac.Principal{ActorID: "confined", Scopes: []string{"proxy:read", "proxy:admin"}, ServerAllowlist: []string{"node-b"}}}
	urls := shareURLs(t, getDiscovered(t, srv, confined))
	if len(urls) != 1 || !strings.HasPrefix(urls[0], "vless://"+readScopeVLESSUUID+"@198.51.100.9") {
		t.Fatalf("a node-confined admin sees only its own node, whole: %v", urls)
	}
	// A reader confined to node-b gets node-b's link redacted.
	urls = shareURLs(t, getDiscovered(t, srv, principal{Principal: rbac.Principal{ActorID: "confined-reader", Scopes: []string{"proxy:read"}, ServerAllowlist: []string{"node-b"}}}))
	if len(urls) != 1 || urls[0] != "vless://"+vpnCoreRedactedCredential+"@198.51.100.9:443?security=reality#b" {
		t.Fatalf("a node-confined reader must get its node's link redacted: %v", urls)
	}
}

func TestComposedEntriesAreRedactedForADirectReadScopedCall(t *testing.T) {
	composed, err := composeGraphSubscription(testGraphComposeSnapshot(),
		graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeRootUUID}}, time.Unix(1_700_000_000, 0))
	if err != nil || !composed.OK || !strings.Contains(composed.Raw, composeIdentityUUID+"@") {
		t.Fatalf("fixture: want a composed entry with the identity credential, got %+v err=%v", composed, err)
	}
	redacted := redactComposedSubscription(composed)
	if !redacted.OK || redacted.SourceVersion != composed.SourceVersion || string(redacted.SourceManifest) != string(composed.SourceManifest) {
		t.Fatalf("redaction must keep the result, its version and its manifest: %+v", redacted)
	}
	if len(redacted.Entries) != len(composed.Entries) || redacted.Raw != strings.Join(redacted.Entries, "\n") {
		t.Fatalf("redacted entries and raw disagree: %+v", redacted)
	}
	wire, _ := json.Marshal(redacted)
	if strings.Contains(string(wire), composeIdentityUUID) || !strings.Contains(redacted.Raw, vpnCoreRedactedCredential+"@") {
		t.Fatalf("the redacted compose still carries the identity credential: %s", wire)
	}

	direct := func(scopes []string, allowlist ...string) context.Context {
		ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{},
			principal{Principal: rbac.Principal{ActorID: "op", Scopes: scopes, ServerAllowlist: allowlist}})
		return context.WithValue(ctx, operatorCoreCallKey{}, vpnCoreSubscriptionSourcesService)
	}
	nested := context.WithValue(context.WithValue(context.Background(), pluginOperatorPrincipalKey{},
		principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"substore:read"}}}), operatorCoreCallKey{}, "latticenet.sub-store/subscription")
	for name, tc := range map[string]struct {
		ctx  context.Context
		want bool
	}{
		"subscription serving, no operator":            {context.Background(), true},
		"a plugin's rpc:call under a read operator":    {context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, principal{Principal: rbac.Principal{Scopes: []string{"substore:read"}}}), true},
		"a core service the operator called composes":  {nested, true},
		"direct call at vpncore:read":                  {direct([]string{"vpncore:read"}), false},
		"direct call at proxy:read":                    {direct([]string{"proxy:read"}), false},
		"direct call at vpncore:admin":                 {direct([]string{"vpncore:admin"}), true},
		"direct call at proxy:admin":                   {direct([]string{"proxy:admin"}), true},
		"direct call at vpncore:admin, node-confined":  {direct([]string{"vpncore:admin"}, "node-a"), false},
		"direct call that lost its operator principal": {context.WithValue(context.Background(), operatorCoreCallKey{}, vpnCoreSubscriptionSourcesService), false},
	} {
		if got := vpnCoreComposeCredentialsAllowed(tc.ctx); got != tc.want {
			t.Fatalf("%s: credentials allowed = %v, want %v", name, got, tc.want)
		}
	}
}

// The gateway stamps the core service an operator called, and only on that
// call: a core provider sees its own service name, and a runtime plugin's
// rpc:call never passes through this path.
func TestThePluginGatewayMarksAnOperatorsDirectCoreCall(t *testing.T) {
	srv := newLinemetaTestServer(t, mustOpenStore(t))
	manifest := plugin.Manifest{Schema: plugin.ManifestSchemaV2, ID: "p", Name: "Probe", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{Service: "p/probe", Backing: plugin.BackingCore,
			MethodSpecs: []plugin.InterfaceMethod{{Name: "probe", Effect: plugin.InterfaceEffectRead, Scopes: []string{"proxy:read"}}}}}}
	if err := srv.store.UpsertPluginInstallation(model.PluginInstallation{ID: "p", Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	srv.plugins = append(srv.plugins, plugin.Loaded{Manifest: manifest})
	seen := ""
	if err := srv.pluginRPC.Register("p", "p/probe", "v1", []string{"probe"}, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		seen = operatorCalledCoreService(ctx)
		return []byte(`{}`), nil
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(`{"id":"p","service":"p/probe","method":"probe","payload":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{ActorID: "reader", Scopes: []string{"proxy:read"}}})
	if rec.Code != http.StatusOK || seen != "p/probe" {
		t.Fatalf("call %d %s, the provider saw service %q, want p/probe", rec.Code, rec.Body.String(), seen)
	}
	if got := operatorCalledCoreService(context.Background()); got != "" {
		t.Fatalf("an unmarked context reports %q", got)
	}
}
