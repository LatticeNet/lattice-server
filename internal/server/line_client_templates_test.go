package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	tmplOwnerUUID = "5b2c7d1e-3f4a-4b5c-8d6e-7f8091a2b3c4"
	tmplOwnerPass = "Own3rP4ssw0rdSecret"
	tmplOtherUUID = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
	tmplOtherPass = "ident1tyPassw0rdXyZ"
)

func vmessShareURL(t *testing.T, fields map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

// Every share URL shape the node script builds (lr00rl/sing-box core.sh,
// info()) yields a template with no part of the owner's credential in it, and
// the template with the owner's own credential filled back in gives the URI
// the node reported, which is the proof that it holds everything a client
// entry needs. Filled with another identity's credential, the URI carries
// that credential and none of the owner's.
func TestLineClientTemplateFromEveryShareURLShape(t *testing.T) {
	socksOwner := base64.StdEncoding.EncodeToString([]byte("owner:???>>>")) // holds a slash
	for _, tc := range []struct {
		name, protocol, shareURL string
		owner, other             lineUserCredentialPayload
		host                     string
		port                     int
	}{
		{name: "vless reality", protocol: "vless",
			shareURL: "vless://" + tmplOwnerUUID + "@203.0.113.5:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=www.example.com&pbk=Zm9vYmFyYmF6cXV4&fp=chrome#lr00rl-reality-203.0.113.5",
			owner:    lineUserCredentialPayload{UUID: tmplOwnerUUID, Flow: "xtls-rprx-vision"}, other: lineUserCredentialPayload{UUID: tmplOtherUUID, Flow: "xtls-rprx-vision"},
			host: "203.0.113.5", port: 443},
		{name: "vless reality on IPv6", protocol: "vless",
			shareURL: "vless://" + tmplOwnerUUID + "@[2001:db8::5]:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=www.example.com&pbk=Zm9v&fp=chrome#lr00rl-reality-[2001:db8::5]",
			owner:    lineUserCredentialPayload{UUID: tmplOwnerUUID, Flow: "xtls-rprx-vision"}, other: lineUserCredentialPayload{UUID: tmplOtherUUID},
			host: "2001:db8::5", port: 443},
		{name: "vless ws behind tls", protocol: "vless",
			shareURL: "vless://" + tmplOwnerUUID + "@cdn.example.com:443?encryption=none&security=tls&type=ws&host=cdn.example.com&path=/a1b2#lr00rl-ws-cdn.example.com",
			owner:    lineUserCredentialPayload{UUID: tmplOwnerUUID}, other: lineUserCredentialPayload{UUID: tmplOtherUUID},
			host: "cdn.example.com", port: 443},
		{name: "trojan ws behind tls", protocol: "trojan",
			shareURL: "trojan://" + tmplOwnerPass + "@cdn.example.com:443?encryption=none&security=tls&type=ws&host=cdn.example.com&path=/t9#lr00rl-ws-cdn.example.com",
			owner:    lineUserCredentialPayload{Password: tmplOwnerPass}, other: lineUserCredentialPayload{Password: tmplOtherPass},
			host: "cdn.example.com", port: 443},
		{name: "trojan tcp", protocol: "trojan",
			shareURL: "trojan://" + tmplOwnerPass + "@203.0.113.5:443?type=tcp&security=tls&insecure=1&allowInsecure=1#lr00rl-tcp-203.0.113.5",
			owner:    lineUserCredentialPayload{Password: tmplOwnerPass}, other: lineUserCredentialPayload{Password: tmplOtherPass},
			host: "203.0.113.5", port: 443},
		{name: "hysteria2 pinned", protocol: "hysteria2",
			shareURL: "hysteria2://" + tmplOwnerPass + "@203.0.113.5:8443?alpn=h3&insecure=1&allowInsecure=1&pinSHA256=AB12CD34EF56#lr00rl-udp-203.0.113.5",
			owner:    lineUserCredentialPayload{Password: tmplOwnerPass}, other: lineUserCredentialPayload{Password: tmplOtherPass},
			host: "203.0.113.5", port: 8443},
		{name: "tuic", protocol: "tuic",
			shareURL: "tuic://" + tmplOwnerUUID + ":" + tmplOwnerPass + "@203.0.113.5:9443?alpn=h3&insecure=1&allowInsecure=1&congestion_control=bbr#lr00rl-udp-203.0.113.5",
			owner:    lineUserCredentialPayload{UUID: tmplOwnerUUID, Password: tmplOwnerPass}, other: lineUserCredentialPayload{UUID: tmplOtherUUID, Password: tmplOtherPass},
			host: "203.0.113.5", port: 9443},
		{name: "anytls with a domain", protocol: "anytls",
			shareURL: "anytls://" + tmplOwnerPass + "@any.example.com:443#lr00rl-tcp-any.example.com",
			owner:    lineUserCredentialPayload{Password: tmplOwnerPass}, other: lineUserCredentialPayload{Password: tmplOtherPass},
			host: "any.example.com", port: 443},
		{name: "anytls insecure", protocol: "anytls",
			shareURL: "anytls://" + tmplOwnerPass + "@203.0.113.5:443?insecure=1&allowInsecure=1#lr00rl-tcp-203.0.113.5",
			owner:    lineUserCredentialPayload{Password: tmplOwnerPass}, other: lineUserCredentialPayload{Password: tmplOtherPass},
			host: "203.0.113.5", port: 443},
		{name: "socks, base64 with a slash", protocol: "socks",
			shareURL: "socks://" + socksOwner + "@203.0.113.5:1080#lr00rl-tcp-203.0.113.5",
			owner:    lineUserCredentialPayload{Username: "owner", Password: "???>>>"}, other: lineUserCredentialPayload{Username: "u_0123456789abcdef", Password: tmplOtherPass},
			host: "203.0.113.5", port: 1080},
		{name: "vmess ws behind tls", protocol: "vmess",
			shareURL: vmessShareURL(t, map[string]any{"v": 2, "ps": "lr00rl-ws-cdn.example.com", "add": "cdn.example.com", "port": "443", "id": tmplOwnerUUID, "aid": "0", "net": "ws", "host": "cdn.example.com", "path": "/vm", "tls": "tls"}),
			owner:    lineUserCredentialPayload{UUID: tmplOwnerUUID}, other: lineUserCredentialPayload{UUID: tmplOtherUUID},
			host: "cdn.example.com", port: 443},
		{name: "vmess tcp", protocol: "vmess",
			shareURL: vmessShareURL(t, map[string]any{"v": 2, "ps": "lr00rl-tcp-203.0.113.5", "add": "203.0.113.5", "port": "8080", "id": tmplOwnerUUID, "aid": "0", "net": "tcp", "type": "none"}),
			owner:    lineUserCredentialPayload{UUID: tmplOwnerUUID}, other: lineUserCredentialPayload{UUID: tmplOtherUUID},
			host: "203.0.113.5", port: 8080},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := lineClientTemplateFromShareURL(tc.shareURL, tc.protocol)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(tmpl)
			for _, secret := range []string{tmplOwnerUUID, tmplOwnerPass, socksOwner, "???>>>", "lr00rl"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("the template keeps %q: %s", secret, raw)
				}
			}
			if tmpl.Protocol != tc.protocol || tmpl.Host != tc.host || tmpl.Port != tc.port {
				t.Fatalf("template = %+v", tmpl)
			}
			rebuilt, err := lineClientURI(tmpl, tc.owner, "")
			if err != nil {
				t.Fatal(err)
			}
			if got, want := clientURIShape(t, rebuilt), clientURIShape(t, tc.shareURL); !reflect.DeepEqual(got, want) {
				t.Fatalf("the template filled with the owner's credential does not give the reported URI:\n got %v\nwant %v\n(%s)", got, want, rebuilt)
			}
			forOther, err := lineClientURI(tmpl, tc.other, "Node A / line 1")
			if err != nil {
				t.Fatal(err)
			}
			decoded := forOther
			if tc.protocol == "vmess" {
				body, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(forOther, "vmess://"))
				decoded = string(body)
			}
			for _, secret := range []string{tmplOwnerUUID, tmplOwnerPass, socksOwner} {
				if strings.Contains(decoded, secret) {
					t.Fatalf("another identity's entry carries the owner's credential %q: %s", secret, decoded)
				}
			}
			want := tc.other.UUID
			if want == "" {
				want = tc.other.Password
			}
			if tc.protocol == "socks" {
				want = base64.StdEncoding.EncodeToString([]byte(tc.other.Username + ":" + tc.other.Password))
			}
			if !strings.Contains(decoded, want) {
				t.Fatalf("another identity's entry lacks its own credential: %s", decoded)
			}
		})
	}
}

// clientURIShape is everything a client entry is made of except its label:
// scheme, endpoint, credential and connection parameters.
func clientURIShape(t *testing.T, raw string) map[string]string {
	t.Helper()
	out := map[string]string{}
	scheme, body, _ := strings.Cut(raw, "://")
	out["scheme"] = scheme
	if scheme == "vmess" {
		decoded, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(decoded, &document); err != nil {
			t.Fatal(err)
		}
		for key, value := range document {
			if key != "ps" {
				out["vmess."+key] = fmt.Sprint(value)
			}
		}
		return out
	}
	if scheme == "socks" {
		body, _, _ = strings.Cut(body, "#")
		at := strings.LastIndexByte(body, '@')
		userinfo, _ := base64.StdEncoding.DecodeString(body[:at])
		out["userinfo"], out["endpoint"] = string(userinfo), body[at+1:]
		return out
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	out["host"], out["port"], out["userinfo"] = parsed.Hostname(), parsed.Port(), parsed.User.String()
	for key, values := range parsed.Query() {
		out["q."+key] = strings.Join(values, ",")
	}
	return out
}

// The builder refuses rather than guesses: a URI whose scheme is not the
// line's protocol, a shadowsocks line, and a URI that hides the credential in
// a parameter it would otherwise keep.
func TestLineClientTemplateRefusals(t *testing.T) {
	for name, tc := range map[string]struct{ shareURL, protocol string }{
		"scheme is not the line's protocol": {"trojan://" + tmplOwnerPass + "@203.0.113.5:443?type=tcp", "vless"},
		"shadowsocks":                       {"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:"+tmplOwnerPass)) + "@203.0.113.5:8388", "shadowsocks"},
		"credential in the path":            {"vless://" + tmplOwnerUUID + "@cdn.example.com:443?security=tls&type=ws&path=/" + tmplOwnerUUID, "vless"},
		"credential in the vmess host":      {vmessShareURL(t, map[string]any{"add": "203.0.113.5", "port": "80", "id": tmplOwnerUUID, "host": tmplOwnerUUID + ".example.com"}), "vmess"},
		"no port":                           {"vless://" + tmplOwnerUUID + "@203.0.113.5?security=reality", "vless"},
		"socks without a credential":        {"socks://203.0.113.5:1080", "socks"},
	} {
		t.Run(name, func(t *testing.T) {
			if tmpl, err := lineClientTemplateFromShareURL(tc.shareURL, tc.protocol); err == nil {
				t.Fatalf("want a refusal, got %+v", tmpl)
			}
		})
	}
}

// A parameter the template does not keep is dropped, and named, so the
// template says it is lossy: a hysteria2 line with salamander obfuscation
// needs obfs and obfs-password, and an entry built without them connects to
// nothing. lineClientURI refuses such a template instead of building that
// entry. The owner's flow is not a loss, since the identity's payload carries
// its own; the values of what was dropped are never kept.
func TestLineClientTemplateNamesWhatItDropped(t *testing.T) {
	const obfsPassword = "salamanderSecret42"
	tmpl, err := lineClientTemplateFromShareURL("hysteria2://"+tmplOwnerPass+"@203.0.113.5:8443?alpn=h3&obfs=salamander&obfs-password="+obfsPassword+"&flow=x&future=1", "hysteria2")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tmpl.Params, map[string]string{"alpn": "h3"}) {
		t.Fatalf("params = %v", tmpl.Params)
	}
	if !reflect.DeepEqual(tmpl.Dropped, []string{"future", "obfs", "obfs-password"}) || !tmpl.Lossy() {
		t.Fatalf("dropped = %v", tmpl.Dropped)
	}
	if raw, _ := json.Marshal(tmpl); strings.Contains(string(raw), obfsPassword) || strings.Contains(string(raw), "salamander") {
		t.Fatalf("a dropped parameter's value is kept: %s", raw)
	}
	if entry, err := lineClientURI(tmpl, lineUserCredentialPayload{Password: tmplOtherPass}, "x"); err == nil {
		t.Fatalf("a lossy template must not give an entry, got %s", entry)
	}

	// vmess: a field outside the allowlist is named the same way.
	vm, err := lineClientTemplateFromShareURL(vmessShareURL(t, map[string]any{"v": "2", "ps": "x", "add": "203.0.113.5", "port": "443", "id": tmplOwnerUUID, "aid": "0", "net": "tcp", "scy": "auto", "tls": ""}), "vmess")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(vm.Dropped, []string{"scy"}) {
		t.Fatalf("vmess dropped = %v", vm.Dropped)
	}

	// Every shape the fork builds keeps everything it set.
	for _, shareURL := range []string{
		"vless://" + tmplOwnerUUID + "@203.0.113.5:443?encryption=none&security=reality&flow=&type=h2&sni=www.example.com&pbk=Zm9v&fp=chrome#lr00rl",
		"tuic://" + tmplOwnerUUID + ":" + tmplOwnerPass + "@203.0.113.5:9443?alpn=h3&insecure=1&allowInsecure=1&congestion_control=bbr#lr00rl",
	} {
		scheme, _, _ := strings.Cut(shareURL, "://")
		got, err := lineClientTemplateFromShareURL(shareURL, scheme)
		if err != nil || got.Lossy() {
			t.Fatalf("%s: template %+v err %v", scheme, got, err)
		}
	}
}

// A template value never takes the place of the identity's credential or the
// endpoint: lineClientURI refuses a reserved key, which the builder never
// keeps but a record from somewhere else could carry.
func TestLineClientURIRefusesReservedParams(t *testing.T) {
	for _, tc := range []struct {
		protocol, key string
	}{{"vmess", "id"}, {"vmess", "add"}, {"vmess", "port"}, {"vmess", "ps"}, {"vless", "flow"}} {
		tmpl := store.LineClientTemplate{Protocol: tc.protocol, Host: "203.0.113.5", Port: 443, Params: map[string]string{"net": "tcp", tc.key: tmplOwnerUUID}}
		if entry, err := lineClientURI(tmpl, lineUserCredentialPayload{UUID: tmplOtherUUID}, "x"); err == nil {
			t.Fatalf("%s %s: want a refusal, got %s", tc.protocol, tc.key, entry)
		}
	}
}

func templateInventory(at time.Time, nodes ...model.SingBoxNode) model.SingBoxInventory {
	return model.SingBoxInventory{NodeID: "node-t", At: at, Status: "ok", Nodes: nodes}
}

// The sync keeps one template per adopted line of every live node, keyed by
// the line's hash, written only when one changes. A node behind NAT is
// reached at its provider's edge on the declared public port. A node that
// goes quiet keeps its templates, and so does a restart, which is what they
// are for; a line the node stops reporting loses its template.
func TestSyncLineClientTemplatesFromTheReadModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := newLinemetaTestServer(t, st)
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	now := t0
	srv.now = func() time.Time { return now }
	if err := st.UpsertNode(model.Node{ID: "node-t", Name: "Node T"}); err != nil {
		t.Fatal(err)
	}
	reality := model.SingBoxNode{Name: "reality-443", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "443",
		ShareURL: "vless://" + tmplOwnerUUID + "@203.0.113.5:443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=www.example.com&pbk=Zm9v&fp=chrome#lr00rl"}
	natTrojan := model.SingBoxNode{Name: "trojan-488", Protocol: "trojan", Network: "tcp", Address: "10.0.0.5", Port: "488", PublicPort: "50100",
		ShareURL: "trojan://" + tmplOwnerPass + "@10.0.0.5:488?type=tcp&security=tls&insecure=1#lr00rl"}
	shadowsocks := model.SingBoxNode{Name: "ss-8388", Protocol: "shadowsocks", Network: "tcp", Address: "203.0.113.5", Port: "8388",
		ShareURL: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:"+tmplOwnerPass)) + "@203.0.113.5:8388#lr00rl"}
	report := func(inv model.SingBoxInventory) {
		srv.singboxInvMu.Lock()
		srv.singboxInv = map[string]model.SingBoxInventory{"node-t": inv}
		srv.singboxInvMu.Unlock()
		srv.invalidateLineReadModel()
	}
	inv := templateInventory(now, reality, natTrojan, shadowsocks)
	inv.ProviderEdge = "edge.provider.example"
	report(inv)
	if err := srv.syncLineClientTemplates(now); err != nil {
		t.Fatal(err)
	}
	realityLine := findLine(t, srv.buildLineGroups(), "node-t", "reality-443")
	trojanLine := findLine(t, srv.buildLineGroups(), "node-t", "trojan-488")
	got := st.LineClientTemplates()
	if len(got) != 2 {
		t.Fatalf("want the reality and trojan templates, shadowsocks has no per-line users: %+v", got)
	}
	rt, _ := st.LineClientTemplate(realityLine.LineHashID)
	if rt.NodeID != "node-t" || rt.Tag != "reality-443" || rt.LineUUID != realityLine.LineUUID || rt.Host != "203.0.113.5" || rt.Port != 443 || !rt.UpdatedAt.Equal(t0) {
		t.Fatalf("reality template = %+v", rt)
	}
	tt, _ := st.LineClientTemplate(trojanLine.LineHashID)
	if tt.Host != "edge.provider.example" || tt.Port != 50100 {
		t.Fatalf("a NAT line's template must carry the public endpoint: %+v", tt)
	}
	for _, tmpl := range got {
		raw, _ := json.Marshal(tmpl)
		if strings.Contains(string(raw), tmplOwnerUUID) || strings.Contains(string(raw), tmplOwnerPass) {
			t.Fatalf("a stored template carries the owner's credential: %s", raw)
		}
	}

	// An identical report a minute later writes nothing.
	now = t0.Add(time.Minute)
	inv.At = now
	report(inv)
	if err := srv.syncLineClientTemplates(now); err != nil {
		t.Fatal(err)
	}
	if rt, _ := st.LineClientTemplate(realityLine.LineHashID); !rt.UpdatedAt.Equal(t0) {
		t.Fatalf("an unchanged line must keep its template's time: %+v", rt)
	}

	// The node goes quiet: its inventory ages out, its templates stay.
	now = t0.Add(time.Hour)
	if err := srv.syncLineClientTemplates(now); err != nil {
		t.Fatal(err)
	}
	if len(st.LineClientTemplates()) != 2 {
		t.Fatal("a silent node must keep its templates")
	}
	// A restart keeps them too, with no inventory at all.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv = newLinemetaTestServer(t, reopened)
	srv.now = func() time.Time { return now }
	if len(reopened.LineClientTemplates()) != 2 {
		t.Fatal("templates must survive a restart")
	}
	// Back with one line gone: that line's template goes.
	report(templateInventory(now, reality))
	if err := srv.syncLineClientTemplates(now); err != nil {
		t.Fatal(err)
	}
	if all := reopened.LineClientTemplates(); len(all) != 1 || all[0].Tag != "reality-443" {
		t.Fatalf("after the node stopped reporting the trojan line: %+v", all)
	}
	// A failed listing is not a report of no lines.
	failed := templateInventory(now)
	failed.Status, failed.Error = "error", "sb: command not found"
	report(failed)
	if err := srv.syncLineClientTemplates(now); err != nil {
		t.Fatal(err)
	}
	if len(reopened.LineClientTemplates()) != 1 {
		t.Fatal("a node whose listing failed must keep its templates")
	}
}

// templateSyncFixture is a server with one live node, node-t, whose sing-box
// inventory the test sets with report.
func templateSyncFixture(t *testing.T) (srv *Server, st *store.Store, now *time.Time, report func(...model.SingBoxNode)) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv = newLinemetaTestServer(t, st)
	clock := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return clock }
	if err := st.UpsertNode(model.Node{ID: "node-t", Name: "Node T"}); err != nil {
		t.Fatal(err)
	}
	report = func(nodes ...model.SingBoxNode) {
		srv.singboxInvMu.Lock()
		srv.singboxInv = map[string]model.SingBoxInventory{"node-t": templateInventory(clock, nodes...)}
		srv.singboxInvMu.Unlock()
		srv.invalidateLineReadModel()
	}
	return srv, st, &clock, report
}

func realityTemplateNode(host string) model.SingBoxNode {
	shareHost := host
	if strings.Contains(host, ":") {
		shareHost = "[" + host + "]"
	}
	return model.SingBoxNode{Name: "reality-443", Protocol: "vless", Network: "tcp", Address: host, Port: "443",
		ShareURL: "vless://" + tmplOwnerUUID + "@" + shareHost + ":443?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=www.example.com&pbk=Zm9v&fp=chrome#lr00rl"}
}

// A live node that lists a line but gives no usable share URL for it this
// time, empty or one the builder refuses, keeps that line's template. Only a
// line the node stops listing loses it.
func TestSyncLineClientTemplatesKeepsALineItCannotRebuild(t *testing.T) {
	srv, st, now, report := templateSyncFixture(t)
	good := realityTemplateNode("203.0.113.5")
	report(good)
	if err := srv.syncLineClientTemplates(*now); err != nil {
		t.Fatal(err)
	}
	line := findLine(t, srv.buildLineGroups(), "node-t", "reality-443")
	want, ok := st.LineClientTemplate(line.LineHashID)
	if !ok {
		t.Fatal("the first sync must store the template")
	}
	for name, shareURL := range map[string]string{
		"empty share url":    "",
		"refused share url":  "trojan://" + tmplOwnerPass + "@203.0.113.5:443?type=tcp",
		"unparseable":        "vless://%zz",
		"credential in path": "vless://" + tmplOwnerUUID + "@203.0.113.5:443?security=tls&type=ws&path=/" + tmplOwnerUUID,
	} {
		*now = now.Add(time.Minute)
		broken := good
		broken.ShareURL = shareURL
		report(broken)
		if err := srv.syncLineClientTemplates(*now); err != nil {
			t.Fatal(err)
		}
		if got, ok := st.LineClientTemplate(line.LineHashID); !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: a listed line must keep its template: %+v ok=%v", name, got, ok)
		}
	}
	*now = now.Add(time.Minute)
	report()
	if err := srv.syncLineClientTemplates(*now); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.LineClientTemplate(line.LineHashID); ok {
		t.Fatal("a line the node no longer lists must lose its template")
	}
}

// A changed template is stored only once two consecutive syncs build it, so a
// share host that flips between address families and back writes nothing,
// while a change that holds lands one sync later.
func TestSyncLineClientTemplatesConfirmsAChangeBeforeStoringIt(t *testing.T) {
	srv, st, now, report := templateSyncFixture(t)
	t0 := *now
	report(realityTemplateNode("203.0.113.5"))
	if err := srv.syncLineClientTemplates(*now); err != nil {
		t.Fatal(err)
	}
	line := findLine(t, srv.buildLineGroups(), "node-t", "reality-443")
	stored := func() store.LineClientTemplate {
		t.Helper()
		got, ok := st.LineClientTemplate(line.LineHashID)
		if !ok {
			t.Fatal("template missing")
		}
		return got
	}
	if got := stored(); got.Host != "203.0.113.5" || !got.UpdatedAt.Equal(t0) {
		t.Fatalf("a new line takes its template at once: %+v", got)
	}
	// Flapping: v6, v4, v6, v4. No sync sees the same new value twice in a
	// row, so nothing is written.
	for i, host := range []string{"2001:db8::5", "203.0.113.5", "2001:db8::5", "203.0.113.5"} {
		*now = now.Add(time.Minute)
		report(realityTemplateNode(host))
		if err := srv.syncLineClientTemplates(*now); err != nil {
			t.Fatal(err)
		}
		if got := stored(); got.Host != "203.0.113.5" || !got.UpdatedAt.Equal(t0) {
			t.Fatalf("flap %d to %s: %+v", i, host, got)
		}
	}
	// A change that holds: held at the first sighting, stored at the second.
	*now = now.Add(time.Minute)
	report(realityTemplateNode("198.51.100.7"))
	if err := srv.syncLineClientTemplates(*now); err != nil {
		t.Fatal(err)
	}
	if got := stored(); got.Host != "203.0.113.5" {
		t.Fatalf("first sighting of a change must not store it: %+v", got)
	}
	*now = now.Add(time.Minute)
	if err := srv.syncLineClientTemplates(*now); err != nil {
		t.Fatal(err)
	}
	if got := stored(); got.Host != "198.51.100.7" || !got.UpdatedAt.Equal(*now) {
		t.Fatalf("a change seen twice in a row must be stored: %+v", got)
	}
}
