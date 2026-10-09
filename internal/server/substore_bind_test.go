package server

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The identity every bind fixture serves, and its vless credential.
const (
	bindIdentityID   = "vu-bind"
	bindIdentityUUID = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
	bindIdentityFlow = "xtls-rprx-vision"
)

type bindEnv struct {
	*catalogueEnv
	identity VpnUser
	rows     []model.LineCatalogueRow
}

// bindFixture is the catalogue fixture (vless Reality lines) plus an
// identity bound to every line, with the identity's current credential
// applied on each, so an identity link would serve every line.
func bindFixture(t testing.TB, nodes, perNode int) *bindEnv {
	t.Helper()
	e := catalogueFixture(t, nodes, perNode)
	rows := e.read(t, "").Rows
	u := VpnUser{ID: bindIdentityID, Email: "bind@example.com", Name: "Bind", Enabled: true, CreatedAt: e.now, UpdatedAt: e.now,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: bindIdentityUUID, Flow: bindIdentityFlow}}}
	for _, row := range rows {
		u.Bindings = append(u.Bindings, LineBinding{LineHashID: row.LineHashID, Enabled: true, AppliedCredentialSHA256: bindAppliedSHA(t, u, row.LineUUID)})
	}
	if err := e.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	return &bindEnv{catalogueEnv: e, identity: u, rows: rows}
}

// bindAppliedSHA is the applied-credential hash a line-user plan records
// for the identity's vless credential on a line.
func bindAppliedSHA(t testing.TB, u VpnUser, lineUUID string) string {
	t.Helper()
	payload, err := lineUserCredential(u, "vless", userLineName(u.ID, lineUUID))
	if err != nil {
		t.Fatal(err)
	}
	sha, err := lineUserCredentialSHA(payload)
	if err != nil {
		t.Fatal(err)
	}
	return sha
}

// placeholder draws a fresh placeholder for one field of one line.
func bindPlaceholder(t testing.TB, lineUUID, field string) string {
	t.Helper()
	p, err := model.NewPlanPlaceholder(lineUUID, field)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// bindNode is the node the plugin builds for a catalogue row: the vless
// Reality line as the URI parser reads its template, with a placeholder in
// the uuid. edit changes the node's fields before it is encoded; a nil value
// deletes a field.
func bindNode(t testing.TB, row model.LineCatalogueRow, placeholder string, edit map[string]any) model.SelectionPlanNode {
	t.Helper()
	fields := []struct {
		key   string
		value any
	}{
		{"name", row.NodeName + " " + row.Name}, {"type", "vless"}, {"server", row.Template.Host}, {"port", row.Template.Port},
		{"uuid", placeholder}, {"udp", true}, {"tls", true}, {"sni", "www.example.com"}, {"network", "tcp"},
		{"reality-opts", map[string]any{"public-key": "Zm9vYmFyYmF6", "short-id": "0a1b"}},
		{"client-fingerprint", "chrome"}, {"encryption", "none"}, {"packet-encoding", "xudp"},
		{"skip-cert-verify", false}, {"_h2", false}, {"line_uuid", row.LineUUID},
	}
	var b strings.Builder
	b.WriteByte('{')
	seen := map[string]bool{}
	write := func(key string, value any) {
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(key)
		v, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	for _, f := range fields {
		seen[f.key] = true
		value, edited := edit[f.key]
		if edited && value == nil {
			continue
		}
		if !edited {
			value = f.value
		}
		write(f.key, value)
	}
	for key, value := range edit {
		if !seen[key] && value != nil {
			write(key, value)
		}
	}
	b.WriteByte('}')
	return model.SelectionPlanNode{LineUUID: row.LineUUID, Placeholders: map[string]string{"uuid": placeholder}, Node: json.RawMessage(b.String())}
}

// bindNodesPlan is a typed-node plan of one node per row.
func bindNodesPlan(t testing.TB, rows []model.LineCatalogueRow) model.SelectionPlan {
	t.Helper()
	plan := model.SelectionPlan{Kind: model.SelectionPlanKindNodes}
	for _, row := range rows {
		plan.Nodes = append(plan.Nodes, bindNode(t, row, bindPlaceholder(t, row.LineUUID, "uuid"), nil))
	}
	return plan
}

// selection is the snapshot selection of every fixture row.
func (e *bindEnv) selection() map[string]bool {
	out := make(map[string]bool, len(e.rows))
	for _, row := range e.rows {
		out[row.LineUUID] = true
	}
	return out
}

// bindRun builds a fresh catalogue, round-trips the plan through the SDK's
// strict codec the way a render reply arrives, and binds it. A nil selected
// is the selection of every fixture row.
func (e *bindEnv) bindRun(t testing.TB, plan model.SelectionPlan, selected map[string]bool) substoreBindResult {
	t.Helper()
	if selected == nil {
		selected = e.selection()
	}
	raw, err := model.EncodeSelectionPlan(plan)
	if err != nil {
		t.Fatalf("plan does not encode: %v", err)
	}
	decoded, err := model.DecodeSelectionPlan(raw)
	if err != nil {
		t.Fatalf("plan does not decode: %v", err)
	}
	catalogue, err := e.srv.buildLineCatalogue("")
	if err != nil {
		t.Fatal(err)
	}
	u, ok := e.srv.getVpnUser(bindIdentityID)
	if !ok {
		t.Fatal("bind identity missing")
	}
	return substoreBindPlan(decoded, u, catalogue, selected)
}

// reasons maps each excluded plan index to its reason.
func (r substoreBindResult) reasons() map[int]string {
	out := map[int]string{}
	for _, x := range r.Excluded {
		out[x.Index] = x.Reason
	}
	return out
}

func TestSubstoreBindBindsTheIdentityIntoEveryValidatedNode(t *testing.T) {
	e := bindFixture(t, 2, 2)
	plan := bindNodesPlan(t, e.rows)
	result := e.bindRun(t, plan, nil)
	if result.Refused != "" || len(result.Excluded) != 0 || len(result.Entries) != len(e.rows) || len(result.nodes) != len(e.rows) {
		t.Fatalf("a valid plan: refused %q, excluded %+v, %d entries, %d nodes", result.Refused, result.Excluded, len(result.Entries), len(result.nodes))
	}
	for i, node := range result.nodes {
		obj, err := parseSubstoreNodeObject(node)
		if err != nil {
			t.Fatal(err)
		}
		if uuid, _ := obj.string("uuid"); uuid != bindIdentityUUID {
			t.Fatalf("node %d carries uuid %q, want the identity's", i, uuid)
		}
		if flow, _ := obj.string("flow"); flow != bindIdentityFlow {
			t.Fatalf("node %d carries flow %q, want the identity's", i, flow)
		}
		if strings.Contains(string(node), model.PlanPlaceholderPrefix) {
			t.Fatalf("node %d still carries a placeholder: %s", i, node)
		}
		// The bound node keeps the plugin's field order: name first, the
		// flow the binder added last.
		if obj.keys[0] != "name" || obj.keys[len(obj.keys)-1] != "flow" {
			t.Fatalf("node %d field order %v", i, obj.keys)
		}
	}
	// The preview half carries no credential.
	preview, _ := json.Marshal(struct {
		E []substoreBindEntry
		X []substoreBindExclusion
	}{result.Entries, result.Excluded})
	if carriesCredential(string(preview), bindIdentityUUID) {
		t.Fatalf("the preview entries carry the identity's credential: %s", preview)
	}
	if entry := result.Entries[0]; entry.LineUUID != e.rows[0].LineUUID || entry.Clone != 1 || entry.Port != e.rows[0].Template.Port ||
		entry.Label != "Node 000 vless-20000" || entry.Protocol != "vless" {
		t.Fatalf("entry = %+v", entry)
	}
	// An entry's digest leaves the credential out, so a fresh placeholder
	// draw of the same plan digests the same, and an entry that dials
	// differently does not.
	again := e.bindRun(t, bindNodesPlan(t, e.rows), nil)
	for i := range result.Entries {
		if result.Entries[i].Digest == "" || result.Entries[i].Digest != again.Entries[i].Digest {
			t.Fatalf("entry %d digests %q then %q", i, result.Entries[i].Digest, again.Entries[i].Digest)
		}
	}
	moved := bindNodesPlan(t, e.rows)
	moved.Nodes[0] = bindNode(t, e.rows[0], moved.Nodes[0].Placeholders["uuid"], map[string]any{"client-fingerprint": "safari"})
	if e.bindRun(t, moved, nil).Entries[0].Digest == result.Entries[0].Digest {
		t.Fatal("an entry with another fingerprint has the same digest")
	}
}

// Check 3: a node whose server is outside the line's allowed set is excluded
// with plan_rejected:server, so a script cannot move a line to its own host.
func TestSubstoreBindRejectsAServerOutsideTheLinesAllowedSet(t *testing.T) {
	e := bindFixture(t, 3, 1)
	for name, server := range map[string]string{
		"a name it controls":       "relay.attacker.example",
		"another node's address":   catalogueNodeIP(2),
		"an address nobody listed": "198.51.100.200",
	} {
		plan := model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{
			bindNode(t, e.rows[0], bindPlaceholder(t, e.rows[0].LineUUID, "uuid"), map[string]any{"server": server}),
			bindNode(t, e.rows[1], bindPlaceholder(t, e.rows[1].LineUUID, "uuid"), nil),
		}}
		result := e.bindRun(t, plan, nil)
		if got := result.reasons()[0]; got != "plan_rejected:server" {
			t.Fatalf("%s: node 0 reason %q, want plan_rejected:server", name, got)
		}
		if len(result.nodes) != 1 {
			t.Fatalf("%s: the honest node must still bind: %d nodes", name, len(result.nodes))
		}
		obj, err := parseSubstoreNodeObject(result.nodes[0])
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := obj.string("server"); got != e.rows[1].Template.Host {
			t.Fatalf("%s: the bound node dials %q", name, got)
		}
	}
	port := bindNode(t, e.rows[0], bindPlaceholder(t, e.rows[0].LineUUID, "uuid"), map[string]any{"port": e.rows[0].Template.Port + 1})
	if got := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{port}}, nil).reasons()[0]; got != "plan_rejected:port" {
		t.Fatalf("a moved port: %q", got)
	}
}

// The allowed set is the template host, the provider edge, a verified DDNS
// name and the catalogue's addresses; an unverified name is not in it.
func TestSubstoreBindServerAllowedSet(t *testing.T) {
	tmpl := store.LineClientTemplate{Host: "203.0.114.7", Port: 443}
	row := model.LineCatalogueRow{ProviderEdge: "edge.provider.example", Addresses: []string{"203.0.114.7", "2001:db9::7"},
		DDNSNames: []model.LineCatalogueDDNSName{{Name: "node.ddns.example", Verified: true}, {Name: "stale.ddns.example"}}}
	for server, want := range map[string]bool{
		"203.0.114.7": true, "edge.provider.example": true, "EDGE.provider.example": true, "node.ddns.example": true,
		"[2001:db9::7]": true, "2001:db9:0::7": true,
		"stale.ddns.example": false, "203.0.114.8": false, "": false, "attacker.example": false,
	} {
		if got := substoreBindServerAllowed(server, tmpl, row); got != want {
			t.Fatalf("server %q allowed = %v, want %v", server, got, want)
		}
	}
	named := store.LineClientTemplate{Host: "line.example", Port: 443}
	if !substoreBindServerAllowed("line.example", named, model.LineCatalogueRow{}) || substoreBindServerAllowed("203.0.114.7", named, model.LineCatalogueRow{}) {
		t.Fatal("a template host name is allowed by name only")
	}
}

// Check 2: the credential field must carry its own placeholder, untouched,
// and nowhere else.
func TestSubstoreBindRejectsAnAlteredPlaceholder(t *testing.T) {
	e := bindFixture(t, 1, 2)
	row, other := e.rows[0], e.rows[1]
	p := bindPlaceholder(t, row.LineUUID, "uuid")
	altered := p[:len(p)-1] + map[bool]string{true: "0", false: "1"}[p[len(p)-1] != '0']
	cases := map[string]model.SelectionPlanNode{
		"altered":            bindNode(t, row, p, map[string]any{"uuid": altered}),
		"replaced":           bindNode(t, row, p, map[string]any{"uuid": "11111111-2222-4333-8444-555555555555"}),
		"removed":            bindNode(t, row, p, map[string]any{"uuid": nil}),
		"copied into a name": bindNode(t, row, p, map[string]any{"name": "copy " + p}),
		"another line's":     bindNode(t, row, p, map[string]any{"name": "copy " + bindPlaceholder(t, other.LineUUID, "uuid")}),
		"a second field":     bindNode(t, row, p, map[string]any{"password": "LATTICE"}),
		"case changed":       bindNode(t, row, p, map[string]any{"uuid": strings.ToLower(p)}),
	}
	for name, node := range cases {
		result := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{node}}, nil)
		if got := result.reasons()[0]; got != "plan_rejected:credential" {
			t.Fatalf("%s: reason %q, want plan_rejected:credential", name, got)
		}
		if result.Refused != substoreBindRefusedNoLine || len(result.nodes) != 0 {
			t.Fatalf("%s: a plan with no includable line must be refused, got %q", name, result.Refused)
		}
	}
	// The placeholders map must name exactly the protocol's fields.
	extra := bindNode(t, row, p, nil)
	extra.Placeholders["password"] = bindPlaceholder(t, row.LineUUID, "password")
	if got := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{extra}}, nil).reasons()[0]; got != "plan_rejected:credential" {
		t.Fatalf("an extra placeholder field: %q", got)
	}
}

// Check 2 and 4: type, transport, security and the fields outside the
// mutable set are the template's.
func TestSubstoreBindRejectsAChangedShape(t *testing.T) {
	e := bindFixture(t, 1, 1)
	row := e.rows[0]
	for edit, want := range map[string]struct {
		field string
		value any
	}{
		"plan_rejected:type":            {"type", "trojan"},
		"plan_rejected:network":         {"network", "ws"},
		"plan_rejected:tls":             {"tls", false},
		"plan_rejected:reality-opts":    {"reality-opts", map[string]any{"public-key": "YXR0YWNrZXI", "short-id": "0a1b"}},
		"plan_rejected:sni":             {"sni", "attacker.example"},
		"plan_rejected:encryption":      {"encryption", "mlkem768x25519plus"},
		"plan_rejected:dialer-proxy":    {"dialer-proxy", "relay"},
		"plan_rejected:tls-fingerprint": {"tls-fingerprint", "ab:cd"},
		"plan_rejected:line_uuid":       {"line_uuid", "11111111-2222-4333-8444-555555555555"},
		"plan_rejected:_ca":             {"_ca", "-----BEGIN CERTIFICATE-----"},
		// The annotations that carry raw extra options or a gRPC authority
		// can name a second endpoint, and no catalogue template sets them.
		"plan_rejected:_extra":             {"_extra", `{"downloadSettings":{"address":"relay.attacker.example","port":443}}`},
		"plan_rejected:_extra_unsupported": {"_extra_unsupported", map[string]any{"downloadSettings": map[string]any{"address": "relay.attacker.example"}}},
		"plan_rejected:_grpc-authority":    {"_grpc-authority", "relay.attacker.example"},
		// A transport options object of another network is a script's.
		"plan_rejected:xhttp-opts": {"xhttp-opts", map[string]any{"path": "/x"}},
		// Certificate checks stay on where the template keeps them on, and
		// the flag is a boolean.
		"plan_rejected:skip-cert-verify": {"skip-cert-verify", true},
	} {
		node := bindNode(t, row, bindPlaceholder(t, row.LineUUID, "uuid"), map[string]any{want.field: want.value})
		if got := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{node}}, nil).reasons()[0]; got != edit {
			t.Fatalf("%s=%v: reason %q, want %q", want.field, want.value, got, edit)
		}
	}
	quoted := bindNode(t, row, bindPlaceholder(t, row.LineUUID, "uuid"), map[string]any{"skip-cert-verify": "true"})
	if got := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{quoted}}, nil).reasons()[0]; got != "plan_rejected:skip-cert-verify" {
		t.Fatalf("skip-cert-verify as a string: %q", got)
	}
	// The mutable set changes freely.
	node := bindNode(t, row, bindPlaceholder(t, row.LineUUID, "uuid"), map[string]any{"name": "Tokyo 01", "udp": false, "tfo": true,
		"client-fingerprint": "safari", "alpn": []string{"h2"}, "skip-cert-verify": false, "script": map[string]any{"_tag": "x"}})
	result := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{node}}, nil)
	if len(result.Excluded) != 0 || result.Entries[0].Name != "Tokyo 01" {
		t.Fatalf("mutable fields: excluded %+v, entries %+v", result.Excluded, result.Entries)
	}
	// A template that turns certificate checks off lets the node do so.
	insecure := e.lineFor(t, e.rows[0], store.LineClientTemplate{Protocol: "vless", Host: row.Template.Host, Port: row.Template.Port,
		Params: map[string]string{"security": "tls", "sni": "www.example.com", "allowInsecure": "1", "type": "tcp"}})
	off := bindRawNode(t, row.LineUUID, `{"name":"a","type":"vless","server":"`+row.Template.Host+`","port":`+strconv.Itoa(row.Template.Port)+
		`,"uuid":"%s","tls":true,"sni":"www.example.com","skip-cert-verify":true}`)
	if field := bindCheck(t, off, insecure); field != "" {
		t.Fatalf("an insecure template's node: %q", field)
	}
}

// lineFor is a bind line for row with template t, the way substoreBindLineOf
// builds one, for checks against templates the catalogue fixture lacks.
func (e *bindEnv) lineFor(t testing.TB, row model.LineCatalogueRow, tmpl store.LineClientTemplate) *substoreBindLine {
	t.Helper()
	shape, ok := substoreBindTemplateShape(tmpl)
	if !ok {
		t.Fatalf("no shape for %+v", tmpl)
	}
	return &substoreBindLine{row: row, template: tmpl, shape: shape}
}

// bindRawNode is a plan node of line lineUUID from a JSON object whose %s
// stands for the uuid placeholder.
func bindRawNode(t testing.TB, lineUUID, object string) model.SelectionPlanNode {
	t.Helper()
	p := bindPlaceholder(t, lineUUID, "uuid")
	return model.SelectionPlanNode{LineUUID: lineUUID, Placeholders: map[string]string{"uuid": p}, Node: json.RawMessage(fmt.Sprintf(object, p))}
}

// bindCheck runs checks 2 to 4 on one node against one line.
func bindCheck(t testing.TB, node model.SelectionPlanNode, line *substoreBindLine) string {
	t.Helper()
	obj, err := parseSubstoreNodeObject(node.Node)
	if err != nil {
		t.Fatalf("node %s: %v", node.Node, err)
	}
	return substoreBindCheckNode(node.Node, obj, node, line)
}

// Every transport options object is checked key by key: it belongs to the
// node's network, carries only the keys a template sets, and every host it
// names is the line's. A node whose server and port are honest cannot send
// the credential to another origin through a Host header, an h2 or xhttp
// host, or xhttp's download settings.
func TestSubstoreBindChecksTransportOptions(t *testing.T) {
	e := bindFixture(t, 1, 1)
	row := e.rows[0]
	edge := "203.0.113.250"
	row.ProviderEdge = "edge.provider.example"
	node := func(network, opts string) model.SelectionPlanNode {
		object := `{"name":"a","type":"vless","server":"` + edge + `","port":443,"uuid":"%s","tls":true,"sni":"cdn.example","network":"` + network + `"`
		if opts != "" {
			object += "," + opts
		}
		return bindRawNode(t, row.LineUUID, object+"}")
	}
	line := func(params map[string]string) *substoreBindLine {
		params["security"], params["sni"] = "tls", "cdn.example"
		return e.lineFor(t, row, store.LineClientTemplate{Protocol: "vless", Host: edge, Port: 443, Params: params})
	}
	ws := line(map[string]string{"type": "ws", "host": "cdn.example", "path": "/ws"})
	xhttp := line(map[string]string{"type": "xhttp", "host": "cdn.example", "path": "/x", "mode": "auto"})
	h2 := line(map[string]string{"type": "http", "host": "cdn.example,alt.cdn.example", "path": "/h2"})
	grpc := line(map[string]string{"type": "grpc", "serviceName": "svc"})
	httpLine := line(map[string]string{"type": "tcp", "headerType": "http", "host": "cdn.example", "path": "/"})
	for _, tc := range []struct {
		name string
		line *substoreBindLine
		node model.SelectionPlanNode
		want string
	}{
		{"honest ws", ws, node("ws", `"ws-opts":{"path":"/ws","headers":{"Host":"cdn.example"},"max-early-data":2048,"early-data-header-name":"Sec-WebSocket-Protocol"}`), ""},
		{"ws Host pinned to the provider edge name", ws, node("ws", `"ws-opts":{"path":"/ws","headers":{"host":"edge.provider.example"}}`), ""},
		{"ws Host elsewhere", ws, node("ws", `"ws-opts":{"path":"/ws","headers":{"Host":"origin.attacker.example"}}`), "plan_rejected:ws-opts.headers"},
		{"ws another header", ws, node("ws", `"ws-opts":{"path":"/ws","headers":{"X-Forwarded-Host":"cdn.example"}}`), "plan_rejected:ws-opts.headers"},
		{"ws early data in Host", ws, node("ws", `"ws-opts":{"path":"/ws","max-early-data":2048,"early-data-header-name":"Host"}`), "plan_rejected:ws-opts.early-data-header-name"},
		{"honest xhttp", xhttp, node("xhttp", `"xhttp-opts":{"path":"/x","host":"cdn.example","mode":"auto"}`), ""},
		{"xhttp download settings", xhttp, node("xhttp", `"xhttp-opts":{"path":"/x","host":"cdn.example","download-settings":{"server":"relay.attacker.example","port":443}}`), "plan_rejected:xhttp-opts.download-settings"},
		{"xhttp host elsewhere", xhttp, node("xhttp", `"xhttp-opts":{"path":"/x","host":"origin.attacker.example"}`), "plan_rejected:xhttp-opts.host"},
		{"xhttp Host header elsewhere", xhttp, node("xhttp", `"xhttp-opts":{"path":"/x","headers":{"Host":"origin.attacker.example"}}`), "plan_rejected:xhttp-opts.headers"},
		{"xhttp ws-opts", xhttp, node("xhttp", `"ws-opts":{"path":"/x"}`), "plan_rejected:ws-opts"},
		{"honest h2", h2, node("h2", `"h2-opts":{"path":"/h2","host":["cdn.example","alt.cdn.example"]}`), ""},
		{"h2 host elsewhere", h2, node("h2", `"h2-opts":{"path":"/h2","host":["cdn.example","origin.attacker.example"]}`), "plan_rejected:h2-opts.host"},
		{"honest grpc", grpc, node("grpc", `"grpc-opts":{"grpc-service-name":"svc"}`), ""},
		{"grpc authority", grpc, node("grpc", `"grpc-opts":{"grpc-service-name":"svc","authority":"origin.attacker.example"}`), "plan_rejected:grpc-opts.authority"},
		{"honest http", httpLine, node("http", `"http-opts":{"path":["/"],"headers":{"Host":["cdn.example"]},"method":"GET"}`), ""},
		{"http Host elsewhere", httpLine, node("http", `"http-opts":{"path":["/"],"headers":{"Host":["origin.attacker.example"]}}`), "plan_rejected:http-opts.headers"},
		{"a path object", ws, node("ws", `"ws-opts":{"path":{"server":"origin.attacker.example"}}`), "plan_rejected:ws-opts.path"},
	} {
		got := bindCheck(t, tc.node, tc.line)
		if got != "" {
			got = substoreBindRejectedPrefix + got
		}
		if got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// At most MaxPlanClonesPerLine nodes bind per line; the fifth is excluded.
func TestSubstoreBindExcludesTheFifthClone(t *testing.T) {
	e := bindFixture(t, 1, 1)
	row := e.rows[0]
	p := bindPlaceholder(t, row.LineUUID, "uuid")
	plan := model.SelectionPlan{Kind: model.SelectionPlanKindNodes}
	for i := 0; i < model.MaxPlanClonesPerLine+1; i++ {
		plan.Nodes = append(plan.Nodes, bindNode(t, row, p, map[string]any{"name": "clone " + strconv.Itoa(i)}))
	}
	result := e.bindRun(t, plan, nil)
	if len(result.nodes) != model.MaxPlanClonesPerLine || len(result.Excluded) != 1 ||
		result.Excluded[0].Index != model.MaxPlanClonesPerLine || result.Excluded[0].Reason != substoreBindReasonCloneLimit {
		t.Fatalf("five clones: %d bound, excluded %+v", len(result.nodes), result.Excluded)
	}
	if last := result.Entries[len(result.Entries)-1]; last.Clone != model.MaxPlanClonesPerLine {
		t.Fatalf("the fourth clone is numbered %d", last.Clone)
	}
}

// A fleet node without a line_uuid is excluded with no_line; a provider node
// passes through unbound.
func TestSubstoreBindExcludesANodeWithoutALine(t *testing.T) {
	e := bindFixture(t, 1, 1)
	foreign := model.SelectionPlanNode{Node: json.RawMessage(`{"name":"injected","type":"vless","server":"relay.attacker.example","port":443,"uuid":"11111111-2222-4333-8444-555555555555"}`)}
	// A provider node is passed through as it is: a fleet placeholder a
	// script copied into it stays a placeholder and binds nothing.
	copied := bindPlaceholder(t, e.rows[0].LineUUID, "uuid")
	provider := model.SelectionPlanNode{Provider: true, Node: json.RawMessage(`{"name":"provider","type":"vless","server":"relay.attacker.example","port":443,"uuid":"` + copied + `"}`)}
	plan := model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{
		foreign, bindNode(t, e.rows[0], bindPlaceholder(t, e.rows[0].LineUUID, "uuid"), nil), provider}}
	result := e.bindRun(t, plan, nil)
	if got := result.reasons(); len(got) != 1 || got[0] != substoreBindReasonNoLine {
		t.Fatalf("exclusions %v", got)
	}
	if len(result.nodes) != 2 || string(result.nodes[1]) != string(provider.Node) || !result.Entries[1].Provider {
		t.Fatalf("bound nodes %d, entries %+v", len(result.nodes), result.Entries)
	}
}

// Check 1: the line must be in the catalogue, in the snapshot's selection and
// bound to the identity; then the identity link's own line checks apply.
func TestSubstoreBindAppliesTheLineAndIdentityChecks(t *testing.T) {
	e := bindFixture(t, 1, 5)
	u := e.identity
	u.Bindings[1].Enabled = false
	u.Bindings[2].AppliedCredentialSHA256 = ""
	u.Bindings = append(u.Bindings[:3], u.Bindings[4:]...)
	if err := e.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	unknown := e.rows[0]
	unknown.LineUUID = "11111111-2222-4333-8444-555555555555"
	plan := bindNodesPlan(t, append(append([]model.LineCatalogueRow(nil), e.rows...), unknown))
	result := e.bindRun(t, plan, nil)
	want := map[int]string{1: identityLineBindingDisabled, 2: identityLineNotApplied, 3: substoreBindReasonNotBound, 5: identityLineUnknown}
	if got := result.reasons(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("exclusions %v, want %v", got, want)
	}
	if len(result.nodes) != 2 {
		t.Fatalf("%d nodes bound, want 2", len(result.nodes))
	}
	// A line the snapshot did not select is a plan the chain changed.
	selected := map[string]bool{e.rows[0].LineUUID: true}
	if got := e.bindRun(t, bindNodesPlan(t, e.rows[:1]), selected).reasons(); len(got) != 0 {
		t.Fatalf("a selected line was excluded: %v", got)
	}
	if got := e.bindRun(t, bindNodesPlan(t, e.rows[3:4]), selected).reasons()[0]; got != "plan_rejected:line_uuid" {
		t.Fatalf("an unselected line: %q", got)
	}
}

// bindDocument writes a mihomo-style document whose proxies are the plan
// nodes in block style: each value as its JSON text (a YAML flow scalar or
// mapping), each placeholder plain, as a producer writes one, and the
// Lattice line_uuid left out. edits replaces the text of a field of one
// proxy.
func bindDocument(t testing.TB, nodes []model.SelectionPlanNode, edits map[int]map[string]string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("mixed-port: 7890\nproxies:\n")
	var names []string
	for i, node := range nodes {
		obj, err := parseSubstoreNodeObject(node.Node)
		if err != nil {
			t.Fatal(err)
		}
		prefix := "  - "
		for _, key := range obj.keys {
			if key == "line_uuid" {
				continue
			}
			value := string(obj.values[key])
			if text, ok := obj.string(key); ok && strings.HasPrefix(text, model.PlanPlaceholderPrefix) {
				value = text
			}
			if text, ok := edits[i][key]; ok {
				value = text
			}
			b.WriteString(prefix + key + ": " + value + "\n")
			prefix = "    "
		}
		names = append(names, string(obj.values["name"]))
	}
	b.WriteString("proxy-groups:\n  - name: auto\n    type: select\n    proxies:\n")
	for _, name := range names {
		b.WriteString("      - " + name + "\n")
	}
	return b.String()
}

// A document plan is served only when its text is tied to the validated
// nodes: each placeholder that receives a credential is that credential's
// value in a proxy mapping that passes the node checks for its line, at the
// place it was read from. Honest typed nodes beside a rewritten text are
// refused.
func TestSubstoreBindDocumentPlanTiesTheTextToTheValidatedNodes(t *testing.T) {
	e := bindFixture(t, 1, 3)
	var p []string
	var nodes []model.SelectionPlanNode
	for _, row := range e.rows {
		p = append(p, bindPlaceholder(t, row.LineUUID, "uuid"))
		nodes = append(nodes, bindNode(t, row, p[len(p)-1], nil))
	}
	run := func(document string, nodes []model.SelectionPlanNode) substoreBindResult {
		t.Helper()
		return e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindDocument, Nodes: nodes, Document: document}, nil)
	}
	document := bindDocument(t, nodes, nil)
	result := run(document, nodes)
	if result.Refused != "" || result.document == nil || result.document.Content != document || len(result.document.Substitutions) != len(p) {
		t.Fatalf("a valid document: refused %q, document %+v", result.Refused, result.document)
	}
	for _, placeholder := range p {
		if result.document.Substitutions[placeholder] != bindIdentityUUID {
			t.Fatalf("substitution of %s: %q", placeholder, result.document.Substitutions[placeholder])
		}
	}
	if err := result.document.Validate(); err != nil {
		t.Fatal(err)
	}
	// The same proxies as one line of JSON, a name in CJK before the first
	// placeholder: the position check counts characters, as the parser does.
	named := append([]model.SelectionPlanNode{bindNode(t, e.rows[0], p[0], map[string]any{"name": "东京 01 高速"})}, nodes[1:]...)
	var objects []string
	for _, node := range named {
		objects = append(objects, string(node.Node))
	}
	if result := run(`{"proxies":[`+strings.Join(objects, ",")+`]}`, named); result.Refused != "" {
		t.Fatalf("a JSON document: refused %q", result.Refused)
	}

	firstUUID := "uuid: " + p[0]
	for name, tc := range map[string]struct {
		document string
		want     string
	}{
		"a placeholder copied into a comment": {document + "# backup " + p[1] + "\n", substoreBindReasonPlaceholderCount},
		"the server rewritten in the text": {bindDocument(t, nodes, map[int]map[string]string{0: {"server": "relay.attacker.example"}}),
			"plan_rejected:server"},
		"two servers rewritten": {bindDocument(t, nodes, map[int]map[string]string{0: {"server": "evil.example"}, 1: {"server": "evil2.example"}}),
			"plan_rejected:server"},
		"the port rewritten":         {bindDocument(t, nodes, map[int]map[string]string{2: {"port": "8443"}}), "plan_rejected:port"},
		"certificate checks off":     {bindDocument(t, nodes, map[int]map[string]string{0: {"skip-cert-verify": "true"}}), "plan_rejected:skip-cert-verify"},
		"a YAML 1.1 boolean":         {bindDocument(t, nodes, map[int]map[string]string{0: {"skip-cert-verify": "yes"}}), substoreBindReasonPlaceholderContext},
		"a duplicate server":         {strings.Replace(document, firstUUID, firstUUID+"\n    server: relay.attacker.example", 1), substoreBindReasonPlaceholderContext},
		"the credential moved":       {strings.Replace(document, firstUUID, "password: "+p[0], 1), substoreBindReasonPlaceholderContext},
		"inside a longer value":      {strings.Replace(document, firstUUID, "uuid: x-"+p[0], 1), substoreBindReasonPlaceholderContext},
		"a tagged credential":        {strings.Replace(document, firstUUID, "uuid: !!str "+p[0], 1), substoreBindReasonPlaceholderContext},
		"an anchored credential":     {strings.Replace(document, firstUUID, "uuid: &u "+p[0], 1), substoreBindReasonPlaceholderContext},
		"an escape and a comment":    {strings.Replace(document, firstUUID, `uuid: "\u004c`+p[0][1:]+`"`, 1) + "# " + p[0] + "\n", substoreBindReasonPlaceholderContext},
		"two documents":              {document + "---\nproxies: []\n", "plan_rejected:document"},
		"text that is not YAML":      {"{" + p[0] + " " + p[1] + " " + p[2], "plan_rejected:document"},
		"a URI list":                 {"vless://" + p[0] + "@relay.attacker.example:443\nvless://" + p[1] + "@a.example:443\nvless://" + p[2] + "@b.example:443\n", substoreBindReasonPlaceholderContext},
		"the credential in a URL":    {strings.Replace(document, firstUUID, "uuid: "+lineCatalogueValidationUUID, 1) + "rule-providers:\n  r:\n    url: https://relay.attacker.example/?k=" + p[0] + "\n", substoreBindReasonPlaceholderContext},
		"an alias to the credential": {strings.Replace(document, firstUUID, "uuid: &u "+p[0], 1) + "extra:\n  - {name: evil, type: vless, server: relay.attacker.example, port: 443, uuid: *u}\n", substoreBindReasonPlaceholderContext},
		"a merge of a whole proxy": {strings.Replace(document, "proxies:\n  - name:", "proxies:\n  - &h\n    name:", 1) + "extra:\n  - {<<: *h, server: relay.attacker.example}\n",
			substoreBindReasonPlaceholderContext},
	} {
		result := run(tc.document, nodes)
		if result.Refused != tc.want || result.document != nil {
			t.Errorf("%s: refused %q, want %q", name, result.Refused, tc.want)
		}
	}

	// A typed node that fails validation refuses the document whole.
	tampered := append([]model.SelectionPlanNode{}, nodes...)
	tampered[1] = bindNode(t, e.rows[1], p[1], map[string]any{"server": "relay.attacker.example"})
	if result := run(document, tampered); result.Refused != "plan_rejected:server" || result.document != nil {
		t.Fatalf("a tampered typed node: refused %q", result.Refused)
	}

	// An operational exclusion keeps the document: the line's node carries an
	// inert credential and is listed as excluded, and the others are bound.
	u := e.identity
	u.Bindings[1].AppliedCredentialSHA256 = ""
	u.Bindings[2].Enabled = false
	if err := e.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	result = run(document, nodes)
	if result.Refused != "" || result.document == nil || fmt.Sprint(result.reasons()) != fmt.Sprint(map[int]string{1: identityLineNotApplied, 2: identityLineBindingDisabled}) {
		t.Fatalf("a document with excluded lines: refused %q, exclusions %v", result.Refused, result.reasons())
	}
	if got := result.document.Substitutions; got[p[0]] != bindIdentityUUID || got[p[1]] != lineCatalogueValidationUUID || got[p[2]] != lineCatalogueValidationUUID {
		t.Fatalf("substitutions %v", got)
	}
	if len(result.Entries) != 1 || result.Entries[0].Index != 0 {
		t.Fatalf("entries %+v", result.Entries)
	}
	// An inert line's text is not held to the proxy checks: no credential
	// reaches it.
	if result := run(bindDocument(t, nodes, map[int]map[string]string{2: {"server": "elsewhere.example"}}), nodes); result.Refused != "" {
		t.Fatalf("an inert line's text: refused %q", result.Refused)
	}
	// With every line excluded nothing is served.
	u.Bindings[0].Enabled = false
	if err := e.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if result := run(document, nodes); result.Refused != substoreBindRefusedNoLine {
		t.Fatalf("a document with no includable line: refused %q", result.Refused)
	}
}

// A plan with fleet nodes is refused when the record's snapshot does not say
// which lines it selected: the identity's bindings never stand in for the
// selection.
func TestSubstoreBindRefusesAPlanWithoutASelection(t *testing.T) {
	e := bindFixture(t, 1, 2)
	catalogue, err := e.srv.buildLineCatalogue("")
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range []model.SelectionPlan{
		bindNodesPlan(t, e.rows),
		{Kind: model.SelectionPlanKindDocument, Nodes: bindNodesPlan(t, e.rows).Nodes, Document: "proxies: []\n"},
	} {
		result := substoreBindPlan(plan, e.identity, catalogue, nil)
		if result.Refused != substoreBindRefusedSelection || len(result.nodes) != 0 || result.document != nil || len(result.Entries) != 0 {
			t.Fatalf("a %s plan without a selection: refused %q, %d nodes, entries %+v", plan.Kind, result.Refused, len(result.nodes), result.Entries)
		}
	}
	row := `{"line_uuid":"` + e.rows[0].LineUUID + `"}`
	for name, raw := range map[string]string{
		"a URI list":                   "vless://" + bindIdentityUUID + "@a.example:443",
		"a document without a version": `{"rows":[` + row + `]}`,
		"a version of another kind":    `{"catalogue_version":"v1-abc","rows":[` + row + `]}`,
		"a collection envelope":        `{"members":[{"catalogue_version":"lcv1-abc","rows":[` + row + `]}]}`,
	} {
		if got := substoreBindSelection(model.SubscriptionSnapshot{Raw: raw}); got != nil {
			t.Fatalf("%s gave a selection: %v", name, got)
		}
	}
	// A plan of provider nodes alone binds no credential and needs none.
	provider := model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{
		{Provider: true, Node: json.RawMessage(`{"name":"p","type":"trojan","server":"p.example","port":443,"password":"provider-own"}`)}}}
	if result := substoreBindPlan(provider, e.identity, catalogue, nil); result.Refused != "" || len(result.nodes) != 1 {
		t.Fatalf("a provider plan: refused %q", result.Refused)
	}
}

// The template shape follows the URI parsers for every template protocol.
func TestSubstoreBindTemplateShapes(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		params   map[string]string
		want     substoreBindShape
	}{
		{"vless", map[string]string{"security": "tls", "type": "ws", "sni": "a.example"},
			substoreBindShape{typ: "vless", credential: []string{"uuid"}, network: "ws", compareTLS: true, tls: true, sni: "a.example"}},
		{"vless", map[string]string{"type": "http"}, substoreBindShape{typ: "vless", credential: []string{"uuid"}, network: "h2", compareTLS: true}},
		{"trojan", map[string]string{"security": "reality", "pbk": "k", "sid": "s"},
			substoreBindShape{typ: "trojan", credential: []string{"password"}, network: "tcp", compareTLS: true, tls: true, reality: true, publicKey: "k", shortID: "s"}},
		{"hysteria2", map[string]string{"pinSHA256": "ab", "insecure": "1"},
			substoreBindShape{typ: "hysteria2", credential: []string{"password"}, network: "tcp", pin: "ab", insecure: true}},
		{"tuic", nil, substoreBindShape{typ: "tuic", credential: []string{"password", "uuid"}, network: "tcp"}},
		{"vmess", map[string]string{"net": "ws", "tls": "tls", "sni": "v.example", "aid": "0"},
			substoreBindShape{typ: "vmess", credential: []string{"uuid"}, network: "ws", anyNetwork: true, compareTLS: true, tls: true, sni: "v.example"}},
		{"socks", nil, substoreBindShape{typ: "socks5", credential: []string{"password", "username"}, network: "tcp", compareTLS: true}},
	} {
		got, ok := substoreBindTemplateShape(store.LineClientTemplate{Protocol: tc.protocol, Params: tc.params})
		if !ok || fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", tc.want) {
			t.Fatalf("%s %v: shape %+v, want %+v", tc.protocol, tc.params, got, tc.want)
		}
	}
	if _, ok := substoreBindTemplateShape(store.LineClientTemplate{Protocol: "shadowsocks"}); ok {
		t.Fatal("a protocol without a client template has a shape")
	}
}

// BenchmarkSubstoreBindThousandLines binds a 1000-line typed-node plan
// against a fresh catalogue build, the core's share of a fleet-bound render
// on a cache miss.
func BenchmarkSubstoreBindThousandLines(b *testing.B) {
	e := bindFixture(b, 100, 10)
	plan := bindNodesPlan(b, e.rows)
	u, _ := e.srv.getVpnUser(bindIdentityID)
	selected := e.selection()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		catalogue, err := e.srv.buildLineCatalogue("")
		if err != nil {
			b.Fatal(err)
		}
		if result := substoreBindPlan(plan, u, catalogue, selected); len(result.nodes) != len(e.rows) {
			b.Fatalf("%d of %d nodes bound", len(result.nodes), len(e.rows))
		}
	}
}
