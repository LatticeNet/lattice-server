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

// bindRun builds a fresh catalogue, round-trips the plan through the SDK's
// strict codec the way a render reply arrives, and binds it.
func (e *bindEnv) bindRun(t testing.TB, plan model.SelectionPlan, selected map[string]bool) substoreBindResult {
	t.Helper()
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
	} {
		node := bindNode(t, row, bindPlaceholder(t, row.LineUUID, "uuid"), map[string]any{want.field: want.value})
		if got := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{node}}, nil).reasons()[0]; got != edit {
			t.Fatalf("%s=%v: reason %q, want %q", want.field, want.value, got, edit)
		}
	}
	// The mutable set changes freely, and turning certificate checks off is
	// counted.
	node := bindNode(t, row, bindPlaceholder(t, row.LineUUID, "uuid"), map[string]any{"name": "Tokyo 01", "udp": false, "tfo": true,
		"client-fingerprint": "safari", "alpn": []string{"h2"}, "skip-cert-verify": true, "script": map[string]any{"_tag": "x"}})
	result := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{node}}, nil)
	if len(result.Excluded) != 0 || result.Insecure != 1 || result.Entries[0].Name != "Tokyo 01" {
		t.Fatalf("mutable fields: excluded %+v, insecure %d, entries %+v", result.Excluded, result.Insecure, result.Entries)
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
	provider := model.SelectionPlanNode{Provider: true, Node: json.RawMessage(`{"name":"provider","type":"trojan","server":"p.example","port":443,"password":"provider-own"}`)}
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

// A document plan carries the produced text with placeholders still in it.
// Each placeholder must occur exactly as often as its validated nodes; one
// copied into a comment is refused with placeholder_count.
func TestSubstoreBindDocumentPlanCountsPlaceholders(t *testing.T) {
	e := bindFixture(t, 1, 2)
	p0, p1 := bindPlaceholder(t, e.rows[0].LineUUID, "uuid"), bindPlaceholder(t, e.rows[1].LineUUID, "uuid")
	nodes := []model.SelectionPlanNode{bindNode(t, e.rows[0], p0, nil), bindNode(t, e.rows[1], p1, nil)}
	document := "proxies:\n  - {name: a, type: vless, uuid: " + p0 + "}\n  - {name: b, type: vless, uuid: " + p1 + "}\n"
	result := e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindDocument, Nodes: nodes, Document: document}, nil)
	if result.Refused != "" || result.document == nil || len(result.document.Substitutions) != 2 ||
		result.document.Substitutions[p0] != bindIdentityUUID || result.document.Content != document {
		t.Fatalf("a valid document: refused %q, document %+v", result.Refused, result.document)
	}
	if err := result.document.Validate(); err != nil {
		t.Fatal(err)
	}

	commented := document + "# backup uuid " + p1 + "\n"
	result = e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindDocument, Nodes: nodes, Document: commented}, nil)
	if result.Refused != substoreBindReasonPlaceholderCount || result.document != nil {
		t.Fatalf("a placeholder copied into a comment: refused %q", result.Refused)
	}
	// A document is served whole or not at all: a validated node that cannot
	// be bound refuses it with that node's reason.
	u := e.identity
	u.Bindings[1].AppliedCredentialSHA256 = ""
	if err := e.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	result = e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindDocument, Nodes: nodes, Document: document}, nil)
	if result.Refused != identityLineNotApplied || result.document != nil {
		t.Fatalf("a document with an unbound node: refused %q", result.Refused)
	}
	// A node that fails validation is not counted, so the text it left in
	// the document breaks the count.
	u.Bindings[1].Enabled = false
	if err := e.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	result = e.bindRun(t, model.SelectionPlan{Kind: model.SelectionPlanKindDocument, Nodes: nodes, Document: document}, nil)
	if result.Refused != substoreBindReasonPlaceholderCount || result.reasons()[1] != identityLineBindingDisabled {
		t.Fatalf("a document with an unvalidated node: refused %q, exclusions %v", result.Refused, result.reasons())
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
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		catalogue, err := e.srv.buildLineCatalogue("")
		if err != nil {
			b.Fatal(err)
		}
		if result := substoreBindPlan(plan, u, catalogue, nil); len(result.nodes) != len(e.rows) {
			b.Fatalf("%d of %d nodes bound", len(result.nodes), len(e.rows))
		}
	}
}
