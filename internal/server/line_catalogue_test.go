package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The line owner's credential every fixture share URL carries. No row may
// carry it, with or without an identity named.
const catalogueOwnerUUID = "6f1c2e3b-4d5e-4f60-8a9b-0c1d2e3f4a5b"

var catalogueCountries = []string{"DE", "JP", "US"}

type catalogueEnv struct {
	srv *Server
	st  *store.Store
	now time.Time
}

// catalogueNodeIP is node n's synthetic public address.
func catalogueNodeIP(n int) string {
	return fmt.Sprintf("45.%d.%d.%d", 10+n/250, n%250, 7)
}

// catalogueFixture is a server with nodes live nodes of perNode adopted
// vless Reality lines each, reported through the sing-box inventory, with
// their client templates synced from the share URLs the way the minute sync
// does it. Node n is in catalogueCountries[n%3] and carries tag "tier-<n%2>".
func catalogueFixture(t testing.TB, nodes, perNode int) *catalogueEnv {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	inventories := map[string]model.SingBoxInventory{}
	for n := 0; n < nodes; n++ {
		nodeID := fmt.Sprintf("node-%03d", n)
		ip := catalogueNodeIP(n)
		if err := st.UpsertNode(model.Node{ID: nodeID, Name: fmt.Sprintf("Node %03d", n), PublicIP: ip, Tags: []string{fmt.Sprintf("tier-%d", n%2)},
			Geo: &model.NodeGeo{Country: catalogueCountries[n%3], Region: "Region " + catalogueCountries[n%3], City: "City", ASN: 64500 + n, Provider: "Example Host",
				Source: "test", UpdatedAt: now}}); err != nil {
			t.Fatal(err)
		}
		var lines []model.SingBoxNode
		for l := 0; l < perNode; l++ {
			port := strconv.Itoa(20000 + l)
			lines = append(lines, model.SingBoxNode{Name: "vless-" + port, Protocol: "vless", Network: "tcp", Address: ip, Port: port,
				ShareURL: "vless://" + catalogueOwnerUUID + "@" + ip + ":" + port +
					"?encryption=none&security=reality&flow=xtls-rprx-vision&type=tcp&sni=www.example.com&pbk=Zm9vYmFyYmF6&sid=0a1b&fp=chrome#owner"})
		}
		inventories[nodeID] = model.SingBoxInventory{NodeID: nodeID, At: now, Status: "ok", Nodes: lines}
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = inventories
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()
	if err := srv.syncLineClientTemplates(now); err != nil {
		t.Fatal(err)
	}
	return &catalogueEnv{srv: srv, st: st, now: now}
}

// read calls the catalogue the way a plugin's rpc:call reaches it.
func (e *catalogueEnv) read(t testing.TB, request string) model.LineCatalogueResponse {
	t.Helper()
	raw, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), []byte(request))
	if err != nil {
		t.Fatalf("catalogue %s: %v", request, err)
	}
	var page model.LineCatalogueResponse
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	if err := page.Validate(); err != nil {
		t.Fatalf("catalogue page fails the SDK's own check: %v", err)
	}
	return page
}

// readAll follows the cursor to the end and checks every page carries one
// version.
func (e *catalogueEnv) readAll(t testing.TB, selector string, limit int) ([]model.LineCatalogueRow, string, int) {
	t.Helper()
	var rows []model.LineCatalogueRow
	cursor, version, pages := "", "", 0
	for {
		req := map[string]any{"limit": limit}
		if selector != "" {
			req["selector"] = json.RawMessage(selector)
		}
		if cursor != "" {
			req["cursor"] = cursor
		}
		raw, _ := json.Marshal(req)
		page := e.read(t, string(raw))
		pages++
		if version == "" {
			version = page.CatalogueVersion
			if !slices.Equal(page.SelectorFields, model.LineCatalogueSelectorFields()) {
				t.Fatalf("the first page advertises %v", page.SelectorFields)
			}
		} else if page.CatalogueVersion != version {
			t.Fatalf("page %d carries version %s, the read began at %s", pages, page.CatalogueVersion, version)
		} else if len(page.SelectorFields) != 0 {
			t.Fatalf("a later page repeats selector_fields")
		}
		rows = append(rows, page.Rows...)
		if page.Cursor == "" {
			return rows, version, pages
		}
		cursor = page.Cursor
	}
}

func rowUUIDs(rows []model.LineCatalogueRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.LineUUID)
	}
	return out
}

func catalogueAPIError(t *testing.T, err error) model.APIError {
	t.Helper()
	var opErr *pluginOperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("want an API error, got %v", err)
	}
	var body model.APIErrorResponse
	if json.Unmarshal(opErr.Body, &body) != nil {
		t.Fatalf("error body %s", opErr.Body)
	}
	return body.Error
}

// Every line comes back once, joined with its node, with a template that
// carries no part of the owner's credential, across pages that agree on one
// version; the cursor walks the selection in catalogue order.
func TestLineCataloguePagesEveryLineCredentialFree(t *testing.T) {
	e := catalogueFixture(t, 3, 4)
	full := e.read(t, "")
	if len(full.Rows) != 12 || full.Cursor != "" || !strings.HasPrefix(full.CatalogueVersion, lineCatalogueVersionPrefix) {
		t.Fatalf("one page of everything: %d rows, cursor %q, version %q", len(full.Rows), full.Cursor, full.CatalogueVersion)
	}
	raw, _ := json.Marshal(full)
	if strings.Contains(strings.ToLower(string(raw)), catalogueOwnerUUID) {
		t.Fatal("the catalogue carries the line owner's credential")
	}
	row := full.Rows[0]
	if row.NodeID != "node-000" || row.NodeName != "Node 000" || row.Protocol != "vless" || row.Transport != "tcp" ||
		row.Geo == nil || row.Geo.Country != "DE" || row.Geo.UpdatedAt != (time.Time{}) || !slices.Equal(row.NodeTags, []string{"tier-0"}) ||
		row.Chain.Role != model.LineChainRoleSingle || row.Probe != nil || row.Usage != nil {
		t.Fatalf("first row = %+v", row)
	}
	if row.Template == nil || row.Template.Protocol != "vless" || row.Template.Host != catalogueNodeIP(0) || row.Template.Port != 20000 ||
		row.Template.Params["pbk"] != "Zm9vYmFyYmF6" || row.Template.Params["flow"] != "" || !strings.HasPrefix(row.Template.Digest, "sha256:") {
		t.Fatalf("first row's template = %+v", row.Template)
	}
	if !slices.Equal(row.Addresses, []string{catalogueNodeIP(0)}) {
		t.Fatalf("addresses = %v", row.Addresses)
	}

	rows, version, pages := e.readAll(t, "", 5)
	if pages != 3 || version != full.CatalogueVersion || !slices.Equal(rowUUIDs(rows), rowUUIDs(full.Rows)) {
		t.Fatalf("paged read: %d pages, version %s, rows %v", pages, version, rowUUIDs(rows))
	}

	// A read in progress is served from the build its first page made, so a
	// fleet change between pages neither restarts it nor mixes two builds.
	first := e.read(t, `{"limit":5}`)
	if err := e.st.UpsertNode(model.Node{ID: "node-001", Name: "Renamed", PublicIP: catalogueNodeIP(1)}); err != nil {
		t.Fatal(err)
	}
	e.srv.invalidateLineReadModel()
	second := e.read(t, `{"limit":5,"cursor":"`+first.Cursor+`"}`)
	if second.CatalogueVersion != first.CatalogueVersion || second.Rows[0].NodeName != "Node 001" {
		t.Fatalf("the second page of a read moved: version %s, node %q", second.CatalogueVersion, second.Rows[0].NodeName)
	}

	// The version is the selection's: a new read sees the change.
	moved := e.read(t, "{}")
	if moved.CatalogueVersion == full.CatalogueVersion || moved.Rows[4].NodeName != "Renamed" {
		t.Fatal("renaming a node did not move the version")
	}
	// A cursor whose read is gone, or used with another request, reads a
	// fresh build and says so with that build's version.
	other := e.read(t, `{"limit":5,"cursor":"`+first.Cursor+`","selector":{"countries":["DE"]}}`)
	if other.CatalogueVersion == first.CatalogueVersion {
		t.Fatal("a cursor reused with another selector was served the first read's rows")
	}
}

// The plugin pushes only the fields a core advertises. A field this core
// does not know is refused by name, and the refusal lists the fields it does
// know, so a newer plugin learns what to run itself.
func TestLineCatalogueRefusesAnUnknownSelectorField(t *testing.T) {
	e := catalogueFixture(t, 1, 1)
	_, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), []byte(`{"selector":{"countries":["DE"],"colour":["red"]}}`))
	apiErr := catalogueAPIError(t, err)
	if apiErr.Code != apiErrorCatalogueSelectorUnsupported || !strings.Contains(apiErr.Message, `"colour"`) {
		t.Fatalf("unknown selector field: %+v", apiErr)
	}
	_, listed, ok := strings.Cut(apiErr.Message, "selector_fields: ")
	if !ok || !slices.Equal(strings.Split(listed, ","), model.LineCatalogueSelectorFields()) {
		t.Fatalf("the refusal lists %q", listed)
	}
	// Anything else malformed is a plain bad request.
	for _, request := range []string{`{"identity":"x"}`, `{"limit":5000}`, `{"limit":1,"limit":2}`, `{"cursor":"nope"}`} {
		_, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), []byte(request))
		if apiErr := catalogueAPIError(t, err); apiErr.Code != model.APIErrorBadRequest {
			t.Fatalf("%s: %+v", request, apiErr)
		}
	}
}

// A selector the core cannot read one way only is refused as a selector, with
// the fields the core evaluates: given twice, under keys the decoder takes
// for the same field, or naming a field twice. A later selector key must not
// hide an unknown field in an earlier one, and two selectors must not merge.
func TestLineCatalogueRefusesADuplicatedSelector(t *testing.T) {
	e := catalogueFixture(t, 1, 1)
	for _, request := range []string{
		`{"selector":{"colour":["red"]},"selector":null}`,
		`{"selector":{"countries":["DE"]},"selector":{}}`,
		`{"selector":{"countries":["DE"]},"Selector":{"regions":["Region DE"]}}`,
		`{"selector":{"countries":["DE"],"countries":["JP"]}}`,
	} {
		_, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), []byte(request))
		apiErr := catalogueAPIError(t, err)
		_, listed, ok := strings.Cut(apiErr.Message, "selector_fields: ")
		if apiErr.Code != apiErrorCatalogueSelectorUnsupported || !strings.Contains(apiErr.Message, "more than once") ||
			!ok || !slices.Equal(strings.Split(listed, ","), model.LineCatalogueSelectorFields()) {
			t.Fatalf("%s: %+v", request, apiErr)
		}
	}
	// One selector under a key the decoder folds to it is still read.
	if got := e.read(t, `{"Selector":{"countries":["DE"]}}`).Rows; len(got) != 1 {
		t.Fatalf("a single selector key in another case: %d rows", len(got))
	}
}

// Every selector field is evaluated here: set fields AND, values of one
// field OR, an explicit line list keeps its own order, and country reads the
// exit's geo for a chained line.
func TestLineCatalogueSelectorPushdown(t *testing.T) {
	e := catalogueFixture(t, 6, 2)
	all := e.read(t, "").Rows
	byNode := func(rows []model.LineCatalogueRow) []string {
		var out []string
		for _, row := range rows {
			out = append(out, row.NodeID)
		}
		return out
	}
	if got := byNode(e.read(t, `{"selector":{"countries":["de","JP"]}}`).Rows); !slices.Equal(got, []string{"node-000", "node-000", "node-001", "node-001", "node-003", "node-003", "node-004", "node-004"}) {
		t.Fatalf("countries: %v", got)
	}
	if got := byNode(e.read(t, `{"selector":{"countries":["DE"],"node_tags":["tier-1"]}}`).Rows); !slices.Equal(got, []string{"node-003", "node-003"}) {
		t.Fatalf("countries and tags: %v", got)
	}
	if got := e.read(t, `{"selector":{"protocols":["trojan"]}}`).Rows; len(got) != 0 {
		t.Fatalf("protocols: %d rows", len(got))
	}
	pinned := []string{all[7].LineUUID, all[2].LineUUID, all[4].LineUUID}
	req, _ := json.Marshal(map[string]any{"selector": map[string]any{"line_uuids": pinned}})
	if got := rowUUIDs(e.read(t, string(req)).Rows); !slices.Equal(got, pinned) {
		t.Fatalf("an explicit line list must keep its order: %v", got)
	}
	req, _ = json.Marshal(map[string]any{"selector": map[string]any{"line_uuids": pinned, "countries": []string{"DE"}}})
	if got := rowUUIDs(e.read(t, string(req)).Rows); !slices.Equal(got, []string{all[7].LineUUID}) {
		t.Fatalf("line list and country: %v", got)
	}

	// Renewal reads the soonest machine profile of the node.
	for i, days := range map[string]int{"node-002": 3, "node-005": 40} {
		if err := e.st.UpsertMachineProfile(model.MachineProfile{ID: "m-" + i, NodeID: i, Vendor: "Example", Region: "fra1", NextRenewal: e.now.Add(time.Duration(days) * 24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := byNode(e.read(t, `{"selector":{"renewal_within_days":7}}`).Rows); !slices.Equal(got, []string{"node-002", "node-002"}) {
		t.Fatalf("renewal: %v", got)
	}
	if got := e.read(t, `{"selector":{"probe_passed_within_hours":24}}`).Rows; len(got) != 0 {
		t.Fatalf("a null probe block never matches a probe predicate: %d rows", len(got))
	}
	if got := e.read(t, `{"selector":{"chain_roles":["single"],"service_states":["unknown","running","down","restarting"]}}`).Rows; len(got) != len(all) {
		t.Fatalf("roles and service states: %d rows", len(got))
	}
	if a, b := e.read(t, `{"selector":{"countries":["DE"]}}`).CatalogueVersion, e.read(t, `{"selector":{"countries":["JP"]}}`).CatalogueVersion; a == b {
		t.Fatal("two selections share a version")
	}
}

// A relay whose outbound names another line's endpoint is that chain's entry,
// the other line its exit, and the entry's effective geo is the exit's.
func TestLineCatalogueChainBlockAndExitGeo(t *testing.T) {
	e := catalogueFixture(t, 2, 1)
	e.srv.singboxInvMu.Lock()
	inv := e.srv.singboxInv["node-000"]
	inv.Nodes[0].OutboundRef = "relay-out"
	inv.Nodes[0].OutboundServer = catalogueNodeIP(1)
	inv.Nodes[0].OutboundPort = "20000"
	e.srv.singboxInv["node-000"] = inv
	e.srv.singboxInvMu.Unlock()
	e.srv.invalidateLineReadModel()

	rows := e.read(t, "").Rows
	entry, exit := rows[0], rows[1]
	if entry.Chain.Role != model.LineChainRoleEntry || entry.Chain.DownstreamLineUUID != exit.LineUUID ||
		entry.Chain.ExitGeo == nil || entry.Chain.ExitGeo.Country != "JP" || entry.Geo.Country != "DE" {
		t.Fatalf("entry chain = %+v", entry.Chain)
	}
	if exit.Chain.Role != model.LineChainRoleExit || exit.Chain.ExitGeo != nil || exit.Chain.Root {
		t.Fatalf("exit chain = %+v", exit.Chain)
	}
	if got := rowUUIDs(e.read(t, `{"selector":{"countries":["JP"]}}`).Rows); !slices.Equal(got, []string{entry.LineUUID, exit.LineUUID}) {
		t.Fatalf("a JP filter must take the relay that leaves in JP: %v", got)
	}
	if got := rowUUIDs(e.read(t, `{"selector":{"chain_roles":["entry"]}}`).Rows); !slices.Equal(got, []string{entry.LineUUID}) {
		t.Fatalf("chain_roles entry: %v", got)
	}
}

// A committed root's template is the entry compose builds, without the
// identity's credential, and its path state is compose's verdict.
func TestLineCatalogueComposedRootTemplate(t *testing.T) {
	root := "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"
	line := Line{LineHashID: "h-root", LineUUID: root, NodeID: "n1", Name: "root", Tag: "vless-443", Core: "sing-box", Type: "vless",
		Transport: "tcp", Status: "ok", Overlay: true, OverlayStatus: managedLineStatusApplied, PublicHost: "203.0.114.9"}
	compile := lineChainCompileSnapshot{
		Lines: map[string][]Line{root: {line}},
		Definitions: map[string]managedLineDef{root: {LineHashID: "h-root", Status: managedLineStatusApplied, Port: 443, SNI: "www.example.com",
			RealityPublicKey: "Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eHF1dXg", ShortID: "0A1B"}},
		Nodes: map[string]model.Node{"n1": {ID: "n1"}},
	}
	tmpl := lineCatalogueComposedTemplate(compile, root)
	if tmpl == nil {
		t.Fatal("an applied overlay root has no composed template")
	}
	if tmpl.Protocol != "vless" || tmpl.Host != "203.0.114.9" || tmpl.Port != 443 || tmpl.Params["security"] != "reality" ||
		tmpl.Params["sid"] != "0a1b" || tmpl.Params["fp"] != "chrome" || tmpl.Params["sni"] != "www.example.com" || tmpl.Params["flow"] != "" {
		t.Fatalf("composed template = %+v", tmpl)
	}
	if strings.Contains(fmt.Sprint(tmpl), lineCatalogueValidationUUID) {
		t.Fatal("the placeholder credential leaked into the template")
	}
	// The template fills exactly as compose's entry: same endpoint and
	// public material for the identity's uuid.
	uri, err := lineClientURI(*tmpl, lineUserCredentialPayload{UUID: "2c3d4e5f-6071-4b8c-9d0e-1f2a3b4c5d6e", Flow: lineCatalogueComposeFlow}, "root")
	if err != nil || !strings.HasPrefix(uri, "vless://2c3d4e5f-6071-4b8c-9d0e-1f2a3b4c5d6e@203.0.114.9:443?") || !strings.Contains(uri, "flow=xtls-rprx-vision") {
		t.Fatalf("filled composed template: %q %v", uri, err)
	}
	unapplied := compile
	unapplied.Definitions = map[string]managedLineDef{root: {LineHashID: "h-root", Status: "planned", Port: 443}}
	if lineCatalogueComposedTemplate(unapplied, root) != nil {
		t.Fatal("a root compose refuses has a template")
	}
	for err, want := range map[error]string{nil: model.LinePathConverged, composeFailure("graph_busy"): model.LinePathBusy,
		composeFailure("graph_drifted"): model.LinePathDrifted, composeFailure("graph_not_converged"): model.LinePathDrifted} {
		if got := lineCataloguePathState(err); got != want {
			t.Fatalf("path state of %v = %s, want %s", err, got, want)
		}
	}
}

// catalogueIdentity stores an identity with a vless uuid and a trojan
// password and binds it to every line of the catalogue.
func catalogueIdentity(t *testing.T, e *catalogueEnv, uuid, password string) VpnUser {
	t.Helper()
	u := VpnUser{ID: "vu-cat", Email: "cat@example.com", Name: "Cat", Enabled: true, CreatedAt: e.now, UpdatedAt: e.now,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: uuid, Flow: "xtls-rprx-vision"}, {Protocol: "trojan", Password: password}}}
	for _, row := range e.read(t, "").Rows {
		u.Bindings = append(u.Bindings, LineBinding{LineHashID: row.LineHashID, Enabled: true})
	}
	if err := e.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

// plantTemplateParam stores a template for one line with a value the
// template builder would never keep, as a corrupted or hand-made record
// would hold.
func plantTemplateParam(t *testing.T, e *catalogueEnv, lineHashID, key, value string) {
	t.Helper()
	all := e.st.LineClientTemplates()
	var node string
	for _, tmpl := range all {
		if tmpl.LineHashID == lineHashID {
			node = tmpl.NodeID
		}
	}
	var set []store.LineClientTemplate
	for _, tmpl := range all {
		if tmpl.NodeID != node {
			continue
		}
		if tmpl.LineHashID == lineHashID {
			tmpl.Params[key] = value
		}
		set = append(set, tmpl)
	}
	if _, err := e.st.SyncLineClientTemplates(map[string][]store.LineClientTemplate{node: set}, e.now); err != nil {
		t.Fatal(err)
	}
}

// carriesCredential reports whether body carries a credential, ignoring
// case, raw or in the form JSON escapes it to.
func carriesCredential(body, credential string) bool {
	lower := strings.ToLower(body)
	escaped, _ := json.Marshal(credential)
	return strings.Contains(lower, strings.ToLower(credential)) || strings.Contains(lower, strings.ToLower(string(escaped[1:len(escaped)-1])))
}

// carriesFragment reports whether body carries any four-byte run of a
// credential, ignoring case. It suits a credential whose runs cannot occur
// by chance in a catalogue; a uuid's hex runs occur in every digest.
func carriesFragment(body, credential string) bool {
	lower, credential := strings.ToLower(body), strings.ToLower(credential)
	for start := 0; start+4 <= len(credential); start++ {
		if strings.Contains(lower, credential[start:start+4]) {
			return true
		}
	}
	return false
}

// A request that names an identity returns no part of that identity's
// credential four bytes or longer anywhere in the body, whatever a stored
// template holds: a row whose template carries one is served without it,
// a row that still carries one is withheld. The same rows read without the
// identity are untouched, so it is the identity check that removed them.
func TestLineCatalogueWithAnIdentityCarriesNoCredentialFragment(t *testing.T) {
	e := catalogueFixture(t, 2, 3)
	const identityUUID = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
	const password = `Tr0jan"pa<ss>&word`
	u := catalogueIdentity(t, e, identityUUID, password)
	rows := e.read(t, "").Rows
	plantTemplateParam(t, e, rows[0].LineHashID, "path", "/"+strings.ToUpper(identityUUID))
	plantTemplateParam(t, e, rows[4].LineHashID, "host", password)
	if err := e.st.UpsertNode(model.Node{ID: "node-001", Name: "named " + password, PublicIP: catalogueNodeIP(1)}); err != nil {
		t.Fatal(err)
	}
	e.srv.invalidateLineReadModel()
	if err := e.st.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{{UserID: u.ID, Day: store.UsageDay(e.now), Uplink: 100, Downlink: 200,
		ByLine: map[string]store.UsageDayUserLine{rows[1].LineHashID: {Uplink: 100, Downlink: 200}}}}}); err != nil {
		t.Fatal(err)
	}

	plain, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(string(plain)), identityUUID) {
		t.Fatal("without an identity the planted template should still be served; the fixture is not testing anything")
	}

	body, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), []byte(`{"identity_id":"vu-cat"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{identityUUID, password} {
		if carriesCredential(string(body), credential) {
			t.Fatalf("the catalogue for %s carries its credential %q: %s", u.ID, credential, body)
		}
	}
	if carriesFragment(string(body), password) {
		t.Fatalf("the catalogue for %s carries a four-byte run of its password: %s", u.ID, body)
	}
	var page model.LineCatalogueResponse
	if err := json.Unmarshal(body, &page); err != nil || page.Validate() != nil {
		t.Fatalf("page: %v", err)
	}
	if len(page.Rows) != 3 {
		t.Fatalf("node-001's rows carry the password in their node name and must be withheld; got %d rows", len(page.Rows))
	}
	if page.Rows[0].Template != nil || page.Rows[1].Template == nil {
		t.Fatalf("templates: %+v / %+v", page.Rows[0].Template, page.Rows[1].Template)
	}
	for i, row := range page.Rows {
		if row.Usage == nil || row.Usage.IdentityID != u.ID {
			t.Fatalf("row %d has no usage for the identity: %+v", i, row.Usage)
		}
	}
	if page.Rows[1].Usage.UsedBytes != 300 || page.Rows[2].Usage.UsedBytes != 0 || page.Rows[1].Usage.From.Day() != 1 {
		t.Fatalf("usage = %+v / %+v", page.Rows[1].Usage, page.Rows[2].Usage)
	}
	catalogue, err := e.srv.buildLineCatalogue(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := catalogue.BindTemplate(rows[0].LineUUID); ok {
		t.Fatal("a row served without its template still binds")
	}

	if _, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), []byte(`{"identity_id":"vu-nobody"}`)); catalogueAPIError(t, err).Code != model.APIErrorNotFound {
		t.Fatalf("unknown identity: %v", err)
	}
}

// A template that still carries a part of the owner's credential, which the
// node reports in its share URL, is refused the way the template store
// refuses it, and the line cannot be bound.
func TestLineCatalogueRefusesATemplateCarryingTheOwnerCredential(t *testing.T) {
	e := catalogueFixture(t, 1, 2)
	rows := e.read(t, "").Rows
	plantTemplateParam(t, e, rows[1].LineHashID, "serviceName", "grpc-"+catalogueOwnerUUID)
	got := e.read(t, "").Rows
	if got[0].Template == nil || got[1].Template != nil {
		t.Fatalf("templates after planting the owner's uuid: %+v / %+v", got[0].Template, got[1].Template)
	}
	catalogue, err := e.srv.buildLineCatalogue("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := catalogue.BindTemplate(rows[1].LineUUID); ok {
		t.Fatal("a refused template still binds")
	}
	if bind, ok := catalogue.BindTemplate(rows[0].LineUUID); !ok || bind.Host != catalogueNodeIP(0) || bind.LineUUID != rows[0].LineUUID {
		t.Fatalf("bind template = %+v %v", bind, ok)
	}
}

// Names resolve on the template sync's clock: a line's host name and a node's
// DDNS name enter the row only with public addresses, a DDNS name is verified
// only when it resolves to the node's current public address, and a name with
// an internal address is refused whole.
func TestLineCatalogueAddressesAndVerifiedDDNS(t *testing.T) {
	e := catalogueFixture(t, 1, 1)
	e.srv.singboxInvMu.Lock()
	inv := e.srv.singboxInv["node-000"]
	inv.ProviderEdge = "edge.provider.example"
	e.srv.singboxInv["node-000"] = inv
	e.srv.singboxInvMu.Unlock()
	e.srv.invalidateLineReadModel()
	if err := e.st.UpsertDDNSProfile(model.DDNSProfile{ID: "d1", NodeID: "node-000", Domains: []string{"Home.Example.org", "stale.example.org", "lan.example.org"}}); err != nil {
		t.Fatal(err)
	}
	answers := map[string][]string{
		"edge.provider.example": {"46.1.2.3", "2a01:4f8::1"},
		"home.example.org":      {catalogueNodeIP(0)},
		"stale.example.org":     {"46.9.9.9"},
		"lan.example.org":       {"46.1.2.4", "10.0.0.8"},
	}
	e.srv.substoreCatalogue.names.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		var out []net.IPAddr
		for _, a := range answers[host] {
			out = append(out, net.IPAddr{IP: net.ParseIP(a)})
		}
		if out == nil {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
	e.srv.refreshLineCatalogueNames(e.now)
	row := e.read(t, "").Rows[0]
	if !slices.Equal(row.Addresses, []string{"2a01:4f8::1", "45.10.0.7", "46.1.2.3"}) {
		t.Fatalf("addresses = %v", row.Addresses)
	}
	want := []model.LineCatalogueDDNSName{{Name: "home.example.org", Verified: true}, {Name: "lan.example.org"}, {Name: "stale.example.org"}}
	if !slices.Equal(row.DDNSNames, want) {
		t.Fatalf("ddns = %+v", row.DDNSNames)
	}

	// A failed lookup keeps the last good answer for a while.
	delete(answers, "home.example.org")
	e.srv.refreshLineCatalogueNames(e.now.Add(time.Minute))
	if row := e.read(t, "").Rows[0]; !row.DDNSNames[0].Verified {
		t.Fatal("one failed lookup dropped a verified name")
	}
	e.srv.refreshLineCatalogueNames(e.now.Add(lineCatalogueNameStale + time.Minute))
	if row := e.read(t, "").Rows[0]; row.DDNSNames[0].Verified {
		t.Fatal("an answer older than the stale bound still verifies the name")
	}
}

// An operator's own call through the gateway needs vpncore:read in core; a
// plugin's rpc:call is held to its signed grant by the registry instead.
func TestLineCatalogueOperatorCallNeedsVPNCoreRead(t *testing.T) {
	e := catalogueFixture(t, 1, 1)
	direct := func(scopes ...string) context.Context {
		p := principal{Principal: rbac.Principal{ActorID: "op", Scopes: scopes}}
		return context.WithValue(context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, p), operatorCoreCallKey{}, vpnCoreLinesService)
	}
	if _, err := e.srv.vpnCoreLinesCatalogueRPC(direct("node:read"), nil); catalogueAPIError(t, err).Code != model.APIErrorCapabilityDenied {
		t.Fatalf("an operator without vpncore:read: %v", err)
	}
	if _, err := e.srv.vpnCoreLinesCatalogueRPC(direct("vpncore:read"), nil); err != nil {
		t.Fatalf("an operator with vpncore:read: %v", err)
	}
	if _, err := e.srv.vpnCoreIdentitiesRPC(direct("node:read"), "list", nil); catalogueAPIError(t, err).Code != model.APIErrorCapabilityDenied {
		t.Fatalf("identities without vpncore:read: %v", err)
	}
	// The registry routes both methods, and a plugin reaches them only under
	// a grant naming the method.
	e.srv.pluginRPC.SetOwnerActive(func(string) bool { return true })
	const caller = "latticenet.sub-store"
	if _, err := e.srv.pluginRPC.Call(context.Background(), caller, vpnCoreLinesService, "catalogue", []byte(`{}`)); err == nil {
		t.Fatal("a plugin without a grant read the catalogue")
	}
	e.srv.pluginRPC.AllowMethods(caller, vpnCoreLinesService, []string{"catalogue"})
	e.srv.pluginRPC.AllowMethods(caller, vpnCoreIdentitiesService, []string{"list"})
	raw, err := e.srv.pluginRPC.Call(context.Background(), caller, vpnCoreLinesService, "catalogue", []byte(`{"limit":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var page model.LineCatalogueResponse
	if json.Unmarshal(raw, &page) != nil || len(page.Rows) != 1 {
		t.Fatalf("catalogue through the registry: %s", raw)
	}
	if _, err := e.srv.pluginRPC.Call(context.Background(), caller, vpnCoreLinesService, "list", nil); err == nil {
		t.Fatal("a catalogue grant also opened lines list")
	}
	if raw, err := e.srv.pluginRPC.Call(context.Background(), caller, vpnCoreIdentitiesService, "list", nil); err != nil || !strings.Contains(string(raw), `"identities":[]`) {
		t.Fatalf("identities through the registry: %s %v", raw, err)
	}
}

// One page of 1000 synthetic lines comes back whole; the benchmark below
// times it against the 50 ms target.
func TestLineCatalogueThousandLinesInOnePage(t *testing.T) {
	e := catalogueFixture(t, 50, 20)
	page := e.read(t, "")
	if len(page.Rows) != 1000 || page.Cursor != "" {
		t.Fatalf("1000 lines: %d rows, cursor %q", len(page.Rows), page.Cursor)
	}
	start := time.Now()
	e.read(t, "")
	t.Logf("one 1000-row page in %s", time.Since(start))
}

func BenchmarkLineCatalogueThousandLines(b *testing.B) {
	e := catalogueFixture(b, 50, 20)
	request := []byte(`{}`)
	if _, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), request); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), request); err != nil {
			b.Fatal(err)
		}
	}
}
