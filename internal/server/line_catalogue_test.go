package server

import (
	"bytes"
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

// catalogueRealityPublicKey is the Reality public key of every managed line
// catalogueChainRoots plants. The stored templates carry another one, so a
// row carrying this one carries the composed entry.
const catalogueRealityPublicKey = "Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eHF1dXg"

// catalogueChainRoots commits n chains on a catalogue fixture the way an
// applied and observed plan leaves them: the first line of node 2k becomes a
// managed root whose committed chain leads to the first line of node 2k+1, a
// managed terminal, both definitions converged and the root's node reporting
// the committed downstream. It returns the roots' line uuids.
func catalogueChainRoots(t testing.TB, e *catalogueEnv, n int) []string {
	t.Helper()
	first := map[string]model.LineCatalogueRow{}
	for _, row := range e.read(t, "").Rows {
		if _, ok := first[row.NodeID]; !ok {
			first[row.NodeID] = row
		}
	}
	var roots []string
	for k := 0; k < n; k++ {
		root, terminal := first[fmt.Sprintf("node-%03d", 2*k)], first[fmt.Sprintf("node-%03d", 2*k+1)]
		for _, row := range []model.LineCatalogueRow{root, terminal} {
			if err := e.srv.putManagedLineDef(managedLineDef{LineUUID: row.LineUUID, NodeID: row.NodeID, LineHashID: row.LineHashID, Tag: row.Name,
				Port: row.Template.Port, SNI: "www.example.com", RealityPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				RealityPublicKey: catalogueRealityPublicKey, ShortID: "0a1b", Status: managedLineStatusApplied}); err != nil {
				t.Fatal(err)
			}
		}
		e.srv.singboxInvMu.Lock()
		inv := e.srv.singboxInv[root.NodeID]
		for i := range inv.Nodes {
			if inv.Nodes[i].Name == root.Name {
				inv.Nodes[i].DownstreamLineUUID = terminal.LineUUID
			}
		}
		e.srv.singboxInv[root.NodeID] = inv
		e.srv.singboxInvMu.Unlock()
		commitCatalogueChain(t, e.srv, root, terminal.LineUUID)
		commitCatalogueChain(t, e.srv, terminal, "")
		roots = append(roots, root.LineUUID)
	}
	e.srv.invalidateLineReadModel()
	return roots
}

// commitCatalogueChain takes one chain definition for source through the
// store's plan, approve, lease, result and observation steps: a set to target,
// or, with no target, the converged remove tombstone that declares a path's
// last hop.
func commitCatalogueChain(t testing.TB, srv *Server, source model.LineCatalogueRow, target string) {
	t.Helper()
	operation, method, outboundTag := store.LineChainOperationSet, lineChainSetMethod, deterministicLineChainTag(source.LineUUID, target)
	if target == "" {
		operation, method, outboundTag = store.LineChainOperationRemove, lineChainRemoveMethod, ""
	}
	artifact := "catalogue-artifact-" + source.LineUUID
	approval := model.Approval{ID: "catalogue-approval-" + source.LineUUID, NodeID: source.NodeID, Plugin: lineChainPlugin, PluginVersion: "test-fixture",
		Service: lineChainService, Method: method, Action: lineChainActionPrefix + artifact, ArtifactDigest: artifact,
		RequestSHA256: "catalogue-request-" + source.LineUUID, Plan: `{"fixture":"catalogue"}`, Status: model.ApprovalPending, Targets: []string{source.NodeID}}
	attempt := store.LineChainAttempt{ApprovalID: approval.ID, Operation: operation, SourceLineUUID: source.LineUUID, SourceNodeID: source.NodeID,
		CandidateTargetLineUUID: target, CandidateArtifactSHA256: artifact, RequestSHA256: approval.RequestSHA256,
		CandidateDefinition: store.LineChainDefinition{SourceLineUUID: source.LineUUID, SourceNodeID: source.NodeID, SourceLineHashID: source.LineHashID,
			SourceInboundTag: source.Name, TargetLineUUID: target, OutboundTag: outboundTag, ArtifactSHA256: artifact},
		PlanGraphRevision: srv.store.LineChainSnapshot().Revision}
	if _, _, err := srv.store.PlanLineChainApproval(attempt, approval); err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApproved
	task := model.Task{ID: "catalogue-task-" + source.LineUUID, ApprovalID: approval.ID, Targets: []string{source.NodeID}, Script: "catalogue-fixture", Status: model.TaskQueued}
	if _, committed, err := srv.store.ApproveLineChain(approval, task); err != nil || !committed {
		t.Fatalf("approve chain of %s: committed=%v err=%v", source.LineUUID, committed, err)
	}
	accept := func(store.LineChainCompileStateSnapshot, model.Approval, store.LineChainAttempt, model.Task) error {
		return nil
	}
	deliveries, err := srv.store.LeaseTaskDeliveriesWithLineChainValidator(source.NodeID, 1, false, true, accept)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("lease chain of %s: %d deliveries, err=%v", source.LineUUID, len(deliveries), err)
	}
	result := model.TaskResult{TaskID: task.ID, NodeID: source.NodeID, LeaseID: deliveries[0].Task.LeaseID, FinishedAt: time.Now().UTC()}
	if committed, err := srv.store.CompleteLineChainTaskResult(result, approval, store.LineChainStatusAppliedUnobserved, "", ""); err != nil || !committed {
		t.Fatalf("complete chain of %s: committed=%v err=%v", source.LineUUID, committed, err)
	}
	observed := map[string]store.LineChainObservation{source.LineUUID: {OutboundTag: outboundTag, DownstreamLineUUID: target}}
	if committed, err := srv.store.ReconcileLineChains(observed); err != nil || !committed {
		t.Fatalf("observe chain of %s: committed=%v err=%v", source.LineUUID, committed, err)
	}
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

// catalogue_version is the selection's: it stays put when only a geo's
// bookkeeping moves or when a row outside the selection changes, and moves
// when a selected row does.
func TestLineCatalogueVersionFollowsOnlyTheSelection(t *testing.T) {
	e := catalogueFixture(t, 3, 2)
	const de = `{"selector":{"countries":["DE"]}}`
	version := func(request string) string { return e.read(t, request).CatalogueVersion }
	edit := func(nodeID string, change func(*model.Node)) {
		node, ok := e.st.Node(nodeID)
		if !ok {
			t.Fatalf("no node %s", nodeID)
		}
		change(&node)
		if err := e.st.UpsertNode(node); err != nil {
			t.Fatal(err)
		}
		e.srv.invalidateLineReadModel()
	}
	baseDE, baseAll := version(de), version("")

	// node-000 is in DE. A geo re-read moves only Source and UpdatedAt.
	edit("node-000", func(n *model.Node) {
		geo := *n.Geo
		geo.Source, geo.UpdatedAt = "rdap", e.now.Add(time.Hour)
		n.Geo = &geo
	})
	if version(de) != baseDE || version("") != baseAll {
		t.Fatal("a geo's Source and UpdatedAt moved catalogue_version")
	}
	// node-001 is in JP, outside the DE selection.
	edit("node-001", func(n *model.Node) { n.Tags = append(n.Tags, "edge") })
	if version("") == baseAll {
		t.Fatal("the edit changed no row; the test tests nothing")
	}
	if version(de) != baseDE {
		t.Fatal("a row outside the selection moved its catalogue_version")
	}
	edit("node-000", func(n *model.Node) { n.Tags = append(n.Tags, "edge") })
	if version(de) == baseDE {
		t.Fatal("a selected row changed and catalogue_version did not")
	}
}

// A page is cut by bytes as well as rows: every page of a selection that does
// not fit MaxLineCataloguePageBytes encodes within it, holds rows until the
// next one would not fit, and the cursors walk every row once, in order.
func TestLineCataloguePageSplitsAtTheByteBound(t *testing.T) {
	version := lineCatalogueVersion("", nil)
	var rows [][]byte
	for i := range 240 {
		rows = append(rows, fmt.Appendf(nil, `{"n":%d,"pad":%q}`, i, strings.Repeat("x", model.MaxLineCatalogueRowBytes/2+i*97)))
	}
	offset, pages := 0, 0
	for {
		body, more, err := lineCataloguePageOf(rows, version, offset, 0, offset == 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > model.MaxLineCataloguePageBytes {
			t.Fatalf("page %d encodes to %d bytes, bound %d", pages, len(body), model.MaxLineCataloguePageBytes)
		}
		var page lineCataloguePage
		if err := json.Unmarshal(body, &page); err != nil || len(page.Rows) == 0 {
			t.Fatalf("page %d: %d rows, %v", pages, len(page.Rows), err)
		}
		for i, row := range page.Rows {
			if !bytes.Equal(row, rows[offset+i]) {
				t.Fatalf("page %d row %d is not row %d", pages, i, offset+i)
			}
		}
		end := offset + len(page.Rows)
		if !more {
			if end != len(rows) || page.Cursor != "" {
				t.Fatalf("the last page ends at %d of %d with cursor %q", end, len(rows), page.Cursor)
			}
			break
		}
		// The page reserves room for the longest cursor this read can carry.
		room := model.MaxLineCataloguePageBytes - len(body) - (len(strconv.Itoa(len(rows))) - len(strconv.Itoa(end)))
		if 1+len(rows[end]) <= room {
			t.Fatalf("page %d was cut at row %d with room for it", pages, end)
		}
		if next, v, err := parseLineCatalogueCursor(page.Cursor); err != nil || next != end || v != version {
			t.Fatalf("page %d cursor %q: offset %d version %s err %v", pages, page.Cursor, next, v, err)
		}
		offset, pages = end, pages+1
	}
	if pages < 2 {
		t.Fatalf("%d pages; the rows fit one page and the test tests nothing", pages+1)
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

// A committed chain read through the catalogue build: the root is the chain's
// entry with root set, the committed target as its downstream, the terminal
// node's geo as its exit geo, compose's verdict as its path state and the
// composed entry as its template; the terminal is the exit and no root. When
// the root's node stops reporting the committed downstream, the path state
// says drifted while the committed edge still places the root.
func TestLineCatalogueCommittedChainRoot(t *testing.T) {
	e := catalogueFixture(t, 2, 2)
	roots := catalogueChainRoots(t, e, 1)
	catalogue, err := e.srv.buildLineCatalogue("")
	if err != nil {
		t.Fatal(err)
	}
	rows := catalogue.Select(nil)
	root, single, terminal := rows[0], rows[1], rows[2]
	if root.LineUUID != roots[0] || root.NodeID != "node-000" || terminal.NodeID != "node-001" {
		t.Fatalf("rows: %s on %s, terminal on %s", root.LineUUID, root.NodeID, terminal.NodeID)
	}
	if root.Chain.Role != model.LineChainRoleEntry || !root.Chain.Root || root.Chain.DownstreamLineUUID != terminal.LineUUID ||
		root.Chain.PathState != model.LinePathConverged || root.Chain.ExitGeo == nil || root.Chain.ExitGeo.Country != "JP" {
		t.Fatalf("root chain = %+v", root.Chain)
	}
	if root.Template == nil || root.Template.Params["pbk"] != catalogueRealityPublicKey || root.Template.Params["sid"] != "0a1b" ||
		root.Template.Host != catalogueNodeIP(0) || root.Template.Port != 20000 {
		t.Fatalf("the root's template is not the composed entry: %+v", root.Template)
	}
	if bind, ok := catalogue.BindTemplate(root.LineUUID); !ok || bind.Params["pbk"] != catalogueRealityPublicKey {
		t.Fatalf("root bind template = %+v %v", bind, ok)
	}
	if terminal.Chain.Role != model.LineChainRoleExit || terminal.Chain.Root || terminal.Chain.PathState != "" || terminal.Chain.ExitGeo != nil {
		t.Fatalf("terminal chain = %+v", terminal.Chain)
	}
	if single.Chain.Role != model.LineChainRoleSingle || single.Chain.Root {
		t.Fatalf("a line outside the chain = %+v", single.Chain)
	}

	e.srv.singboxInvMu.Lock()
	inv := e.srv.singboxInv["node-000"]
	for i := range inv.Nodes {
		inv.Nodes[i].DownstreamLineUUID = ""
	}
	e.srv.singboxInv["node-000"] = inv
	e.srv.singboxInvMu.Unlock()
	e.srv.invalidateLineReadModel()
	drifted, ok := e.read(t, "").Rows, false
	for _, row := range drifted {
		if row.LineUUID == root.LineUUID {
			ok = true
			if !row.Chain.Root || row.Chain.DownstreamLineUUID != terminal.LineUUID || row.Chain.PathState != model.LinePathDrifted {
				t.Fatalf("drifted root chain = %+v", row.Chain)
			}
		}
	}
	if !ok {
		t.Fatal("the drifted root left the catalogue")
	}
}

// A node's groups, explicit members and selector matches alike, reach the rows
// of its lines through the catalogue build, sorted, and group_ids selects by
// them.
func TestLineCatalogueRowsCarryTheNodeGroups(t *testing.T) {
	e := catalogueFixture(t, 3, 2)
	for _, g := range []model.Group{
		{ID: "grp-pinned", Name: "Pinned", Slug: "pinned", Members: []string{"node-000", "node-002"}},
		{ID: "grp-tier1", Name: "Tier 1", Slug: "tier-1", Selector: &model.GroupSelector{MatchTagsAny: []string{"tier-1"}}},
		{ID: "grp-jp", Name: "Japan", Slug: "jp", Selector: &model.GroupSelector{MatchCountry: []string{"JP"}}},
		{ID: "grp-empty", Name: "Empty", Slug: "empty", Selector: &model.GroupSelector{}},
	} {
		if err := e.st.UpsertGroup(g); err != nil {
			t.Fatal(err)
		}
	}
	catalogue, err := e.srv.buildLineCatalogue("")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"node-000": {"grp-pinned"}, "node-001": {"grp-jp", "grp-tier1"}, "node-002": {"grp-pinned"}}
	rows := catalogue.Select(nil)
	if len(rows) != 6 {
		t.Fatalf("%d rows", len(rows))
	}
	for _, row := range rows {
		if !slices.Equal(row.GroupIDs, want[row.NodeID]) {
			t.Fatalf("%s on %s carries groups %v, want %v", row.LineUUID, row.NodeID, row.GroupIDs, want[row.NodeID])
		}
	}
	if got := e.read(t, `{"selector":{"group_ids":["grp-jp"]}}`).Rows; len(got) != 2 || got[0].NodeID != "node-001" || got[1].NodeID != "node-001" {
		t.Fatalf("group_ids grp-jp selected %v", rowUUIDs(got))
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

// One page of 1000 synthetic lines, ten of them committed chain roots, comes
// back whole, and the deterministic gates of the performance gate rule hold
// it: allocations per read, cold (the read model rebuilt, as the first read
// after any fleet write) and warm, and the page's size. Each bound is about
// one and a half times what was measured when it was set, with the measured
// value beside it; CI runs this under -race -cover, which measured about 1.17
// times the plain allocation counts. The benchmarks below time it against the
// 50 ms target.
func TestLineCatalogueThousandLinesInOnePage(t *testing.T) {
	const (
		// Measured 2026-10-09 on darwin/arm64, go1.26.6: 253,050 allocations
		// a cold read, 294,600 under -race -cover.
		coldAllocsBound = 380_000
		// Measured the same day: 230,750 allocations a warm read, 272,300
		// under -race -cover.
		warmAllocsBound = 346_000
		// Measured the same day: 778,587 bytes, about 779 a row.
		pageBytesBound = 1_168_000
	)
	e := catalogueFixture(t, 50, 20)
	roots := catalogueChainRoots(t, e, 10)
	page := e.read(t, "")
	if len(page.Rows) != 1000 || page.Cursor != "" {
		t.Fatalf("1000 lines: %d rows, cursor %q", len(page.Rows), page.Cursor)
	}
	converged := 0
	for _, row := range page.Rows {
		if row.Chain.Root && row.Chain.PathState == model.LinePathConverged && row.Template != nil {
			converged++
		}
	}
	if converged != len(roots) {
		t.Fatalf("%d of %d chain roots read converged with a composed entry; the chain work is not exercised", converged, len(roots))
	}
	request := []byte(`{}`)
	body, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	cold := testing.AllocsPerRun(5, func() {
		e.srv.invalidateLineReadModel()
		if _, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	})
	warm := testing.AllocsPerRun(5, func() {
		if _, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("one 1000-row page: %d bytes, %.0f allocations cold, %.0f warm", len(body), cold, warm)
	if len(body) > pageBytesBound {
		t.Errorf("one 1000-row page is %d bytes, bound %d", len(body), pageBytesBound)
	}
	if cold > coldAllocsBound {
		t.Errorf("a cold 1000-row read allocates %.0f times, bound %d", cold, coldAllocsBound)
	}
	if warm > warmAllocsBound {
		t.Errorf("a warm 1000-row read allocates %.0f times, bound %d", warm, warmAllocsBound)
	}
}

// One 1000-row page, warm (the read model served from its cache, as between
// fleet writes) and cold (the read model rebuilt first, as the first read
// after one).
func BenchmarkLineCatalogueThousandLines(b *testing.B) {
	benchmarkLineCatalogueThousandLines(b, 0)
}

// The same page over a fleet with ten committed chain roots, so the chain
// state capture and compose's path walk run on every build.
func BenchmarkLineCatalogueThousandLinesWithChainRoots(b *testing.B) {
	benchmarkLineCatalogueThousandLines(b, 10)
}

func benchmarkLineCatalogueThousandLines(b *testing.B, chainRoots int) {
	e := catalogueFixture(b, 50, 20)
	catalogueChainRoots(b, e, chainRoots)
	request := []byte(`{}`)
	for _, mode := range []string{"warm", "cold"} {
		b.Run(mode, func(b *testing.B) {
			if _, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), request); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if mode == "cold" {
					e.srv.invalidateLineReadModel()
				}
				if _, err := e.srv.vpnCoreLinesCatalogueRPC(context.Background(), request); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
