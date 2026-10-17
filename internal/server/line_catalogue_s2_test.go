package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// catalogueResolver answers the name refresh from a fixed table.
func catalogueResolver(e *catalogueEnv, answers map[string][]string) {
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
}

// A cname profile's name is verified by a DNS answer that lands on the
// provider edge's addresses, and its Target is that edge; a name whose answer
// lands elsewhere is not verified whatever the profile's target says, and a
// cname name that resolves to the node's own public address is not verified
// either, since behind NAT that address is the provider's shared egress.
func TestCatalogueVerifiesCNAMEByResolutionToEdge(t *testing.T) {
	e := catalogueFixture(t, 1, 1)
	e.srv.singboxInvMu.Lock()
	inv := e.srv.singboxInv["node-000"]
	inv.ProviderEdge = "edge.provider.example"
	e.srv.singboxInv["node-000"] = inv
	e.srv.singboxInvMu.Unlock()
	e.srv.invalidateLineReadModel()
	if err := e.st.UpsertDDNSProfile(model.DDNSProfile{ID: "cname", NodeID: "node-000", RecordType: "cname", CNAMETarget: "edge.provider.example",
		Domains: []string{"nat.example.org", "hijacked.example.org", "egress.example.org"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.UpsertDDNSProfile(model.DDNSProfile{ID: "addr", NodeID: "node-000", Domains: []string{"home.example.org"}}); err != nil {
		t.Fatal(err)
	}
	catalogueResolver(e, map[string][]string{
		"edge.provider.example": {"46.1.2.3"},
		"nat.example.org":       {"46.1.2.3"},
		"hijacked.example.org":  {"46.6.6.6"},
		"egress.example.org":    {catalogueNodeIP(0)},
		"home.example.org":      {catalogueNodeIP(0)},
	})
	row := e.read(t, "").Rows[0]
	want := []model.LineCatalogueDDNSName{
		{Name: "egress.example.org"},
		{Name: "hijacked.example.org"},
		{Name: "home.example.org", Verified: true},
		{Name: "nat.example.org", Verified: true, Target: "edge.provider.example"},
	}
	if !slices.Equal(row.DDNSNames, want) {
		t.Fatalf("ddns = %+v", row.DDNSNames)
	}
	// The answer moves off the edge: the name is no longer verified, though
	// the profile still names the edge as its target.
	catalogueResolver(e, map[string][]string{
		"edge.provider.example": {"46.1.2.3"},
		"nat.example.org":       {"46.7.7.7"},
		"home.example.org":      {catalogueNodeIP(0)},
	})
	for _, name := range e.read(t, "").Rows[0].DDNSNames {
		if name.Name == "nat.example.org" && (name.Verified || name.Target != "") {
			t.Fatalf("a cname answering off the edge is still verified: %+v", name)
		}
	}
}

// A line whose inventory leaves its security empty carries the security its
// template states: a URI template's security parameter, a vmess template's
// tls field.
func TestCatalogueFillsSecurityFromTemplate(t *testing.T) {
	e := catalogueFixture(t, 1, 2)
	vmess, _ := json.Marshal(map[string]string{"v": "2", "ps": "owner", "add": catalogueNodeIP(0), "port": "20001", "id": catalogueOwnerUUID,
		"aid": "0", "net": "ws", "path": "/ws", "tls": "tls", "sni": "www.example.com"})
	editSingBoxLine(t, e.srv, "node-000", "vless-20001", func(n *model.SingBoxNode) {
		n.Protocol = "vmess"
		n.ShareURL = "vmess://" + base64.StdEncoding.EncodeToString(vmess)
	})
	if err := e.srv.syncLineClientTemplates(e.now); err != nil {
		t.Fatal(err)
	}
	rows := e.read(t, "").Rows
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
	got := map[string]string{}
	for _, row := range rows {
		if row.Template == nil {
			t.Fatalf("row %s has no template", row.Name)
		}
		got[row.Protocol] = row.Security
	}
	if got["vless"] != "reality" || got["vmess"] != "tls" {
		t.Fatalf("security per protocol = %v, want vless reality and vmess tls", got)
	}
	if sec := lineCatalogueTemplateSecurity(store.LineClientTemplate{Protocol: "trojan", Params: map[string]string{"security": "none"}}); sec != "" {
		t.Fatalf("security none filled as %q", sec)
	}
}

// relayTo points a node's first line's outbound at host:port.
func relayTo(t *testing.T, e *catalogueEnv, nodeID, host, port string) {
	t.Helper()
	editSingBoxLine(t, e.srv, nodeID, "vless-20000", func(n *model.SingBoxNode) {
		n.OutboundRef, n.OutboundServer, n.OutboundPort = "relay-out", host, port
	})
}

// A relay whose outbound resolves to no fleet line is Unresolved and has no
// exit geo, and so is every line whose path ends at it: their traffic leaves
// from a server the fleet does not hold.
func TestCatalogueMarksUnresolvedRelay(t *testing.T) {
	e := catalogueFixture(t, 3, 1)
	relayTo(t, e, "node-000", catalogueNodeIP(1), "20000")
	relayTo(t, e, "node-001", "203.0.113.50", "443")
	rows := e.read(t, "").Rows
	entry, relay, single := rows[0], rows[1], rows[2]
	if !relay.Chain.Unresolved || relay.Chain.ExitGeo != nil || relay.Chain.Role != model.LineChainRoleRelay {
		t.Fatalf("relay to a foreign server = %+v", relay.Chain)
	}
	if !entry.Chain.Unresolved || entry.Chain.ExitGeo != nil || entry.Chain.DownstreamLineUUID != relay.LineUUID {
		t.Fatalf("entry whose path ends at the unresolved relay = %+v", entry.Chain)
	}
	if single.Chain.Unresolved || single.Chain.Role != model.LineChainRoleSingle {
		t.Fatalf("a line with no outbound = %+v", single.Chain)
	}
	// A direct outbound is not a relay.
	editSingBoxLine(t, e.srv, "node-001", "vless-20000", func(n *model.SingBoxNode) { n.OutboundRef = "direct" })
	rows = e.read(t, "").Rows
	if rows[1].Chain.Unresolved || rows[0].Chain.Unresolved || rows[0].Chain.ExitGeo == nil {
		t.Fatalf("a direct outbound still reads unresolved: entry %+v, exit %+v", rows[0].Chain, rows[1].Chain)
	}
}

// The matcher is the SDK's: an unresolved relay matches no country or region,
// whatever its own node's geo, while its other predicates still apply.
func TestCatalogueMatcherTreatsUnresolvedGeoAsUnknown(t *testing.T) {
	e := catalogueFixture(t, 3, 1)
	relayTo(t, e, "node-000", "203.0.113.50", "443")
	rows := e.read(t, "").Rows
	unresolved := rows[0]
	if !unresolved.Chain.Unresolved || unresolved.Geo.Country != "DE" {
		t.Fatalf("fixture: %+v geo %+v", unresolved.Chain, unresolved.Geo)
	}
	if got := rowUUIDs(e.read(t, `{"selector":{"countries":["DE"]}}`).Rows); slices.Contains(got, unresolved.LineUUID) {
		t.Fatalf("a DE filter took the unresolved relay on its own node's geo: %v", got)
	}
	if got := rowUUIDs(e.read(t, `{"selector":{"regions":["Region DE"]}}`).Rows); slices.Contains(got, unresolved.LineUUID) {
		t.Fatalf("a region filter took the unresolved relay: %v", got)
	}
	if got := rowUUIDs(e.read(t, `{"selector":{"protocols":["vless"]}}`).Rows); !slices.Contains(got, unresolved.LineUUID) {
		t.Fatalf("a protocol filter dropped the unresolved relay: %v", got)
	}
	sel := &model.LineCatalogueSelector{Countries: []string{"DE"}}
	if lineCatalogueMatches(&unresolved, sel, e.now) != model.LineCatalogueSelectorMatches(&unresolved, sel, e.now) {
		t.Fatal("core's matcher and the SDK's disagree")
	}
}

// Every line with a path carries the worst service state along it: down,
// then restarting, then unknown, then running; a line with no path carries
// none.
func TestCataloguePathServiceState(t *testing.T) {
	e := catalogueFixture(t, 4, 1)
	relayTo(t, e, "node-000", catalogueNodeIP(1), "20000")
	relayTo(t, e, "node-001", catalogueNodeIP(2), "20000")
	for node, state := range map[string]string{"node-000": serviceStateRunning, "node-001": serviceStateRestarting, "node-002": serviceStateRunning, "node-003": serviceStateRunning} {
		if _, _, err := e.st.UpsertSingBoxLiveness(store.SingBoxLiveness{NodeID: node, State: state, ReceivedAt: e.now}); err != nil {
			t.Fatal(err)
		}
	}
	e.srv.invalidateLineReadModel()
	rows := e.read(t, "").Rows
	if got := rows[0].Chain.PathServiceState; got != model.LineServiceStateRestarting {
		t.Fatalf("entry over a restarting relay = %q", got)
	}
	if got := rows[1].Chain.PathServiceState; got != model.LineServiceStateRestarting {
		t.Fatalf("the restarting relay = %q", got)
	}
	if got := rows[2].Chain.PathServiceState; got != "" {
		t.Fatalf("an exit with no path out = %q", got)
	}
	if got := rows[3].Chain.PathServiceState; got != "" {
		t.Fatalf("a single line = %q", got)
	}
	if _, _, err := e.st.UpsertSingBoxLiveness(store.SingBoxLiveness{NodeID: "node-002", State: serviceStateDown, ReceivedAt: e.now}); err != nil {
		t.Fatal(err)
	}
	e.srv.invalidateLineReadModel()
	if got := e.read(t, "").Rows[0].Chain.PathServiceState; got != model.LineServiceStateDown {
		t.Fatalf("entry over a down exit = %q", got)
	}
	if got := lineCatalogueWorstServiceState([]string{"a", "b"}, map[string]string{"a": "running"}); got != model.LineServiceStateUnknown {
		t.Fatalf("an unreported state ranks as %q", got)
	}
}

// Every page names the probe block unavailable while no probe producer
// fills it, so the plugin offers no probe predicate.
func TestCatalogueListsProbeUnavailable(t *testing.T) {
	e := catalogueFixture(t, 3, 2)
	rows, _, pages := e.readAll(t, "", 2)
	if pages < 2 || len(rows) != 6 {
		t.Fatalf("%d rows over %d pages", len(rows), pages)
	}
	cursor := ""
	for {
		req := map[string]any{"limit": 2}
		if cursor != "" {
			req["cursor"] = cursor
		}
		raw, _ := json.Marshal(req)
		page := e.read(t, string(raw))
		if !slices.Equal(page.Unavailable, []string{model.LineCatalogueUnavailableProbe}) {
			t.Fatalf("page unavailable = %v", page.Unavailable)
		}
		for _, row := range page.Rows {
			if row.Probe != nil {
				t.Fatalf("row %s carries a probe block", row.LineUUID)
			}
		}
		if page.Cursor == "" {
			break
		}
		cursor = page.Cursor
	}
}

// The row's label is the entry label bind shows for the same line, for a
// line with a name, one named only by its tag, and one named by neither.
func TestCatalogueRowLabelEqualsBindEntryLabel(t *testing.T) {
	e := catalogueFixture(t, 2, 2)
	rows := e.read(t, "").Rows
	catalogue, err := e.srv.buildLineCatalogue("")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		ln, ok := catalogue.Line(row.LineUUID)
		if !ok {
			t.Fatalf("no line behind row %s", row.LineUUID)
		}
		want := identityLinkEntryLabel(row.NodeName, identityLinkLineName(ln))
		if row.Label == "" || row.Label != want {
			t.Fatalf("row %s label %q, bind shows %q", row.LineUUID, row.Label, want)
		}
	}
	for _, ln := range []Line{{Name: "hk-01", Tag: "tag", LineHashID: "h"}, {Tag: "conf-7.json", LineHashID: "h"}, {LineHashID: "lh-1"}} {
		if got, want := identityLinkEntryLabel("Node", identityLinkLineName(ln)), "Node "+identityLinkLineName(ln); got != want {
			t.Fatalf("label %q, want %q", got, want)
		}
	}
}
