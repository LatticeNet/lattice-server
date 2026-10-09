package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A Reality short id is the line's public material, the same for every
// identity, so it may reach a plugin, but only as a template's sid param, for
// a stored template and for a composed root alike. A sid param that is not a
// short id costs the row its template, so the slot cannot carry anything
// else.
func TestLineCatalogueRealityShortIDTravelsOnlyAsTheSidParam(t *testing.T) {
	e := catalogueFixture(t, 1, 3)
	rows := e.read(t, "").Rows
	const sid = "c0ffee5eed5a1e77"
	plantTemplateParam(t, e, rows[0].LineHashID, "sid", sid)
	plantTemplateParam(t, e, rows[1].LineHashID, "sid", "9f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a")
	plantTemplateParam(t, e, rows[2].LineHashID, "sid", "0a1b2")

	got := e.read(t, "").Rows
	raw, _ := json.Marshal(got[0])
	if got[0].Template == nil || got[0].Template.Params["sid"] != sid || strings.Count(strings.ToLower(string(raw)), sid) != 1 {
		t.Fatalf("the short id must appear once, as the sid param: %s", raw)
	}
	if got[1].Template != nil || got[2].Template != nil {
		t.Fatalf("a sid that is not a short id was served: %+v / %+v", got[1].Template, got[2].Template)
	}
	catalogue, err := e.srv.buildLineCatalogue("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := catalogue.BindTemplate(rows[1].LineUUID); ok {
		t.Fatal("a template refused for its sid still binds")
	}

	root := "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d"
	compile := lineChainCompileSnapshot{
		Lines: map[string][]Line{root: {{LineHashID: "h-root", LineUUID: root, NodeID: "n1", Name: "root", Tag: "vless-443", Core: "sing-box", Type: "vless",
			Transport: "tcp", Status: "ok", Overlay: true, OverlayStatus: managedLineStatusApplied, PublicHost: "203.0.114.9"}}},
		Definitions: map[string]managedLineDef{root: {LineHashID: "h-root", Status: managedLineStatusApplied, Port: 443, SNI: "www.example.com",
			RealityPublicKey: "Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eHF1dXg", ShortID: strings.ToUpper(sid)}},
		Nodes: map[string]model.Node{"n1": {ID: "n1"}},
	}
	composed := lineCatalogueComposedTemplate(compile, root)
	if composed == nil {
		t.Fatal("no composed template")
	}
	served, err := lineCatalogueTemplate(*composed)
	if err != nil {
		t.Fatal(err)
	}
	var carriers []string
	for key, value := range served.Params {
		if strings.Contains(strings.ToLower(value), sid) {
			carriers = append(carriers, key)
		}
	}
	if !slices.Equal(carriers, []string{"sid"}) {
		t.Fatalf("the composed root's short id is carried by %v", carriers)
	}
}

// The identity guard finds a whole credential part in each encoding a row
// could carry it in, not only raw: without its dashes, as base64 of the text
// or of the uuid's bytes, percent-encoded. Each planted row loses its
// template when the identity is named, and keeps it when none is.
func TestLineCatalogueIdentityGuardFindsEncodedCredentials(t *testing.T) {
	e := catalogueFixture(t, 1, 7)
	const identityUUID = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
	// The password's base64 differs between the two alphabets.
	const password = "Tr0jan pa??ss>>>word"
	catalogueIdentity(t, e, identityUUID, password)
	rows := e.read(t, "").Rows
	uuidBytes, _ := hex.DecodeString(strings.ReplaceAll(identityUUID, "-", ""))
	planted := []string{
		strings.ToUpper(strings.ReplaceAll(identityUUID, "-", "")),
		base64.StdEncoding.EncodeToString([]byte(password)),
		base64.URLEncoding.EncodeToString([]byte(password)),
		url.QueryEscape(password),
		url.PathEscape(password),
		base64.URLEncoding.EncodeToString(uuidBytes),
	}
	for i, value := range planted {
		plantTemplateParam(t, e, rows[i].LineHashID, "path", "/x"+value)
	}
	for i, row := range e.read(t, "").Rows {
		if row.Template == nil {
			t.Fatalf("without an identity row %d lost its template; the fixture tests nothing", i)
		}
	}
	named := e.read(t, `{"identity_id":"vu-cat"}`).Rows
	if len(named) != len(rows) {
		t.Fatalf("%d of %d rows served; a row without its template is still a row", len(named), len(rows))
	}
	for i := range planted {
		if named[i].Template != nil {
			t.Fatalf("row %d carries the identity's credential as %q in its template", i, planted[i])
		}
	}
	if named[len(planted)].Template == nil {
		t.Fatal("a row with nothing planted lost its template")
	}
}

// The forms the guard looks for, pinned: a uuid also without its dashes and
// as base64 of its bytes, every part percent-encoded and base64 on its own,
// each JSON-escaped too, and nothing shorter than four bytes.
func TestLineCatalogueSecretFormsArePinned(t *testing.T) {
	// jsonAmp is how encoding/json escapes an ampersand.
	jsonAmp := strings.ReplaceAll("#u0026", "#", "\\")
	m := newLineCatalogueSecrets([]string{"7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d", `p"w&d x`, "??>>>", "abc"})
	for _, carried := range []string{
		"7A8B9C0D1E2F4A3B8C4D5E6F7A8B9C0D", "eoucDR4vSjuMTV5veoucDQ", "N2E4YjljMGQtMWUyZi00YTNiLThjNGQtNWU2ZjdhOGI5YzBk",
		`p\"w` + jsonAmp + `d x`, "p%22w%26d+x", "p%22w&d%20x", "cCJ3JmQgeA", `p%22w` + jsonAmp + `d%20x`,
		"Pz8+Pj4", "Pz8-Pj4",
	} {
		if !m.in([]byte(`{"v":"` + carried + `"}`)) {
			t.Errorf("the guard misses %q", carried)
		}
	}
	if m.in([]byte(`{"v":"abc YWJj 7a8b9c0d"}`)) {
		t.Error("the guard matched a part under four bytes or a slice of a uuid")
	}
}

// Several reads paging at once each finish from their own first page's
// build: one read's first page does not evict another read in progress.
func TestLineCataloguePagedReadsDoNotEvictEachOther(t *testing.T) {
	e := catalogueFixture(t, 2, 3)
	selectors := []string{`{"countries":["DE"]}`, `{"countries":["JP"]}`, `{"node_tags":["tier-0"]}`, `{"node_tags":["tier-1"]}`,
		`{"protocols":["vless"]}`, `{"transports":["tcp"]}`}
	type read struct{ cursor, version, selector string }
	var reads []read
	for _, selector := range selectors {
		page := e.read(t, `{"limit":1,"selector":`+selector+`}`)
		if page.Cursor == "" {
			t.Fatalf("selector %s fits one page; the test needs a cursor", selector)
		}
		reads = append(reads, read{page.Cursor, page.CatalogueVersion, selector})
	}
	if err := e.st.UpsertNode(model.Node{ID: "node-000", Name: "Renamed", PublicIP: catalogueNodeIP(0)}); err != nil {
		t.Fatal(err)
	}
	e.srv.invalidateLineReadModel()
	for _, r := range reads {
		page := e.read(t, `{"limit":1,"selector":`+r.selector+`,"cursor":"`+r.cursor+`"}`)
		if page.CatalogueVersion != r.version {
			t.Fatalf("the read of %s restarted: its build was evicted by the reads after it", r.selector)
		}
	}
}

// The page cache is bounded by bytes as well as entries, makes room by
// dropping the oldest build, and always keeps the newest.
func TestLineCataloguePageCacheEvictsTheOldestBuildByBytes(t *testing.T) {
	var c lineCataloguePageCache
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	third := [][]byte{make([]byte, lineCataloguePageCacheBytes/3)}
	c.put("a", third, now)
	c.put("b", third, now.Add(time.Second))
	c.put("c", third, now.Add(2*time.Second))
	for key, want := range map[string]bool{"a": true, "b": true, "c": true} {
		if _, ok := c.get(key, now.Add(3*time.Second)); ok != want {
			t.Fatalf("%s cached = %v under the byte bound", key, ok)
		}
	}
	c.put("d", third, now.Add(3*time.Second))
	for key, want := range map[string]bool{"a": false, "b": true, "c": true, "d": true} {
		if _, ok := c.get(key, now.Add(4*time.Second)); ok != want {
			t.Fatalf("%s cached = %v after the bound was reached", key, ok)
		}
	}
	c.put("huge", [][]byte{make([]byte, lineCataloguePageCacheBytes+1)}, now.Add(5*time.Second))
	if _, ok := c.get("huge", now.Add(6*time.Second)); !ok || len(c.entries) != 1 {
		t.Fatalf("a build over the whole bound must be kept alone; %d entries", len(c.entries))
	}
	for i := range lineCataloguePageCacheEntries + 1 {
		c.put(fmt.Sprint("small-", i), [][]byte{{'x'}}, now.Add(time.Duration(10+i)*time.Second))
	}
	if len(c.entries) != lineCataloguePageCacheEntries {
		t.Fatalf("%d entries, bound %d", len(c.entries), lineCataloguePageCacheEntries)
	}
	if _, ok := c.get("small-0", now.Add(time.Minute)); ok {
		t.Fatal("the oldest small build survived the entry bound")
	}
}

// The selector's pushdown rules, pinned, because a plugin running a
// predicate itself must match them byte for byte: case folding for
// countries, regions, protocols, transports and service states; exact match
// for node tags, group ids and chain roles; geo from the chain's exit with no
// fallback to the entry; a renewal already past inside any window.
func TestLineCatalogueSelectorSemanticsArePinned(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	row := model.LineCatalogueRow{Protocol: "vless", Transport: "tcp", ServiceState: "running",
		NodeTags: []string{"Tier-1"}, GroupIDs: []string{"grp-A"}, Geo: &model.NodeGeo{Country: "DE", Region: "Hesse"},
		Chain:   model.LineCatalogueChain{Role: model.LineChainRoleEntry, ExitGeo: &model.NodeGeo{Country: "JP"}},
		Machine: &model.LineCatalogueMachine{NextRenewal: now.Add(-48 * time.Hour)}}
	week := 7
	for name, c := range map[string]struct {
		sel  model.LineCatalogueSelector
		want bool
	}{
		"country folds case":              {model.LineCatalogueSelector{Countries: []string{"jp"}}, true},
		"country reads the exit geo":      {model.LineCatalogueSelector{Countries: []string{"DE"}}, false},
		"region has no entry fallback":    {model.LineCatalogueSelector{Regions: []string{"Hesse"}}, false},
		"protocol folds case":             {model.LineCatalogueSelector{Protocols: []string{"VLESS"}}, true},
		"transport folds case":            {model.LineCatalogueSelector{Transports: []string{"TCP"}}, true},
		"service state folds case":        {model.LineCatalogueSelector{ServiceStates: []string{"Running"}}, true},
		"node tag is exact":               {model.LineCatalogueSelector{NodeTags: []string{"tier-1"}}, false},
		"node tag matches itself":         {model.LineCatalogueSelector{NodeTags: []string{"Tier-1"}}, true},
		"group id is exact":               {model.LineCatalogueSelector{GroupIDs: []string{"grp-a"}}, false},
		"chain role is exact":             {model.LineCatalogueSelector{ChainRoles: []string{"Entry"}}, false},
		"a past renewal is in the window": {model.LineCatalogueSelector{RenewalWithinDays: &week}, true},
	} {
		if got := lineCatalogueMatches(&row, &c.sel, now); got != c.want {
			t.Errorf("%s: matched %v", name, got)
		}
	}
}

// The identity read's cost: every row and the page are screened for the
// identity's credential in each form. Same 50 ms target as the plain read.
func BenchmarkLineCatalogueThousandLinesForAnIdentity(b *testing.B) {
	e := catalogueFixture(b, 50, 20)
	u := VpnUser{ID: "vu-bench", Name: "Bench", Enabled: true, CreatedAt: e.now, UpdatedAt: e.now,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"}, {Protocol: "trojan", Password: "Tr0jan pa/ss&word"}}}
	if err := e.srv.putVpnUser(u); err != nil {
		b.Fatal(err)
	}
	request := []byte(`{"identity_id":"vu-bench"}`)
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
