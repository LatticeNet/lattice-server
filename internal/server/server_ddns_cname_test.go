package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/ddns/cffake"
)

// The real case: frontier egresses from 47.148.162.50 but is reached through
// its NAT provider's hostname, and the operator made the CNAME by hand.
const (
	frontierHost   = "frontier.nat.aaitr.roobli.org"
	frontierTarget = "nat-us-28tz.aproxy.top"
	frontierEgress = "47.148.162.50"
)

type ddnsCNAMEView struct {
	ID          string   `json:"id"`
	RecordType  string   `json:"record_type"`
	CNAMETarget string   `json:"cname_target"`
	LastTarget  string   `json:"last_target"`
	LastIPv4    string   `json:"last_ipv4"`
	LastIPv6    string   `json:"last_ipv6"`
	LastError   string   `json:"last_error"`
	Warnings    []string `json:"warnings"`
}

func decodeCNAMEView(t *testing.T, raw string) ddnsCNAMEView {
	t.Helper()
	var v ddnsCNAMEView
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

func listCNAMEViews(t *testing.T, handler http.Handler, cookies []*http.Cookie) []ddnsCNAMEView {
	t.Helper()
	var views []ddnsCNAMEView
	if err := json.Unmarshal([]byte(listRaw(t, handler, cookies)), &views); err != nil {
		t.Fatal(err)
	}
	return views
}

func frontierCNAMEBody(extra string) string {
	return `{"name":"frontier","node_id":"n1","provider":"cloudflare","domains":["` + frontierHost + `"],"cf_api_token":"t","record_type":"cname","cname_target":"` + frontierTarget + `"` + extra + `}`
}

func seedFrontierNode(t *testing.T, srv *Server) {
	t.Helper()
	if err := srv.store.UpsertNode(model.Node{ID: "n1", Name: "[cd]-Aaitr-Frontier-NAT", PublicIP: frontierEgress}); err != nil {
		t.Fatal(err)
	}
}

func runNow(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, id string) int {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/ddns/run", `{"id":"`+id+`"}`, cookies, csrf)
	res.Body.Close()
	return res.StatusCode
}

// Adopting the hand-made CNAME: the save normalizes the target, raises no
// NAT warning and no conflict warning, "Run now" writes only the comment, and
// the view says CNAME to the target with no address, even though the node
// has one.
func TestDDNSCNAMEAdoptsExistingRecord(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	setTestInventory(srv, &model.SingBoxInventory{NodeID: "n1", At: time.Now(), Network: "nat", ProviderEdge: frontierTarget,
		Nodes: []model.SingBoxNode{{Name: "in", Protocol: "vless", Port: "443"}}})
	fake.Seed(cffake.Record{Type: "CNAME", Name: frontierHost, Content: frontierTarget, TTL: 1, Comment: "made by hand"})

	code, _, raw := saveDDNS(t, handler, strings.Replace(frontierCNAMEBody(`,"enable_ipv4":true,"enable_ipv6":true`), frontierTarget, "NAT-us-28tz.aproxy.top.", 1), cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("save: %d %s", code, raw)
	}
	made := decodeCNAMEView(t, raw)
	if made.RecordType != "cname" || made.CNAMETarget != frontierTarget {
		t.Fatalf("saved view: %+v", made)
	}
	if len(made.Warnings) != 0 {
		t.Fatalf("adopting a CNAME behind NAT is the right setup, warnings: %q", made.Warnings)
	}
	if ev := auditByActionAndScope(t, st, "ddns.create", "ddns:admin"); ev.Metadata["record_type"] != "cname" {
		t.Fatalf("create audit metadata: %+v", ev.Metadata)
	}

	if code := runNow(t, handler, cookies, csrf, made.ID); code != http.StatusOK {
		t.Fatalf("run now: %d", code)
	}
	recs := fake.Find(frontierHost, "")
	if len(recs) != 1 || recs[0].Type != "CNAME" || recs[0].Content != frontierTarget || recs[0].Proxied {
		t.Fatalf("records after run now: %+v", recs)
	}
	if !strings.HasPrefix(recs[0].Comment, "Lattice DDNS for [cd]-Aaitr-Frontier-NAT, ") {
		t.Fatalf("run now did not refresh the comment: %q", recs[0].Comment)
	}
	for _, w := range fake.Writes() {
		if string(w.Body["content"]) != `"`+frontierTarget+`"` || w.Method != http.MethodPatch {
			t.Fatalf("adopting wrote something other than the same CNAME: %s %+v", w.Method, w.Body)
		}
	}
	views := listCNAMEViews(t, handler, cookies)
	if len(views) != 1 || views[0].LastTarget != frontierTarget || views[0].LastIPv4 != "" || views[0].LastIPv6 != "" || views[0].LastError != "" {
		t.Fatalf("list view: %+v", views)
	}
}

// An A record on the name: the save warns with the sentence the run stores,
// "Run now" fails without touching the record, and last_error says what to do.
func TestDDNSCNAMEConflictWithARecord(t *testing.T) {
	srv, handler, _, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	fake.Seed(cffake.Record{Type: "A", Name: frontierHost, Content: "1.2.3.4", TTL: 60})
	want := frontierHost + " already has an A record (1.2.3.4); a name cannot hold a CNAME and other records. Remove it in Cloudflare, then run again."

	code, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("save: %d %s", code, raw)
	}
	made := decodeCNAMEView(t, raw)
	if len(made.Warnings) != 1 || made.Warnings[0] != want {
		t.Fatalf("save warning\n got %q\nwant %q", made.Warnings, want)
	}
	if code := runNow(t, handler, cookies, csrf, made.ID); code != http.StatusBadGateway {
		t.Fatalf("run now against an A record: %d", code)
	}
	views := listCNAMEViews(t, handler, cookies)
	if len(views) != 1 || views[0].LastError != want || views[0].LastTarget != "" {
		t.Fatalf("last_error\n got %+v\nwant %s", views, want)
	}
	if recs := fake.Find(frontierHost, ""); len(recs) != 1 || recs[0].Type != "A" || recs[0].Content != "1.2.3.4" {
		t.Fatalf("the A record was touched: %+v", recs)
	}
	if n := len(fake.Writes()); n != 0 {
		t.Fatalf("a conflict wrote %d times", n)
	}
}

func TestDDNSCNAMESaveRefusals(t *testing.T) {
	_, handler, st := newDDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	cases := map[string]string{
		"needs the cloudflare provider": `{"name":"w","node_id":"n1","provider":"webhook","webhook_url":"https://example.com/h","domains":["a.example.com"],"record_type":"cname","cname_target":"` + frontierTarget + `"}`,
		"cannot point into the names":   strings.Replace(frontierCNAMEBody(""), frontierTarget, "edge."+frontierHost+".", 1),
		"not an IP address":             strings.Replace(frontierCNAMEBody(""), frontierTarget, "40.160.254.9", 1),
		"cname_target is required":      strings.Replace(frontierCNAMEBody(""), frontierTarget, "", 1),
		"must be address or cname":      strings.Replace(frontierCNAMEBody(""), `"record_type":"cname"`, `"record_type":"txt"`, 1),
	}
	for want, body := range cases {
		code, _, raw := saveDDNS(t, handler, body, cookies, csrf)
		if code != http.StatusBadRequest || !strings.Contains(raw, want) {
			t.Fatalf("got %d %s, want 400 mentioning %q", code, raw, want)
		}
	}
	if n := len(st.DDNSProfiles()); n != 0 {
		t.Fatalf("a refused profile was stored: %d", n)
	}
}

// A target the control plane cannot resolve is worth a warning, never a
// refusal: the provider may publish it later, and the control plane's view
// of DNS is not the clients'.
func TestDDNSCNAMEWarnsWhenTargetDoesNotResolve(t *testing.T) {
	srv, handler, st, _ := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	srv.ddnsLookupHost = func(context.Context, string) ([]string, error) {
		return nil, errors.New("lookup nat-us-28tz.aproxy.top: no such host")
	}
	code, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("an unresolvable target must not refuse the save: %d %s", code, raw)
	}
	made := decodeCNAMEView(t, raw)
	if len(made.Warnings) != 1 || !strings.Contains(made.Warnings[0], frontierTarget+" does not resolve from the control plane") || !strings.Contains(made.Warnings[0], "no such host") {
		t.Fatalf("warnings: %q", made.Warnings)
	}
	if len(st.DDNSProfiles()) != 1 {
		t.Fatal("profile not saved")
	}
}

// The NAT warning stays for an address profile on the same node, so its
// absence for a CNAME profile is the record type's doing.
func TestDDNSNATWarningOnlyForAddressProfiles(t *testing.T) {
	srv, handler, _, _ := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	setTestInventory(srv, &model.SingBoxInventory{NodeID: "n1", At: time.Now(), Network: "nat", ProviderEdge: frontierTarget,
		Nodes: []model.SingBoxNode{{Name: "in", Protocol: "vless", Port: "443"}}})
	_, address, _ := saveDDNS(t, handler, `{"name":"a","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"cf_api_token":"t","enable_ipv4":true}`, cookies, csrf)
	if len(address.Warnings) != 1 || !strings.Contains(address.Warnings[0], "behind NAT") {
		t.Fatalf("address profile warnings: %q", address.Warnings)
	}
	_, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf)
	if strings.Contains(raw, "behind NAT") {
		t.Fatalf("a CNAME profile got the NAT warning: %s", raw)
	}
}

// recordingProvider wraps the fake-backed provider and reports every record a
// run tries to set, so a test can wait for an asynchronous trigger.
type recordingProvider struct {
	ddns.Provider
	ch chan ddns.Record
}

func (p recordingProvider) SetRecord(ctx context.Context, r ddns.Record) error {
	p.ch <- r
	return p.Provider.SetRecord(ctx, r)
}

// A heartbeat that moves the node's address republishes its address profiles
// and leaves its CNAME profiles alone.
func TestDDNSCNAMEIgnoresHeartbeatAddressChange(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	if _, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf); !strings.Contains(raw, `"record_type":"cname"`) {
		t.Fatalf("save cname: %s", raw)
	}
	if code, _, raw := saveDDNS(t, handler, `{"name":"addr","node_id":"n1","provider":"cloudflare","domains":["egress.example.com"],"cf_api_token":"t","enable_ipv4":true}`, cookies, csrf); code != http.StatusOK {
		t.Fatalf("save address: %d %s", code, raw)
	}
	seen := make(chan ddns.Record, 8)
	build := srv.ddnsProvider
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		prov, err := build(p)
		if err != nil {
			return nil, err
		}
		return recordingProvider{Provider: prov, ch: seen}, nil
	}

	srv.maybeTriggerDDNS("n1", frontierEgress, "", "47.148.162.51", "")
	select {
	case rec := <-seen:
		if rec.Name != "egress.example.com" {
			t.Fatalf("first record set on a heartbeat: %+v", rec)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the address profile was not republished")
	}
	select {
	case rec := <-seen:
		t.Fatalf("a heartbeat touched another record: %+v", rec)
	case <-time.After(300 * time.Millisecond):
	}
	if recs := fake.Find(frontierHost, ""); len(recs) != 0 {
		t.Fatalf("a heartbeat published the CNAME: %+v", recs)
	}
	for _, p := range st.DDNSProfiles() {
		if ddns.IsCNAME(p) && !p.LastRunAt.IsZero() {
			t.Fatalf("a heartbeat ran the CNAME profile: %+v", p)
		}
	}
}

// The scheduled check: a profile in sync costs a read and nothing else, a
// CNAME somebody retargeted by hand is put back, and one somebody removed is
// recreated.
func TestDDNSCNAMESweepRepairsDrift(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	clock := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return clock }
	tick := func() { clock = clock.Add(10 * time.Minute) }
	var mu sync.Mutex
	ran := 0
	build := srv.ddnsProvider
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		mu.Lock()
		ran++
		mu.Unlock()
		return build(p)
	}
	fake.Seed(cffake.Record{Type: "CNAME", Name: frontierHost, Content: frontierTarget, TTL: 1})
	_, _, raw := saveDDNS(t, handler, frontierCNAMEBody(`,"comment_mode":"none"`), cookies, csrf)
	profileID := decodeCNAMEView(t, raw).ID

	// The first sweep confirms the adopted record and records the target.
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("first sweep ran %d profiles, want 1", n)
	}
	if got, _ := st.DDNSProfile(profileID); got.LastTarget != frontierTarget || got.LastError != "" {
		t.Fatalf("after the first sweep: %+v", got)
	}
	runs := countAuditAction(st, "ddns.run")

	// In sync: nothing written, nothing audited, the clock advances.
	tick()
	if n := srv.sweepDDNSOnce(); n != 0 {
		t.Fatalf("an in-sync sweep ran %d profiles", n)
	}
	if n := len(fake.Writes()); n != 0 {
		t.Fatalf("an in-sync sweep wrote %d times", n)
	}
	if got := countAuditAction(st, "ddns.run"); got != runs {
		t.Fatalf("an in-sync sweep was audited: %d runs, was %d", got, runs)
	}
	if got, _ := st.DDNSProfile(profileID); !got.LastRunAt.Equal(clock) {
		t.Fatalf("an in-sync check did not advance the clock: %v, want %v", got.LastRunAt, clock)
	}

	// Not yet due: not even a read.
	mu.Lock()
	before := ran
	mu.Unlock()
	if n := srv.sweepDDNSOnce(); n != 0 {
		t.Fatalf("a sweep before the interval ran %d profiles", n)
	}
	mu.Lock()
	if ran != before {
		t.Fatalf("a profile not yet due was checked")
	}
	mu.Unlock()

	// Retargeted by hand in Cloudflare: put back on the next check.
	retargetByHand(t, fake, frontierHost, "somewhere-else.example.net")
	tick()
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("a drifted sweep ran %d profiles, want 1", n)
	}
	if recs := fake.Find(frontierHost, "CNAME"); len(recs) != 1 || recs[0].Content != frontierTarget {
		t.Fatalf("drift not repaired: %+v", recs)
	}
}

// retargetByHand changes a CNAME's target the way an operator would in the
// Cloudflare dashboard, through the fake's API.
func retargetByHand(t *testing.T, fake *cffake.Server, name, target string) {
	t.Helper()
	recs := fake.Find(name, "CNAME")
	if len(recs) != 1 {
		t.Fatalf("no CNAME to retarget at %s: %+v", name, recs)
	}
	req, _ := http.NewRequest(http.MethodPatch, fake.URL+"/zones/zone2/dns_records/"+recs[0].ID, strings.NewReader(`{"content":"`+target+`"}`))
	res, err := fake.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := fake.Find(name, "CNAME"); got[0].Content != target {
		t.Fatalf("hand retarget did not land: %+v", got)
	}
	// The hand edit is not Lattice's write.
	fake.ForgetWrites()
}

// Editing the target counts as drift too: the next check publishes it even
// though Cloudflare still holds the old target in sync with the old setting.
func TestDDNSCNAMEEditedTargetIsPublishedByTheSweep(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	fake.Seed(cffake.Record{Type: "CNAME", Name: frontierHost, Content: frontierTarget, TTL: 1})
	_, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf)
	made := decodeCNAMEView(t, raw)
	srv.sweepDDNSOnce()

	_, _, raw = saveDDNS(t, handler, strings.Replace(frontierCNAMEBody(`,"id":"`+made.ID+`"`), frontierTarget, "nat-us-29tz.aproxy.top", 1), cookies, csrf)
	edited := decodeCNAMEView(t, raw)
	if edited.LastTarget != frontierTarget || edited.CNAMETarget != "nat-us-29tz.aproxy.top" {
		t.Fatalf("edit view: %+v", edited)
	}
	stored, _ := st.DDNSProfile(made.ID)
	stored.LastRunAt = time.Time{}
	if err := st.UpsertDDNSProfile(stored); err != nil {
		t.Fatal(err)
	}
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("sweep after an edit ran %d profiles, want 1", n)
	}
	if recs := fake.Find(frontierHost, "CNAME"); len(recs) != 1 || recs[0].Content != "nat-us-29tz.aproxy.top" {
		t.Fatalf("edited target not published: %+v", recs)
	}
	if got, _ := st.DDNSProfile(made.ID); got.LastTarget != "nat-us-29tz.aproxy.top" {
		t.Fatalf("last_target after the run: %q", got.LastTarget)
	}
}

// Switching a profile between record types drops the other type's status,
// so the view never shows an address for a CNAME profile.
func TestDDNSRecordTypeSwitchDropsOtherStatus(t *testing.T) {
	srv, handler, st, _ := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	if err := st.UpsertDDNSProfile(model.DDNSProfile{ID: "ddns_frontier", Name: "frontier", NodeID: "n1", Provider: model.DDNSProviderCloudflare,
		Domains: []string{frontierHost}, EnableIPv4: true, CFAPIToken: "t", LastIPv4: frontierEgress}); err != nil {
		t.Fatal(err)
	}
	_, _, raw := saveDDNS(t, handler, frontierCNAMEBody(`,"id":"ddns_frontier"`), cookies, csrf)
	if v := decodeCNAMEView(t, raw); v.LastIPv4 != "" || v.RecordType != "cname" {
		t.Fatalf("switched to cname: %+v", v)
	}
	stored, _ := st.DDNSProfile("ddns_frontier")
	stored.LastTarget = frontierTarget
	if err := st.UpsertDDNSProfile(stored); err != nil {
		t.Fatal(err)
	}
	_, _, raw = saveDDNS(t, handler, `{"id":"ddns_frontier","name":"frontier","node_id":"n1","provider":"cloudflare","domains":["`+frontierHost+`"],"enable_ipv4":true,"record_type":"address","cname_target":"`+frontierTarget+`"}`, cookies, csrf)
	if v := decodeCNAMEView(t, raw); v.LastTarget != "" || v.RecordType != "address" || v.CNAMETarget != frontierTarget {
		t.Fatalf("switched back to address: %+v", v)
	}
}

// A DNS deployment that borrows a CNAME profile's credential still publishes
// A records for its own hostname: a name server's host has to be an address,
// since an NS record may not point at a CNAME.
func TestDNSPublishReusingCNAMEProfilePublishesAddress(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	fp := &fakeProvider{}
	var seen model.DDNSProfile
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		seen = p
		return fp, nil
	}
	if err := st.UpsertDDNSProfile(model.DDNSProfile{
		ID: "ddns_cname", Name: "frontier", NodeID: "n1", Provider: model.DDNSProviderCloudflare,
		Domains: []string{frontierHost}, CFAPIToken: "shared-token",
		RecordType: model.DDNSRecordCNAME, CNAMETarget: frontierTarget,
	}); err != nil {
		t.Fatal(err)
	}
	node, _ := st.Node("n1")
	node.PublicIP = "203.0.113.89"
	if err := st.UpsertNode(node); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
		"name":"private dns","node_id":"n1","hostname":"ns.dns.roobli.org","ddns_profile_id":"ddns_cname",
		"publish_ipv4":true,"record_ttl":60,"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
	}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	create.Body.Close()
	publish := doJSON(t, handler, http.MethodPost, "/api/dns/publish", `{"id":"`+created.ID+`"}`, cookies, csrf)
	publish.Body.Close()
	if publish.StatusCode != http.StatusOK {
		t.Fatalf("publish: %d", publish.StatusCode)
	}
	if ddns.IsCNAME(seen) || seen.CFAPIToken != "shared-token" {
		t.Fatalf("deployment profile: %+v", seen)
	}
	if len(fp.records) != 1 || fp.records[0].Type != "A" || fp.records[0].IP != "203.0.113.89" || fp.records[0].Name != "ns.dns.roobli.org" {
		t.Fatalf("published: %+v", fp.records)
	}
}

// A relay naming a CNAME profile's domain on the NAT node's public (forwarded)
// port or its listen port resolves to that node's line, the same as for an
// address profile.
func TestBuildLineGroupsResolvesJumpEdgesThroughCNAMEProfile(t *testing.T) {
	srv := newLinesTestServer(t)
	for _, n := range []model.Node{
		{ID: "hub", Name: "Hub", PublicIP: "203.0.113.5"},
		{ID: "frontier", Name: "[cd]-Aaitr-Frontier-NAT", PublicIP: frontierEgress},
	} {
		if err := srv.store.UpsertNode(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := srv.store.UpsertDDNSProfile(model.DDNSProfile{
		ID: "ddns_baioum5vmvw66ups", Name: "frontier", NodeID: "frontier", Provider: "cloudflare",
		Domains: []string{frontierHost}, RecordType: model.DDNSRecordCNAME, CNAMETarget: frontierTarget,
	}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"hub": {
			NodeID: "hub", At: srv.now(), Status: "ok",
			Nodes: []model.SingBoxNode{
				{Name: "hub-public", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "443",
					OutboundRef: "to-frontier-public", OutboundServer: frontierHost, OutboundPort: "30443", OutboundType: "vless"},
				{Name: "hub-listen", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "444",
					OutboundRef: "to-frontier-listen", OutboundServer: frontierHost, OutboundPort: "1080", OutboundType: "vless"},
			},
		},
		// Reports its own bare address and a forwarded port; neither the
		// record name nor the provider's edge is what the relay names.
		"frontier": {
			NodeID: "frontier", At: srv.now(), Status: "ok", Network: "nat", ProviderEdge: "edge-elsewhere.aproxy.top",
			Nodes: []model.SingBoxNode{
				{Name: "frontier-in", Protocol: "vless", Network: "tcp", Address: frontierEgress, Port: "1080", PublicPort: "30443"},
			},
		},
	}
	srv.singboxInvMu.Unlock()

	groups := srv.buildLineGroups()
	lines := map[string]*Line{}
	for gi := range groups {
		for li := range groups[gi].Lines {
			lines[groups[gi].Lines[li].Tag] = &groups[gi].Lines[li]
		}
	}
	frontier := lines["frontier-in"]
	if frontier == nil || lines["hub-public"] == nil || lines["hub-listen"] == nil {
		t.Fatalf("expected all lines: %+v", groups)
	}
	for _, tag := range []string{"hub-public", "hub-listen"} {
		if edges := lines[tag].JumpEdges; len(edges) != 1 || edges[0] != frontier.LineHashID {
			t.Fatalf("%s through the CNAME profile's domain: %v, want [%s]", tag, edges, frontier.LineHashID)
		}
	}
}
