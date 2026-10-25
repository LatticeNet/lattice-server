package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// dnsMethods are what an agent that runs dns checks reports.
var dnsMethods = []string{"beacon", "dns", "http", "icmp", "tcp"}

// Design 32 S5a: every create rule of a dns check, one case each, with the
// field each refusal names (R6).
func TestDNSCheckCreateValidation(t *testing.T) {
	_, handler, _ := checksFleet(t)
	c := newCheckClient(t, handler)
	dns := func(fields map[string]any) map[string]any {
		body := map[string]any{"name": "r", "type": "dns", "target": "udp://9.9.9.9", "dns_name": "example.com", "node_ids": []string{"node-new"}}
		for k, v := range fields {
			if v == nil {
				delete(body, k)
				continue
			}
			body[k] = v
		}
		return body
	}
	var many []string
	for i := 0; i < 17; i++ {
		many = append(many, "192.0.2."+itoa64(int64(i+1)))
	}
	refused := []struct {
		name  string
		body  map[string]any
		field string
		want  string
	}{
		{"a private resolver", dns(map[string]any{"target": "udp://10.0.0.53"}), "target", "private"},
		{"a loopback resolver", dns(map[string]any{"target": "tcp://127.0.0.1:5353"}), "target", "loopback"},
		{"the metadata service", dns(map[string]any{"target": "udp://169.254.169.254"}), "target", "metadata"},
		{"localhost over DoT", dns(map[string]any{"target": "tls://localhost"}), "target", "loopback"},
		{"a numeric host", dns(map[string]any{"target": "udp://2130706433"}), "target", "numeric"},
		{"an unknown scheme", dns(map[string]any{"target": "quic://dns.example"}), "target", "scheme"},
		{"a bare host", dns(map[string]any{"target": "9.9.9.9:53"}), "target", "resolver endpoint"},
		{"a DoH target without a path", dns(map[string]any{"target": "https://dns.example"}), "target", "names its path"},
		{"a DoH target with a query", dns(map[string]any{"target": "https://dns.example/dns-query?key=1"}), "target", "query"},
		{"no name", dns(map[string]any{"dns_name": nil}), "dns_name", "asks a name"},
		{"a name over 253 bytes", dns(map[string]any{"dns_name": strings.Repeat("a.", 127) + "a"}), "dns_name", "at most 253"},
		{"a name with a space", dns(map[string]any{"dns_name": "exa mple.com"}), "dns_name", "letters, digits"},
		{"an HTTPS question", dns(map[string]any{"dns_type": "HTTPS"}), "dns_type", "dns_type is one of"},
		{"seventeen expected values", dns(map[string]any{"dns_expect": many}), "dns_expect", "at most 16"},
		{"an expected value of another type", dns(map[string]any{"dns_expect": []string{"192.0.2.1", "2001:db8::1"}}), "dns_expect[1]", "IPv4"},
		{"an expected SERVFAIL", dns(map[string]any{"dns_expect_rcode": "SERVFAIL"}), "dns_expect_rcode", "NOERROR or NXDOMAIN"},
		{"NXDOMAIN with expected values", dns(map[string]any{"dns_expect_rcode": "NXDOMAIN", "dns_expect": []string{"192.0.2.1"}}), "dns_expect", "no expected values"},
		{"a node target", dns(map[string]any{"target": nil, "target_node": "node-tgt"}), "target_node", "resolver endpoint"},
		{"packets", dns(map[string]any{"packets": 3}), "packets", "icmp and beacon checks only"},
		{"a status set", dns(map[string]any{"expect_status": "200"}), "expect_status", "http checks only"},
		{"a dns name on a tcp check", map[string]any{"name": "t", "type": "tcp", "target": "example.com:443", "dns_name": "example.com", "node_ids": []string{"node-new"}}, "dns_name", "dns checks only"},
		{"an expected rcode on a tls check", map[string]any{"name": "c", "type": "tls", "target": "example.com:443", "dns_expect_rcode": "NXDOMAIN"}, "dns_expect_rcode", "dns checks only"},
	}
	for _, tc := range refused {
		code, raw := c.do(http.MethodPost, "/api/monitors", tc.body)
		if code != http.StatusBadRequest || !strings.Contains(raw, tc.want) || apiErrorOf(t, raw).Field != tc.field {
			t.Errorf("%s: %d %s; want 400 on %s containing %q", tc.name, code, raw, tc.field, tc.want)
		}
	}

	// A save stores the canonical forms an agent compares in.
	code, raw := c.do(http.MethodPost, "/api/monitors", dns(map[string]any{
		"target": "HTTPS://Dns.Example:443/dns-query", "dns_name": "WWW.Example.COM.", "dns_type": "aaaa",
		"dns_expect": []string{"2001:DB8::1", "2001:db8:0::1", "2001:db8::2"}, "dns_expect_rcode": "noerror",
	}))
	if code != http.StatusOK {
		t.Fatalf("create = %d %s", code, raw)
	}
	var mon model.Monitor
	if err := json.Unmarshal([]byte(raw), &mon); err != nil {
		t.Fatal(err)
	}
	if mon.Target != "https://dns.example/dns-query" || mon.DNSName != "www.example.com" || mon.DNSType != "AAAA" ||
		!slices.Equal(mon.DNSExpect, []string{"2001:db8::1", "2001:db8::2"}) || mon.DNSExpectRcode != "" || mon.Packets != 0 {
		t.Fatalf("stored = %+v", mon)
	}
	code, raw = c.do(http.MethodPost, "/api/monitors", dns(map[string]any{"dns_expect_rcode": "nxdomain"}))
	if code != http.StatusOK || !strings.Contains(raw, `"dns_type":"A"`) || !strings.Contains(raw, `"dns_expect_rcode":"NXDOMAIN"`) {
		t.Fatalf("an NXDOMAIN check = %d %s", code, raw)
	}
}

// An edit changes the question in place and keeps the canonical forms; the
// resolver is the check's target and cannot change, though another spelling
// of the same endpoint is the same target. Empty dns fields an editor
// echoes on another kind change nothing; set ones are refused.
func TestDNSCheckEdit(t *testing.T) {
	_, handler, st := checksFleet(t)
	c := newCheckClient(t, handler)
	code, raw := c.do(http.MethodPost, "/api/monitors", map[string]any{
		"name": "r", "type": "dns", "target": "udp://9.9.9.9", "dns_name": "example.com", "node_ids": []string{"node-new"},
	})
	if code != http.StatusOK {
		t.Fatalf("create = %d %s", code, raw)
	}
	var mon model.Monitor
	_ = json.Unmarshal([]byte(raw), &mon)
	typ, expect, target := "mx", []string{"MX1.Example.com."}, "udp://9.9.9.9:53"
	code, raw = c.do(http.MethodPost, "/api/monitors/update", model.MonitorUpdate{ID: mon.ID, Version: mon.Version, Target: &target, DNSType: &typ, DNSExpect: &expect})
	if code != http.StatusOK {
		t.Fatalf("edit = %d %s", code, raw)
	}
	stored, _ := st.Monitor(mon.ID)
	if stored.DNSType != "MX" || !slices.Equal(stored.DNSExpect, []string{"mx1.example.com"}) || stored.DNSName != "example.com" {
		t.Fatalf("after the edit = %+v", stored)
	}
	other := "udp://1.1.1.1"
	code, raw = c.do(http.MethodPost, "/api/monitors/update", model.MonitorUpdate{ID: mon.ID, Version: stored.Version, Target: &other})
	if code != http.StatusBadRequest || apiErrorOf(t, raw).Field != "target" {
		t.Fatalf("a new resolver = %d %s", code, raw)
	}
	rcode, cleared := "NXDOMAIN", []string{}
	code, raw = c.do(http.MethodPost, "/api/monitors/update", model.MonitorUpdate{ID: mon.ID, Version: stored.Version, DNSExpectRcode: &rcode})
	if code != http.StatusBadRequest || apiErrorOf(t, raw).Field != "dns_expect" {
		t.Fatalf("NXDOMAIN over stored expected values = %d %s", code, raw)
	}
	code, raw = c.do(http.MethodPost, "/api/monitors/update", model.MonitorUpdate{ID: mon.ID, Version: stored.Version, DNSExpectRcode: &rcode, DNSExpect: &cleared})
	if code != http.StatusOK {
		t.Fatalf("NXDOMAIN with the values cleared = %d %s", code, raw)
	}
	if stored, _ = st.Monitor(mon.ID); stored.DNSExpectRcode != "NXDOMAIN" || stored.DNSExpect != nil {
		t.Fatalf("after NXDOMAIN = %+v", stored)
	}

	code, raw = c.do(http.MethodPost, "/api/monitors", map[string]any{"name": "t", "type": "tcp", "target": "example.com:443", "node_ids": []string{"node-new"}})
	if code != http.StatusOK {
		t.Fatalf("tcp create = %d %s", code, raw)
	}
	var tcp model.Monitor
	_ = json.Unmarshal([]byte(raw), &tcp)
	empty, name := "", "example.com"
	if code, raw = c.do(http.MethodPost, "/api/monitors/update", model.MonitorUpdate{ID: tcp.ID, Version: tcp.Version, DNSName: &empty, DNSExpect: &cleared}); code != http.StatusOK {
		t.Fatalf("empty dns fields echoed on tcp = %d %s", code, raw)
	}
	tcp, _ = st.Monitor(tcp.ID)
	code, raw = c.do(http.MethodPost, "/api/monitors/update", model.MonitorUpdate{ID: tcp.ID, Version: tcp.Version, DNSName: &name})
	if code != http.StatusBadRequest || apiErrorOf(t, raw).Field != "dns_name" {
		t.Fatalf("a dns name on tcp = %d %s", code, raw)
	}
}

// A source is handed a dns check only when its agent reports dns; any
// other source reads agent_too_old, never down.
func TestDNSCheckGatedByProbeMethods(t *testing.T) {
	srv, _, st := checksFleet(t)
	upsertNodes(t, st, model.Node{ID: "node-dns", Name: "dns", PublicIP: "203.0.113.13", Online: true, ProbeMethods: dnsMethods})
	if err := st.UpsertMonitor(model.Monitor{ID: "mon-dns", Name: "r", Type: model.MonitorTypeDNS, Target: "udp://9.9.9.9", DNSName: "example.com", DNSType: "A",
		IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-dns", "node-new", "node-old"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for nodeID, want := range map[string][]string{"node-dns": {"mon-dns"}, "node-new": {}, "node-old": {}} {
		got := agentMonitorList(t, srv, st, nodeID)
		if !slices.Equal(monitorIDs(got), want) {
			t.Errorf("%s is handed %v, want %v", nodeID, monitorIDs(got), want)
		}
		if len(got) == 1 && (got[0].DNSName != "example.com" || got[0].DNSType != "A") {
			t.Errorf("the agent is handed %+v without its question", got[0])
		}
	}
	matrix, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"node-new", "node-old"} {
		if cell := pathCellFor(t, matrix, source, "mon-dns"); cell.Reason != model.PathReasonAgentTooOld {
			t.Errorf("%s dns path = %+v, want %s", source, cell, model.PathReasonAgentTooOld)
		}
	}
	if cell := pathCellFor(t, matrix, "node-dns", "mon-dns"); cell.Reason == model.PathReasonAgentTooOld {
		t.Errorf("a source that runs dns reads too old: %+v", cell)
	}
}

// A dns definition takes resolver endpoints as addresses: two addresses
// over two sources are two monitors and four paths, each monitor carrying
// the question in canonical form. An edit of the question alone rewrites
// every monitor (managedMonitorEqual compares every field), a source whose
// agent lacks dns reads agent_too_old, and the dry run equals the save.
func TestDNSDefinitionExpandsAddressesOverSources(t *testing.T) {
	srv, handler, st := checkFleet(t)
	for _, id := range []string{"node-sh", "node-jp"} {
		n, _ := st.Node(id)
		n.ProbeMethods = dnsMethods
		upsertNodes(t, st, n)
	}
	c := newCheckClient(t, handler)
	save := model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "resolvers", Type: model.MonitorTypeDNS, IntervalSec: 300, TimeoutSec: 3, Enabled: true,
		Sources:   model.TargetSelector{Nodes: []string{"node-sh", "node-jp"}},
		Addresses: []string{"HTTPS://dns.example.net/dns-query", "tls://9.9.9.9:853", "tls://9.9.9.9"},
		DNSName:   "Example.org.", DNSExpect: []string{"192.0.2.1"},
	}}
	pre := c.preview(save)
	view := c.create(save)
	if view.Summary.Monitors != 2 || view.Summary.Paths != 4 || !slices.Equal(view.Addresses, []string{"https://dns.example.net/dns-query", "tls://9.9.9.9"}) {
		t.Fatalf("definition = %+v", view)
	}
	if view.DNSName != "example.org" || view.DNSType != "A" || !slices.Equal(view.DNSExpect, []string{"192.0.2.1"}) {
		t.Fatalf("stored question = %+v", view.CheckDefinitionSpec)
	}
	if len(pre.Writes.Created) != 2 {
		t.Fatalf("dry run = %+v", pre.Writes)
	}
	mons := definitionMonitors(st, view.ID)
	for _, address := range view.Addresses {
		mon := monitorTo(t, mons, "", address)
		if mon.Type != model.MonitorTypeDNS || mon.DNSName != "example.org" || mon.DNSType != "A" || !slices.Equal(mon.DNSExpect, []string{"192.0.2.1"}) ||
			!slices.Equal(mon.NodeIDs, []string{"node-jp", "node-sh"}) || !mon.Enabled || mon.Packets != 0 {
			t.Fatalf("monitor to %s = %+v", address, mon)
		}
		// A create's dry run has no definition id yet; the target's hash,
		// the id's last part, is the same.
		hash := mon.ID[strings.LastIndexByte(mon.ID, '_')+1:]
		if !slices.ContainsFunc(pre.Writes.Created, func(id string) bool { return strings.HasSuffix(id, "_"+hash) }) {
			t.Fatalf("the dry run did not name %s: %+v", mon.ID, pre.Writes)
		}
	}

	edit := saveOf(view)
	edit.DNSExpect = []string{"192.0.2.1", "192.0.2.2"}
	edited := c.update(edit)
	for _, mon := range definitionMonitors(st, view.ID) {
		if !slices.Equal(mon.DNSExpect, []string{"192.0.2.1", "192.0.2.2"}) {
			t.Fatalf("an edit of dns_expect alone did not reach %s: %+v", mon.ID, mon)
		}
	}
	if !slices.Equal(monitorIDs(definitionMonitors(st, view.ID)), monitorIDs(mons)) {
		t.Fatal("an edit of the question changed the monitor ids")
	}

	edit = saveOf(edited)
	edit.Sources.Nodes = append(edit.Sources.Nodes, "node-us")
	c.update(edit)
	matrix, err := srv.pathMatrixFor(principal{Principal: adminPrincipalForTest()}, model.PathWindowHour, checkT0)
	if err != nil {
		t.Fatal(err)
	}
	for _, mon := range definitionMonitors(st, view.ID) {
		if cell := pathCellFor(t, matrix, "node-us", mon.ID); cell.Reason != model.PathReasonAgentTooOld {
			t.Fatalf("node-us without dns on %s = %+v", mon.ID, cell)
		}
	}
	if got := agentMonitorList(t, srv, st, "node-us"); len(got) != 0 {
		t.Fatalf("node-us is handed %v", monitorIDs(got))
	}
}

// A dns definition takes addresses only and the address rules of a single
// check; another method takes no dns field.
func TestDNSDefinitionValidation(t *testing.T) {
	_, handler, _ := checkFleet(t)
	c := newCheckClient(t, handler)
	base := func(edit func(*model.CheckDefinitionSpec)) model.CheckDefinitionSave {
		spec := model.CheckDefinitionSpec{Name: "r", Type: model.MonitorTypeDNS, Enabled: true, Sources: model.TargetSelector{Nodes: []string{"node-sh"}},
			Addresses: []string{"udp://9.9.9.9"}, DNSName: "example.com"}
		edit(&spec)
		return model.CheckDefinitionSave{CheckDefinitionSpec: spec}
	}
	for _, tc := range []struct {
		name, field, want string
		save              model.CheckDefinitionSave
	}{
		{"node targets", "targets", "takes addresses", base(func(s *model.CheckDefinitionSpec) { s.Targets = model.TargetSelector{Nodes: []string{"node-jp"}} })},
		{"a private resolver", "addresses[1]", "private", base(func(s *model.CheckDefinitionSpec) { s.Addresses = []string{"udp://9.9.9.9", "udp://192.168.1.1"} })},
		{"an unknown scheme", "addresses[0]", "scheme", base(func(s *model.CheckDefinitionSpec) { s.Addresses = []string{"dns://9.9.9.9"} })},
		{"no name", "dns_name", "asks a name", base(func(s *model.CheckDefinitionSpec) { s.DNSName = "" })},
		{"an expected NXDOMAIN with values", "dns_expect", "no expected values", base(func(s *model.CheckDefinitionSpec) {
			s.DNSExpectRcode, s.DNSExpect = "NXDOMAIN", []string{"192.0.2.1"}
		})},
		{"a dns type on a tcp definition", "dns_type", "dns checks only", model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
			Name: "t", Type: model.MonitorTypeTCP, Sources: model.TargetSelector{Nodes: []string{"node-sh"}}, Targets: model.TargetSelector{Nodes: []string{"node-jp"}}, DNSType: "A",
		}}},
	} {
		code, raw := c.do(http.MethodPost, "/api/monitors/definitions", tc.save)
		if code != http.StatusBadRequest || !strings.Contains(raw, tc.want) || apiErrorOf(t, raw).Field != tc.field {
			t.Errorf("%s: %d %s, want 400 on %s mentioning %q", tc.name, code, raw, tc.field, tc.want)
		}
	}
}

// A dns result keeps its response code and answers within the bounds, and a
// certificate expiry only when the resolver is DoH or DoT; another kind's
// result keeps neither. The latest view and the history carry them.
func TestDNSResultIngestionBounds(t *testing.T) {
	srv, _, st := checksFleet(t)
	upsertNodes(t, st, model.Node{ID: "node-dns", Name: "dns", PublicIP: "203.0.113.13", Online: true, ProbeMethods: dnsMethods})
	for _, mon := range []model.Monitor{
		{ID: "mon-doh", Name: "doh", Type: model.MonitorTypeDNS, Target: "https://dns.example/dns-query", DNSName: "example.com", DNSType: "TXT", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-dns"}, Enabled: true},
		{ID: "mon-udp", Name: "udp", Type: model.MonitorTypeDNS, Target: "udp://9.9.9.9", DNSName: "example.com", DNSType: "A", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-dns"}, Enabled: true},
		{ID: "mon-tcp", Name: "tcp", Type: model.MonitorTypeTCP, Target: "example.com:443", IntervalSec: 30, TimeoutSec: 5, NodeIDs: []string{"node-dns"}, Enabled: true},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	var answers []string
	for i := 0; i < 20; i++ {
		answers = append(answers, strings.Repeat("x", 300))
	}
	cert := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	at := time.Now().UTC().Add(-time.Minute)
	results := []model.MonitorResult{
		{MonitorID: "mon-doh", At: at, Success: false, LatencyMs: 12, Error: "dns_mismatch: lacks y", DNSRcode: "NOERROR", DNSAnswers: answers, CertNotAfter: cert},
		{MonitorID: "mon-udp", At: at, Success: false, LatencyMs: 9, Error: "dns_rcode: SERVFAIL", DNSRcode: "SERVFAIL", DNSAnswers: []string{"192.0.2.1"}, CertNotAfter: cert},
		{MonitorID: "mon-udp", At: at.Add(time.Second), Success: false, Error: "x", DNSRcode: "not a code!"},
		{MonitorID: "mon-udp", At: at.Add(2 * time.Second), Reason: model.PathReasonDestinationRefused, Error: "refused", DNSRcode: "NOERROR", DNSAnswers: []string{"192.0.2.1"}},
		{MonitorID: "mon-tcp", At: at, Success: true, LatencyMs: 3, DNSRcode: "NOERROR", DNSAnswers: []string{"192.0.2.1"}, CertNotAfter: cert},
	}
	outcomes, err := st.IngestAgentMonitorResults("node-dns", results, at.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range outcomes {
		if o.Dropped != "" {
			t.Fatalf("result %d dropped: %+v", i, o)
		}
	}
	doh := storedMonitorResults(t, st, "mon-doh")
	if len(doh) != 1 || doh[0].DNSRcode != "NOERROR" || len(doh[0].DNSAnswers) != model.MonitorDNSAnswersMax ||
		len(doh[0].DNSAnswers[0]) != model.MonitorDNSValueMax || !doh[0].CertNotAfter.Equal(cert) {
		t.Fatalf("DoH row = %+v", doh)
	}
	udp := storedMonitorResults(t, st, "mon-udp")
	byAt := map[time.Time]store.MonitorResultRecord{}
	for _, r := range udp {
		byAt[r.At] = r
	}
	if r := byAt[at]; r.DNSRcode != "SERVFAIL" || !slices.Equal(r.DNSAnswers, []string{"192.0.2.1"}) || !r.CertNotAfter.IsZero() {
		t.Fatalf("a UDP check keeps no certificate: %+v", r)
	}
	if r := byAt[at.Add(time.Second)]; r.DNSRcode != "" {
		t.Fatalf("a code of the wrong shape was kept: %+v", r)
	}
	if r := byAt[at.Add(2*time.Second)]; r.DNSRcode != "" || r.DNSAnswers != nil {
		t.Fatalf("an unknown run keeps an answer: %+v", r)
	}
	if tcp := storedMonitorResults(t, st, "mon-tcp"); len(tcp) != 1 || tcp[0].DNSRcode != "" || tcp[0].DNSAnswers != nil || !tcp[0].CertNotAfter.IsZero() {
		t.Fatalf("a tcp row kept dns fields: %+v", tcp)
	}

	latest, err := st.LatestMonitorResults()
	if err != nil {
		t.Fatal(err)
	}
	mon, _ := st.Monitor("mon-doh")
	views := monitorLatestViews(principal{Principal: adminPrincipalForTest()}, mon, latest["mon-doh"])
	raw, _ := json.Marshal(views)
	if len(views) != 1 || views[0].DNSRcode != "NOERROR" || len(views[0].DNSAnswers) != model.MonitorDNSAnswersMax || !strings.Contains(string(raw), `"dns_answers"`) {
		t.Fatalf("latest view = %s", raw)
	}
	_ = srv

	// A certificate on a run that measured nothing, or one no certificate
	// carries, is dropped before it can reach Expiring.
	later := []model.MonitorResult{
		{MonitorID: "mon-doh", At: at.Add(time.Second), Reason: model.PathReasonDestinationRefused, Error: "refused", CertNotAfter: cert},
		{MonitorID: "mon-doh", At: at.Add(2 * time.Second), Success: true, CertNotAfter: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)},
		{MonitorID: "mon-doh", At: at.Add(3 * time.Second), Success: true, CertNotAfter: at.AddDate(60, 0, 0)},
	}
	if _, err := st.IngestAgentMonitorResults("node-dns", later, at.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, r := range storedMonitorResults(t, st, "mon-doh") {
		if !r.At.Equal(at) && !r.CertNotAfter.IsZero() {
			t.Fatalf("an unknown run or an implausible expiry was kept: %+v", r)
		}
	}
}

// A DoH or DoT check feeds Expiring with the soonest of its sources' newest
// certificate readings; a plain dns check does not.
func TestExpiringListsADNSResolverCertificate(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	now := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	serverClock(t, srv).set(now)
	upsertNodes(t, st,
		model.Node{ID: "node-a", Name: "a", ProbeMethods: dnsMethods},
		model.Node{ID: "node-b", Name: "b", ProbeMethods: dnsMethods},
		model.Node{ID: "node-c", Name: "c", ProbeMethods: dnsMethods},
	)
	for _, mon := range []model.Monitor{
		{ID: "mon_dot", Name: "Resolver DoT", Type: model.MonitorTypeDNS, Target: "tls://dns.example.org", DNSName: "example.org", DNSType: "A", NodeIDs: []string{"node-a", "node-b", "node-c"}, IntervalSec: 300, TimeoutSec: 3, Enabled: true},
		{ID: "mon_udp", Name: "Resolver UDP", Type: model.MonitorTypeDNS, Target: "udp://9.9.9.9", DNSName: "example.org", DNSType: "A", NodeIDs: []string{"node-a"}, IntervalSec: 300, TimeoutSec: 3, Enabled: true},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	soon, later := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	ingest := func(node string, at time.Time, r model.MonitorResult) {
		r.At = at
		if _, err := st.IngestAgentMonitorResults(node, []model.MonitorResult{r}, at); err != nil {
			t.Fatal(err)
		}
	}
	// node-a renewed (its newest reading is later); node-b still sees the
	// old certificate, then fails before its handshake.
	ingest("node-a", now.Add(-3*time.Hour), model.MonitorResult{MonitorID: "mon_dot", Success: true, CertNotAfter: soon})
	ingest("node-a", now.Add(-2*time.Hour), model.MonitorResult{MonitorID: "mon_dot", Success: true, CertNotAfter: later})
	ingest("node-b", now.Add(-2*time.Hour), model.MonitorResult{MonitorID: "mon_dot", Success: true, CertNotAfter: soon})
	ingest("node-b", now.Add(-time.Hour), model.MonitorResult{MonitorID: "mon_dot", Error: "dns_transport: no answer before the check's timeout"})
	ingest("node-a", now.Add(-time.Hour), model.MonitorResult{MonitorID: "mon_udp", Success: true, CertNotAfter: soon})
	// node-c last read a certificate nine days before the others and has
	// failed since: its stale reading no longer holds the resolver.
	ingest("node-c", now.Add(-9*24*time.Hour), model.MonitorResult{MonitorID: "mon_dot", Success: true, CertNotAfter: now.Add(24 * time.Hour)})
	ingest("node-c", now.Add(-time.Hour), model.MonitorResult{MonitorID: "mon_dot", Error: "dns_transport: tls: handshake failure"})

	cookies, _ := loginSession(t, handler)
	req := httptest.NewRequest(http.MethodGet, "/api/expiring", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	out := getExpiring(t, handler, req)
	var found []expiringItem
	for _, item := range out.Items {
		if item.Kind == expiringKindTLS {
			found = append(found, item)
		}
	}
	if len(found) != 1 || found[0].ID != "mon_dot" || !found[0].DueAt.Equal(soon) || found[0].Subtitle != "tls://dns.example.org" || found[0].Href != "/monitoring/mon_dot" {
		t.Fatalf("certificate items = %+v", found)
	}

	// Once node-b is no longer a source, its reading no longer counts.
	mon, _ := st.Monitor("mon_dot")
	mon.NodeIDs = []string{"node-a", "node-c"}
	if err := st.UpsertMonitor(mon); err != nil {
		t.Fatal(err)
	}
	out = getExpiring(t, handler, req)
	for _, item := range out.Items {
		if item.ID == "mon_dot" && !item.DueAt.Equal(later) {
			t.Fatalf("after node-b left: %+v", item)
		}
	}
}
