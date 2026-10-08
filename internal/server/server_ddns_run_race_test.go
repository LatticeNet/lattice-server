package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/ddns/cffake"
)

// gatedProvider holds every SetRecord until release is closed, the way a
// provider that is slow to answer does, and reports each one on entered.
type gatedProvider struct {
	ddns.Provider
	entered chan<- struct{}
	release <-chan struct{}
}

func (p gatedProvider) SetRecord(ctx context.Context, r ddns.Record) error {
	p.entered <- struct{}{}
	<-p.release
	return p.Provider.SetRecord(ctx, r)
}

func gateDDNSProvider(srv *Server) (entered <-chan struct{}, release chan struct{}) {
	in := make(chan struct{}, 32)
	release = make(chan struct{})
	build := srv.ddnsProvider
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		prov, err := build(p)
		if err != nil {
			return nil, err
		}
		return gatedProvider{Provider: prov, entered: in, release: release}, nil
	}
	return in, release
}

func waitEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the run never reached the provider")
	}
}

// An edit saved while a run waits on Cloudflare survives the run. The run
// used to write back the whole profile it started from, so the new target
// and the new name were lost and Cloudflare kept the old target. The run's
// own outcome still lands, and the next check publishes the edit.
func TestDDNSCNAMERunKeepsAnEditSavedWhileItRan(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	clock := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return clock }
	_, _, raw := saveDDNS(t, handler, frontierCNAMEBody(`,"comment_mode":"none"`), cookies, csrf)
	made := decodeCNAMEView(t, raw)
	entered, release := gateDDNSProvider(srv)

	swept := make(chan int, 1)
	go func() { swept <- srv.sweepDDNSOnce() }()
	waitEntered(t, entered)
	const newTarget, secondHost = "nat-us-29tz.aproxy.top", "frontier2.nat.aaitr.roobli.org"
	edit := strings.Replace(frontierCNAMEBody(`,"comment_mode":"none","id":"`+made.ID+`"`), frontierTarget, newTarget, 1)
	edit = strings.Replace(edit, `"domains":["`+frontierHost+`"]`, `"domains":["`+frontierHost+`","`+secondHost+`"]`, 1)
	if code, _, raw := saveDDNS(t, handler, edit, cookies, csrf); code != http.StatusOK {
		t.Fatalf("edit during the run: %d %s", code, raw)
	}
	close(release)
	if n := <-swept; n != 1 {
		t.Fatalf("the sweep ran %d profiles, want 1", n)
	}

	got, _ := st.DDNSProfile(made.ID)
	if got.CNAMETarget != newTarget || len(got.Domains) != 2 {
		t.Fatalf("the run undid the edit: target %q domains %v", got.CNAMETarget, got.Domains)
	}
	if got.LastTarget != frontierTarget || got.LastError != "" || !got.LastRunAt.Equal(clock) {
		t.Fatalf("the run's own outcome: %+v", got)
	}

	clock = clock.Add(10 * time.Minute)
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("the check after the edit ran %d profiles, want 1", n)
	}
	for _, host := range []string{frontierHost, secondHost} {
		if recs := fake.Find(host, "CNAME"); len(recs) != 1 || recs[0].Content != newTarget {
			t.Fatalf("%s after the next check: %+v", host, recs)
		}
	}
}

// The same holds for an address profile republished by a heartbeat.
func TestDDNSAddressRunKeepsAnEditSavedWhileItRan(t *testing.T) {
	srv, handler, st, _ := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	const body = `{"name":"egress","node_id":"n1","provider":"cloudflare","cf_api_token":"t","enable_ipv4":true,"comment_mode":"none","domains":["egress.example.com"`
	_, _, raw := saveDDNS(t, handler, body+`]}`, cookies, csrf)
	made := decodeCNAMEView(t, raw)
	entered, release := gateDDNSProvider(srv)

	srv.maybeTriggerDDNS("n1", frontierEgress, "", "47.148.162.51", "")
	waitEntered(t, entered)
	if code, _, raw := saveDDNS(t, handler, body+`,"egress2.example.com"],"id":"`+made.ID+`"}`, cookies, csrf); code != http.StatusOK {
		t.Fatalf("edit during the run: %d %s", code, raw)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := st.DDNSProfile(made.ID)
		if got.LastIPv4 == "47.148.162.51" {
			if len(got.Domains) != 2 {
				t.Fatalf("the run undid the edit: domains %v", got.Domains)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the heartbeat run did not finish: %+v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// holdFirstPost holds the first record create until release is closed, after
// the run has already listed the name and found it empty.
type holdFirstPost struct {
	base    http.RoundTripper
	once    *sync.Once
	entered chan struct{}
	release chan struct{}
}

func (h holdFirstPost) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		held := false
		h.once.Do(func() { held = true })
		if held {
			close(h.entered)
			<-h.release
		}
	}
	return h.base.RoundTrip(req)
}

// "Run now" pressed while the sweep is creating the CNAME waits for it, then
// adopts what the sweep made. Run side by side, both found the name empty,
// both posted a create, and the one Cloudflare refused stored a conflict
// error about a record Lattice had just made itself.
func TestDDNSRunsOfOneProfileDoNotOverlap(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	_, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf)
	made := decodeCNAMEView(t, raw)
	hold := holdFirstPost{base: fake.Client().Transport, once: &sync.Once{}, entered: make(chan struct{}), release: make(chan struct{})}
	srv.ddnsProvider = func(p model.DDNSProfile) (ddns.Provider, error) {
		prov, err := ddns.NewProvider(p, &http.Client{Transport: hold})
		if cf, ok := prov.(*ddns.Cloudflare); ok {
			cf.BaseURL = fake.URL
		}
		return prov, err
	}

	swept := make(chan int, 1)
	go func() { swept <- srv.sweepDDNSOnce() }()
	select {
	case <-hold.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep never posted the create")
	}
	ran := make(chan int, 1)
	go func() {
		res := doJSON(t, handler, http.MethodPost, "/api/ddns/run", `{"id":"`+made.ID+`"}`, cookies, csrf)
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		ran <- res.StatusCode
	}()
	select {
	case code := <-ran:
		t.Fatalf("run now finished (%d) while the sweep's create was in flight", code)
	case <-time.After(300 * time.Millisecond):
	}
	close(hold.release)
	if n := <-swept; n != 1 {
		t.Fatalf("the sweep ran %d profiles, want 1", n)
	}
	if code := <-ran; code != http.StatusOK {
		t.Fatalf("run now after the sweep: %d", code)
	}

	posts := 0
	for _, w := range fake.Writes() {
		if w.Method == http.MethodPost {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("%d creates, want 1: %+v", posts, fake.Writes())
	}
	if recs := fake.Find(frontierHost, ""); len(recs) != 1 || recs[0].Type != "CNAME" || recs[0].Content != frontierTarget {
		t.Fatalf("records: %+v", recs)
	}
	if got, _ := st.DDNSProfile(made.ID); got.LastError != "" || got.LastTarget != frontierTarget {
		t.Fatalf("profile after both runs: %+v", got)
	}
}

// A CNAME does not publish its node's address, so the sweep and "Run now"
// run it when the node is gone.
func TestDDNSCNAMERunsWithoutItsNode(t *testing.T) {
	srv, handler, st, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	code, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("save: %d %s", code, raw)
	}
	made := decodeCNAMEView(t, raw)
	if _, ok := st.Node("n1"); ok {
		t.Fatal("the node exists")
	}
	if n := srv.sweepDDNSOnce(); n != 1 {
		t.Fatalf("the sweep ran %d profiles, want 1", n)
	}
	if recs := fake.Find(frontierHost, "CNAME"); len(recs) != 1 || recs[0].Content != frontierTarget {
		t.Fatalf("records after the sweep: %+v", recs)
	}
	if code := runNow(t, handler, cookies, csrf, made.ID); code != http.StatusOK {
		t.Fatalf("run now without the node: %d", code)
	}
}

// A resolver that hangs on the CNAME target uses up only its own budget: the
// record reads after it still run, and the conflict they find is reported.
func TestDDNSSaveWarningsGiveTheLookupItsOwnBudget(t *testing.T) {
	srv, handler, _, fake := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	fake.Seed(cffake.Record{Type: "A", Name: frontierHost, Content: "1.2.3.4", TTL: 60})
	srv.ddnsLookupTimeout = 50 * time.Millisecond
	srv.ddnsLookupHost = func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	code, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf)
	if code != http.StatusOK {
		t.Fatalf("save: %d %s", code, raw)
	}
	warnings := decodeCNAMEView(t, raw).Warnings
	if len(warnings) != 2 || !strings.Contains(warnings[0], "does not resolve from the control plane") ||
		!strings.HasPrefix(warnings[1], frontierHost+" already has an A record (1.2.3.4)") {
		t.Fatalf("warnings: %q", warnings)
	}
}

// A CNAME profile may not chain into another one, in either save order, and
// may not share a name with a DNS deployment's hostname, in either save
// order. A CNAME to an address profile's name is fine.
func TestDDNSCNAMESaveRefusesChainsAndDeploymentHostnames(t *testing.T) {
	srv, handler, st, _ := newDDNSServerWithCloudflare(t)
	cookies, csrf := loginSession(t, handler)
	seedFrontierNode(t, srv)
	if code, _, raw := saveDDNS(t, handler, frontierCNAMEBody(""), cookies, csrf); code != http.StatusOK {
		t.Fatalf("save frontier: %d %s", code, raw)
	}
	cname := func(name, domain, target string) string {
		return `{"name":"` + name + `","node_id":"n1","provider":"cloudflare","domains":["` + domain + `"],"cf_api_token":"t","record_type":"cname","cname_target":"` + target + `"}`
	}
	refusals := map[string]string{
		"target is frontier's name":    cname("chain", "b.roobli.org", frontierHost),
		"name is frontier's target":    cname("chain", frontierTarget, "nat-b.aproxy.top"),
		"target under frontier's name": cname("chain", "b.roobli.org", "edge."+frontierHost),
	}
	for label, body := range refusals {
		code, _, raw := saveDDNS(t, handler, body, cookies, csrf)
		if code != http.StatusBadRequest || !strings.Contains(raw, `CNAME profile \"frontier\"`) {
			t.Fatalf("%s: got %d %s, want 400 naming the frontier profile", label, code, raw)
		}
	}
	if code, _, raw := saveDDNS(t, handler, `{"name":"node","node_id":"n1","provider":"cloudflare","domains":["node.example.com"],"cf_api_token":"t","enable_ipv4":true}`, cookies, csrf); code != http.StatusOK {
		t.Fatalf("save address profile: %d %s", code, raw)
	}
	if code, _, raw := saveDDNS(t, handler, cname("www", "www.example.com", "node.example.com"), cookies, csrf); code != http.StatusOK {
		t.Fatalf("a CNAME to an address profile's name: %d %s", code, raw)
	}

	deployment := func(hostname string) (int, string) {
		res := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{
			"name":"private dns","node_id":"n1","hostname":"`+hostname+`","cf_api_token":"t",
			"publish_ipv4":true,"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]
		}`, cookies, csrf)
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(raw)
	}
	if code, raw := deployment(strings.ToUpper(frontierHost)); code != http.StatusBadRequest || !strings.Contains(raw, `is a CNAME the DDNS profile \"frontier\" publishes`) {
		t.Fatalf("deployment on the CNAME's name: %d %s", code, raw)
	}
	if code, raw := deployment("ns.roobli.org"); code != http.StatusOK {
		t.Fatalf("deployment on a free name: %d %s", code, raw)
	}
	code, _, raw := saveDDNS(t, handler, cname("ns", "ns.roobli.org.", "nat-c.aproxy.top"), cookies, csrf)
	if code != http.StatusBadRequest || !strings.Contains(raw, `the DNS deployment \"private dns\" publishes`) {
		t.Fatalf("CNAME on a deployment's hostname: %d %s", code, raw)
	}
	for _, p := range st.DDNSProfiles() {
		if p.Name == "chain" || p.Name == "ns" {
			t.Fatalf("a refused profile was stored: %+v", p)
		}
	}
}
