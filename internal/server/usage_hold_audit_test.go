package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// A held report has to reach the audit surface, and putting inbound_deferred
// into auditMeta is not enough on its own to get it there.
//
// shouldAuditProxyUsage writes an event only when proxyUsageAuditFingerprint
// changes or six hours pass. Before inbound_deferred joined that fingerprint,
// a node whose topology went cold with nothing else about it changing could
// hold for the whole 15-minute bound and store no event carrying the key: the
// metadata was correct and unreachable. This drives the real HTTP handler with
// a real agent token and asserts on what the store actually kept, because the
// response body carrying the flag was never the thing in question.
func TestHeldUsageReportReachesTheAuditSurface(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	// Deliberately no createProxyPlanFixtures: it persists a line for the node,
	// which survives clearing the discovery mirror, so the node never goes cold
	// and the hold never triggers. The first report auto-registers the profile.

	report := func(uptime int, bytes int) *proxyUsageApplyResult {
		t.Helper()
		body := `{"node_id":"node-a","snapshot":{"core_uptime_sec":` + strconv.Itoa(uptime) +
			`,"user_bytes":{},"inbound_traffic":{"direct-a":{"uplink":` + strconv.Itoa(bytes) + `,"downlink":0}}}}`
		res := doAgentRaw(t, handler, http.MethodPost, "/api/agent/proxy-usage", body, nodeToken)
		if res.Code != http.StatusOK {
			t.Fatalf("usage report failed: %d %s", res.Code, res.Body.String())
		}
		var out proxyUsageApplyResult
		if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode usage response: %v", err)
		}
		return &out
	}

	// Warm the discovery mirror so direct-a is a known line. Without this the
	// tag has never resolved and the report is a genuine unknown tag rather
	// than a cold one, which is a different case and not what this asserts.
	warm := func() {
		srv.singboxInvMu.Lock()
		srv.singboxInv = map[string]model.SingBoxInventory{"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok",
			Nodes: []model.SingBoxNode{{Name: "direct-a", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "80", OutboundRef: "direct"}}}}
		srv.singboxInvMu.Unlock()
		srv.invalidateLineReadModel()
	}
	warm()
	if len(srv.usageAttributionContext().byNodeTag["node-a"]) == 0 {
		t.Fatal("node-a has no lines after warming; the fixture is wrong, not the code")
	}

	// Three reports, not two, and the middle one is the point. The first
	// auto-registers the profile, which moves profile_registered in the
	// fingerprint, so an event fires on the second for a reason that has
	// nothing to do with a hold. A two-report version of this test passes with
	// or without the fix and proves nothing. The second report lets the
	// fingerprint settle, so the only thing that can differ on the third is the
	// hold itself.
	report(100, 100)
	report(150, 200)
	before := countUsageAudits(t, st)

	// Go cold the way eviction leaves it: the node exists and has no lines.
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{}
	srv.singboxInvMu.Unlock()
	srv.invalidateLineReadModel()

	if n := len(srv.usageAttributionContext().byNodeTag["node-a"]); n != 0 {
		t.Fatalf("node-a still has %d lines after going cold; the mirror is not the only source", n)
	}
	held := report(200, 900)
	if !held.InboundDeferred {
		t.Fatalf("report was recorded rather than held, so this test is not exercising a hold: %+v", held)
	}

	after := countUsageAudits(t, st)
	if after <= before {
		t.Fatalf("the hold stored no new proxy.usage.report event (%d then %d): the flag is in the metadata "+
			"but the gate never fires, so an operator asking why a number stopped moving sees nothing", before, after)
	}
	if !auditMetadataSeen(st, "proxy.usage.report", "inbound_deferred", "true") {
		t.Fatal("an event was stored for the held report but carries no inbound_deferred key")
	}

	// And the gate still does its job. The reason byte counts are excluded from
	// the fingerprint is that one event per report is 285,000 a day; a hold can
	// last the whole bound, so if this key produced an event per report it
	// would reopen exactly that. It is a boolean stable across an episode, so a
	// second consecutive hold must add nothing.
	held2 := report(300, 1500)
	if !held2.InboundDeferred {
		t.Fatalf("the second report was not held, so this assertion is not testing a continuing episode: %+v", held2)
	}
	if got := countUsageAudits(t, st); got != after {
		t.Fatalf("a continuing hold stored another event (%d then %d): one per report is the storm the gate exists to prevent", after, got)
	}
}

func countUsageAudits(t *testing.T, st *store.Store) int {
	t.Helper()
	n := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == "proxy.usage.report" {
			n++
		}
	}
	return n
}
