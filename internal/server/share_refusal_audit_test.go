package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func shareDenyEvents(st *store.Store) []model.AuditEvent {
	var out []model.AuditEvent
	for _, ev := range st.AuditEvents() {
		if ev.Action == auditActionShareFetch && ev.Decision == "deny" {
			out = append(out, ev)
		}
	}
	return out
}

// refusalServer is a share server on a frozen clock with one real share, so
// the flood below mixes refusals before and after a token resolves.
func refusalServer(t *testing.T) (*Server, *store.Store, *time.Time) {
	t.Helper()
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "share_team", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "nobody"},
	})
	return s, st, &now
}

// floodShapes are the refusals an unauthenticated caller can send without a
// valid token. The share limiter (burst 20) turns most of a flood from one
// source into "rate limited" refusals, which are covered by the same throttle.
var floodShapes = []struct{ method, path string }{
	{http.MethodGet, "/sub/team/" + strings.Repeat("z", 32)},
	{http.MethodGet, "/sub/team/" + strings.Repeat("z", 32) + "?format=xml"},
	{http.MethodGet, "/sub/x/y/z"},
	{http.MethodPost, "/sub/team/" + strings.Repeat("z", 32)},
	{http.MethodGet, "/sub/" + strings.Repeat("z", 32)},
}

func TestShareRefusalFloodFromOneSourceWritesOneEventAndASummary(t *testing.T) {
	s, st, now := refusalServer(t)
	handler := s.Handler()
	const before = 0 // a fresh server has no refusals on record

	var reference *responseFingerprint
	const flood = 1000
	for i := 0; i < flood; i++ {
		shape := floodShapes[i%len(floodShapes)]
		req := httptest.NewRequest(shape.method, shape.path, nil)
		req.RemoteAddr = "203.0.113.7:5000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		got := fingerprint(rec)
		if reference == nil {
			reference = &got
		} else if got != *reference {
			t.Fatalf("request %d (%s %s) answered differently from the first refusal:\n got: %+v\nwant: %+v", i, shape.method, shape.path, got, *reference)
		}
	}
	if reference.Status != http.StatusNotFound || reference.Body != "" {
		t.Fatalf("the refusal is not the decoy 404: %+v", *reference)
	}
	s.shareRefusalAudits.Wait()

	events := shareDenyEvents(st)
	if len(events) != 1 {
		t.Fatalf("a flood of %d refusals from one source wrote %d audit events, want 1", flood, len(events))
	}
	if events[0].Metadata["source_ip"] != "203.0.113.7" {
		t.Fatalf("the recorded refusal lost its source: %+v", events[0].Metadata)
	}

	// Nothing more is written while the window is open, and the flush after
	// it closes reports what was folded in one record.
	s.flushShareRefusalAudit(*now)
	if got := len(shareDenyEvents(st)) - before; got != 1 {
		t.Fatalf("a flush inside the window wrote a summary: %d events", got)
	}
	*now = now.Add(shareRefusalAuditWindow)
	s.flushShareRefusalAudit(*now)
	all := shareDenyEvents(st)
	var summary *model.AuditEvent
	for i := range all {
		if all[i].Reason == shareRefusalSummaryReason {
			summary = &all[i]
		}
	}
	if summary == nil {
		t.Fatalf("no summary after the window closed: %+v", all)
	}
	if summary.Metadata["suppressed_repeats"] != fmt.Sprint(flood-1) || summary.Metadata["sources"] != "1" {
		t.Fatalf("summary does not count the folded refusals: %+v", summary.Metadata)
	}
	s.flushShareRefusalAudit(now.Add(time.Hour))
	if got := len(shareDenyEvents(st)) - before; got != 2 {
		t.Fatalf("a flush with nothing to report wrote an event: %d events", got)
	}
}

func TestShareRefusalFloodFromRotatingSourcesIsCapped(t *testing.T) {
	s, st, now := refusalServer(t)
	handler := s.Handler()
	before := len(shareDenyEvents(st))

	const flood = 1000
	for i := 0; i < flood; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sub/team/"+strings.Repeat("z", 32), nil)
		req.RemoteAddr = fmt.Sprintf("198.51.%d.%d:5000", i/250, i%250+1)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	s.shareRefusalAudits.Wait()
	written := len(shareDenyEvents(st)) - before
	if written > shareRefusalAuditBurst {
		t.Fatalf("%d rotating sources wrote %d audit events, want at most the global burst %d", flood, written, shareRefusalAuditBurst)
	}
	*now = now.Add(shareRefusalAuditWindow)
	s.flushShareRefusalAudit(*now)
	var dropped string
	for _, ev := range shareDenyEvents(st) {
		if ev.Reason == shareRefusalSummaryReason {
			dropped = ev.Metadata["global_suppressed"]
		}
	}
	if dropped != fmt.Sprint(flood-written) {
		t.Fatalf("summary global_suppressed = %q, want %d", dropped, flood-written)
	}

	// Hopping inside one IPv6 /64 is one source.
	before = len(shareDenyEvents(st))
	*now = now.Add(time.Hour)
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sub/team/"+strings.Repeat("z", 32), nil)
		req.RemoteAddr = fmt.Sprintf("[2001:db8:1:2::%x]:5000", i+1)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	s.shareRefusalAudits.Wait()
	if got := len(shareDenyEvents(st)) - before; got != 1 {
		t.Fatalf("200 addresses in one /64 wrote %d events, want 1", got)
	}
}

// The decoy is on the wire before the audit write starts, so a slow store
// never slows a refusal. The hook stands in for an audit append stuck on fsync.
func TestShareRefusalAnswersBeforeTheAuditWrite(t *testing.T) {
	s, st, _ := refusalServer(t)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	s.shareRefusalAuditHook = func() {
		entered <- struct{}{}
		<-release
	}
	before := len(shareDenyEvents(st))

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, httptest.NewRequest(http.MethodGet, "/sub/team/"+strings.Repeat("z", 32), nil))
		done <- rec
	}()
	select {
	case rec := <-done:
		if rec.Code != http.StatusNotFound {
			t.Fatalf("refusal status = %d", rec.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the refusal waited on its audit write")
	}
	<-entered
	if got := len(shareDenyEvents(st)) - before; got != 0 {
		t.Fatalf("the audit was written before the hook released it: %d", got)
	}
	close(release)
	s.shareRefusalAudits.Wait()
	if got := len(shareDenyEvents(st)) - before; got != 1 {
		t.Fatalf("the refusal was never audited: %d events", got)
	}
}

// A prober on the same network as a real client cannot fold the client's
// share failure out of the log: a refusal after a valid token is keyed by the
// share too.
func TestShareRefusalAfterAValidTokenIsNotFoldedBehindProbes(t *testing.T) {
	s, st, _ := refusalServer(t)
	probe := httptest.NewRequest(http.MethodGet, "/sub/team/"+strings.Repeat("z", 32), nil)
	probe.RemoteAddr = "203.0.113.7:5000"
	s.handleSubscriptionShare(httptest.NewRecorder(), probe)
	real := httptest.NewRequest(http.MethodGet, "/sub/team/"+strings.Repeat("a", 32), nil)
	real.RemoteAddr = "203.0.113.7:5001"
	s.handleSubscriptionShare(httptest.NewRecorder(), real)
	s.shareRefusalAudits.Wait()

	events := shareDenyEvents(st)
	if len(events) != 2 {
		t.Fatalf("want the probe and the share failure as two events, got %d: %+v", len(events), events)
	}
	var shareFailure bool
	for _, ev := range events {
		if ev.Metadata["share_id"] == "share_team" {
			shareFailure = true
		}
	}
	if !shareFailure {
		t.Fatalf("the share's own refusal was folded: %+v", events)
	}
}

func TestAuditFailureThrottleFlush(t *testing.T) {
	th := newAuditFailureThrottle(time.Minute, 2, 0)
	t0 := time.Unix(1_700_000_000, 0)
	for i := 0; i < 5; i++ {
		th.Allow("a", t0)
	}
	th.Allow("b", t0)
	th.Allow("c", t0) // global bucket empty: dropped
	if sources, suppressed, dropped := th.Flush(t0.Add(30 * time.Second)); sources != 0 || suppressed != 0 || dropped != 1 {
		t.Fatalf("flush inside the window = (%d, %d, %d), want (0, 0, 1)", sources, suppressed, dropped)
	}
	if sources, suppressed, dropped := th.Flush(t0.Add(time.Minute)); sources != 1 || suppressed != 4 || dropped != 0 {
		t.Fatalf("flush after the window = (%d, %d, %d), want (1, 4, 0)", sources, suppressed, dropped)
	}
	if len(th.entries) != 0 {
		t.Fatalf("closed keys were kept: %d", len(th.entries))
	}
	// A flushed count is not reported twice.
	th.globalTokens = 2
	if emit, suppressed, _ := th.Allow("a", t0.Add(2*time.Minute)); !emit || suppressed != 0 {
		t.Fatalf("after a flush, Allow = (%v, %d), want (true, 0)", emit, suppressed)
	}
}
