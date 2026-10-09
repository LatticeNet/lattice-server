package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func responseShareServer(t *testing.T, body string, userinfo *string) (*Server, *store.Store, string, *time.Time) {
	t.Helper()
	s, st := newShareTestServer(t)
	now := time.Date(2026, 10, 2, 10, 15, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	token := strings.Repeat("r", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "s1", Slug: "team", Token: token, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "rec"}})
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "rec", Raw: "nodes", FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: "nodes"}, nil
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte(body), Userinfo: *userinfo, RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	return s, st, "/sub/team/" + token, &now
}

func TestShareResponseCarriesLengthAndAValidatorAndAnswers304(t *testing.T) {
	userinfo := "upload=1; download=2; total=3"
	s, _, path, _ := responseShareServer(t, "vless://a\nvless://b\n", &userinfo)
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
	etag := rec.Header().Get("ETag")
	if rec.Code != http.StatusOK || etag == "" || rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
		t.Fatalf("first response %d etag %q length %q body %d", rec.Code, etag, rec.Header().Get("Content-Length"), rec.Body.Len())
	}

	req := shareRequest(path, "curl/8")
	req.Header.Set("If-None-Match", `"something-else", `+etag)
	rec = httptest.NewRecorder()
	s.handleSubscriptionShare(rec, req)
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 || rec.Header().Get("ETag") != etag {
		t.Fatalf("conditional response %d body %q etag %q", rec.Code, rec.Body.String(), rec.Header().Get("ETag"))
	}
	if rec.Header().Get("Subscription-Userinfo") != userinfo {
		t.Fatalf("a 304 dropped the quota header: %q", rec.Header().Get("Subscription-Userinfo"))
	}

	// Only the quota moved: a client that updates its quota display on a 200
	// must get one, so the validator changes with the header it carries.
	userinfo = "upload=5; download=6; total=7"
	s.subscriptionCache.InvalidateShare("s1")
	req = shareRequest(path, "curl/8")
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	s.handleSubscriptionShare(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == etag {
		t.Fatalf("quota change answered %d with etag %q (was %q)", rec.Code, rec.Header().Get("ETag"), etag)
	}
}

func TestShareValidatorCoversTheDescribingHeaders(t *testing.T) {
	userinfo := "upload=1; download=2; total=3"
	s, _, path, _ := responseShareServer(t, "vless://a\nvless://b\n", &userinfo)
	plan := "Team"
	render := s.subscriptionRender
	s.subscriptionRender = func(ctx context.Context, share model.SubscriptionShare, ua, format string, variant shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		out, err := render(ctx, share, ua, format, variant, snap)
		out.Headers = map[string]string{model.ResponseHeaderPlanName: plan}
		return out, err
	}
	fetch := func(ifNoneMatch string) *httptest.ResponseRecorder {
		req := shareRequest(path, "curl/8")
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, req)
		return rec
	}
	first := fetch("")
	etag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || etag == "" || first.Header().Get("Plan-Name") != plan {
		t.Fatalf("first response %d etag %q plan %q", first.Code, etag, first.Header().Get("Plan-Name"))
	}
	if again := fetch(etag); again.Code != http.StatusNotModified || again.Header().Get("ETag") != etag {
		t.Fatalf("unchanged headers answered %d with etag %q (was %q)", again.Code, again.Header().Get("ETag"), etag)
	}

	// Only the plan name moved: the body and the quota are the same, and the
	// client must still get a 200 with the new header.
	plan = "Team Pro"
	s.subscriptionCache.InvalidateShare("s1")
	moved := fetch(etag)
	if moved.Code != http.StatusOK || moved.Header().Get("ETag") == etag || moved.Header().Get("Plan-Name") != plan {
		t.Fatalf("a header-only change answered %d with etag %q (was %q) and plan %q",
			moved.Code, moved.Header().Get("ETag"), etag, moved.Header().Get("Plan-Name"))
	}
	if moved.Body.String() != first.Body.String() {
		t.Fatalf("the body changed: %q, was %q", moved.Body.String(), first.Body.String())
	}
}

func TestShareETagCoversEachDescribingHeader(t *testing.T) {
	hash := sha256.Sum256([]byte("body"))
	base := http.Header{}
	for _, name := range shareDescribingHeaders {
		base.Set(name, "a")
	}
	want := shareETag(hash, "", base, false)
	for _, name := range shareDescribingHeaders {
		moved := base.Clone()
		moved.Set(name, "b")
		if shareETag(hash, "", moved, false) == want {
			t.Fatalf("the validator ignores %s", name)
		}
	}
	other := base.Clone()
	other.Set("X-Request-Id", "unrelated")
	if shareETag(hash, "", other, false) != want {
		t.Fatal("the validator moved with a header that does not describe the document")
	}
}

func TestShareResponseIsGzippedForClientsThatAcceptIt(t *testing.T) {
	userinfo := ""
	doc := strings.Repeat("proxies:\n  - {name: node, type: vless, server: example.com}\n", 200)
	s, _, path, _ := responseShareServer(t, doc, &userinfo)

	req := shareRequest(path, "clash-verge/v2")
	req.Header.Set("Accept-Encoding", "br;q=1, gzip;q=0.8")
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("gzip response %d encoding %q vary %q", rec.Code, rec.Header().Get("Content-Encoding"), rec.Header().Get("Vary"))
	}
	if rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) || rec.Body.Len() >= len(doc) {
		t.Fatalf("gzip length header %q body %d of %d", rec.Header().Get("Content-Length"), rec.Body.Len(), len(doc))
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil || string(plain) != doc {
		t.Fatalf("gzip body did not inflate to the document: err %v, %d bytes", err, len(plain))
	}
	gzTag := rec.Header().Get("ETag")

	for _, refused := range []string{"", "gzip;q=0", "identity"} {
		req = shareRequest(path, "clash-verge/v2")
		if refused != "" {
			req.Header.Set("Accept-Encoding", refused)
		}
		rec = httptest.NewRecorder()
		s.handleSubscriptionShare(rec, req)
		if rec.Header().Get("Content-Encoding") != "" || rec.Body.String() != doc || rec.Header().Get("ETag") == gzTag {
			t.Fatalf("Accept-Encoding %q got encoding %q and etag %q", refused, rec.Header().Get("Content-Encoding"), rec.Header().Get("ETag"))
		}
	}
}

// The client holds its whole document before any audit write starts. The
// first fetch from a new family is audited, but only after the handler has
// returned with the complete body.
func TestShareAnswersBeforeAnyAuditWrite(t *testing.T) {
	userinfo := ""
	s, st, path, _ := responseShareServer(t, "vless://a\n", &userinfo)
	release := make(chan struct{})
	s.shareFetchAuditHook = func() { <-release }
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, shareRequest(path, "Surge/5"))
		done <- rec
	}()
	select {
	case rec := <-done:
		if rec.Code != http.StatusOK || rec.Body.String() != "vless://a\n" {
			t.Fatalf("answer %d %q", rec.Code, rec.Body.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the handler waited on the audit write")
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action == auditActionShareFetch {
			t.Fatalf("an audit event was written before the hook released: %+v", ev)
		}
	}
	close(release)
	s.shareFetchAudits.Wait()
	found := false
	for _, ev := range st.AuditEvents() {
		if ev.Action == auditActionShareFetch && ev.Reason == shareFetchFirstSeenReason && ev.Metadata["ua_class"] == "surge" && ev.Metadata["source_ip"] != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("the first fetch from the surge family was not audited")
	}
}

// Successful fetches are counted per link per hour and written as one
// summary when the hour closes, instead of one durable event per fetch.
func TestShareFetchesAreSummarizedPerHour(t *testing.T) {
	userinfo := ""
	s, st, path, now := responseShareServer(t, "vless://a\n", &userinfo)
	fetch := func(ua string, extra ...string) {
		req := shareRequest(path, ua)
		if len(extra) > 0 {
			req.Header.Set("If-None-Match", extra[0])
		}
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, req)
		if rec.Code != http.StatusOK && rec.Code != http.StatusNotModified {
			t.Fatalf("fetch answered %d", rec.Code)
		}
	}
	fetch("Surge/5")
	fetch("Surge/5")
	fetch("clash-verge/v2")
	fetch("Surge/5", "*")
	s.shareFetchAudits.Wait()
	countEvents := func(reason string) []model.AuditEvent {
		var out []model.AuditEvent
		for _, ev := range st.AuditEvents() {
			if ev.Action == auditActionShareFetch && ev.Reason == reason {
				out = append(out, ev)
			}
		}
		return out
	}
	if got := len(countEvents(shareFetchFirstSeenReason)); got != 2 {
		t.Fatalf("first-seen events = %d, want one per family (surge, clashmeta)", got)
	}
	if got := len(countEvents(shareFetchSummaryReason)); got != 0 {
		t.Fatalf("a summary was written before the hour closed")
	}

	// The fetch that opens the next hour queues the closed one; the flush
	// writes it, never the request path.
	*now = now.Add(time.Hour)
	fetch("Surge/5")
	s.shareFetchAudits.Wait()
	if got := len(countEvents(shareFetchSummaryReason)); got != 0 {
		t.Fatalf("a closed hour was written on the request path")
	}
	s.flushShareFetchStats(*now, false)
	summaries := countEvents(shareFetchSummaryReason)
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d after the hour closed", len(summaries))
	}
	md := summaries[0].Metadata
	wantEntry := "slug=team fetches=4 cache_hits=2 not_modified=1 stale_served=0 families=clashmeta=1,surge=3" +
		" last_fetch_at=2026-10-02T10:15:00Z token_sha256_prefix=" + proxySubTokenAuditHash(strings.Repeat("r", 32))[:16]
	if md["links"] != "1" || md["fetches"] != "4" || md["hour_start"] != "2026-10-02T10:00:00Z" || md["partial"] != "" ||
		md["part"] != "" || md["share.s1"] != wantEntry {
		t.Fatalf("summary = %+v", md)
	}

	// An hour nobody fetched in again is closed by the periodic flush, and a
	// shutdown writes the open hour as partial.
	*now = now.Add(time.Hour)
	s.flushShareFetchStats(*now, false)
	fetch("Surge/5")
	s.flushShareFetchStats(*now, true)
	summaries = countEvents(shareFetchSummaryReason)
	if len(summaries) != 3 {
		t.Fatalf("summaries = %d, want the flushed hour and the partial one", len(summaries))
	}
	partial := 0
	for _, ev := range summaries {
		if ev.Metadata["partial"] == "true" {
			partial++
		}
	}
	if partial != 1 {
		t.Fatalf("partial summaries = %d", partial)
	}
}

// A thousand active links used to cost a thousand audit appends back to back
// at every hour boundary. Closed hours are packed, at most
// shareFetchSummaryLinksPerEvent links of one hour per event.
func TestHourlyFetchSummariesArePackedPerHour(t *testing.T) {
	ten := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	var hours []*shareFetchHour
	for i := 0; i < 2*shareFetchSummaryLinksPerEvent+5; i++ {
		hours = append(hours, &shareFetchHour{shareID: "s" + strconv.Itoa(1000+i), slug: "team", start: ten, last: ten.Add(time.Minute),
			fetches: 2, hits: 1, families: map[string]int{"surge": 2}})
	}
	hours = append(hours, &shareFetchHour{shareID: "s0", slug: "late", start: ten.Add(time.Hour), last: ten.Add(time.Hour), fetches: 1, families: map[string]int{"other": 1}})
	events := shareFetchSummaryEvents(hours, false)
	if len(events) != 4 {
		t.Fatalf("events = %d, want three for the first hour and one for the next", len(events))
	}
	links, fetches := 0, 0
	for i, ev := range events[:3] {
		md := ev.Metadata
		if md["hour_start"] != "2026-10-02T10:00:00Z" || md["part"] != strconv.Itoa(i+1)+"/3" {
			t.Fatalf("event %d = hour %q part %q", i, md["hour_start"], md["part"])
		}
		n, _ := strconv.Atoi(md["links"])
		f, _ := strconv.Atoi(md["fetches"])
		entries := 0
		for key := range md {
			if strings.HasPrefix(key, shareFetchSummaryKeyPrefix) {
				entries++
			}
		}
		if n > shareFetchSummaryLinksPerEvent || entries != n || f != 2*n {
			t.Fatalf("event %d carries links=%d entries=%d fetches=%d", i, n, entries, f)
		}
		links += n
		fetches += f
	}
	if links != 2*shareFetchSummaryLinksPerEvent+5 || fetches != 2*links {
		t.Fatalf("packed links = %d, fetches = %d", links, fetches)
	}
	last := events[3].Metadata
	if last["hour_start"] != "2026-10-02T11:00:00Z" || last["links"] != "1" || last["part"] != "" || !strings.HasPrefix(last["share.s0"], "slug=late ") {
		t.Fatalf("the next hour's event = %+v", last)
	}
}

// The minute flushers of the link audits used to run until the process
// exited, so one could write after Close's final flush and after the store
// closed, and each test server leaked two goroutines. Close now stops them
// before it writes the last summaries, and a second Close is harmless.
func TestCloseStopsTheLinkAuditFlushersBeforeTheFinalFlush(t *testing.T) {
	userinfo := ""
	s, st, path, _ := responseShareServer(t, "vless://a\n", &userinfo)
	s.startShareFetchStatsFlush()
	s.startShareRefusalAuditFlush()
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest(path, "Surge/5"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		s.shareFlushers.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the link audit flushers were still running after Close")
	}
	partial := 0
	for _, ev := range st.AuditEvents() {
		if ev.Reason == shareFetchSummaryReason && ev.Metadata["partial"] == "true" {
			partial++
		}
	}
	if partial != 1 {
		t.Fatalf("partial summaries written by Close = %d", partial)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
