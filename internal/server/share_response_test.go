package server

import (
	"bytes"
	"compress/gzip"
	"context"
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

	*now = now.Add(time.Hour)
	fetch("Surge/5")
	s.shareFetchAudits.Wait()
	summaries := countEvents(shareFetchSummaryReason)
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d after the hour closed", len(summaries))
	}
	md := summaries[0].Metadata
	if md["share_id"] != "s1" || md["fetches"] != "4" || md["not_modified"] != "1" || md["cache_hits"] != "2" ||
		md["families"] != "clashmeta=1,surge=3" || md["hour_start"] != "2026-10-02T10:00:00Z" || md["partial"] != "" {
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
