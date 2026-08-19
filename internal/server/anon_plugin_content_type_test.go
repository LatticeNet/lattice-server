package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// handleSubscriptionShare states its own invariant at the top of the file: the
// core owns the response, and "a source only ever produces bytes; it cannot see
// the token, set a header, or decide a status code."
//
// The Content-Type is a header, and the plugin decides it. renderShare copies
// the plugin's reply.content_type onto renderedSubscription, and the handler
// writes it to the wire with no allowlist, so the only value the core insists on
// is the fallback used when the plugin sends nothing.
//
// That hands a plugin the one thing the sandbox exists to withhold: the ability
// to choose how the control plane's own origin interprets bytes it serves
// anonymously. A plugin that answers text/html gets markup rendered at
// /sub/<slug>/<token>, on the console's origin and certificate. The shipped CSP
// blocks inline script, but script-src 'self' admits a script served from a
// second share on the same origin, so two shares from one plugin reach script
// execution against any operator who opens the link.
//
// This test asserts the invariant the file already claims: a source cannot pick
// the Content-Type.
func TestPluginCannotChooseTheSubscriptionContentType(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	token := strings.Repeat("a", 32)

	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "s1", Slug: "team", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: "graph"},
	})
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{
		PluginID: "p", SubscriptionID: "graph", Raw: "nodes", FetchedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: "nodes", FetchedAt: now}, nil
	}
	// A plugin returning markup and asking for it to be treated as markup.
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string,
		_ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{
			Body:        []byte(`<html><body><script src="/sub/other/x"></script>owned</body></html>`),
			ContentType: "text/html; charset=utf-8",
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt,
			RevalidationVersion: subscriptionRevalidationVersion(snap),
		}, nil
	}

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token, "curl/8"))

	if rec.Code != http.StatusOK {
		t.Fatalf("render did not reach the wire: status %d", rec.Code)
	}
	got := rec.Header().Get("Content-Type")
	if strings.Contains(strings.ToLower(got), "html") {
		t.Fatalf("a plugin set the response Content-Type to %q, so the control plane renders plugin bytes as markup on its own origin", got)
	}
}
