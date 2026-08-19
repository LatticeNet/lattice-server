package server

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// userinfoShareServer wires a share whose source returns a chosen quota string.
func userinfoShareServer(t *testing.T, userinfo string) (*Server, string) {
	t.Helper()
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
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string,
		_ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{
			Body: []byte("nodes"), ContentType: "text/plain; charset=utf-8", Userinfo: userinfo,
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt,
			RevalidationVersion: subscriptionRevalidationVersion(snap),
		}, nil
	}
	return s, token
}

// Subscription-Userinfo is the one response header whose value comes from the
// source: the provider's quota figures, which only the provider knows. It cannot
// be derived the way Content-Type now is, so what matters is that it cannot be
// used to forge the rest of the response.
//
// It cannot. Go's header serialiser replaces CR and LF with spaces, so a source
// that returns a quota string containing a line break gets a mangled value, not
// a second header. This test pins the outcome at the wire rather than trusting
// that behaviour to stay: it serialises the real response and looks for the
// injected header.
func TestSourceCannotForgeHeadersThroughTheQuotaValue(t *testing.T) {
	s, token := userinfoShareServer(t, "upload=1\r\nX-Injected: yes\r\nX-Also: no")

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token, "curl/8"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	// Serialise the real response, then read it back as a client would. A
	// substring search would not do: the payload survives inside the mangled
	// value, and what matters is whether it becomes a header of its own.
	var wire bytes.Buffer
	if err := rec.Result().Write(&wire); err != nil {
		t.Fatal(err)
	}
	parsed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(wire.Bytes())), nil)
	if err != nil {
		t.Fatalf("re-reading the serialised response: %v", err)
	}
	defer parsed.Body.Close()
	for _, forged := range []string{"X-Injected", "X-Also"} {
		if parsed.Header.Get(forged) != "" {
			t.Fatalf("a source forged the %s response header through the quota value:\n%s", forged, wire.String())
		}
	}
	// The line break is gone rather than honoured, which is what keeps the
	// payload inside one value instead of starting a new header.
	if quota := parsed.Header.Get("Subscription-Userinfo"); strings.ContainsAny(quota, "\r\n") {
		t.Fatalf("the quota value still carries a line break: %q", quota)
	}
}

// A source should not be able to spend the response envelope either. The quota
// header is a small, well-known string; anything the size of a body is not a
// quota figure, and passing it through would let a source push arbitrary bytes
// into the header block of every response for a share.
func TestOversizedQuotaValueIsNotPutOnTheWire(t *testing.T) {
	s, token := userinfoShareServer(t, strings.Repeat("A", 64*1024))

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token, "curl/8"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Subscription-Userinfo"); got != "" {
		t.Fatalf("a %d byte quota value reached the wire", len(got))
	}
}

// The bound must not disturb a real quota string, which is what the live share
// actually returns.
func TestOrdinaryQuotaValueStillReachesTheClient(t *testing.T) {
	const real = "upload=455727941; download=8231525376; total=107374182400; expire=1799999999"
	s, token := userinfoShareServer(t, real)

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest("/sub/team/"+token, "curl/8"))
	if got := rec.Header().Get("Subscription-Userinfo"); got != real {
		t.Fatalf("quota header = %q, want %q", got, real)
	}
}
