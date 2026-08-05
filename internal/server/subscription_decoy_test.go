package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// responseFingerprint is everything a prober can observe about a response apart
// from timing.
type responseFingerprint struct {
	Status  int
	Body    string
	Headers string
}

func fingerprint(rec *httptest.ResponseRecorder) responseFingerprint {
	var names []string
	for name := range rec.Header() {
		names = append(names, name)
	}
	// Sorted so the comparison does not depend on map order.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return responseFingerprint{Status: rec.Code, Body: rec.Body.String(), Headers: strings.Join(names, ",")}
}

// The point of the whole decoy: a prober must not be able to tell a valid token
// with empty content from a token that was never issued, nor either of those
// from a path this server does not serve at all.
func TestEverySubscriptionRejectionIsByteIdentical(t *testing.T) {
	s, st := newShareTestServer(t)
	past := s.now().Add(-time.Hour)
	valid := strings.Repeat("a", 32)

	// A share whose source cannot render: its token IS valid, which is exactly
	// the fact that must not leak.
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "empty", Slug: "team", Token: valid, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "nobody"},
	})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "off", Slug: "off", Token: strings.Repeat("b", 32), Enabled: false})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "old", Slug: "old", Token: strings.Repeat("c", 32), Enabled: true, ExpiresAt: &past})

	probe := func(method, path string) responseFingerprint {
		rec := httptest.NewRecorder()
		s.handleSubscriptionShare(rec, httptest.NewRequest(method, path, nil))
		return fingerprint(rec)
	}

	cases := map[string]responseFingerprint{
		"valid token, unrenderable source": probe(http.MethodGet, "/sub/team/"+valid),
		"unknown token":                    probe(http.MethodGet, "/sub/team/"+strings.Repeat("z", 32)),
		"valid token wrong slug":           probe(http.MethodGet, "/sub/other/"+valid),
		"disabled share":                   probe(http.MethodGet, "/sub/off/"+strings.Repeat("b", 32)),
		"expired share":                    probe(http.MethodGet, "/sub/old/"+strings.Repeat("c", 32)),
		"valid token bad format":           probe(http.MethodGet, "/sub/team/"+valid+"?format=xml"),
		"unknown token bad format":         probe(http.MethodGet, "/sub/team/"+strings.Repeat("z", 32)+"?format=xml"),
		"removed single-segment form":      probe(http.MethodGet, "/sub/"+valid),
		"wrong method":                     probe(http.MethodPost, "/sub/team/"+valid),
		"garbage path":                     probe(http.MethodGet, "/sub/x/y/z"),
	}

	var reference responseFingerprint
	var referenceName string
	for name, got := range cases {
		if referenceName == "" {
			reference, referenceName = got, name
			continue
		}
		if got != reference {
			t.Fatalf("%q is distinguishable from %q:\n got: %+v\nwant: %+v", name, referenceName, got, reference)
		}
	}
	if reference.Status != http.StatusNotFound {
		t.Fatalf("decoy status = %d, want 404", reference.Status)
	}
	if reference.Body != "" {
		t.Fatalf("decoy body is not empty: %q", reference.Body)
	}
	if strings.Contains(reference.Headers, requestIDHeader) {
		t.Fatalf("the decoy carries a request id header, which identifies the software: %s", reference.Headers)
	}
}

// The response says nothing, so the audit log has to say everything - otherwise
// the operator has no way to find out why their own subscription stopped working.
func TestRejectionsAreStillAuditedWithTheRealReason(t *testing.T) {
	s, st := newShareTestServer(t)
	valid := strings.Repeat("a", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{
		ID: "empty", Slug: "team", Token: valid, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "nobody"},
	})

	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, httptest.NewRequest(http.MethodGet, "/sub/team/"+valid, nil))

	var reasons []string
	for _, ev := range st.AuditEvents() {
		if ev.Action == auditActionShareFetch && ev.Decision == "deny" {
			reasons = append(reasons, ev.Reason)
		}
	}
	if len(reasons) == 0 {
		t.Fatal("a rejection was not audited; the operator would have no way to diagnose it")
	}
	joined := strings.Join(reasons, "|")
	if !strings.Contains(joined, "render failed") && !strings.Contains(joined, "empty render") {
		t.Fatalf("the audit does not name the real reason: %v", reasons)
	}
	for _, ev := range st.AuditEvents() {
		for _, v := range ev.Metadata {
			if strings.Contains(v, valid) {
				t.Fatal("a raw token reached the audit log")
			}
		}
	}
}

// An operator whose reverse proxy serves a specific 404 page can make this match
// it exactly, so the two are indistinguishable.
func TestDecoyIsConfigurable(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass,
		SubscriptionDecoy: subscriptionDecoyOptions{
			Status: http.StatusForbidden, Body: "nope", ContentType: "text/plain",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.handleSubscriptionShare(rec, httptest.NewRequest(http.MethodGet, "/sub/team/"+strings.Repeat("a", 32), nil))
	if rec.Code != http.StatusForbidden || rec.Body.String() != "nope" {
		t.Fatalf("decoy not configurable: %d %q", rec.Code, rec.Body.String())
	}
}
