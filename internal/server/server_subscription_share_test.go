package server

import (
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestSharePathFromRequest(t *testing.T) {
	validToken := strings.Repeat("a", 32)
	cases := []struct {
		name      string
		path      string
		wantSlug  string
		wantToken string
		wantOK    bool
	}{
		{"two segments", "/sub/team-alpha/" + validToken, "team-alpha", validToken, true},
		{"single segment is gone", "/sub/" + validToken, "", "", false},
		{"three segments", "/sub/a/b/c", "", "", false},
		{"empty slug", "/sub//" + validToken, "", "", false},
		{"empty token", "/sub/team/", "", "", false},
		{"slug rejects uppercase", "/sub/Team/" + validToken, "", "", false},
		{"slug rejects leading hyphen", "/sub/-team/" + validToken, "", "", false},
		{"slug rejects underscore", "/sub/team_a/" + validToken, "", "", false},
		{"token too short", "/sub/team/short", "", "", false},
		{"traversal", "/sub/../" + validToken, "", "", false},
		{"not a sub path", "/api/team/" + validToken, "", "", false},
		{"bare prefix", "/sub/", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slug, token, ok := sharePathFromRequest(tc.path)
			if ok != tc.wantOK || slug != tc.wantSlug || token != tc.wantToken {
				t.Fatalf("got (%q,%q,%v) want (%q,%q,%v)", slug, token, ok, tc.wantSlug, tc.wantToken, tc.wantOK)
			}
		})
	}
}

// The slug charset must stay narrow enough that a slug can never be mistaken for
// a token, and never carry path syntax.
func TestShareSlugRejectsPathSyntax(t *testing.T) {
	for _, bad := range []string{"a/b", "a\\b", "..", ".", "a b", "a%2fb", ""} {
		if shareSlugRe.MatchString(bad) {
			t.Fatalf("slug %q was accepted", bad)
		}
	}
	for _, good := range []string{"a", "team", "team-alpha", "share-for-someone", "a1-2-3"} {
		if !shareSlugRe.MatchString(good) {
			t.Fatalf("slug %q was rejected", good)
		}
	}
}

func newShareTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func mustUpsertShare(t *testing.T, st *store.Store, share model.SubscriptionShare) {
	t.Helper()
	if err := st.UpsertSubscriptionShare(share); err != nil {
		t.Fatalf("upsert share %s: %v", share.ID, err)
	}
}

// Every rejection reason must be the same nothing. A caller able to tell them
// apart would learn which of its guesses was a real token.
func TestResolveShareRejectionsAreIndistinguishable(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Now().UTC()
	past := now.Add(-time.Hour)

	mustUpsertShare(t, st, model.SubscriptionShare{ID: "a", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "b", Slug: "off", Token: strings.Repeat("b", 32), Enabled: false})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "c", Slug: "old", Token: strings.Repeat("c", 32), Enabled: true, ExpiresAt: &past})

	if _, ok := s.resolveShare("team", strings.Repeat("a", 32), now); !ok {
		t.Fatal("valid share did not resolve")
	}
	for _, tc := range []struct{ name, slug, token string }{
		{"unknown token", "team", strings.Repeat("z", 32)},
		{"right token wrong slug", "wrong", strings.Repeat("a", 32)},
		{"disabled share", "off", strings.Repeat("b", 32)},
		{"expired share", "old", strings.Repeat("c", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := s.resolveShare(tc.slug, tc.token, now); ok {
				t.Fatalf("%s resolved; every rejection must look the same", tc.name)
			}
		})
	}
}

// A share whose expiry is in the future still resolves; the boundary is
// exclusive at the instant of expiry.
func TestResolveShareExpiryBoundary(t *testing.T) {
	s, st := newShareTestServer(t)
	now := time.Now().UTC()
	at := now
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "a", Slug: "team", Token: strings.Repeat("a", 32), Enabled: true, ExpiresAt: &at})
	if _, ok := s.resolveShare("team", strings.Repeat("a", 32), now); ok {
		t.Fatal("a share expiring exactly now still resolved")
	}
	future := now.Add(time.Minute)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "b", Slug: "live", Token: strings.Repeat("b", 32), Enabled: true, ExpiresAt: &future})
	if _, ok := s.resolveShare("live", strings.Repeat("b", 32), now); !ok {
		t.Fatal("a share expiring in the future did not resolve")
	}
}
