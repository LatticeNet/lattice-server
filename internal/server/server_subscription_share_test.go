package server

import (
	"strings"
	"testing"
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
