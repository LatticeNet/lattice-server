package oidc

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestResolveIdentity(t *testing.T) {
	prov := model.OIDCProvider{Issuer: "https://idp", ClientID: "c", AllowedDomains: []string{"example.com"}}
	userByEmail := func(want string) func(string) (string, bool) {
		return func(email string) (string, bool) {
			if email == want {
				return "user-1", true
			}
			return "", false
		}
	}
	none := func(string) (string, bool) { return "", false }

	cases := []struct {
		name     string
		provider model.OIDCProvider
		claims   Claims
		existing string
		lookup   func(string) (string, bool)
		wantUser string
		wantBind bool
		wantErr  bool
	}{
		{
			name:     "existing link, no domain policy, ignores email",
			provider: model.OIDCProvider{Issuer: "https://idp", ClientID: "c"}, // no AllowedDomains
			claims:   Claims{Subject: "s1", Email: "changed@other.com", EmailVerified: false},
			existing: "user-existing",
			lookup:   none,
			wantUser: "user-existing",
			wantBind: false,
		},
		{
			name:     "existing link, domain policy satisfied, logs in",
			provider: prov,
			claims:   Claims{Subject: "s1b", Email: "still@example.com", EmailVerified: true},
			existing: "user-existing",
			lookup:   none,
			wantUser: "user-existing",
			wantBind: false,
		},
		{
			name:     "existing link RE-CHECKED: denied when domain no longer allowed",
			provider: prov,
			claims:   Claims{Subject: "s1c", Email: "moved@other.com", EmailVerified: true},
			existing: "user-existing",
			lookup:   none,
			wantErr:  true,
		},
		{
			name:     "existing link RE-CHECKED: denied when email now unverified",
			provider: prov,
			claims:   Claims{Subject: "s1d", Email: "still@example.com", EmailVerified: false},
			existing: "user-existing",
			lookup:   none,
			wantErr:  true,
		},
		{
			name:     "first login binds when verified+allowed+local user exists",
			provider: prov,
			claims:   Claims{Subject: "s2", Email: "Alice@example.com", EmailVerified: true},
			lookup:   userByEmail("alice@example.com"), // lookup receives lowercased email
			wantUser: "user-1",
			wantBind: true,
		},
		{
			name:     "denied: email not verified",
			provider: prov,
			claims:   Claims{Subject: "s3", Email: "alice@example.com", EmailVerified: false},
			lookup:   userByEmail("alice@example.com"),
			wantErr:  true,
		},
		{
			name:     "denied: domain not allowed",
			provider: prov,
			claims:   Claims{Subject: "s4", Email: "bob@evil.com", EmailVerified: true},
			lookup:   userByEmail("bob@evil.com"),
			wantErr:  true,
		},
		{
			name:     "denied: no local user",
			provider: prov,
			claims:   Claims{Subject: "s5", Email: "ghost@example.com", EmailVerified: true},
			lookup:   none,
			wantErr:  true,
		},
		{
			name:     "denied: empty email",
			provider: prov,
			claims:   Claims{Subject: "s6", Email: "", EmailVerified: true},
			lookup:   userByEmail(""),
			wantErr:  true,
		},
		{
			name:     "no domain restriction relies on local-user check",
			provider: model.OIDCProvider{Issuer: "https://idp", ClientID: "c"}, // empty AllowedDomains
			claims:   Claims{Subject: "s7", Email: "x@anywhere.io", EmailVerified: true},
			lookup:   userByEmail("x@anywhere.io"),
			wantUser: "user-1",
			wantBind: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ResolveIdentity(tc.provider, tc.claims, tc.existing, tc.lookup)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got resolution %+v", res)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.UserID != tc.wantUser || res.BindSubject != tc.wantBind {
				t.Fatalf("got %+v, want user=%s bind=%v", res, tc.wantUser, tc.wantBind)
			}
		})
	}
}

func TestSanitizeRedirect(t *testing.T) {
	cases := map[string]string{
		"":                    "/",
		"/":                   "/",
		"/dashboard":          "/dashboard",
		"/a/b?x=1":            "/a/b?x=1",
		"//evil.com":          "/", // protocol-relative
		"https://evil.com":    "/", // absolute
		"http://evil.com":     "/", // absolute
		"javascript:alert(1)": "/", // no leading slash
		"/path\ninjection":    "/", // control char
		"/path\\back":         "/", // backslash
	}
	for in, want := range cases {
		if got := SanitizeRedirect(in); got != want {
			t.Fatalf("SanitizeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDomainAllowed(t *testing.T) {
	if !domainAllowed("a@x.com", nil) {
		t.Fatal("empty allowlist should permit")
	}
	if !domainAllowed("a@X.com", []string{"x.com"}) {
		t.Fatal("domain match should be case-insensitive")
	}
	if domainAllowed("a@y.com", []string{"x.com"}) {
		t.Fatal("non-matching domain should be denied")
	}
	if domainAllowed("noatsign", []string{"x.com"}) {
		t.Fatal("malformed email should be denied")
	}
	if domainAllowed("a@", []string{"x.com"}) {
		t.Fatal("empty domain should be denied")
	}
}
