package oidc

import (
	"fmt"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// IdentityResolution is the outcome of mapping verified OIDC claims to a local
// user.
type IdentityResolution struct {
	UserID      string
	Email       string
	BindSubject bool // create a new (issuer,sub) link for this user
}

// ResolveIdentity decides which local user an OIDC login maps to, per ADR-001
// D9 (allowlist-gated, no auto-provisioning). The provider's domain policy is
// re-evaluated on EVERY login (not just the first), so tightening the allowlist
// or a user's email becoming unverified is retroactive for already-linked
// subjects:
//
//  1. If the provider restricts domains, require a verified email in an allowed
//     domain — for both returning (linked) and first-time logins.
//  2. If a durable link already exists, use it (the stable-sub path).
//  3. Otherwise first login: require a verified email and a pre-existing local
//     user whose username equals the verified email; bind the sub. Else denied.
//
// existingLinkUserID is "" when no link exists. userByEmail reports a local user
// whose username equals the given email (case-insensitive in the store).
func ResolveIdentity(p model.OIDCProvider, claims Claims, existingLinkUserID string, userByEmail func(email string) (string, bool)) (IdentityResolution, error) {
	email := strings.ToLower(strings.TrimSpace(claims.Email))

	// Domain policy is enforced on every login, link or not.
	if len(p.AllowedDomains) > 0 {
		if !claims.EmailVerified {
			return IdentityResolution{}, fmt.Errorf("oidc: email not verified")
		}
		if !domainAllowed(email, p.AllowedDomains) {
			return IdentityResolution{}, fmt.Errorf("oidc: email domain not in the provider allowlist")
		}
	}

	if existingLinkUserID != "" {
		return IdentityResolution{UserID: existingLinkUserID, Email: claims.Email}, nil
	}

	// First login binds the subject: require a verified email and a local user.
	if !claims.EmailVerified {
		return IdentityResolution{}, fmt.Errorf("oidc: email not verified")
	}
	if email == "" {
		return IdentityResolution{}, fmt.Errorf("oidc: no email claim")
	}
	userID, ok := userByEmail(email)
	if !ok {
		return IdentityResolution{}, fmt.Errorf("oidc: no local account for %q; an admin must provision a user whose username is that email", email)
	}
	return IdentityResolution{UserID: userID, Email: email, BindSubject: true}, nil
}

// domainAllowed reports whether the email's domain is permitted. An empty
// allowlist means "rely on the pre-existing-user check" (any domain), since a
// local user must still exist for that email.
func domainAllowed(email string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, a := range allowed {
		if strings.ToLower(strings.TrimSpace(a)) == domain {
			return true
		}
	}
	return false
}

// SanitizeRedirect returns a safe post-login landing path. To prevent open
// redirects it accepts only a single-slash-rooted relative path (no scheme,
// host, or protocol-relative "//"); anything else collapses to "/".
func SanitizeRedirect(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "/"
	}
	if strings.ContainsAny(p, "\\\r\n") {
		return "/"
	}
	return p
}
