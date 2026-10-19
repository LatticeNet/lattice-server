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
	// LinkIgnored reports that a link exists for this provider and subject
	// but was not honoured: it was recorded under another issuer (or none),
	// or names no account. IgnoredLinkIssuer is that link's issuer. Both are
	// set whether or not the resolution succeeded, so the caller can audit.
	LinkIgnored       bool
	IgnoredLinkIssuer string
}

// ResolveIdentity decides which local user an OIDC login maps to, per ADR-001
// D9 (allowlist-gated, no auto-provisioning). The provider's domain policy is
// re-evaluated on EVERY login (not just the first), so tightening the allowlist
// or a user's email becoming unverified is retroactive for already-linked
// subjects:
//
//  1. If the provider restricts domains, require a verified email in an allowed
//     domain — for both returning (linked) and first-time logins.
//  2. If a durable link exists and was recorded under the issuer the claims
//     were verified against (p.Issuer), use it (the stable-sub path).
//  3. Otherwise first login: require a verified email and a pre-existing local
//     user whose username equals the verified email; bind the sub. Else denied.
//
// Subjects are unique only per issuer, so a link answers only for the issuer
// it was created under: a provider repointed at another issuer, whoever runs
// that issuer, cannot present a linked subject and inherit the link. Under the
// new issuer the same subject string is a different identity, judged as a
// first sign-in.
//
// link is nil when no link exists. p must be the provider record the claims
// were verified with. userByEmail reports a local user whose username equals
// the given email (case-insensitive in the store).
func ResolveIdentity(p model.OIDCProvider, claims Claims, link *model.OIDCIdentity, userByEmail func(email string) (string, bool)) (IdentityResolution, error) {
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	base := IdentityResolution{}
	honoured := link != nil && link.Issuer != "" && link.Issuer == p.Issuer && link.UserID != ""
	if link != nil && !honoured {
		base.LinkIgnored, base.IgnoredLinkIssuer = true, link.Issuer
	}

	// Domain policy is enforced on every login, link or not.
	if len(p.AllowedDomains) > 0 {
		if !claims.EmailVerified {
			return base, fmt.Errorf("oidc: email not verified")
		}
		if !domainAllowed(email, p.AllowedDomains) {
			return base, fmt.Errorf("oidc: email domain not in the provider allowlist")
		}
	}

	if honoured {
		base.UserID, base.Email = link.UserID, claims.Email
		return base, nil
	}

	// First login binds the subject: require a verified email and a local user.
	if !claims.EmailVerified {
		return base, fmt.Errorf("oidc: email not verified")
	}
	if email == "" {
		return base, fmt.Errorf("oidc: no email claim")
	}
	userID, ok := userByEmail(email)
	if !ok {
		return base, fmt.Errorf("oidc: no local account for the verified email; an admin must provision a user whose username is that email")
	}
	base.UserID, base.Email, base.BindSubject = userID, email, true
	return base, nil
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
