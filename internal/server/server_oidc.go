package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/oidc"
)

// oidcStateTTL bounds how long a started login may sit before the callback.
const oidcStateTTL = 10 * time.Minute

// oidcCallbackPath is the single redirect path shared by all providers; the
// provider is recovered from the stored auth state keyed by `state`.
const oidcCallbackPath = "/api/auth/oidc/callback"

// redirectURL is the absolute OIDC redirect URI registered with providers.
func (s *Server) redirectURL() string {
	if s.publicURL == "" {
		return ""
	}
	return s.publicURL + oidcCallbackPath
}

// handleOIDCList returns the enabled providers for the login page. Public: it
// exposes only id + display name, never secrets.
func (s *Server) handleOIDCList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	type view struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
	}
	out := []view{}
	if s.redirectURL() != "" {
		for _, p := range s.store.EnabledOIDCProviders() {
			out = append(out, view{ID: p.ID, DisplayName: p.DisplayName})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

// handleOIDCStart begins an auth-code + PKCE login and redirects to the provider.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.loginLimiter.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts; slow down"))
		return
	}
	if s.redirectURL() == "" {
		writeError(w, http.StatusServiceUnavailable, errors.New("sso is not configured (server public URL unset)"))
		return
	}
	provider, ok := s.store.OIDCProvider(r.URL.Query().Get("provider"))
	if !ok || !provider.Enabled {
		writeError(w, http.StatusNotFound, errors.New("unknown or disabled identity provider"))
		return
	}
	redirectAfter := oidc.SanitizeRedirect(r.URL.Query().Get("redirect"))
	verifier := oidc.GenerateCodeVerifier()
	binding, err := auth.NewRandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	st, err := auth.NewOIDCAuthState(provider.ID, s.clientIP(r), redirectAfter, verifier, binding, oidcStateTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	authURL, err := s.oidc.AuthCodeURL(r.Context(), provider, s.redirectURL(), st.State, st.Nonce, verifier)
	if err != nil {
		s.logger.Printf("oidc start (%s): %v", provider.ID, err)
		writeError(w, http.StatusBadGateway, errors.New("identity provider is unavailable"))
		return
	}
	if err := s.store.PutOIDCAuthState(st); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	s.setOIDCBindingCookie(w, binding)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// oidcBindingCookie carries the per-flow browser-binding token. SameSite=Lax so
// it survives the top-level GET redirect back from the IdP; scoped to the OIDC
// paths; HttpOnly so scripts cannot read it.
const oidcBindingCookie = "lattice_oidc_bind"

func (s *Server) setOIDCBindingCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcBindingCookie,
		Value:    token,
		Path:     "/api/auth/oidc",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oidcStateTTL.Seconds()),
	})
}

func (s *Server) clearOIDCBindingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcBindingCookie,
		Value:    "",
		Path:     "/api/auth/oidc",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// totpChallengeCookie binds a post-SSO TOTP challenge to the initiating browser.
// Its value is the challenge id and a browser-binding secret ("<id>.<secret>",
// see ssoChallengeFromCookie). handleLoginTOTP requires it for every
// SSO-issued challenge, and handlePendingSSOSecondFactor reads it to name the
// provider that verified the first factor.
const totpChallengeCookie = "lattice_totp_challenge"

// ssoChallengeCookieValue joins a challenge id and its browser-binding secret.
// Challenge ids are base64url and never contain a dot.
func ssoChallengeCookieValue(challengeID, secret string) string {
	return challengeID + "." + secret
}

// ssoChallengeFromCookie returns the SSO-issued challenge this browser holds:
// the cookie must name an active SSO challenge, carry the secret whose hash
// the challenge stores, and arrive from the address the challenge was issued
// to. The challenge id alone, which an observer of the redirect URL has, is
// not enough.
func (s *Server) ssoChallengeFromCookie(r *http.Request) (auth.TOTPChallenge, bool) {
	c, err := r.Cookie(totpChallengeCookie)
	if err != nil || c.Value == "" {
		return auth.TOTPChallenge{}, false
	}
	challengeID, secret, ok := strings.Cut(c.Value, ".")
	if !ok || challengeID == "" || secret == "" {
		return auth.TOTPChallenge{}, false
	}
	challenge, ok := s.store.TOTPChallenge(challengeID)
	if !ok || challenge.SSOProviderID == "" || challenge.SSOBindingHash == "" || challenge.ClientIP != s.clientIP(r) {
		return auth.TOTPChallenge{}, false
	}
	if subtle.ConstantTimeCompare([]byte(auth.HashBindingToken(secret)), []byte(challenge.SSOBindingHash)) != 1 {
		return auth.TOTPChallenge{}, false
	}
	return challenge, true
}

func (s *Server) setTOTPChallengeCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     totpChallengeCookie,
		Value:    value,
		Path:     "/api/login/totp",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
}

func (s *Server) clearTOTPChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     totpChallengeCookie,
		Value:    "",
		Path:     "/api/login/totp",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// pendingSSOSecondFactorView is what GET /api/login/totp tells the browser
// that holds a post-SSO second-factor challenge: the provider's display name
// and whom it verified, the verified email or, without one, the subject, both
// masked. The page only has to confirm which account signed in; the whole
// address is not needed for that and does not leave the server here.
type pendingSSOSecondFactorView struct {
	Provider string `json:"provider"`
	Email    string `json:"email,omitempty"`
	Subject  string `json:"subject,omitempty"`
}

// handlePendingSSOSecondFactor answers GET /api/login/totp so the second-factor
// page can say which provider already verified the operator. It reads the
// challenge only from the HttpOnly cookie the SSO callback set for this
// browser, never from the URL, and requires the cookie's binding secret and
// the client IP the challenge was issued to (ssoChallengeFromCookie).
// Anything else (no cookie, a wrong secret, an expired, spent or unknown
// challenge, or a password-path challenge) gets a 404 that names nobody. It is
// read-only: it neither counts against the login limiter nor touches the
// challenge.
func (s *Server) handlePendingSSOSecondFactor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	none := func() { writeError(w, http.StatusNotFound, errors.New("no pending sso sign-in")) }
	challenge, ok := s.ssoChallengeFromCookie(r)
	if !ok {
		none()
		return
	}
	if user, ok := s.store.User(challenge.UserID); !ok || !user.TOTPEnabled {
		none()
		return
	}
	view := pendingSSOSecondFactorView{Provider: challenge.SSOProviderID}
	if p, ok := s.store.OIDCProvider(challenge.SSOProviderID); ok && strings.TrimSpace(p.DisplayName) != "" {
		view.Provider = strings.TrimSpace(p.DisplayName)
	}
	if challenge.SSOEmail != "" {
		view.Email = maskSSOEmail(challenge.SSOEmail)
	} else {
		view.Subject = maskSSOSubject(challenge.SSOSubject)
	}
	writeJSON(w, http.StatusOK, view)
}

// maskSSOEmail keeps the first and last character of the local part and the
// whole domain, with a fixed-width mask between so the length does not show:
// lidongguinb@gmail.com reads l***b@gmail.com. A value that is not an address
// is masked as a subject.
func maskSSOEmail(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return maskSSOSubject(email)
	}
	local, domain := []rune(email[:at]), email[at+1:]
	switch {
	case len(local) == 0 || domain == "":
		return "***"
	case len(local) == 1:
		return "***@" + domain
	case len(local) == 2:
		return string(local[0]) + "***@" + domain
	default:
		return string(local[0]) + "***" + string(local[len(local)-1]) + "@" + domain
	}
}

// maskSSOSubject keeps the last four characters of a provider subject, enough
// to tell two accounts apart, and nothing of a subject that short.
func maskSSOSubject(subject string) string {
	r := []rune(strings.TrimSpace(subject))
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 4:
		return "***"
	default:
		return "***" + string(r[len(r)-4:])
	}
}

// handleCancelPendingSSOSecondFactor answers DELETE /api/login/totp: the
// operator left the second-factor step, so the challenge the SSO callback
// issued to this browser is spent and its cookie cleared. Like the read, it
// takes the challenge only from the HttpOnly cookie, with its binding secret,
// and only from the client address it was issued to; it answers 204 whatever
// it found, so it is no oracle for challenge ids.
func (s *Server) handleCancelPendingSSOSecondFactor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if challenge, ok := s.ssoChallengeFromCookie(r); ok {
		if err := s.store.ConsumeTOTPChallenge(challenge.ID); err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: challenge.UserID, Action: "login.oidc.second_factor_cancelled", Decision: "observe"})
		s.clearTOTPChallengeCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleOIDCCallback completes the login: validates and consumes the state,
// exchanges the code (PKCE), verifies the ID token, maps the identity to a local
// user, and starts a session. All failures redirect back to the login page with
// a short, non-sensitive code rather than leaking detail.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.loginLimiter.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts; slow down"))
		return
	}
	q := r.URL.Query()
	if provErr := q.Get("error"); provErr != "" {
		s.oidcFail(w, r, "/", "provider_error", "")
		return
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		s.oidcFail(w, r, "/", "bad_request", "")
		return
	}
	st, ok := s.store.ConsumeOIDCAuthState(state)
	if !ok {
		s.oidcFail(w, r, "/", "expired", "")
		return
	}
	// Browser-binding (login-CSRF defense): the callback must carry the cookie
	// set at /start. This is the primary tie; the IP check is defense-in-depth.
	s.clearOIDCBindingCookie(w)
	bindCookie, _ := r.Cookie(oidcBindingCookie)
	if bindCookie == nil || subtle.ConstantTimeCompare([]byte(auth.HashBindingToken(bindCookie.Value)), []byte(st.BindingHash)) != 1 {
		s.oidcFail(w, r, st.RedirectAfter, "csrf", "")
		return
	}
	if st.ClientIP != s.clientIP(r) {
		s.oidcFail(w, r, st.RedirectAfter, "ip_mismatch", "")
		return
	}
	provider, ok := s.store.OIDCProvider(st.ProviderID)
	if !ok || !provider.Enabled {
		s.oidcFail(w, r, st.RedirectAfter, "unavailable", "")
		return
	}
	claims, err := s.oidc.Exchange(r.Context(), provider, s.redirectURL(), code, st.CodeVerifier, st.Nonce)
	if err != nil {
		s.logger.Printf("oidc callback exchange (%s): %v", provider.ID, err)
		s.oidcFail(w, r, st.RedirectAfter, "verify_failed", "")
		return
	}

	existingUserID := ""
	if link, ok := s.store.OIDCIdentity(provider.ID, claims.Subject); ok {
		existingUserID = link.UserID
	}
	res, err := oidc.ResolveIdentity(provider, claims, existingUserID, func(email string) (string, bool) {
		u, ok := s.store.UserByUsername(email)
		if !ok {
			return "", false
		}
		return u.ID, true
	})
	if err != nil {
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), Action: "login.oidc", Decision: "deny", Reason: err.Error(), Metadata: map[string]string{"provider": provider.ID, "sub": claims.Subject}})
		s.oidcFail(w, r, st.RedirectAfter, "denied", "")
		return
	}
	user, ok := s.store.User(res.UserID)
	if !ok {
		s.oidcFail(w, r, st.RedirectAfter, "denied", "")
		return
	}
	if res.BindSubject {
		if err := s.store.PutOIDCIdentity(model.OIDCIdentity{
			ProviderID: provider.ID,
			Issuer:     provider.Issuer,
			Subject:    claims.Subject,
			UserID:     user.ID,
			Email:      res.Email,
			CreatedAt:  time.Now().UTC(),
		}); err != nil {
			s.oidcFail(w, r, st.RedirectAfter, "denied", "")
			return
		}
	}
	// A provider the operator marked as the whole first and second factor
	// (SkipLocalTOTP) opens the console without the local code, but only
	// through a subject this account already confirmed with that code in its
	// current security epoch; see ssoVouchesForSecondFactor. The policy is
	// read again here, after the code exchange's round trip to the provider,
	// so a flag turned off or a provider disabled meanwhile is honoured.
	if current, ok := s.store.OIDCProvider(provider.ID); ok && user.TOTPEnabled && s.ssoVouchesForSecondFactor(current, claims.Subject, user) {
		if _, err := s.startSessionAudited(w, r, user, model.AuditEvent{
			Action: "login.oidc.totp_skipped",
			Reason: "local second factor skipped by provider policy",
			Metadata: map[string]string{
				"provider": provider.ID,
				"policy":   "skip_local_totp",
				"subject":  maskSSOSubject(claims.Subject),
				"epoch":    strconv.FormatUint(user.SecurityEpoch, 10),
			},
		}); err != nil {
			s.oidcFail(w, r, st.RedirectAfter, "session_failed", "")
			return
		}
		http.Redirect(w, r, oidc.SanitizeRedirect(st.RedirectAfter), http.StatusFound)
		return
	}
	// Honor a Lattice-local second factor: SSO proves the IdP identity, but if
	// the account also has TOTP enabled we still require it (no silent 2FA
	// bypass). Carry the challenge to the dashboard, which completes it exactly
	// like the password→TOTP step.
	if user.TOTPEnabled {
		challenge, err := auth.NewTOTPChallenge(user.ID, s.clientIP(r), 5*time.Minute)
		if err != nil {
			s.oidcFail(w, r, st.RedirectAfter, "session_failed", "")
			return
		}
		bindingSecret, err := auth.NewRandomToken(32)
		if err != nil {
			s.oidcFail(w, r, st.RedirectAfter, "session_failed", "")
			return
		}
		challenge.SSOBindingHash = auth.HashBindingToken(bindingSecret)
		// Remember who the provider verified, so the second-factor page can
		// tell the operator the provider step already succeeded.
		challenge.SSOProviderID = provider.ID
		challenge.SSOSubject = claims.Subject
		challenge.SSOIssuer = provider.Issuer
		if claims.EmailVerified {
			challenge.SSOEmail = strings.TrimSpace(claims.Email)
		}
		if err := s.store.PutTOTPChallenge(challenge); err != nil {
			s.oidcFail(w, r, st.RedirectAfter, "session_failed", "")
			return
		}
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login.oidc.totp_required", Decision: "observe"})
		// Bind the post-SSO TOTP challenge to THIS browser: the challenge id also
		// travels in the front-channel redirect (?totp_challenge=), which an
		// attacker who only sees the URL could replay. The cookie carries the
		// binding secret the attacker does not have; handleLoginTOTP requires it
		// for every SSO-issued challenge, so only the browser that completed SSO
		// can finish 2FA. [C14]
		s.setTOTPChallengeCookie(w, ssoChallengeCookieValue(challenge.ID, bindingSecret))
		s.oidcRedirect(w, r, st.RedirectAfter, "totp_challenge", challenge.ID)
		return
	}
	if _, err := s.startSession(w, r, user, "login.oidc"); err != nil {
		s.oidcFail(w, r, st.RedirectAfter, "session_failed", "")
		return
	}
	http.Redirect(w, r, oidc.SanitizeRedirect(st.RedirectAfter), http.StatusFound)
}

// ssoVouchesForSecondFactor reports whether a sign-in through provider as
// subject may stand in for user's local TOTP. All of these must hold: the
// provider is enabled and carries SkipLocalTOTP; the subject is linked to this
// user under the provider's current issuer; and the link was confirmed by
// completing the local TOTP code in a sign-in from this subject
// (confirmSSOSecondFactor) while the user's security epoch was what it is now.
// The confirmation keeps the trust on the provider account the operator proved
// once, not on whatever account the provider says has the same verified email:
// a first sign-in links by email match, and that link is written before the
// TOTP step, so a link alone proves nothing. Subjects are unique only per
// issuer, so repointing the provider at another issuer withdraws the trust. A
// password change, 2FA disable or session revoke bumps the epoch and with it
// withdraws the trust until the next confirmed sign-in.
func (s *Server) ssoVouchesForSecondFactor(provider model.OIDCProvider, subject string, user model.User) bool {
	if !provider.Enabled || !provider.SkipLocalTOTP {
		return false
	}
	link, ok := s.store.OIDCIdentity(provider.ID, subject)
	return ok && link.UserID == user.ID && link.Issuer == provider.Issuer &&
		!link.SecondFactorAt.IsZero() && link.SecondFactorEpoch == user.SecurityEpoch
}

// confirmSSOSecondFactor records on the identity link that the user completed
// the local TOTP code for a challenge the SSO callback issued, so a provider
// with SkipLocalTOTP may later stand in for it. handleLoginTOTP calls it only
// for the browser that holds the challenge cookie and only after a TOTP code,
// never a recovery code. The link is confirmed under the issuer the callback
// saw; a challenge without one (issued before this field existed) confirms
// nothing. A failure is logged and does not fail the sign-in; the next one
// asks again.
func (s *Server) confirmSSOSecondFactor(r *http.Request, challenge auth.TOTPChallenge, user model.User) {
	if challenge.SSOProviderID == "" || challenge.SSOSubject == "" || challenge.SSOIssuer == "" {
		return
	}
	prior, ok, err := s.store.ConfirmOIDCIdentitySecondFactor(challenge.SSOProviderID, challenge.SSOIssuer, challenge.SSOSubject, user.ID, s.now(), user.SecurityEpoch)
	if err != nil {
		s.logger.Printf("oidc second-factor confirmation (%s): %v", challenge.SSOProviderID, err)
		return
	}
	if !ok {
		return
	}
	// A confirmation that lets a provider account open the console from now
	// on, where it could not a moment ago, is a new way in: say so beyond the
	// audit log. A routine re-confirmation of an account already trusted is
	// only audited.
	provider, _ := s.store.OIDCProvider(challenge.SSOProviderID)
	wasTrusted := !prior.SecondFactorAt.IsZero() && prior.SecondFactorEpoch == user.SecurityEpoch && prior.Issuer == challenge.SSOIssuer
	newlyTrusted := provider.Enabled && provider.SkipLocalTOTP && provider.Issuer == challenge.SSOIssuer && !wasTrusted
	s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login.oidc.second_factor_confirmed", Decision: "observe",
		Metadata: map[string]string{
			"provider":      challenge.SSOProviderID,
			"subject":       maskSSOSubject(challenge.SSOSubject),
			"epoch":         strconv.FormatUint(user.SecurityEpoch, 10),
			"newly_trusted": strconv.FormatBool(newlyTrusted),
		}})
	if newlyTrusted {
		name := strings.TrimSpace(provider.DisplayName)
		if name == "" {
			name = provider.ID
		}
		s.emitNotify("Single sign-on account trusted for sign-in",
			fmt.Sprintf("user %s confirmed a %s account (subject %s) with the authenticator code; from now on signing in through %s opens the console without the code", user.Username, name, maskSSOSubject(challenge.SSOSubject), name))
	}
}

// oidcRedirect redirects to a sanitized landing path carrying a single query
// parameter (key=value). Used for both success continuations (e.g. a pending
// totp_challenge) and failures.
func (s *Server) oidcRedirect(w http.ResponseWriter, r *http.Request, redirectAfter, key, value string) {
	dest := oidc.SanitizeRedirect(redirectAfter)
	sep := "?"
	if strings.Contains(dest, "?") {
		sep = "&"
	}
	http.Redirect(w, r, dest+sep+url.QueryEscape(key)+"="+url.QueryEscape(value), http.StatusFound)
}

// oidcFail redirects to the login page with a short, non-sensitive error code so
// the dashboard can show a message without leaking which check failed.
func (s *Server) oidcFail(w http.ResponseWriter, r *http.Request, redirectAfter, codeStr, _ string) {
	s.oidcRedirect(w, r, redirectAfter, "sso_error", codeStr)
}

// --- admin provider config ----------------------------------------------

// oidcProviderView is the secret-free projection returned by the admin API.
type oidcProviderView struct {
	ID             string   `json:"id"`
	DisplayName    string   `json:"display_name"`
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	HasSecret      bool     `json:"has_secret"`
	Scopes         []string `json:"scopes,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	Enabled        bool     `json:"enabled"`
	SkipLocalTOTP  bool     `json:"skip_local_totp"`
}

func toOIDCProviderView(p model.OIDCProvider) oidcProviderView {
	return oidcProviderView{
		ID:             p.ID,
		DisplayName:    p.DisplayName,
		Issuer:         p.Issuer,
		ClientID:       p.ClientID,
		HasSecret:      p.ClientSecret != "",
		Scopes:         p.Scopes,
		AllowedDomains: p.AllowedDomains,
		Enabled:        p.Enabled,
		SkipLocalTOTP:  p.SkipLocalTOTP,
	}
}

// handleOIDCProviders lists (GET) or upserts (POST) provider config. The client
// secret is write-only: GET never returns it, and an empty secret on update
// preserves the stored one.
func (s *Server) handleOIDCProviders(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		providers := s.store.OIDCProviders()
		out := make([]oidcProviderView, 0, len(providers))
		for _, pr := range providers {
			out = append(out, toOIDCProviderView(pr))
		}
		writeJSON(w, http.StatusOK, map[string]any{"providers": out})
	case http.MethodPost:
		// Rewriting an SSO provider is fleet-wide authentication surgery, the
		// widest blast radius a confined token could reach past its allowlist.
		if s.refuseConfinedFleetWrite(w, p, "oidc.provider.upsert", "oidc:admin") {
			return
		}
		var body struct {
			model.OIDCProvider
			// StepUpGrant is required only to turn skip_local_totp on.
			StepUpGrant string `json:"step_up_grant,omitempty"`
		}
		if !decodeClientJSON(w, r, &body) {
			return
		}
		req := body.OIDCProvider
		req.Issuer = strings.TrimRight(strings.TrimSpace(req.Issuer), "/")
		req.ClientID = strings.TrimSpace(req.ClientID)
		req.DisplayName = strings.TrimSpace(req.DisplayName)
		if !strings.HasPrefix(req.Issuer, "https://") {
			writeError(w, http.StatusBadRequest, errors.New("issuer must be an https URL"))
			return
		}
		if req.ClientID == "" {
			writeError(w, http.StatusBadRequest, errors.New("client_id is required"))
			return
		}
		// Issuer must be unique across providers: identity links are keyed on the
		// provider record, and a shared issuer with relaxed policy would let one
		// provider's links be honored under another's looser rules.
		for _, existing := range s.store.OIDCProviders() {
			if existing.ID != req.ID && strings.EqualFold(existing.Issuer, req.Issuer) {
				writeError(w, http.StatusConflict, errors.New("another provider already uses this issuer"))
				return
			}
		}
		if req.DisplayName == "" {
			req.DisplayName = req.Issuer
		}
		now := time.Now().UTC()
		// The provider-trusted second factor is never inherited from the
		// stored record: a request that leaves skip_local_totp out turns it
		// off, the value that keeps the local TOTP step.
		oldSkipLocalTOTP, oldIssuer := false, ""
		if req.ID == "" {
			req.ID = id.New("oidc")
			req.CreatedAt = now
		} else if existing, ok := s.store.OIDCProvider(req.ID); ok {
			req.CreatedAt = existing.CreatedAt
			oldSkipLocalTOTP, oldIssuer = existing.SkipLocalTOTP, existing.Issuer
			if req.ClientSecret == "" {
				req.ClientSecret = existing.ClientSecret // preserve write-only secret
			}
		} else {
			req.CreatedAt = now
		}
		enablingSkip := req.SkipLocalTOTP && !oldSkipLocalTOTP
		// Turning the local second factor off for everyone who signs in through
		// this provider is a relaxation of sign-in, so it takes what revealing a
		// secret takes: an interactive session with a fresh step-up. A token
		// cannot do it; turning it off needs nothing extra.
		if enablingSkip && !s.stepUpGrantHeld(p, strings.TrimSpace(body.StepUpGrant)) {
			s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "oidc.provider.upsert", Scope: "oidc:admin", Decision: "deny",
				Reason: "skip_local_totp turned on without a fresh second-factor step-up", Metadata: map[string]string{"provider": req.ID}})
			writeError(w, http.StatusForbidden, apiError(apiErrorStepUpRequired,
				"turning on skip_local_totp requires an interactive session with a fresh second-factor step-up"))
			return
		}
		// Confirmations made before the policy was on do not carry over: each
		// account confirms its provider account again, under the policy, before
		// the provider stands in for its code. Cleared before the policy is
		// stored, so no earlier confirmation is honoured in between.
		cleared := 0
		if enablingSkip {
			n, err := s.store.ClearOIDCIdentityConfirmations(req.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			cleared = n
		}
		req.UpdatedAt = now
		if err := s.store.UpsertOIDCProvider(req); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		meta := map[string]string{
			"provider":            req.ID,
			"issuer":              req.Issuer,
			"old_skip_local_totp": strconv.FormatBool(oldSkipLocalTOTP),
			"new_skip_local_totp": strconv.FormatBool(req.SkipLocalTOTP),
		}
		if oldIssuer != "" && oldIssuer != req.Issuer {
			meta["old_issuer"] = oldIssuer
		}
		if enablingSkip {
			meta["confirmations_cleared"] = strconv.Itoa(cleared)
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "oidc.provider.upsert", Scope: "oidc:admin", Decision: "allow", Metadata: meta})
		writeJSON(w, http.StatusOK, toOIDCProviderView(req))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// handleDeleteOIDCProvider removes a provider by id.
func (s *Server) handleDeleteOIDCProvider(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedFleetWrite(w, p, "oidc.provider.delete", "oidc:admin") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	prior, _ := s.store.OIDCProvider(req.ID)
	if err := s.store.DeleteOIDCProvider(req.ID); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	// The links outlive the provider record, so a provider created again
	// under this id would find them. Their confirmations do not outlive it.
	cleared, err := s.store.ClearOIDCIdentityConfirmations(req.ID)
	if err != nil {
		s.logger.Printf("oidc provider delete (%s): clearing confirmations: %v", req.ID, err)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "oidc.provider.delete", Scope: "oidc:admin", Metadata: map[string]string{
		"provider":              req.ID,
		"skip_local_totp":       strconv.FormatBool(prior.SkipLocalTOTP),
		"confirmations_cleared": strconv.Itoa(cleared),
	}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleOIDCProviderTest probes an issuer's OIDC discovery document and reports
// the resolved authorization/token endpoints — the "test connection" check for
// the provider form. Non-destructive: it writes no state and is bounded by a
// short timeout so a slow IdP cannot hang the admin UI. A failed discovery is
// returned as 200 {ok:false,error} (a probe result, not a server error) so the
// UI can render the reason inline; the detailed cause is logged server-side.
func (s *Server) handleOIDCProviderTest(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		Issuer string `json:"issuer"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	issuer := strings.TrimRight(strings.TrimSpace(req.Issuer), "/")
	if !strings.HasPrefix(issuer, "https://") {
		writeError(w, http.StatusBadRequest, errors.New("issuer must be an https URL"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	authEP, tokenEP, err := s.oidc.Probe(ctx, issuer)
	ok := err == nil
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "oidc.provider.test",
		Scope:    "oidc:admin",
		Metadata: map[string]string{"issuer": issuer, "ok": map[bool]string{true: "true", false: "false"}[ok]},
	})
	if err != nil {
		s.logger.Printf("oidc provider test (%s): %v", issuer, err)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     false,
			"issuer": issuer,
			"error":  "discovery failed: provider unreachable or discovery document malformed",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                     true,
		"issuer":                 issuer,
		"authorization_endpoint": authEP,
		"token_endpoint":         tokenEP,
	})
}
