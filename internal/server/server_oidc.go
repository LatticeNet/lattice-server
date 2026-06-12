package server

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
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
		if err := s.store.PutTOTPChallenge(challenge); err != nil {
			s.oidcFail(w, r, st.RedirectAfter, "session_failed", "")
			return
		}
		s.recordRequestAudit(r, model.AuditEvent{ID: id.New("audit"), ActorID: user.ID, Action: "login.oidc.totp_required", Decision: "observe"})
		s.oidcRedirect(w, r, st.RedirectAfter, "totp_challenge", challenge.ID)
		return
	}
	if _, err := s.startSession(w, r, user, "login.oidc"); err != nil {
		s.oidcFail(w, r, st.RedirectAfter, "session_failed", "")
		return
	}
	http.Redirect(w, r, oidc.SanitizeRedirect(st.RedirectAfter), http.StatusFound)
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
		var req model.OIDCProvider
		if !decodeJSON(w, r, &req) {
			return
		}
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
		if req.ID == "" {
			req.ID = id.New("oidc")
			req.CreatedAt = now
		} else if existing, ok := s.store.OIDCProvider(req.ID); ok {
			req.CreatedAt = existing.CreatedAt
			if req.ClientSecret == "" {
				req.ClientSecret = existing.ClientSecret // preserve write-only secret
			}
		} else {
			req.CreatedAt = now
		}
		req.UpdatedAt = now
		if err := s.store.UpsertOIDCProvider(req); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "oidc.provider.upsert", Scope: "oidc:admin", Metadata: map[string]string{"provider": req.ID, "issuer": req.Issuer}})
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
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.store.DeleteOIDCProvider(req.ID); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "oidc.provider.delete", Scope: "oidc:admin", Metadata: map[string]string{"provider": req.ID}})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
