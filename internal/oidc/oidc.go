// Package oidc wraps go-oidc + x/oauth2 into the small surface the server needs
// for SSO login: build an auth-code+PKCE URL, then exchange the code and verify
// the returned ID token. Provider discovery is cached because it is a network
// round trip.
//
// Why a dependency here: ADR-001 D8 — JWT/JWKS validation is the part you must
// not hand-roll. go-oidc (+ go-jose) is the canonical, minimal-surface choice;
// x/oauth2 provides the auth-code + PKCE primitives. These are the first
// external deps of lattice-server, justified in adr-001 and iteration 001.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/LatticeNet/lattice-sdk/model"
)

// netTimeout bounds every outbound call to an IdP (discovery, JWKS, token
// exchange) so a slow or hostile provider cannot pin request goroutines.
const netTimeout = 10 * time.Second

// Claims is the subset of ID-token claims the identity mapping needs.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Manager performs OIDC flows and caches discovered providers by issuer.
type Manager struct {
	mu         sync.Mutex
	providers  map[string]*oidc.Provider
	httpClient *http.Client
}

// NewManager returns a manager whose outbound IdP calls are timeout-bounded.
func NewManager() *Manager {
	return &Manager{
		providers:  map[string]*oidc.Provider{},
		httpClient: &http.Client{Timeout: netTimeout},
	}
}

// netContext attaches the timeout-bounded client so go-oidc (discovery, JWKS)
// and x/oauth2 (token exchange) both honor it.
func (m *Manager) netContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, m.httpClient)
}

// GenerateCodeVerifier returns a fresh PKCE code verifier (high-entropy,
// URL-safe). The server stores it in the auth state and replays it on exchange.
func GenerateCodeVerifier() string {
	return oauth2.GenerateVerifier()
}

// provider returns a discovered *oidc.Provider for the issuer, caching it.
func (m *Manager) provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	m.mu.Lock()
	p, ok := m.providers[issuer]
	m.mu.Unlock()
	if ok {
		return p, nil
	}
	p, err := oidc.NewProvider(m.netContext(ctx), issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %s: %w", issuer, err)
	}
	m.mu.Lock()
	m.providers[issuer] = p
	m.mu.Unlock()
	return p, nil
}

// scopesFor returns the request scopes, always including openid.
func scopesFor(p model.OIDCProvider) []string {
	if len(p.Scopes) == 0 {
		return []string{oidc.ScopeOpenID, "email", "profile"}
	}
	out := make([]string, 0, len(p.Scopes)+1)
	seenOpenID := false
	for _, s := range p.Scopes {
		if s == oidc.ScopeOpenID {
			seenOpenID = true
		}
		out = append(out, s)
	}
	if !seenOpenID {
		out = append([]string{oidc.ScopeOpenID}, out...)
	}
	return out
}

func (m *Manager) oauthConfig(ctx context.Context, p model.OIDCProvider, redirectURL string) (*oauth2.Config, *oidc.Provider, error) {
	prov, err := m.provider(ctx, p.Issuer)
	if err != nil {
		return nil, nil, err
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopesFor(p),
	}, prov, nil
}

// AuthCodeURL builds the provider authorization URL for an auth-code + PKCE
// (S256) login carrying the given state and nonce.
func (m *Manager) AuthCodeURL(ctx context.Context, p model.OIDCProvider, redirectURL, state, nonce, codeVerifier string) (string, error) {
	cfg, _, err := m.oauthConfig(ctx, p, redirectURL)
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(codeVerifier),
	), nil
}

// Exchange swaps the auth code for tokens (proving the PKCE verifier), then
// verifies the ID token's signature/issuer/audience/expiry and matches the
// nonce. It returns the verified claims.
func (m *Manager) Exchange(ctx context.Context, p model.OIDCProvider, redirectURL, code, codeVerifier, nonce string) (Claims, error) {
	ctx = m.netContext(ctx)
	cfg, prov, err := m.oauthConfig(ctx, p, redirectURL)
	if err != nil {
		return Claims{}, err
	}
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Claims{}, errors.New("oidc: token response missing id_token")
	}
	idTok, err := prov.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, rawID)
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	if idTok.Nonce != nonce {
		return Claims{}, errors.New("oidc: id_token nonce mismatch")
	}
	var raw struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idTok.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("oidc: parse claims: %w", err)
	}
	if raw.Sub == "" {
		return Claims{}, errors.New("oidc: id_token missing sub")
	}
	return Claims{
		Subject:       raw.Sub,
		Email:         raw.Email,
		EmailVerified: raw.EmailVerified,
		Name:          raw.Name,
	}, nil
}
