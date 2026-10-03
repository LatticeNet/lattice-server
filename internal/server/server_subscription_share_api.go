package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
	"github.com/LatticeNet/lattice-server/internal/id"
)

const (
	auditActionShareCreate = "subscription.share.create"
	auditActionShareRotate = "subscription.share.rotate"
	auditActionShareDelete = "subscription.share.delete"
	auditActionShareUpdate = "subscription.share.update"
)

// shareView is what the operator API returns. It carries no token: a share
// URL is a credential for whatever the share publishes, and the operator's
// rule (2026-10-02) is that a credential reaches a person only after step-up
// and an agent only through secrets:reveal. The token comes from
// POST /api/subscription-shares/<id>/reveal, which asks the one reveal gate
// (secret_reveal.go). It used to be in every list, create, update and rotate
// answer, on the reasoning that copying a link is a frequent workflow; the
// copy now costs one step-up, which lasts a minute.
type shareView struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	// Token is empty in every view. It stays a field so a decoder written
	// for the old shape reads "no token" rather than failing.
	Token         string            `json:"token,omitempty"`
	Source        model.ShareSource `json:"source"`
	DefaultFormat string            `json:"default_format,omitempty"`
	Enabled       bool              `json:"enabled"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	RotatedAt     *time.Time        `json:"rotated_at,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	// UpdateIntervalHours is the refresh period the link advertises to
	// clients (Profile-Update-Interval): the share's own, or the default.
	UpdateIntervalHours int `json:"update_interval_hours"`
	// RenderBudget is the link's plugin render budget, present once the link
	// has rendered since the server started; exhausted means its new renders
	// answer the decoy until it refills. See share_render_budget.go.
	RenderBudget *shareRenderBudgetView `json:"render_budget,omitempty"`
}

func shareViewOf(share model.SubscriptionShare) shareView {
	return shareView{
		ID: share.ID, Slug: share.Slug, Source: share.Source,
		DefaultFormat: share.DefaultFormat, Enabled: share.Enabled,
		CreatedAt: share.CreatedAt, UpdatedAt: share.UpdatedAt,
		RotatedAt: share.RotatedAt, ExpiresAt: share.ExpiresAt,
		UpdateIntervalHours: shareUpdateIntervalHours(share),
	}
}

// shareViewFor is shareViewOf plus the link's live serving state.
func (s *Server) shareViewFor(share model.SubscriptionShare) shareView {
	view := shareViewOf(share)
	view.RenderBudget = s.shareRenderBudget.status(share.ID)
	return view
}

func (s *Server) handleSubscriptionShares(w http.ResponseWriter, r *http.Request, p principal) {
	// A share token renders endpoints from every node's proxy profile, so a
	// share is a fleet-wide object and every sibling global proxy endpoint
	// refuses a node-restricted principal through this same primitive. This
	// REST path was the one door that did not, which let an operator confined
	// to one node list the plaintext share tokens and then fetch the whole
	// fleet's server addresses, REALITY public keys and short ids from the
	// unauthenticated /sub/ delivery path.
	//
	// Not widened: the plugin gateway already applies this rule to the same
	// material (subStoreSharesRPC), so this aligns the REST door with the rule
	// the rest of the surface already enforces.
	if !s.requireGlobalProxyScope(w, p, "proxy:admin") {
		return
	}
	switch r.Method {
	case http.MethodGet:
		out := make([]shareView, 0, len(s.store.SubscriptionShares()))
		for _, share := range s.store.SubscriptionShares() {
			out = append(out, s.shareViewFor(share))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		s.createSubscriptionShare(w, r, p)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) createSubscriptionShare(w http.ResponseWriter, r *http.Request, p principal) {
	var req struct {
		Slug          string            `json:"slug"`
		Source        model.ShareSource `json:"source"`
		DefaultFormat string            `json:"default_format"`
		ExpiresAt     *time.Time        `json:"expires_at"`
		// 0 or absent advertises the default interval.
		UpdateIntervalHours int `json:"update_interval_hours"`
	}
	if !decodeLimitedJSON(w, r, &req, 1<<20) {
		return
	}
	req.Slug = strings.TrimSpace(req.Slug)
	if !shareSlugRe.MatchString(req.Slug) {
		writeError(w, http.StatusBadRequest, errors.New("slug must be lowercase letters, digits and hyphens, starting with a letter or digit"))
		return
	}
	// Two shares with one slug would make the URL ambiguous to a reader even
	// though lookup is by token, so the collision is refused at creation.
	for _, existing := range s.store.SubscriptionShares() {
		if existing.Slug == req.Slug {
			writeError(w, http.StatusConflict, errors.New("a share with this slug already exists"))
			return
		}
	}
	if err := validateShareSource(req.Source); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Source.Kind == model.ShareSourceCoreProxyUser {
		// The public URL answers a share whose user is missing with the same
		// empty 404 as a wrong token, so a share created for a user that never
		// existed would be listed as live and hand out a dead link with no layer
		// saying so. The id is trimmed before the lookup and before storage so
		// the value checked here is the value the render path will look up.
		req.Source.ProxyUserID = strings.TrimSpace(req.Source.ProxyUserID)
		if _, ok := s.store.ProxyUser(req.Source.ProxyUserID); !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("proxy user %s does not exist", req.Source.ProxyUserID))
			return
		}
	}
	if req.DefaultFormat != "" {
		if _, err := normalizeProxySubscriptionFormat(req.DefaultFormat); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	token, err := s.newUniqueShareToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	share := model.SubscriptionShare{
		ID: id.New("share"), SchemaVersion: model.SubscriptionShareSchemaVersion,
		Slug: req.Slug, Token: token, Source: req.Source,
		DefaultFormat: req.DefaultFormat, Enabled: true, ExpiresAt: req.ExpiresAt,
	}
	share, err = withShareUpdateIntervalHours(share, req.UpdateIntervalHours)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	stored, _ := s.store.SubscriptionShare(share.ID)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionShareCreate, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{"share_id": share.ID, "slug": share.Slug, "token_sha256": proxySubTokenAuditHash(token)},
	})
	writeJSON(w, http.StatusCreated, s.shareViewFor(stored))
}

// handleSubscriptionShareItem serves /api/subscription-shares/<id> and
// /api/subscription-shares/<id>/rotate.
func (s *Server) handleSubscriptionShareItem(w http.ResponseWriter, r *http.Request, p principal) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/subscription-shares/")
	shareID, action, _ := strings.Cut(rest, "/")
	if shareID == "" || strings.Contains(action, "/") {
		writeError(w, http.StatusNotFound, errors.New("share not found"))
		return
	}
	share, ok := s.store.SubscriptionShare(shareID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("share not found"))
		return
	}

	switch {
	case action == "reveal" && r.Method == http.MethodPost:
		s.revealSubscriptionShare(w, r, share, p)
	case action == "rotate" && r.Method == http.MethodPost:
		s.rotateSubscriptionShare(w, share, p)
	case action == "refresh" && r.Method == http.MethodPost:
		s.refreshSubscriptionShare(w, r, share, p)
	case action == "" && r.Method == http.MethodPatch:
		s.updateSubscriptionShare(w, r, share, p)
	case action == "" && r.Method == http.MethodDelete:
		if err := s.store.DeleteSubscriptionShare(share.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// Drop any cached body immediately. Without this the deleted URL keeps
		// answering from cache until its TTL, which is the opposite of what
		// deleting it means.
		s.subscriptionCache.InvalidateShare(share.ID)
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionShareDelete, Scope: "proxy:admin", Decision: "allow",
			Metadata: map[string]string{"share_id": share.ID, "slug": share.Slug, "token_sha256": proxySubTokenAuditHash(share.Token)},
		})
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// auditActionShareReveal names a share token handed to an operator.
const auditActionShareReveal = "subscription.share.reveal"

// linkRevealView is a link's secret part, the answer of every link reveal
// door: share and identity links alike, REST and RPC alike.
type linkRevealView struct {
	Kind string `json:"kind"` // share | identity
	ID   string `json:"id"`
	Slug string `json:"slug"`
	// Token is the bearer secret; Path is /sub/<slug>/<token>; URL is Path
	// under the configured public base, absent when the server has none.
	Token string `json:"token"`
	Path  string `json:"path"`
	URL   string `json:"url,omitempty"`
}

func (s *Server) linkRevealViewOf(kind, id, slug, token string) linkRevealView {
	path := "/sub/" + slug + "/" + token
	view := linkRevealView{Kind: kind, ID: id, Slug: slug, Token: token, Path: path}
	if base := strings.TrimRight(s.publicURL, "/"); base != "" {
		view.URL = base + path
	}
	return view
}

// revealSubscriptionShare hands a share's token to a principal the reveal
// gate admits. The request body is {"step_up_grant": "..."}; a token
// carrying secrets:reveal sends none.
func (s *Server) revealSubscriptionShare(w http.ResponseWriter, r *http.Request, share model.SubscriptionShare, p principal) {
	var req struct {
		StepUpGrant string `json:"step_up_grant"`
	}
	if !decodeLimitedJSON(w, r, &req, 4<<10) {
		return
	}
	ev := model.AuditEvent{Action: auditActionShareReveal, Scope: "proxy:admin",
		Metadata: map[string]string{"share_id": share.ID, "slug": share.Slug, "token_sha256": proxySubTokenAuditHash(share.Token)}}
	reveal, ok := s.requireSecretReveal(w, p, req.StepUpGrant, ev)
	if !ok {
		return
	}
	s.recordSecretReveal(p, reveal, ev)
	writeJSON(w, http.StatusOK, s.linkRevealViewOf("share", share.ID, share.Slug, share.Token))
}

// updateSubscriptionShare changes a share without minting a new URL.
//
// Expiry was settable only at creation, so an operator who wanted to extend a
// share had to delete it and hand out a new link — which is the one thing a
// share exists to avoid. Rotation stays a separate action because it does
// invalidate the URL, and conflating the two would make an edit silently break
// every client holding the old one.
func (s *Server) updateSubscriptionShare(w http.ResponseWriter, r *http.Request, share model.SubscriptionShare, p principal) {
	var req struct {
		// Pointers so "not supplied" is distinguishable from "cleared". A share
		// that never expires and a share whose expiry was not mentioned are
		// different requests, and treating them the same would silently make
		// every edit remove the expiry.
		ExpiresAt     *time.Time `json:"expires_at"`
		ClearExpiry   bool       `json:"clear_expiry"`
		DefaultFormat *string    `json:"default_format"`
		Enabled       *bool      `json:"enabled"`
		// UpdateIntervalHours sets the advertised refresh period; 0 returns
		// the share to the default.
		UpdateIntervalHours *int `json:"update_interval_hours"`
	}
	if !decodeLimitedJSON(w, r, &req, 1<<20) {
		return
	}
	if req.ClearExpiry && req.ExpiresAt != nil {
		writeError(w, http.StatusBadRequest, errors.New("expires_at and clear_expiry cannot both be set"))
		return
	}

	before := share.ExpiresAt
	switch {
	case req.ClearExpiry:
		share.ExpiresAt = nil
	case req.ExpiresAt != nil:
		when := req.ExpiresAt.UTC()
		// An expiry already in the past would create a share that is dead on
		// arrival, and the endpoint answers a dead share exactly like a wrong
		// token — so the operator would get no feedback at all.
		if !when.After(s.now()) {
			writeError(w, http.StatusBadRequest, errors.New("expires_at must be in the future"))
			return
		}
		share.ExpiresAt = &when
	}
	if req.DefaultFormat != nil {
		format := strings.TrimSpace(*req.DefaultFormat)
		if format != "" && !subscriptionFormatIsKnown(format) {
			writeError(w, http.StatusBadRequest, errors.New("unknown subscription format"))
			return
		}
		share.DefaultFormat = format
	}
	if req.Enabled != nil {
		share.Enabled = *req.Enabled
	}
	if req.UpdateIntervalHours != nil {
		updated, err := withShareUpdateIntervalHours(share, *req.UpdateIntervalHours)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		share = updated
	}
	share.UpdatedAt = s.now()

	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// The cached body was rendered under the old settings. A format change makes
	// it the wrong bytes, and a share that has just been disabled must stop
	// answering now rather than when the entry happens to expire.
	s.subscriptionCache.InvalidateShare(share.ID)

	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionShareUpdate, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{
			"share_id":              share.ID,
			"slug":                  share.Slug,
			"token_sha256":          proxySubTokenAuditHash(share.Token),
			"expires_from":          formatShareExpiry(before),
			"expires_to":            formatShareExpiry(share.ExpiresAt),
			"enabled":               strconv.FormatBool(share.Enabled),
			"update_interval_hours": strconv.Itoa(shareUpdateIntervalHours(share)),
		},
	})
	stored, _ := s.store.SubscriptionShare(share.ID)
	writeJSON(w, http.StatusOK, s.shareViewFor(stored))
}

// formatShareExpiry renders an expiry for the audit trail. "never" rather than
// an empty string, so a log reader cannot mistake it for a missing field.
func formatShareExpiry(at *time.Time) string {
	if at == nil {
		return "never"
	}
	return at.UTC().Format(time.RFC3339)
}

func (s *Server) rotateSubscriptionShare(w http.ResponseWriter, share model.SubscriptionShare, p principal) {
	oldToken := share.Token
	token, err := s.newUniqueShareToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	now := s.now()
	share.Token = token
	share.RotatedAt = &now
	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Rotation is a lie if the old URL keeps working, and a cached body is served
	// without ever consulting the token, so the cache must be dropped here rather
	// than left to expire.
	if share.Source.Kind == model.ShareSourcePlugin {
		s.invalidateSharesForSource(share.Source.PluginID, share.Source.SubscriptionID)
	} else {
		s.subscriptionCache.InvalidateShare(share.ID)
	}
	s.shareRenderBudget.reset(share.ID)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionShareRotate, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{
			"share_id":         share.ID,
			"slug":             share.Slug,
			"old_token_sha256": proxySubTokenAuditHash(oldToken),
			"new_token_sha256": proxySubTokenAuditHash(token),
		},
	})
	stored, _ := s.store.SubscriptionShare(share.ID)
	writeJSON(w, http.StatusOK, s.shareViewFor(stored))
}

// refreshSubscriptionShare forces a provider fetch now rather than waiting for
// the lazy refresh a client poll would trigger. It reports what happened rather
// than only whether it succeeded: a refresh that failed but still has a usable
// snapshot is a different situation from one that has nothing, and the operator
// needs to tell them apart.
func (s *Server) refreshSubscriptionShare(w http.ResponseWriter, r *http.Request, share model.SubscriptionShare, p principal) {
	if share.Source.Kind != model.ShareSourcePlugin {
		writeError(w, http.StatusBadRequest, errors.New("only a plugin-sourced share has a provider to refresh"))
		return
	}
	snap, err := s.snapshotFor(r.Context(), share.Source.PluginID, share.Source.SubscriptionID, true)
	if err != nil {
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionSubscriptionFetch, Scope: "proxy:admin", Decision: "deny",
			Reason:   "manual refresh failed with no snapshot to fall back to",
			Metadata: map[string]string{"share_id": share.ID, "slug": share.Slug},
		})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// A forced refresh always invalidates: the whole point is to make the next
	// fetch see new content, and a cached body would hide it.
	s.invalidateSharesForSource(share.Source.PluginID, share.Source.SubscriptionID)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubscriptionFetch, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{"share_id": share.ID, "slug": share.Slug, "stale": fmt.Sprintf("%t", snap.FetchError != "")},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"fetched_at": snap.FetchedAt,
		"bytes":      len(snap.Raw),
		"stale":      snap.FetchError != "",
		"error":      snap.FetchError,
	})
}

func validateShareSource(source model.ShareSource) error {
	switch source.Kind {
	case model.ShareSourceCoreProxyUser:
		if strings.TrimSpace(source.ProxyUserID) == "" {
			return errors.New("a core.proxy_user source requires proxy_user_id")
		}
		if source.PluginID != "" || source.SubscriptionID != "" {
			return errors.New("a core.proxy_user source must not name a plugin")
		}
	case model.ShareSourcePlugin:
		if strings.TrimSpace(source.PluginID) == "" || strings.TrimSpace(source.SubscriptionID) == "" {
			return errors.New("a plugin source requires plugin_id and subscription_id")
		}
		if source.ProxyUserID != "" {
			return errors.New("a plugin source must not name a proxy user")
		}
	default:
		return errors.New("source kind must be core.proxy_user or plugin")
	}
	return nil
}

// newUniqueShareToken mints a token that no existing share holds. It reuses the
// same 256-bit primitive the proxy-user subscription token uses: a share URL is
// unauthenticated, so its only protection is that the token cannot be guessed.
func (s *Server) newUniqueShareToken() (string, error) {
	for i := 0; i < 8; i++ {
		token, err := auth.NewRandomToken(32)
		if err != nil {
			return "", err
		}
		if _, taken := s.store.SubscriptionShareByToken(token); !taken {
			return token, nil
		}
	}
	return "", errors.New("could not generate a unique share token")
}
