package server

import (
	"errors"
	"fmt"
	"net/http"
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
)

// shareView is what the operator API returns. It deliberately includes the token:
// the share URL is copied out of the dashboard repeatedly, so hiding it after
// creation would trade a real workflow for protection the at-rest sealing already
// provides.
type shareView struct {
	ID            string            `json:"id"`
	Slug          string            `json:"slug"`
	Token         string            `json:"token"`
	Source        model.ShareSource `json:"source"`
	DefaultFormat string            `json:"default_format,omitempty"`
	Enabled       bool              `json:"enabled"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	RotatedAt     *time.Time        `json:"rotated_at,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
}

func shareViewOf(share model.SubscriptionShare) shareView {
	return shareView{
		ID: share.ID, Slug: share.Slug, Token: share.Token, Source: share.Source,
		DefaultFormat: share.DefaultFormat, Enabled: share.Enabled,
		CreatedAt: share.CreatedAt, UpdatedAt: share.UpdatedAt,
		RotatedAt: share.RotatedAt, ExpiresAt: share.ExpiresAt,
	}
}

func (s *Server) handleSubscriptionShares(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		out := make([]shareView, 0, len(s.store.SubscriptionShares()))
		for _, share := range s.store.SubscriptionShares() {
			out = append(out, shareViewOf(share))
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
	if err := s.store.UpsertSubscriptionShare(share); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	stored, _ := s.store.SubscriptionShare(share.ID)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionShareCreate, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{"share_id": share.ID, "slug": share.Slug, "token_sha256": proxySubTokenAuditHash(token)},
	})
	writeJSON(w, http.StatusCreated, shareViewOf(stored))
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
	case action == "rotate" && r.Method == http.MethodPost:
		s.rotateSubscriptionShare(w, share, p)
	case action == "refresh" && r.Method == http.MethodPost:
		s.refreshSubscriptionShare(w, r, share, p)
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
	writeJSON(w, http.StatusOK, shareViewOf(stored))
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
