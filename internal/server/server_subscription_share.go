package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
)

// auditActionShareFetch names the public subscription fetch in the audit log.
const auditActionShareFetch = "subscription.share.fetch"

// shareSlugRe bounds the URL's first segment. It is narrow on purpose: the slug
// carries no authority, so the only jobs it has are to be readable and to be
// incapable of expressing path syntax.
var shareSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// sharePathFromRequest splits /sub/<slug>/<token>.
//
// The single-segment form this replaced was removed rather than kept alongside:
// nothing was subscribed to it, and two shapes would mean a permanent branch here
// with two sets of rules to keep in agreement forever.
//
// The slug is a label, not a secret - it reaches reverse-proxy access logs and
// client screenshots. Authorization rests entirely on the token, which is why
// this function validates the slug's shape but never treats a correct slug as
// evidence of anything.
func sharePathFromRequest(value string) (string, string, bool) {
	rest, ok := strings.CutPrefix(value, "/sub/")
	if !ok {
		return "", "", false
	}
	slug, token, found := strings.Cut(rest, "/")
	if !found || strings.Contains(token, "/") {
		return "", "", false
	}
	if !shareSlugRe.MatchString(slug) || !proxySubTokenRe.MatchString(token) {
		return "", "", false
	}
	return slug, token, true
}

// resolveShare returns a usable share or nothing.
//
// Every rejection - unknown token, mismatched slug, disabled, expired - returns
// the same nothing, and the caller turns all of them into the same 404. A
// response that could distinguish them would tell someone probing the endpoint
// which of its guesses was a real token, which is the one fact the token exists
// to keep.
func (s *Server) resolveShare(slug, token string, now time.Time) (model.SubscriptionShare, bool) {
	share, ok := s.store.SubscriptionShareByToken(token)
	if !ok {
		return model.SubscriptionShare{}, false
	}
	if share.Slug != slug {
		return model.SubscriptionShare{}, false
	}
	if !share.Enabled {
		return model.SubscriptionShare{}, false
	}
	if share.ExpiresAt != nil && !now.Before(*share.ExpiresAt) {
		return model.SubscriptionShare{}, false
	}
	return share, true
}

const (
	// subscriptionCacheEntries bounds the rendered-body cache. classifyClientUA
	// bounds the classes per share, so this is a share-count budget rather than a
	// defence against key explosion.
	subscriptionCacheEntries = 512
	// subscriptionCacheTTL keeps a body reusable for long enough to absorb a
	// client's retry burst without making a rotation take noticeably longer to
	// take effect. Rotation does not wait for it: it invalidates directly.
	subscriptionCacheTTL = 300 * time.Second
)

// handleSubscriptionShare serves the public subscription endpoint.
//
// The core owns every part of this - routing, lookup, rate limiting, audit and
// response headers. A source only ever produces bytes; it cannot see the token,
// set a header, or decide a status code.
func (s *Server) handleSubscriptionShare(w http.ResponseWriter, r *http.Request) {
	// Every rejection below writes the same decoy and audits the real reason.
	// The audit is where an operator finds out what happened; the response is
	// where a prober finds out nothing.
	deny := func(reason string, meta map[string]string) {
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionShareFetch, Decision: "deny",
			Reason: reason, Metadata: meta,
		})
		s.writeSubscriptionDecoy(w)
	}

	if r.Method != http.MethodGet {
		// A 405 would confirm the path exists, so a wrong method is treated as a
		// wrong path.
		deny("method not allowed", map[string]string{"method": r.Method})
		return
	}
	slug, token, ok := sharePathFromRequest(r.URL.Path)
	tokenHash := proxySubTokenAuditHash(token)
	if !ok {
		deny("invalid subscription path", map[string]string{"token_sha256": tokenHash})
		return
	}

	// Format is checked before the token is resolved, so a bad format cannot
	// reveal whether the token was good.
	requested := r.URL.Query().Get("format")
	if strings.TrimSpace(requested) != "" && !subscriptionFormatIsKnown(requested) {
		deny("invalid subscription format", map[string]string{"slug": slug, "token_sha256": tokenHash})
		return
	}

	share, ok := s.resolveShare(slug, token, s.now())
	if !ok {
		deny("subscription not found", map[string]string{"slug": slug, "token_sha256": tokenHash})
		return
	}

	if strings.TrimSpace(requested) == "" {
		requested = share.DefaultFormat
	}
	format, err := normalizeProxySubscriptionFormat(requested)
	if err != nil {
		deny("invalid default subscription format", map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
		return
	}

	uaClass := classifyClientUA(r.Header.Get("User-Agent"))
	key := subscriptionCacheKey{ShareID: share.ID, Format: format, UAClass: uaClass}

	body, contentType, userinfo, cached := s.subscriptionCache.Get(key, s.now())
	if !cached {
		rendered, renderErr := s.renderShare(r.Context(), share, format, uaClass)
		if renderErr != nil {
			deny("render failed: "+renderErr.Error(), map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
			return
		}
		body, contentType, userinfo = rendered.Body, rendered.ContentType, rendered.Userinfo
		// A client that receives an empty but successful subscription deletes
		// every node it had. Answering with the decoy keeps that from happening
		// AND keeps the emptiness from confirming that the token was real.
		if len(body) == 0 {
			deny("empty render refused", map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
			return
		}
		s.subscriptionCache.Put(key, body, contentType, userinfo, s.now())
	}

	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", contentType)
	if userinfo != "" {
		w.Header().Set("Subscription-Userinfo", userinfo)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionShareFetch, Decision: "allow",
		Metadata: map[string]string{
			"share_id":     share.ID,
			"slug":         slug,
			"token_sha256": tokenHash,
			"format":       format,
			"ua_class":     uaClass,
			"cache":        strconv.FormatBool(cached),
		},
	})
}

// renderShare asks the share's source for content. It never shows the source the
// token and never lets it influence the response beyond the bytes and a content
// type.
func (s *Server) renderShare(ctx context.Context, share model.SubscriptionShare, format, uaClass string) (renderedSubscription, error) {
	switch share.Source.Kind {
	case model.ShareSourceCoreProxyUser:
		user, ok := s.store.ProxyUser(share.Source.ProxyUserID)
		if !ok {
			return renderedSubscription{}, errors.New("share source user not found")
		}
		endpoints, _, err := proxycore.VLESSRealityEndpoints(user, s.proxySubscriptionProfiles(), s.store.ProxyInbounds(), proxycore.SubscriptionOptions{Now: s.now()})
		if err != nil {
			return renderedSubscription{}, err
		}
		body, contentType, err := proxySubscriptionBody(format, endpoints)
		if err != nil {
			return renderedSubscription{}, err
		}
		// A fleet's own users have server-computed traffic figures rather than a
		// provider's header.
		return renderedSubscription{Body: body, ContentType: contentType, Userinfo: proxycore.SubscriptionUserinfo(user)}, nil
	case model.ShareSourcePlugin:
		// The snapshot is fetched first so the plugin never has to hold it. A
		// failed refresh with a usable snapshot still renders; only a failure with
		// nothing to fall back on reaches the caller as an error.
		snap, err := s.snapshotFor(ctx, share.Source.PluginID, share.Source.SubscriptionID, false)
		if err != nil {
			return renderedSubscription{}, err
		}
		payload, err := json.Marshal(map[string]string{
			"subscription_id": share.Source.SubscriptionID,
			"format":          format,
			"ua_class":        uaClass,
			"raw":             snap.Raw,
		})
		if err != nil {
			return renderedSubscription{}, err
		}
		// nil budget resolves to the method's own declared budget from the signed
		// manifest, which is the only budget this call should ever run under.
		out, err := s.callRuntimePluginService(ctx, share.Source.PluginID, share.Source.PluginID+"/subscription", "render", payload, nil, nil)
		if err != nil {
			return renderedSubscription{}, err
		}
		var reply struct {
			Content     string `json:"content"`
			ContentType string `json:"content_type"`
		}
		if err := json.Unmarshal(out, &reply); err != nil {
			return renderedSubscription{}, fmt.Errorf("decode plugin render reply: %w", err)
		}
		// The provider's traffic figures are passed through verbatim so the
		// client's remaining-quota display stays truthful.
		return renderedSubscription{Body: []byte(reply.Content), ContentType: reply.ContentType, Userinfo: snap.Userinfo}, nil
	default:
		return renderedSubscription{}, fmt.Errorf("unknown share source %q", share.Source.Kind)
	}
}

// renderedSubscription is one produced body plus the metadata the core turns
// into response headers. A source never sets a header itself.
type renderedSubscription struct {
	Body        []byte
	ContentType string
	Userinfo    string
}
