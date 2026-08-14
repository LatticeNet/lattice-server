package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// subscriptionCacheTTL is the revalidation cadence, not the freshness bound:
	// an expired entry whose content hash still matches is extended without a
	// re-render, so the engine only ever runs when the content actually moved.
	// It aligns with subscriptionRefreshInterval so one poll cycle performs at
	// most one provider fetch and zero renders in the steady state.
	subscriptionCacheTTL = 30 * time.Minute
)

// subscriptionContentHash digests the render input. The bytes themselves are
// never stored on the key; the hash is only ever compared for equality.
func subscriptionContentHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

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

	var cacheEntry subscriptionCacheEntry
	var cached bool
	if share.Source.Kind == model.ShareSourcePlugin {
		cacheEntry, cached = s.subscriptionCacheSnapshotForSource(key, false, s.now())
	} else {
		cacheEntry, cached = s.subscriptionCache.GetSnapshot(key, s.now())
	}
	body, contentType, userinfo := cacheEntry.body, cacheEntry.contentType, cacheEntry.userinfo
	staleResponse, sourceVersion, snapshotFetchedAt := cacheEntry.stale, cacheEntry.publicSourceVersion, cacheEntry.fetchedAt
	if (!cached || staleResponse) && share.Source.Kind == model.ShareSourcePlugin {
		// Revalidate before paying for a render. A render boots the plugin's
		// JavaScript engine, which costs seconds; comparing the content digest
		// costs a store read and, at most, one provider fetch. When the digest
		// still matches, the cached body is exact and is extended. When the
		// source cannot be reached at all, the last good body is served — a
		// provider outage must not take a client's configuration with it, the
		// same rule the snapshot layer applies one step down.
		stale, ok := cacheEntry, cached
		if !ok {
			stale, ok = s.subscriptionCacheSnapshotForSource(key, true, s.now())
		}
		if ok {
			snap, snapErr := s.snapshotFor(r.Context(), share.Source.PluginID, share.Source.SubscriptionID, false)
			switch {
			case snapErr != nil:
				// A persistence failure in snapshotFor is not a successful last-good
				// transition. Do not serve a cached stale body as though the failed
				// attempt had been durably recorded.
				cached = false
			case subscriptionRevalidationVersion(snap) == stale.revalidationVersion:
				if s.subscriptionBeforeCacheExtend != nil {
					s.subscriptionBeforeCacheExtend()
				}
				if !s.subscriptionCache.ExtendSnapshot(key, stale.revision, snap.Userinfo, snap.SourceVersion, snap.Stale, snap.FetchedAt, s.now()) {
					cached = false
					break
				}
				body, contentType, userinfo, cached = stale.body, stale.contentType, snap.Userinfo, true
				staleResponse, sourceVersion, snapshotFetchedAt = snap.Stale, snap.SourceVersion, snap.FetchedAt
			}
		}
	}
	if !cached {
		// Plugin rendering races durable source transitions. A rejected epoch is
		// not merely a cache miss: its body was rendered from superseded authority
		// and therefore must not escape in the current response either. Re-capture
		// and render once more; sustained churn fails closed instead of serving a
		// body whose source transition already committed.
		attempts := 1
		if share.Source.Kind == model.ShareSourcePlugin {
			attempts = 2
		}
		accepted := false
		for attempt := 0; attempt < attempts; attempt++ {
			rendered, renderErr := s.renderShare(r.Context(), share, format, uaClass)
			if renderErr != nil {
				s.logger.Printf("subscription share: render failed for share %s (%s)", share.ID, subscriptionDiagnosticSummary(renderErr))
				deny("subscription_render_failed", map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
				return
			}
			// A client that receives an empty but successful subscription deletes
			// every node it had. Answering with the decoy keeps that from happening
			// AND keeps the emptiness from confirming that the token was real.
			if len(rendered.Body) == 0 {
				deny("empty render refused", map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
				return
			}
			entry := subscriptionCacheEntry{body: rendered.Body, contentType: rendered.ContentType, userinfo: rendered.Userinfo,
				revalidationVersion: rendered.RevalidationVersion, publicSourceVersion: rendered.SourceVersion,
				stale: rendered.Stale, fetchedAt: rendered.FetchedAt}
			if share.Source.Kind == model.ShareSourcePlugin &&
				!s.putSubscriptionCacheForSource(key, share.Source.PluginID, share.Source.SubscriptionID, rendered.SourceEpoch, entry, s.now()) {
				continue
			}
			if share.Source.Kind != model.ShareSourcePlugin {
				s.subscriptionCache.PutSnapshot(key, entry.body, entry.contentType, entry.userinfo, entry.revalidationVersion,
					entry.publicSourceVersion, entry.stale, entry.fetchedAt, s.now())
			}
			body, contentType, userinfo = rendered.Body, rendered.ContentType, rendered.Userinfo
			staleResponse, sourceVersion, snapshotFetchedAt = rendered.Stale, rendered.SourceVersion, rendered.FetchedAt
			accepted = true
			break
		}
		if !accepted {
			deny("subscription_source_changed", map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
			return
		}
	}

	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", contentType)
	if userinfo != "" {
		w.Header().Set("Subscription-Userinfo", userinfo)
	}
	if staleResponse {
		w.Header().Set("X-Lattice-Subscription-Stale", "true")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	metadata := map[string]string{
		"share_id": share.ID, "slug": slug, "token_sha256": tokenHash, "format": format, "ua_class": uaClass,
		"cache": strconv.FormatBool(cached), "stale": strconv.FormatBool(staleResponse), "snapshot_age_seconds": snapshotAgeSeconds(s.now(), snapshotFetchedAt),
	}
	if sourceVersion != "" {
		metadata["source_version"] = sourceVersion
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionShareFetch, Decision: "allow",
		Metadata: metadata,
	})
}

// subscriptionCacheSnapshotForSource linearizes plugin cache reads with source
// publication. A lookup observes either the complete old authority or the
// persisted+bumped+invalidated new authority, never the publication gap.
func (s *Server) subscriptionCacheSnapshotForSource(key subscriptionCacheKey, stale bool, now time.Time) (subscriptionCacheEntry, bool) {
	if waiter := s.subscriptionCacheLookupWaiter; waiter != nil {
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
	s.subscriptionRefreshMu.Lock()
	defer s.subscriptionRefreshMu.Unlock()
	if stale {
		return s.subscriptionCache.GetStale(key)
	}
	return s.subscriptionCache.GetSnapshot(key, now)
}

// subscriptionDiagnosticSummary gives protected runtime logs a bounded
// classification without copying or deriving content from an untrusted
// plugin/provider diagnostic (which can contain low-entropy credentials, URIs,
// keys, or arbitrarily large text) into logs, durable state, or audit evidence.
func subscriptionDiagnosticSummary(err error) string {
	if err == nil {
		return "class=nil bytes=0"
	}
	text := err.Error()
	const maxReportedDiagnosticBytes = 1 << 20
	bytes := len(text)
	if bytes > maxReportedDiagnosticBytes {
		bytes = maxReportedDiagnosticBytes
	}
	return fmt.Sprintf("class=%T bytes<=%d", err, bytes)
}

func snapshotAgeSeconds(now, fetchedAt time.Time) string {
	if fetchedAt.IsZero() || now.Before(fetchedAt) {
		return "0"
	}
	return strconv.FormatInt(int64(now.Sub(fetchedAt)/time.Second), 10)
}

// invalidateSharesForPlugin drops every cached body rendered from one plugin's
// store. A mutating management call (save/delete/import/migrate) can change
// what any of its records render to, and the content hash cannot see it — the
// record, not the content, is what changed — so the edit path invalidates here.
func (s *Server) invalidateSharesForPlugin(pluginID string) {
	for _, share := range s.store.SubscriptionShares() {
		if share.Source.Kind == model.ShareSourcePlugin && share.Source.PluginID == pluginID {
			s.subscriptionCache.InvalidateShare(share.ID)
		}
	}
}

// invalidateSharesForSource drops cached bodies for shares sourcing one record.
// The refresh path calls it when a fetch returns different bytes than the
// stored snapshot.
func (s *Server) invalidateSharesForSource(pluginID, subscriptionID string) {
	for _, share := range s.store.SubscriptionShares() {
		if share.Source.Kind == model.ShareSourcePlugin &&
			share.Source.PluginID == pluginID && share.Source.SubscriptionID == subscriptionID {
			s.subscriptionCache.InvalidateShare(share.ID)
		}
	}
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
		epoch, current := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		if !current {
			return renderedSubscription{}, errors.New("subscription source changed during render capture")
		}
		if s.subscriptionRender != nil {
			rendered, err := s.subscriptionRender(ctx, share, format, uaClass, snap)
			rendered.SourceEpoch = epoch
			return rendered, err
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
		return renderedSubscription{Body: []byte(reply.Content), ContentType: reply.ContentType, Userinfo: snap.Userinfo,
			Stale: snap.Stale, RevalidationVersion: subscriptionRevalidationVersion(snap), SourceVersion: snap.SourceVersion, SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	default:
		return renderedSubscription{}, fmt.Errorf("unknown share source %q", share.Source.Kind)
	}
}

// renderedSubscription is one produced body plus the metadata the core turns
// into response headers. A source never sets a header itself.
type renderedSubscription struct {
	Body                []byte
	ContentType         string
	Userinfo            string
	Stale               bool
	RevalidationVersion string
	SourceVersion       string
	SourceEpoch         uint64
	FetchedAt           time.Time
}
