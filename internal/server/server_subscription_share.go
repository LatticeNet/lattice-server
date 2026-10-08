package server

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
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
// subscriptionShareTargets is the bounded set of client targets a share URL
// may name via ?target= — the Sub-Store URL-parity contract. Bounded on
// purpose: the target participates in the render cache key, and an unbounded
// caller-chosen string there is a cache-exhaustion lever on an
// unauthenticated-by-design endpoint.
var subscriptionShareTargets = map[string]bool{
	"URI": true, "Stash": true, "ClashMeta": true, "Egern": true,
	"Surfboard": true, "Surge": true, "SurgeMac": true, "Loon": true,
	"Shadowrocket": true, "QX": true, "sing-box": true, "V2Ray": true,
	"Clash": true, "JSON": true,
}

// shareRenderVariant carries the explicit render parameters of one request,
// under Sub-Store's own query-parameter names (target, includeUnsupportedProxy,
// prettyYaml, noFlow). The zero value means "no parameters", which renders and
// caches exactly as requests did before the parameters existed.
type shareRenderVariant struct {
	Target             string
	IncludeUnsupported bool
	PrettyYAML         bool
	// NoFlow suppresses the Subscription-Userinfo response header — upstream's
	// "不查询订阅流量信息". It affects only the response envelope, never the
	// rendered body, so it deliberately stays OUT of the cache key.
	NoFlow bool
	// UATarget is the client target the core derived from the agent when the
	// URL named none. A plugin that knows it ranks it below a record's pinned
	// target; a released plugin ignores it and maps ua_class itself. It is a
	// function of the UA class, which the cache key already carries, so it
	// stays out of the key.
	UATarget string
}

// cacheToken is the canonical cache-key fragment. Empty for the zero variant
// so pre-existing cache keys are unchanged. NoFlow is absent by design: the
// cached body is identical either way.
func (v shareRenderVariant) cacheToken() string {
	if v.Target == "" && !v.IncludeUnsupported && !v.PrettyYAML {
		return ""
	}
	token := "t=" + v.Target
	if v.IncludeUnsupported {
		token += ";iup=1"
	}
	if v.PrettyYAML {
		token += ";py=1"
	}
	return token
}

// options is the produce() flag map handed to the plugin, under the flag
// names the embedded Sub-Store core reads. Nil when nothing is set, so old
// plugins see the payload they always saw.
func (v shareRenderVariant) options() map[string]bool {
	if !v.IncludeUnsupported && !v.PrettyYAML {
		return nil
	}
	opts := map[string]bool{}
	if v.IncludeUnsupported {
		opts["include-unsupported-proxy"] = true
	}
	if v.PrettyYAML {
		opts["pretty-yaml"] = true
	}
	return opts
}

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
	// subscriptionCacheEntries is the entry bound test servers give their
	// rendered-body cache. The server's own cache is sized by bytes
	// (subscriptionBodyCacheBytes), because a share's documents range from a
	// few kilobytes to megabytes and an entry count bounds neither.
	subscriptionCacheEntries = 512
	// subscriptionBodyCacheBytes bounds the rendered-body cache.
	subscriptionBodyCacheBytes = 64 << 20
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

// maxSubscriptionUserinfoBytes bounds the quota header. Real values are a few
// dozen bytes of "upload=...; download=...; total=...; expire=..."; anything
// approaching a body is not a quota figure and is dropped rather than truncated,
// because half a number is worse than none for a client parsing it.
const maxSubscriptionUserinfoBytes = 512

// subscriptionUserinfoForResponse returns the quota value a source supplied in
// its canonical form, or nothing when it is too large to be one or carries
// none of the fields clients read (canonicalSubscriptionUserinfo).
func subscriptionUserinfoForResponse(userinfo string) string {
	return canonicalSubscriptionUserinfo(userinfo)
}

// subscriptionResponseContentType decides how the response describes itself,
// from what the core negotiated and nothing else.
//
// The source used to choose this. That contradicted the rule stated at the top
// of this file, that a source produces bytes and does not set headers, and it
// was the one header worth taking: a source answering text/html gets markup
// rendered on the control plane's own origin, which the shipped CSP then admits
// because script-src 'self' is satisfied by anything same-origin.
//
// Both inputs here are already validated by the core before a render is even
// attempted: target against subscriptionShareTargets, format against
// normalizeProxySubscriptionFormat. The target decides the body's shape when the
// caller names a client, otherwise the format does.
func subscriptionResponseContentType(format, target string) string {
	switch target {
	case "":
	case "sing-box", "JSON":
		return "application/json; charset=utf-8"
	case "Clash", "ClashMeta", "Stash":
		return "text/yaml; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
	switch format {
	case proxycore.SubscriptionFormatSingBox:
		return "application/json; charset=utf-8"
	case proxycore.SubscriptionFormatClash, proxycore.SubscriptionFormatClashMeta:
		return "text/yaml; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
}

// handleSubscriptionShare serves the public subscription endpoint.
//
// The core owns the routing, the lookup, the rate limit, the audit trail, the
// status code and the content type. A source never sees the token and cannot
// decide how its bytes are interpreted.
//
// One response header does carry source data, and saying otherwise is what let
// two defects live here: Subscription-Userinfo is the provider's own quota
// figures, which only the provider knows, so it cannot be derived the way the
// content type is. It is passed through under two limits instead. Go's header
// serialiser neutralises CR and LF, so it cannot start a second header, and
// subscriptionUserinfoForResponse bounds its length and keeps only the fields
// clients read, so it cannot be used to spend the response envelope. Nothing
// else a source returns reaches a header.
//
// This is the one serving core for every link kind. Share links pass through
// it today, and identity links are meant to pass through the same stages as
// one more source kind rather than a second handler:
//
//   - resolve the token through the store's HMAC index, one rule for every
//     kind (exactly one match, or the decoy);
//   - decide reachability (enabled, unexpired; for an identity, its policy
//     state) and refuse with the decoy, audited through the refusal throttle,
//     except that a known plugin share in a policy state answers with one
//     placeholder entry naming the state (share_placeholder.go);
//   - plan the render (planShareRender): the client target, the envelope, and
//     a cache key that holds only what changes the bytes;
//   - look the body up against the source's current content version
//     (GetVersioned), so a body the source moved past is never served; the
//     only stale body ever served is a plugin source's last good one during a
//     provider outage;
//   - on a miss, render once per key (renderShareShared) within the link's
//     render budget;
//   - answer first (writeShareBody: length, validator, 304, gzip, and the
//     client headers), then count the fetch (noteShareFetch).
func (s *Server) handleSubscriptionShare(w http.ResponseWriter, r *http.Request) {
	// Every rejection below writes the same decoy and audits the real reason.
	// The audit is where an operator finds out what happened; the response is
	// where a prober finds out nothing. The decoy goes first and the audit is
	// throttled per source and written off the request path, so a refusal
	// never waits on an fsync and a flood cannot buy one write per request.
	deny := func(reason string, meta map[string]string) {
		s.writeSubscriptionDecoy(w)
		s.auditShareRefusal(r, reason, meta)
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

	// A known plugin share whose share or identity is in a policy state gets
	// one readable placeholder entry instead of the decoy (share_placeholder.go).
	// It runs before the route check because a share's route facts, enabled
	// and expiry, are two of those states; the slug it requires is the share's
	// whole route, which is projected as /sub/<slug> on every host.
	if s.servePluginSharePlaceholder(w, r, slug, token, tokenHash, requested, deny) {
		return
	}

	// Reachability is the publishing plane's answer, not this handler's. The
	// record says the URL is published, enabled and unexpired; the token check
	// below says the caller may read it. Both must hold, and both failures are
	// the same nothing on the wire.
	//
	// The record for a share is projected rather than stored. Nothing is
	// migrated, so the URL that is already in a client's configuration cannot be
	// broken by a migration that did not run. Stored route overrides are what
	// let a share move off /sub/, and that is S3's job.
	if _, ok := s.publishingRecordForRequest(originPlugin, requestHost(r.Host), r.URL.Path); !ok {
		deny("subscription not found", map[string]string{"slug": slug, "token_sha256": tokenHash})
		return
	}
	share, ok := s.resolveShare(slug, token, s.now())
	if !ok {
		// Not a share: an identity link is the other kind the index holds,
		// served by the same stages in identity_link.go.
		if s.serveIdentityLink(w, r, slug, token, tokenHash, requested, deny) {
			return
		}
		deny("subscription not found", map[string]string{"slug": slug, "token_sha256": tokenHash})
		return
	}

	if strings.TrimSpace(requested) == "" {
		requested = share.DefaultFormat
	}
	// No format anywhere means "each client's native document".
	native := strings.TrimSpace(requested) == ""
	format, err := normalizeProxySubscriptionFormat(requested)
	if err != nil {
		deny("invalid default subscription format", map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
		return
	}

	clientClass := classifyClientUA(r.Header.Get("User-Agent"))

	// Explicit render parameters, Sub-Store URL style: ?target= names the
	// client outright (validated against the bounded target set — this string
	// enters the cache key), and includeUnsupportedProxy rides through to
	// produce() under upstream's own flag name.
	// Upstream also accepts ?platform= as an alias for ?target=; when both are
	// present, target wins. The alias normalizes into the same variant, so the
	// two spellings share one cache entry.
	explicitTarget := strings.TrimSpace(r.URL.Query().Get("target"))
	if explicitTarget == "" {
		explicitTarget = strings.TrimSpace(r.URL.Query().Get("platform"))
	}
	variant := shareRenderVariant{
		Target:             explicitTarget,
		IncludeUnsupported: requestBool(r, "includeUnsupportedProxy"),
		PrettyYAML:         requestBool(r, "prettyYaml") || requestBool(r, "pretty-yaml"),
		NoFlow:             requestBool(r, "noFlow"),
	}
	if variant.Target != "" && !subscriptionShareTargets[variant.Target] {
		deny("invalid subscription target", map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
		return
	}
	plan := planShareRender(share.Source.Kind, format, native, clientClass, variant)
	format, uaClass, variant := plan.Format, plan.UAClass, plan.Variant

	key := subscriptionCacheKey{ShareID: share.ID, Format: format, UAClass: uaClass, Variant: variant.cacheToken()}

	// A core proxy-user source is rendered on every request. Its render is Go
	// over in-memory state, and a content version that covered everything it
	// reads (the user's status, quota and expiry, profiles, inbounds, node
	// liveness) would cost as much as the render. Caching it without one is
	// what kept a suspended or expired user's nodes on the wire for up to 30
	// minutes. A plugin source is cached, looked up against the content
	// version of the snapshot it was rendered from.
	//
	// The user is resolved once per request and the render uses that same
	// resolution: the identity policy behind it reads the quota's usage (one
	// day-row range read for a monthly quota), which this unauthenticated
	// endpoint should pay once, not twice.
	if share.Source.Kind == model.ShareSourceCoreProxyUser {
		if user, ok := s.coreShareUser(share.Source.ProxyUserID, s.now()); ok {
			plan.CoreUser = &user
		}
	}

	var cacheEntry subscriptionCacheEntry
	var cached bool
	var cacheEpoch uint64
	if share.Source.Kind == model.ShareSourcePlugin {
		// A held vpn-core change expires the cached bodies before the lookup.
		s.settleVPNCoreChanges()
		cacheEntry, cached, cacheEpoch = s.subscriptionCacheSnapshotForSource(share.Source.PluginID, share.Source.SubscriptionID, key, false, s.now())
	}
	// served is the body this response carries; userinfo and the snapshot
	// fields below can be refreshed by revalidation without a new body.
	served := cacheEntry
	userinfo, wireType := cacheEntry.userinfo, cacheEntry.wireType
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
			stale, ok, cacheEpoch = s.subscriptionCacheSnapshotForSource(share.Source.PluginID, share.Source.SubscriptionID, key, true, s.now())
		}
		if ok {
			snap, snapErr := s.snapshotFor(r.Context(), share.Source.PluginID, share.Source.SubscriptionID, false)
			switch {
			case snapErr != nil:
				// A refresh or persistence failure is terminal for this request. A
				// second snapshotFor inside renderShare could observe the committed
				// state and turn a durability-degraded transition into HTTP 200.
				s.logger.Printf("subscription share: refresh failed for share %s (%s)", share.ID, subscriptionDiagnosticSummary(snapErr))
				s.subscriptionCache.InvalidateShare(share.ID)
				deny("subscription_refresh_failed", map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
				return
			case subscriptionRevalidationVersion(snap) == stale.revalidationVersion:
				if s.subscriptionBeforeCacheExtend != nil {
					s.subscriptionBeforeCacheExtend()
				}
				if !s.extendSubscriptionCacheForSource(key, share.Source.PluginID, share.Source.SubscriptionID, cacheEpoch, snap, stale.revision, s.now()) {
					cached = false
					break
				}
				served, userinfo, wireType, cached = stale, snap.Userinfo, stale.wireType, true
				staleResponse, sourceVersion, snapshotFetchedAt = snap.Stale, snap.SourceVersion, snap.FetchedAt
			}
		}
	}
	if !cached {
		var outcome shareRenderOutcome
		if share.Source.Kind == model.ShareSourcePlugin {
			outcome = s.renderShareShared(r.Context(), share, plan, key)
		} else {
			outcome = s.renderShareOnce(r.Context(), share, plan, key)
		}
		if outcome.deny != "" {
			deny(outcome.deny, map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID})
			return
		}
		served = outcome.entry
		userinfo, wireType = served.userinfo, served.wireType
		staleResponse, sourceVersion, snapshotFetchedAt = served.stale, served.publicSourceVersion, served.fetchedAt
	}

	w.Header().Set("Cache-Control", "no-store")
	// Derived, never echoed. Whatever the source put in contentType stays where
	// the core can see it and the client cannot. An entry cached before the
	// type was stored with it falls back to the plan.
	if wireType == "" {
		wireType = shareWireContentType(plan, "")
	}
	w.Header().Set("Content-Type", wireType)
	// ?noFlow=1 keeps quota headers off the wire (upstream's 不查询订阅流量) —
	// some clients probe aggressively when they see one.
	quota := subscriptionUserinfoForResponse(userinfo)
	if variant.NoFlow {
		quota = ""
	}
	if quota != "" {
		w.Header().Set("Subscription-Userinfo", quota)
	}
	if staleResponse {
		w.Header().Set("X-Lattice-Subscription-Stale", "true")
	}
	setLinkClientHeaders(w.Header(), share.Slug, shareUpdateIntervalHours(share))
	body := shareBody{body: served.body, gzipBody: served.gzipBody, hash: served.bodyHash}
	if body.hash == ([32]byte{}) || (body.gzipBody == nil && share.Source.Kind != model.ShareSourcePlugin) {
		body = newShareBody(served.body, acceptsGzip(r), gzip.DefaultCompression)
	}
	// Answer first. Everything below runs after the client has its bytes.
	notModified := writeShareBody(w, r, body, quota)
	s.noteShareFetch(r, shareFetch{shareID: share.ID, slug: slug, tokenHash: tokenHash, family: clientClass,
		cacheHit: cached, notModified: notModified, stale: staleResponse}, func() map[string]string {
		metadata := map[string]string{
			"share_id": share.ID, "slug": slug, "token_sha256": tokenHash, "format": format, "ua_class": clientClass,
			"cache": strconv.FormatBool(cached), "stale": strconv.FormatBool(staleResponse), "snapshot_age_seconds": snapshotAgeSeconds(s.now(), snapshotFetchedAt),
		}
		if sourceVersion != "" {
			metadata["source_version"] = sourceVersion
		}
		return metadata
	})
}

// subscriptionCacheSnapshotForSource linearizes plugin cache reads with source
// publication. A lookup observes either the complete old authority or the
// persisted+bumped+invalidated new authority, never the publication gap.
func (s *Server) subscriptionCacheSnapshotForSource(pluginID, subscriptionID string, key subscriptionCacheKey, stale bool, now time.Time) (subscriptionCacheEntry, bool, uint64) {
	if waiter := s.subscriptionCacheLookupWaiter; waiter != nil {
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
	publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: pluginID, subscriptionID: subscriptionID})
	publication.mu.Lock()
	defer publication.mu.Unlock()
	epoch := publication.epoch
	if stale {
		entry, ok := s.subscriptionCache.GetStale(key)
		return entry, ok, epoch
	}
	// The content version is part of the lookup: a body rendered from any
	// snapshot other than the one stored now is a miss, whatever its TTL. The
	// epoch bookkeeping already invalidates on every committed source change;
	// this makes "a stale body cannot be reached" true by construction rather
	// than by every writer remembering to invalidate.
	version := ""
	if snapshot, ok := s.store.SubscriptionSnapshot(pluginID, subscriptionID); ok {
		version = subscriptionRevalidationVersion(snapshot)
	}
	entry, ok := s.subscriptionCache.GetVersioned(key, version, now)
	return entry, ok, epoch
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
	bySource := make(map[subscriptionRefreshKey][]string)
	// Persisted snapshots remain authority even when their last share is deleted.
	// Include them so a later recreated share cannot bypass the mutation epoch.
	for _, snapshot := range s.store.SubscriptionSnapshots() {
		if snapshot.PluginID == pluginID {
			key := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: snapshot.SubscriptionID}
			bySource[key] = nil
		}
	}
	for _, share := range s.store.SubscriptionShares() {
		if share.Source.Kind == model.ShareSourcePlugin && share.Source.PluginID == pluginID {
			key := subscriptionRefreshKey{pluginID: pluginID, subscriptionID: share.Source.SubscriptionID}
			bySource[key] = append(bySource[key], share.ID)
		}
	}
	// A source may currently have neither a share nor a durable snapshot while a
	// fetch or render is in flight. Copy registry keys under the short global
	// mutex so the mutation still advances those source epochs.
	s.subscriptionRefreshMu.Lock()
	for key := range s.subscriptionPublicationStates {
		if key.pluginID == pluginID {
			if _, ok := bySource[key]; !ok {
				bySource[key] = nil
			}
		}
	}
	for key := range s.subscriptionRefreshFlights {
		if key.pluginID == pluginID {
			if _, ok := bySource[key]; !ok {
				bySource[key] = nil
			}
		}
	}
	s.subscriptionRefreshMu.Unlock()
	keys := make([]subscriptionRefreshKey, 0, len(bySource))
	for key := range bySource {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pluginID != keys[j].pluginID {
			return keys[i].pluginID < keys[j].pluginID
		}
		return keys[i].subscriptionID < keys[j].subscriptionID
	})
	for _, key := range keys {
		publication := s.subscriptionPublicationStateFor(key)
		publication.mu.Lock()
		publication.epoch++
		for _, shareID := range bySource[key] {
			s.subscriptionCache.InvalidateShare(shareID)
		}
		publication.mu.Unlock()
	}
}

// coreShareUser is the user a core.proxy_user share renders: the stored
// legacy record, with the policy of the identity behind it written over it
// (vpnUserPolicy.applyTo). The identity owns whether the user is enabled, its
// expiry, its quota and the usage that quota is measured with, so a share
// serves a user exactly when the policy does (adopted-suspend P12), and its
// quota header carries the identity's figures.
func (s *Server) coreShareUser(proxyUserID string, now time.Time) (model.ProxyUser, bool) {
	user, ok := s.store.ProxyUser(proxyUserID)
	if !ok {
		return model.ProxyUser{}, false
	}
	if identity := s.vpnUserForAccounting(proxyUserID); identity != nil {
		user = s.vpnUserPolicyAt(*identity, now).applyTo(user)
	}
	return user, true
}

// invalidateCoreSourceShares drops every cached body a core source rendered.
// A core share renders a user's own record, so any change to a user or an
// identity can change what it serves; the content hash that guards plugin
// shares does not exist for it. Shares are few, so all core shares go rather
// than working out which identity sits behind which share.
func (s *Server) invalidateCoreSourceShares() {
	for _, share := range s.store.SubscriptionShares() {
		if share.Source.Kind == model.ShareSourceCoreProxyUser {
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
// type. coreUser is a core share's user as the handler resolved it
// (coreShareUser), nil when it was not found; other sources ignore it.
func (s *Server) renderShare(ctx context.Context, share model.SubscriptionShare, format, uaClass string, variant shareRenderVariant, coreUser *model.ProxyUser) (renderedSubscription, error) {
	switch share.Source.Kind {
	case model.ShareSourceCoreProxyUser:
		if coreUser == nil {
			return renderedSubscription{}, errors.New("share source user not found")
		}
		user := *coreUser
		endpoints, _, err := proxycore.VLESSRealityEndpoints(user, s.proxySubscriptionProfiles(), s.store.ProxyInbounds(), proxycore.SubscriptionOptions{Now: s.now(), NodeServiceStates: s.singBoxDownNodes()})
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
			rendered, err := s.subscriptionRender(ctx, share, format, uaClass, variant, snap)
			rendered.SourceEpoch = epoch
			return rendered, err
		}
		payload, err := subscriptionRenderPayload(share.Source.SubscriptionID, format, uaClass, variant, snap.Raw)
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
			// Target is the client the plugin rendered for, once it says. The
			// core labels the response from it only after checking it against
			// the bounded target set.
			Target string `json:"target"`
		}
		if err := json.Unmarshal(out, &reply); err != nil {
			return renderedSubscription{}, fmt.Errorf("decode plugin render reply: %w", err)
		}
		// The provider's traffic figures are passed through verbatim so the
		// client's remaining-quota display stays truthful.
		return renderedSubscription{Body: []byte(reply.Content), ContentType: reply.ContentType, Target: reply.Target, Userinfo: snap.Userinfo,
			Stale: snap.Stale, RevalidationVersion: subscriptionRevalidationVersion(snap), SourceVersion: snap.SourceVersion, SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	default:
		return renderedSubscription{}, fmt.Errorf("unknown share source %q", share.Source.Kind)
	}
}

// subscriptionRenderPayload is the plugin's render request. Explicit render
// parameters ride only when set, so a plugin built before they existed
// receives the exact payload it always did.
func subscriptionRenderPayload(subscriptionID, format, uaClass string, variant shareRenderVariant, raw string) ([]byte, error) {
	fields := map[string]any{
		"subscription_id": subscriptionID,
		"format":          format,
		"ua_class":        pluginUAClass(uaClass),
		"raw":             raw,
	}
	if variant.Target != "" {
		fields["target"] = variant.Target
	} else if variant.UATarget != "" {
		fields["ua_target"] = variant.UATarget
	}
	if opts := variant.options(); opts != nil {
		fields["options"] = opts
	}
	return json.Marshal(fields)
}

// renderedSubscription is one produced body plus the metadata the core turns
// into response headers. A source never sets a header itself.
type renderedSubscription struct {
	Body []byte
	// ContentType is what the source said the bytes are. It is kept for
	// diagnostics and cache bookkeeping and deliberately never reaches the
	// wire; the response type is derived by subscriptionResponseContentType.
	ContentType string
	// Target is the client target the source says it rendered. Unvalidated
	// here; reportedRenderTarget bounds it before it can label anything.
	Target              string
	Userinfo            string
	Stale               bool
	RevalidationVersion string
	SourceVersion       string
	SourceEpoch         uint64
	FetchedAt           time.Time
}
