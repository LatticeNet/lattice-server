package server

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
)

// A known plugin share token whose share or identity is in a policy state
// gets one readable placeholder entry, the way an identity link answers for
// an identity that is not active (identity_link.go): the client shows a node
// named for the reason instead of an error, and keeps polling. Everything
// else stays the decoy: an unknown token, a slug that does not match, an
// archived share, a share that is not Sub-Store's, a bad format or target, a
// rate limit (design 28, share serving and tokens).

// Reasons a plugin share answers with the placeholder, as the fetch audit
// names them. An identity in a policy state is "identity_" plus the policy's
// own reason (disabled, operator, expiry, quota).
const (
	sharePlaceholderDisabled        = "share_disabled"
	sharePlaceholderExpired         = "share_expired"
	sharePlaceholderIdentityMissing = "identity_missing"

	// sharePlaceholderCachePrefix keys a placeholder document in the
	// identity link cache, apart from the share's own bodies and from any
	// identity link.
	sharePlaceholderCachePrefix = "share-placeholder:"
)

type pluginSharePlaceholder struct {
	share   model.SubscriptionShare
	reason  string
	message string
	// policy fills the exhausted Subscription-Userinfo: the identity's own
	// when the identity is the reason, else one carrying the share's expiry.
	policy vpnUserPolicy
}

// pluginSharePlaceholderFor reports whether token names a Sub-Store share,
// under this slug and not archived, that is disabled, expired, or bound to an
// identity that is missing or not active. Another plugin's share in a policy
// state answers as a core share does: the decoy.
func (s *Server) pluginSharePlaceholderFor(slug, token string, now time.Time) (pluginSharePlaceholder, bool) {
	share, ok := s.store.SubscriptionShareByToken(token)
	if !ok || share.Slug != slug || !isSubStoreShare(share) || share.ArchivedAt != nil {
		return pluginSharePlaceholder{}, false
	}
	answer := pluginSharePlaceholder{share: share}
	if share.ExpiresAt != nil {
		answer.policy.ExpiresAt = *share.ExpiresAt
	}
	switch {
	case !share.Enabled:
		answer.reason, answer.message = sharePlaceholderDisabled, "Disabled by the operator"
	case share.ExpiresAt != nil && !now.Before(*share.ExpiresAt):
		answer.reason, answer.message = sharePlaceholderExpired, "Expired on "+share.ExpiresAt.UTC().Format("2006-01-02")
	case strings.TrimSpace(share.Source.IdentityID) != "":
		u, ok := s.getVpnUser(share.Source.IdentityID)
		if !ok {
			answer.reason, answer.message = sharePlaceholderIdentityMissing, "Not in service"
			break
		}
		policy := s.vpnUserPolicyAt(u, now)
		if policy.Active() {
			return pluginSharePlaceholder{}, false
		}
		answer.reason, answer.message, answer.policy = "identity_"+policy.Reason, identityLinkPolicyMessage(policy), policy
	default:
		return pluginSharePlaceholder{}, false
	}
	return answer, true
}

// servePluginSharePlaceholder answers a /sub/ request whose token names a
// Sub-Store share in a policy state. It returns false, writing nothing, for any
// other token, so the caller's share and identity link paths answer it.
func (s *Server) servePluginSharePlaceholder(w http.ResponseWriter, r *http.Request, slug, token, tokenHash, requested string, deny func(string, map[string]string)) bool {
	answer, ok := s.pluginSharePlaceholderFor(slug, token, s.now())
	if !ok {
		return false
	}
	share := answer.share
	meta := func(extra map[string]string) map[string]string {
		md := map[string]string{"slug": slug, "token_sha256": tokenHash, "share_id": share.ID, "answer": identityAnswerPlaceholder, "reason": answer.reason}
		for k, v := range extra {
			md[k] = v
		}
		return md
	}
	if strings.TrimSpace(requested) == "" {
		requested = share.DefaultFormat
	}
	native := strings.TrimSpace(requested) == ""
	format, err := normalizeProxySubscriptionFormat(requested)
	if err != nil {
		deny("invalid default subscription format", meta(nil))
		return true
	}
	target, uaClass, ok := identityLinkTarget(r, format, native)
	if !ok {
		deny("invalid subscription target", meta(nil))
		return true
	}
	variant := shareRenderVariant{Target: target, IncludeUnsupported: requestBool(r, "includeUnsupportedProxy"),
		PrettyYAML: requestBool(r, "prettyYaml") || requestBool(r, "pretty-yaml"), NoFlow: requestBool(r, "noFlow")}
	entries := []string{identityLinkPlaceholderEntry(answer.message)}
	served, failure := s.sharePlaceholderDocument(r.Context(), share.ID, entries, format, variant)
	if failure != "" {
		deny(failure, meta(nil))
		return true
	}
	// A share with an age recipient answers in age, as its live body does
	// (share_render_flight.go), so a policy state is not told apart by being
	// plaintext. The placeholder holds no credential, so it is sealed per
	// request, as a core-sourced body is, and its cached document stays plain.
	sealedBody, sealed, err := subStoreSvcSealShareBody(share, served.body)
	if err != nil {
		s.logger.Printf("subscription share: age encryption failed for share %s (%s)", share.ID, subscriptionDiagnosticSummary(err))
		deny("subscription_age_failed", meta(nil))
		return true
	}
	if sealed {
		// The body is age armor now, not the base64 URI list a converter
		// fallback names, so the fallback header is not sent.
		served = identityLinkBody{body: sealedBody, wireType: subStoreSvcAgeWireType, cacheHit: served.cacheHit}
	}

	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", served.wireType)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	if served.fallback != "" {
		header.Set("X-Lattice-Subscription-Fallback", "base64-uri; requested="+served.fallback+"; reason=converter_unavailable")
	}
	quota := identityLinkUserinfo(answer.policy, true)
	if variant.NoFlow {
		quota = ""
	}
	if quota != "" {
		header.Set("Subscription-Userinfo", quota)
	}
	setLinkClientHeaders(header, slug, shareUpdateIntervalHours(share))
	body := shareBody{body: served.body, gzipBody: served.gzipBody, hash: served.hash}
	if body.hash == ([32]byte{}) || body.gzipBody == nil {
		body = newShareBody(served.body, acceptsGzip(r), gzip.DefaultCompression)
	}
	notModified := writeShareBody(w, r, body, quota)
	s.noteShareFetch(r, shareFetch{shareID: share.ID, slug: slug, tokenHash: tokenHash, family: uaClass,
		cacheHit: served.cacheHit, notModified: notModified}, func() map[string]string {
		return meta(map[string]string{"target": firstNonEmpty(variant.Target, "URI"), "ua_class": uaClass,
			"cache": strconv.FormatBool(served.cacheHit)})
	})
	return true
}

// sharePlaceholderDocument writes the placeholder in the requested client's
// document, as identityLinkDocument writes an identity link's: the URI list in
// core, every other client through the Sub-Store convert method, cached by
// content digest in the identity link cache and converted once per key.
func (s *Server) sharePlaceholderDocument(ctx context.Context, shareID string, entries []string, format string, variant shareRenderVariant) (identityLinkBody, string) {
	raw := strings.Join(entries, "\n")
	if identityLinkIsURITarget(variant.Target) {
		if format == proxycore.SubscriptionFormatPlain && variant.Target != "V2Ray" {
			return identityLinkBody{body: []byte(raw), wireType: "text/plain; charset=utf-8"}, ""
		}
		return identityLinkBody{body: []byte(base64.StdEncoding.EncodeToString([]byte(raw))), wireType: "text/plain; charset=utf-8"}, ""
	}
	if !s.identityLinkConvertAvailable() {
		return identityLinkBody{body: []byte(base64.StdEncoding.EncodeToString([]byte(raw))), wireType: "text/plain; charset=utf-8", fallback: variant.Target}, ""
	}
	sum := sha256.Sum256([]byte(raw))
	version := hex.EncodeToString(sum[:])
	key := subscriptionCacheKey{ShareID: sharePlaceholderCachePrefix + shareID, Format: "convert", UAClass: "other", Variant: variant.cacheToken()}
	if entry, ok := s.identityLinkCache.GetVersioned(key, version, s.now()); ok {
		return identityLinkBody{body: entry.body, gzipBody: entry.gzipBody, hash: entry.bodyHash, wireType: entry.wireType, cacheHit: true}, ""
	}
	outcome := s.convertIdentityLinkShared(ctx, key, version, entries, variant)
	if outcome.deny != "" {
		return identityLinkBody{}, outcome.deny
	}
	return identityLinkBody{body: outcome.entry.body, gzipBody: outcome.entry.gzipBody, hash: outcome.entry.bodyHash, wireType: outcome.entry.wireType}, ""
}
