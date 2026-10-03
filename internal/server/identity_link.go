package server

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Per-identity subscription links (identity-sub P5, design B), served by the
// same /sub/<slug>/<token> handler and serving core as share links.
//
// One identity, one link. The token is the identity's SubID, sealed at rest
// and indexed by HMAC in the store's link index next to share tokens, so a
// token is resolved by one rule whatever kind it is. A user gets only their
// own lines: the body is built from this identity's record and nothing else,
// one entry per line where the node is known to hold this identity's current
// credential (LineBinding.AppliedCredentialSHA256 matches it now), each built
// from the line's credential-free client template with this identity's own
// credential filled in (lineClientURI). Every other bound line is left out
// and counted with a reason the console shows.
//
// What a link answers follows the identity's policy, read per request:
//
//   - active, with at least one line: the nodes;
//   - active, no line bound yet: one placeholder entry, "No lines assigned
//     yet";
//   - active, bound, but nothing includable now (a rotation not applied yet,
//     templates not reported since a restart, every line down): the decoy,
//     so a client keeps the nodes it has instead of replacing them with none;
//   - disabled, suspended, expired or over quota: one placeholder entry
//     naming the reason, with an exhausted Subscription-Userinfo (the
//     operator default of 2026-10-02);
//   - unknown token, wrong slug, link disabled or past its expiry, a rotated
//     or revoked token, a deleted identity: the identical decoy.
//
// Nothing about the body is cached except a converted client document, and
// that is keyed by a digest of the identity's own entries, so a suspension,
// expiry, rotation or delete changes what the request builds and a stale body
// cannot be reached. Subscription-Userinfo is computed per request from the
// policy projection.

const (
	identityLinkKind = "identity"
	// identityLinkStatsPrefix keys an identity link in the share-keyed
	// serving state (fetch counters, render budget, cache).
	identityLinkStatsPrefix = "identity:"
	// identityLinkSlugPrefix starts a default slug.
	identityLinkSlugPrefix = "u-"
	// identityLinkCacheEntries bounds converted identity documents; about
	// four client families for a hundred identities, kept apart from the
	// share cache so identity traffic cannot evict share bodies.
	identityLinkCacheEntries = 512
	// identityLinkCacheTTL is long because the key carries the content
	// digest: an entry is only ever exact or unreachable.
	identityLinkCacheTTL = 6 * time.Hour
	// identityLinkConvertTimeout bounds one convert call.
	identityLinkConvertTimeout = 30 * time.Second

	// identityLinkPlaceholderUUID and host make the placeholder entry: a
	// node that names the reason and carries no real host or credential.
	identityLinkPlaceholderUUID = "00000000-0000-0000-0000-000000000000"
	identityLinkPlaceholderHost = "127.0.0.1:1"
)

// Answer kinds and reasons, as the link status read and the fetch audit name
// them.
const (
	identityAnswerNodes       = "nodes"
	identityAnswerPlaceholder = "placeholder"
	identityAnswerDecoy       = "decoy"

	identityReasonActive         = "active"
	identityReasonNoLines        = "no_lines"
	identityReasonTransientEmpty = "transient_empty"
	identityReasonLinkDisabled   = "link_disabled"
	identityReasonLinkExpired    = "link_expired"
	identityReasonNotIssued      = "not_issued"
)

// Why a bound line is left out of the link, and what fixes it.
const (
	identityLineBindingDisabled   = "binding_disabled"
	identityLineUnknown           = "line_unknown"
	identityLineManaged           = "managed_line_unsupported"
	identityLineProtocol          = "protocol_unsupported"
	identityLineNotApplied        = "credential_not_applied"
	identityLineRotationPending   = "rotation_not_applied"
	identityLineCredentialUnknown = "credential_unknown"
	identityLineParked            = "parked_on_line"
	identityLineNoTemplate        = "no_client_template"
	identityLineTemplateLossy     = "template_lossy"
	identityLineTemplateUnusable  = "template_unusable"
	identityLineServiceDown       = "service_down"

	identityFixPlanAdd        = "plan_add"
	identityFixPlanUpdate     = "plan_update"
	identityFixWaitDiscovery  = "wait_for_discovery"
	identityFixWaitTemplate   = "wait_for_template"
	identityFixResume         = "resume"
	identityFixCheckService   = "check_line_service"
	identityFixWaitAllocation = "wait_for_line_uuid"
)

// VpnUserLink is the store's link record.
type VpnUserLink = store.VpnUserLink

func cloneVpnUserLinkRecord(in *VpnUserLink) *VpnUserLink {
	if in == nil {
		return nil
	}
	out := *in
	if in.RotatedAt != nil {
		at := *in.RotatedAt
		out.RotatedAt = &at
	}
	if in.ExpiresAt != nil {
		at := *in.ExpiresAt
		out.ExpiresAt = &at
	}
	return &out
}

// vpnUserLinkSummary is the link as a list shows it: route facts, never the
// token.
type vpnUserLinkSummary struct {
	Slug                string     `json:"slug"`
	Enabled             bool       `json:"enabled"`
	IssuedAt            time.Time  `json:"issued_at"`
	RotatedAt           *time.Time `json:"rotated_at,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	UpdateIntervalHours int        `json:"update_interval_hours"`
}

func vpnUserLinkSummaryOf(link *VpnUserLink) *vpnUserLinkSummary {
	if link == nil {
		return nil
	}
	copied := cloneVpnUserLinkRecord(link)
	return &vpnUserLinkSummary{Slug: copied.Slug, Enabled: !copied.Disabled, IssuedAt: copied.IssuedAt,
		RotatedAt: copied.RotatedAt, ExpiresAt: copied.ExpiresAt, UpdateIntervalHours: identityLinkUpdateIntervalHours(copied)}
}

func identityLinkUpdateIntervalHours(link *VpnUserLink) int {
	if link == nil || link.UpdateIntervalHours < 1 || link.UpdateIntervalHours > maxLinkUpdateIntervalHours {
		return defaultLinkUpdateIntervalHours
	}
	return link.UpdateIntervalHours
}

// identityLinkLine is one bound line as the link status read reports it.
type identityLinkLine struct {
	LineHashID string `json:"line_hash_id"`
	NodeID     string `json:"node_id,omitempty"`
	NodeName   string `json:"node_name,omitempty"`
	LineName   string `json:"line_name,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	// Reason and Fix are set on a line left out: why, and the action that
	// would bring it in. Detail names what a reason needs spelled out (the
	// parameters a lossy template dropped), never a value.
	Reason string `json:"reason,omitempty"`
	Fix    string `json:"fix,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// identityLinkContent is what one identity's link serves now.
type identityLinkContent struct {
	// Entries are the client URIs in serving order. They carry this
	// identity's credential and never leave the serving path.
	Entries  []string
	Included []identityLinkLine
	Excluded []identityLinkLine
	// BoundLines counts the identity's enabled bindings.
	BoundLines int
}

// digest is the content version a converted body is cached under. It is
// derived from credential-bearing entries and never leaves the process.
func (c identityLinkContent) digest() string {
	sum := sha256.Sum256([]byte(strings.Join(c.Entries, "\n")))
	return hex.EncodeToString(sum[:])
}

type identityLinkCandidate struct {
	label, sortNode, sortLine, hash, uri string
}

// identityLinkContent builds the identity's entries from its own record, the
// line read model and the stored client templates. It reads nothing about
// any other identity.
func (s *Server) identityLinkContent(u VpnUser) identityLinkContent {
	groups, index := s.lineReadModel()
	nodeNames := make(map[string]string, len(groups))
	for _, g := range groups {
		nodeNames[g.NodeID] = g.NodeName
	}
	var out identityLinkContent
	var candidates []identityLinkCandidate
	for _, b := range u.Bindings {
		line := identityLinkLine{LineHashID: b.LineHashID}
		exclude := func(reason, fix, detail string) {
			line.Reason, line.Fix, line.Detail = reason, fix, detail
			out.Excluded = append(out.Excluded, line)
		}
		if !b.Enabled {
			exclude(identityLineBindingDisabled, "", "")
			continue
		}
		out.BoundLines++
		ln, known := index[b.LineHashID]
		if known {
			line.NodeID, line.NodeName = ln.NodeID, firstNonEmpty(nodeNames[ln.NodeID], ln.NodeID)
			line.LineName = identityLinkLineName(ln)
			line.Protocol = strings.ToLower(strings.TrimSpace(ln.Type))
		}
		switch {
		case !known:
			exclude(identityLineUnknown, identityFixWaitDiscovery, "")
			continue
		case ln.Managed:
			// The managed render path would need the applied-credential
			// check against the managed render (identity-ground deferred
			// it); production has no managed lines.
			exclude(identityLineManaged, "", "")
			continue
		case !lineUserProtocols[line.Protocol]:
			exclude(identityLineProtocol, "", "")
			continue
		}
		switch lineBindingCredentialState(u, b, ln, true) {
		case lineCredentialCurrent:
		case lineCredentialStale:
			exclude(identityLineRotationPending, identityFixPlanUpdate, "")
			continue
		case lineCredentialUnknown:
			exclude(identityLineCredentialUnknown, identityFixWaitAllocation, "")
			continue
		default:
			exclude(identityLineNotApplied, identityFixPlanAdd, "")
			continue
		}
		name := userLineName(u.ID, ln.LineUUID)
		if identityLinkParked(ln, name) {
			exclude(identityLineParked, identityFixResume, "")
			continue
		}
		if ln.ServiceState == "down" {
			exclude(identityLineServiceDown, identityFixCheckService, "")
			continue
		}
		template, ok := s.store.LineClientTemplate(ln.LineHashID)
		if !ok || template.NodeID != ln.NodeID || template.LineUUID != ln.LineUUID {
			exclude(identityLineNoTemplate, identityFixWaitTemplate, "")
			continue
		}
		if template.Lossy() {
			exclude(identityLineTemplateLossy, "", strings.Join(template.Dropped, ", "))
			continue
		}
		payload, err := lineUserCredential(u, template.Protocol, name)
		if err != nil {
			exclude(identityLineTemplateUnusable, "", "")
			continue
		}
		label := identityLinkEntryLabel(line.NodeName, line.LineName)
		uri, err := lineClientURI(template, payload, label)
		if err != nil {
			exclude(identityLineTemplateUnusable, "", "")
			continue
		}
		out.Included = append(out.Included, line)
		candidates = append(candidates, identityLinkCandidate{label: label, sortNode: line.NodeName, sortLine: line.LineName, hash: ln.LineHashID, uri: uri})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].sortNode != candidates[j].sortNode {
			return candidates[i].sortNode < candidates[j].sortNode
		}
		if candidates[i].sortLine != candidates[j].sortLine {
			return candidates[i].sortLine < candidates[j].sortLine
		}
		return candidates[i].hash < candidates[j].hash
	})
	for _, c := range candidates {
		out.Entries = append(out.Entries, c.uri)
	}
	sortIdentityLinkLines(out.Included)
	sortIdentityLinkLines(out.Excluded)
	return out
}

func sortIdentityLinkLines(lines []identityLinkLine) {
	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].NodeName != lines[j].NodeName {
			return lines[i].NodeName < lines[j].NodeName
		}
		if lines[i].LineName != lines[j].LineName {
			return lines[i].LineName < lines[j].LineName
		}
		return lines[i].LineHashID < lines[j].LineHashID
	})
}

func identityLinkParked(ln Line, name string) bool {
	for _, parked := range ln.ParkedNames {
		if parked == name {
			return true
		}
	}
	return false
}

// identityLinkLineName is the line's name as an entry label shows it.
func identityLinkLineName(ln Line) string {
	return strings.TrimSuffix(firstNonEmpty(ln.Name, ln.Tag, ln.LineHashID), ".json")
}

// identityLinkEntryLabel names an entry from node and line names only, never
// the identity's email, so a body shown on a screen says where, not who.
func identityLinkEntryLabel(nodeName, lineName string) string {
	label := strings.TrimSpace(nodeName + " " + lineName)
	label = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, label)
	if len(label) > 120 {
		label = label[:120]
	}
	return label
}

// identityLinkAnswer is what the link answers for one identity now.
type identityLinkAnswer struct {
	Kind    string
	Reason  string
	Message string
	Policy  vpnUserPolicy
	Content identityLinkContent
}

// decideIdentityLinkAnswer applies the answer table at the top of this file.
// It does not look at the link's own enabled flag or expiry; those are route
// facts the resolver checks first.
func (s *Server) decideIdentityLinkAnswer(u VpnUser, now time.Time) identityLinkAnswer {
	answer := identityLinkAnswer{Policy: s.vpnUserPolicyAt(u, now), Content: s.identityLinkContent(u)}
	switch {
	case !answer.Policy.Active():
		answer.Kind, answer.Reason = identityAnswerPlaceholder, answer.Policy.Reason
		answer.Message = identityLinkPolicyMessage(answer.Policy)
	case answer.Content.BoundLines == 0:
		answer.Kind, answer.Reason, answer.Message = identityAnswerPlaceholder, identityReasonNoLines, "No lines assigned yet"
	case len(answer.Content.Entries) == 0:
		answer.Kind, answer.Reason = identityAnswerDecoy, identityReasonTransientEmpty
	default:
		answer.Kind, answer.Reason = identityAnswerNodes, identityReasonActive
	}
	return answer
}

// identityLinkPolicyMessage is the placeholder's text for an identity that is
// not active, built from its own policy only.
func identityLinkPolicyMessage(policy vpnUserPolicy) string {
	switch policy.Reason {
	case vpnSuspendReasonDisabled:
		return "Disabled by the operator"
	case vpnSuspendReasonOperator:
		return "Suspended by the operator"
	case vpnSuspendReasonExpiry:
		return "Expired on " + policy.ExpiresAt.UTC().Format("2006-01-02")
	case vpnSuspendReasonQuota:
		message := fmt.Sprintf("Quota used: %s of %s", formatLinkBytes(policy.Usage.Used), formatLinkBytes(policy.LimitBytes))
		if !policy.Usage.PeriodEnd.IsZero() {
			message += ", resets " + policy.Usage.PeriodEnd.UTC().Format("2006-01-02")
		}
		return message
	default:
		return "Not in service"
	}
}

func formatLinkBytes(n int64) string {
	const gib = 1 << 30
	const mib = 1 << 20
	if n >= gib {
		return strconv.FormatFloat(float64(n)/gib, 'f', 1, 64) + " GiB"
	}
	return strconv.FormatFloat(float64(n)/mib, 'f', 1, 64) + " MiB"
}

// identityLinkPlaceholderEntry is the one entry a placeholder answer serves.
func identityLinkPlaceholderEntry(message string) string {
	return "vless://" + identityLinkPlaceholderUUID + "@" + identityLinkPlaceholderHost +
		"?encryption=none&security=none&type=tcp#" + url.PathEscape("Lattice: "+message)
}

// identityLinkUserinfo is the quota header for this identity, computed from
// its policy on every request. An exhausted header (every answer that is not
// the nodes) reads as used up in every client: download reaches total, and a
// quota-less identity gets a total equal to what it used, at least one byte,
// because zero would read as unlimited.
func identityLinkUserinfo(policy vpnUserPolicy, exhausted bool) string {
	used, total := policy.Usage.Used, policy.LimitBytes
	if used < 0 {
		used = 0
	}
	if total < 0 {
		total = 0
	}
	if exhausted {
		if total == 0 {
			total = used
			if total < 1 {
				total = 1
			}
		}
		if used < total {
			used = total
		}
	}
	expire := int64(0)
	if !policy.ExpiresAt.IsZero() {
		expire = policy.ExpiresAt.Unix()
	}
	return fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", used, total, expire)
}

// resolveIdentityLink returns the identity a link token names, or nothing.
// Every rejection is the same nothing, as resolveShare's are.
func (s *Server) resolveIdentityLink(slug, token string, now time.Time) (VpnUser, string, bool) {
	userID, ok := s.store.VpnUserIDByLinkToken(token)
	if !ok {
		return VpnUser{}, "subscription not found", false
	}
	u, ok := s.getVpnUser(userID)
	if !ok || u.Link == nil || u.SubID != token {
		return VpnUser{}, "subscription not found", false
	}
	if u.Link.Slug != slug {
		return VpnUser{}, "subscription not found", false
	}
	if u.Link.Disabled {
		return VpnUser{}, identityReasonLinkDisabled, false
	}
	if u.Link.ExpiresAt != nil && !now.Before(*u.Link.ExpiresAt) {
		return VpnUser{}, identityReasonLinkExpired, false
	}
	return u, "", true
}

// identityLinkTarget decides the client document one request gets: the
// URL's target (or platform), else a format only one client reads, else the
// agent's class. "" means the URI list.
func identityLinkTarget(r *http.Request, format string, native bool) (string, string, bool) {
	explicit := strings.TrimSpace(r.URL.Query().Get("target"))
	if explicit == "" {
		explicit = strings.TrimSpace(r.URL.Query().Get("platform"))
	}
	if explicit != "" {
		if !subscriptionShareTargets[explicit] {
			return "", "", false
		}
		return explicit, "other", true
	}
	if implied := formatImpliedTarget(format); implied != "" {
		return implied, "other", true
	}
	class := classifyClientUA(r.Header.Get("User-Agent"))
	if native {
		return subscriptionUATargets[class], class, true
	}
	return "", class, true
}

// identityLinkIsURITarget reports whether the core writes this target itself.
func identityLinkIsURITarget(target string) bool {
	return target == "" || target == "URI" || target == "V2Ray"
}

// identityLinkBody is one served document.
type identityLinkBody struct {
	body     []byte
	gzipBody []byte
	hash     [sha256.Size]byte
	wireType string
	cacheHit bool
	// fallback names the client document the request asked for when the
	// link served its base64 URI list instead (the converter is missing).
	fallback string
}

// serveIdentityLink answers a /sub/ request whose token is not a share's. It
// returns false when no identity link holds the token, leaving the caller's
// decoy to answer; every other outcome, the decoy included, is written here.
func (s *Server) serveIdentityLink(w http.ResponseWriter, r *http.Request, slug, token, tokenHash, requested string, deny func(string, map[string]string)) bool {
	now := s.now()
	u, refusal, ok := s.resolveIdentityLink(slug, token, now)
	if !ok {
		if refusal == "subscription not found" {
			return false
		}
		deny(refusal, map[string]string{"slug": slug, "token_sha256": tokenHash, "link_kind": identityLinkKind})
		return true
	}
	meta := func(extra map[string]string) map[string]string {
		md := map[string]string{"slug": slug, "token_sha256": tokenHash, "link_kind": identityLinkKind, "identity_id": u.ID}
		for k, v := range extra {
			md[k] = v
		}
		return md
	}
	native := strings.TrimSpace(requested) == ""
	format, err := normalizeProxySubscriptionFormat(requested)
	if err != nil {
		deny("invalid subscription format", meta(nil))
		return true
	}
	target, uaClass, ok := identityLinkTarget(r, format, native)
	if !ok {
		deny("invalid subscription target", meta(nil))
		return true
	}
	variant := shareRenderVariant{Target: target, IncludeUnsupported: requestBool(r, "includeUnsupportedProxy"),
		PrettyYAML: requestBool(r, "prettyYaml") || requestBool(r, "pretty-yaml"), NoFlow: requestBool(r, "noFlow")}

	answer := s.decideIdentityLinkAnswer(u, now)
	if answer.Kind == identityAnswerDecoy {
		s.noteIdentityLinkFetch(u.ID, uaClass, answer, now)
		deny("identity_"+answer.Reason, meta(map[string]string{"excluded": strconv.Itoa(len(answer.Content.Excluded))}))
		return true
	}
	entries := answer.Content.Entries
	if answer.Kind == identityAnswerPlaceholder {
		entries = []string{identityLinkPlaceholderEntry(answer.Message)}
	}
	served, failure := s.identityLinkDocument(r.Context(), u, entries, format, variant)
	if failure != "" {
		deny(failure, meta(nil))
		return true
	}

	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", served.wireType)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	if served.fallback != "" {
		// Labelled, not disguised: the client asked for this document and
		// is getting the URI list, because no converter can write it now.
		header.Set("X-Lattice-Subscription-Fallback", "base64-uri; requested="+served.fallback+"; reason=converter_unavailable")
	}
	quota := identityLinkUserinfo(answer.Policy, answer.Kind != identityAnswerNodes)
	if variant.NoFlow {
		quota = ""
	}
	if quota != "" {
		header.Set("Subscription-Userinfo", quota)
	}
	setLinkClientHeaders(header, slug, identityLinkUpdateIntervalHours(u.Link))
	body := shareBody{body: served.body, gzipBody: served.gzipBody, hash: served.hash}
	if body.hash == ([32]byte{}) || body.gzipBody == nil {
		body = newShareBody(served.body, acceptsGzip(r), gzip.DefaultCompression)
	}
	notModified := writeShareBody(w, r, body, quota)
	s.noteIdentityLinkFetch(u.ID, uaClass, answer, now)
	s.noteShareFetch(r, shareFetch{shareID: identityLinkStatsPrefix + u.ID, slug: slug, tokenHash: tokenHash, family: uaClass,
		cacheHit: served.cacheHit, notModified: notModified}, func() map[string]string {
		return meta(map[string]string{"answer": answer.Kind, "reason": answer.Reason, "line_count": strconv.Itoa(len(answer.Content.Included)),
			"excluded_count": strconv.Itoa(len(answer.Content.Excluded)), "target": firstNonEmpty(variant.Target, "URI"), "ua_class": uaClass,
			"cache": strconv.FormatBool(served.cacheHit)})
	})
	return true
}

// identityLinkDocument writes the requested client document from entries.
// The URI list (plain or base64) is written in core; every other client goes
// through the Sub-Store convert method, cached by content digest and
// rendered once per key. Without a converter the base64 URI list is served
// and labelled.
func (s *Server) identityLinkDocument(ctx context.Context, u VpnUser, entries []string, format string, variant shareRenderVariant) (identityLinkBody, string) {
	if identityLinkIsURITarget(variant.Target) {
		raw := strings.Join(entries, "\n")
		if format == proxycore.SubscriptionFormatPlain && variant.Target != "V2Ray" {
			return identityLinkBody{body: []byte(raw), wireType: "text/plain; charset=utf-8"}, ""
		}
		return identityLinkBody{body: []byte(base64.StdEncoding.EncodeToString([]byte(raw))), wireType: "text/plain; charset=utf-8"}, ""
	}
	if !s.identityLinkConvertAvailable() {
		raw := strings.Join(entries, "\n")
		return identityLinkBody{body: []byte(base64.StdEncoding.EncodeToString([]byte(raw))), wireType: "text/plain; charset=utf-8", fallback: variant.Target}, ""
	}
	sum := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	version := hex.EncodeToString(sum[:])
	key := subscriptionCacheKey{ShareID: identityLinkStatsPrefix + u.ID, Format: "convert", UAClass: "other", Variant: variant.cacheToken()}
	if entry, ok := s.identityLinkCache.GetVersioned(key, version, s.now()); ok {
		return identityLinkBody{body: entry.body, gzipBody: entry.gzipBody, hash: entry.bodyHash, wireType: entry.wireType, cacheHit: true}, ""
	}
	outcome := s.convertIdentityLinkShared(ctx, key, version, entries, variant)
	if outcome.deny != "" {
		return identityLinkBody{}, outcome.deny
	}
	return identityLinkBody{body: outcome.entry.body, gzipBody: outcome.entry.gzipBody, hash: outcome.entry.bodyHash, wireType: outcome.entry.wireType}, ""
}

// identityLinkConvertAvailable reports whether the active Sub-Store plugin
// declares the stateless convert method (plugin 0.16.0-alpha.1 and later).
func (s *Server) identityLinkConvertAvailable() bool {
	if s.identityLinkConvert != nil {
		return true
	}
	if !s.pluginIsActive(subStorePluginID) {
		return false
	}
	loaded, ok := s.loadedPlugin(subStorePluginID)
	if !ok {
		return false
	}
	contract, ok := loaded.Manifest.InterfaceFor(subStorePluginID + "/subscription")
	if !ok {
		return false
	}
	_, ok = contract.MethodContract("convert")
	return ok
}

// identityConvertFlightKey names one in-flight convert: the cache key and
// the content version it converts.
//
// A share's version belongs to its source, so every request for a share key
// wants the same body and renderShareShared joins by key alone. An identity
// link's version is built per request from that identity's state, and two
// requests for one key can want different bodies: a request made after a
// suspension, a rotation or a newly applied line must not be handed the body
// a flight started for the entries before it, or a suspended identity would
// get its real nodes for the length of a convert instead of the placeholder.
// So a request joins only a flight for its own version.
type identityConvertFlightKey struct {
	key     subscriptionCacheKey
	version string
}

// convertIdentityLinkShared converts one cache key and content version at
// most once at a time, the way renderShareShared renders a share key, within
// the link's render budget.
func (s *Server) convertIdentityLinkShared(ctx context.Context, key subscriptionCacheKey, version string, entries []string, variant shareRenderVariant) shareRenderOutcome {
	flightKey := identityConvertFlightKey{key: key, version: version}
	s.identityConvertMu.Lock()
	if s.identityConvertFlights == nil {
		s.identityConvertFlights = make(map[identityConvertFlightKey]*shareRenderFlight)
	}
	flight := s.identityConvertFlights[flightKey]
	if flight == nil {
		ticket, ok, _, _ := s.shareRenderBudget.take(key.ShareID, shareRenderVariantKey(key), version)
		if !ok {
			s.identityConvertMu.Unlock()
			return shareRenderOutcome{deny: "subscription_render_budget_exhausted"}
		}
		flight = &shareRenderFlight{done: make(chan struct{})}
		s.identityConvertFlights[flightKey] = flight
		entries = append([]string(nil), entries...)
		go func() {
			convertCtx, cancel := context.WithTimeout(context.Background(), identityLinkConvertTimeout)
			defer cancel()
			outcome := s.convertIdentityLinkOnce(convertCtx, key, version, entries, variant)
			s.shareRenderBudget.settle(ticket, version, outcome.deny != "")
			s.identityConvertMu.Lock()
			flight.outcome = outcome
			delete(s.identityConvertFlights, flightKey)
			close(flight.done)
			s.identityConvertMu.Unlock()
		}()
	}
	s.identityConvertMu.Unlock()
	select {
	case <-flight.done:
		return flight.outcome
	case <-ctx.Done():
		return shareRenderOutcome{deny: "subscription_request_ended"}
	}
}

func (s *Server) convertIdentityLinkOnce(ctx context.Context, key subscriptionCacheKey, version string, entries []string, variant shareRenderVariant) shareRenderOutcome {
	rendered, err := s.convertIdentityEntries(ctx, entries, variant)
	if err != nil {
		s.logger.Printf("identity link: convert failed for %s (%s)", key.ShareID, subscriptionDiagnosticSummary(err))
		return shareRenderOutcome{deny: "identity_convert_failed"}
	}
	if len(rendered.Body) == 0 {
		return shareRenderOutcome{deny: "empty render refused"}
	}
	target := reportedRenderTarget(rendered.Target)
	if target == "" {
		target = variant.Target
	}
	served := newShareBody(rendered.Body, true, gzip.BestCompression)
	entry := subscriptionCacheEntry{body: rendered.Body, contentType: rendered.ContentType, revalidationVersion: version,
		wireType: subscriptionResponseContentType("", target), bodyHash: served.hash, gzipBody: served.gzipBody}
	s.identityLinkCache.putEntry(key, entry, s.now())
	return shareRenderOutcome{entry: entry}
}

// convertIdentityEntries asks the Sub-Store plugin for one client's document
// built from this identity's entries alone. The plugin never sees the token
// and keeps nothing between calls (its convert contract).
func (s *Server) convertIdentityEntries(ctx context.Context, entries []string, variant shareRenderVariant) (renderedSubscription, error) {
	if s.identityLinkConvert != nil {
		return s.identityLinkConvert(ctx, entries, variant)
	}
	fields := map[string]any{"uris": entries, "target": variant.Target}
	if opts := variant.options(); opts != nil {
		fields["options"] = opts
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return renderedSubscription{}, err
	}
	out, err := s.callRuntimePluginService(ctx, subStorePluginID, subStorePluginID+"/subscription", "convert", payload, nil, nil)
	if err != nil {
		return renderedSubscription{}, err
	}
	var reply struct {
		Content     string `json:"content"`
		ContentType string `json:"content_type"`
		Target      string `json:"target"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		return renderedSubscription{}, fmt.Errorf("decode convert reply: %w", err)
	}
	if reply.Content == "" {
		return renderedSubscription{}, errors.New("convert returned no content")
	}
	return renderedSubscription{Body: []byte(reply.Content), ContentType: reply.ContentType, Target: reply.Target}, nil
}

// identityLinkFetchSeen is the last fetch of one identity link since this
// server started. It is memory only: the hourly fetch summaries in the
// audit trail are the durable record, and nothing here writes state.json.
type identityLinkFetchSeen struct {
	At      time.Time `json:"at"`
	UAClass string    `json:"ua_class"`
	Answer  string    `json:"answer"`
}

type identityLinkFetches struct {
	mu   sync.Mutex
	last map[string]identityLinkFetchSeen
}

func (s *Server) noteIdentityLinkFetch(userID, uaClass string, answer identityLinkAnswer, now time.Time) {
	s.identityFetches.mu.Lock()
	defer s.identityFetches.mu.Unlock()
	if s.identityFetches.last == nil {
		s.identityFetches.last = map[string]identityLinkFetchSeen{}
	}
	s.identityFetches.last[userID] = identityLinkFetchSeen{At: now.UTC(), UAClass: uaClass, Answer: answer.Kind}
}

func (s *Server) identityLinkLastFetch(userID string) *identityLinkFetchSeen {
	s.identityFetches.mu.Lock()
	defer s.identityFetches.mu.Unlock()
	seen, ok := s.identityFetches.last[userID]
	if !ok {
		return nil
	}
	return &seen
}

func (s *Server) forgetIdentityLinkFetch(userID string) {
	s.identityFetches.mu.Lock()
	delete(s.identityFetches.last, userID)
	s.identityFetches.mu.Unlock()
}

// dropIdentityLinkServingState forgets everything the serving path holds for
// an identity's link: converted bodies, the render budget and the last
// fetch. Rotation, revocation and delete call it, so nothing rendered for an
// old token outlives it.
func (s *Server) dropIdentityLinkServingState(userID string) {
	s.identityLinkCache.InvalidateShare(identityLinkStatsPrefix + userID)
	s.shareRenderBudget.reset(identityLinkStatsPrefix + userID)
	s.forgetIdentityLinkFetch(userID)
}
