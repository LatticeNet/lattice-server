package server

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Per-line usage attribution. A sing-box node reports one cumulative counter
// per inbound tag and one per named user; this file decides which identity
// an inbound's bytes belong to and what a line's place in a chain means for
// counting. The rules are fixed and ordered, first match wins, and every row
// says which rule fired and whether that rule proves or infers:
//
//	named       a u_<hash> user counter on the line folds to a VpnUser  (proof)
//	credential  a single-credential inbound whose uuid or password is exactly
//	            one VpnUser's credential                                   (proof)
//	binding     exactly one enabled VpnUser binding to the line hash     (inferred)
//	substore    exactly one Sub-Store record whose VPN identity selects
//	            the line                                                  (inferred)
//	none        line usage with no user; candidates listed when there are several
//
// Quota accounting and alerts count named, credential and binding. substore
// and none are reported only. An inbound tag the server cannot join to a line
// is reported as unknown_line and never dropped: the bytes are real egress.
const (
	usageAttributionNamed       = "named"
	usageAttributionCredential  = "credential"
	usageAttributionBinding     = "binding"
	usageAttributionSubstore    = "substore"
	usageAttributionNone        = "none"
	usageAttributionUnknownLine = "unknown_line"

	usageProofProof    = "proof"
	usageProofInferred = "inferred"

	// Chain roles, derived from the declared and inferred jump edges of the
	// line read model. User totals count at the entry only.
	usageRoleDirect = "direct" // no chain edge either way
	usageRoleEntry  = "entry"  // has a downstream chain target, is not one itself
	usageRoleRelay  = "relay"  // both a chain target and a chain source
	usageRoleExit   = "exit"   // a chain target with no direct binding or subscription
	usageRoleShared = "shared" // a chain target that also serves direct users

	// Collector health states for the per-node usage surface.
	usageCollectorStateOK          = model.ProxyUsageCollectorStatusOK
	usageCollectorStateError       = model.ProxyUsageCollectorStatusError
	usageCollectorStateStatsOff    = "stats_off"
	usageCollectorStateNoCollector = "no_collector"

	// proxyUsageCollectorStatusStatsOff is what a node reports when its
	// sing-box config has no experimental.v2ray_api: nothing to collect, and
	// not a collector fault. Kept server-side so the pin on the SDK branch is
	// exactly the agent lane's commit.
	proxyUsageCollectorStatusStatsOff = "stats_off"

	usageSubStoreRecordsKey    = "subscriptions-v1"
	usageSubStoreSourceGraph   = "vpn-core-graph"
	usageSubStoreKVBucket      = "plugin:" + subStorePluginID
	usageMaxSubStoreRecordsLen = 4 << 20
)

// usageCounter is one uplink/downlink pair. Uplink and downlink stay separate
// everywhere new; used_bytes is their sum for old clients.
type usageCounter struct {
	Uplink   int64
	Downlink int64
}

func (c usageCounter) zero() bool   { return c.Uplink == 0 && c.Downlink == 0 }
func (c usageCounter) total() int64 { return c.Uplink + c.Downlink }
func (c *usageCounter) add(o usageCounter) {
	c.Uplink += o.Uplink
	c.Downlink += o.Downlink
}

func (c usageCounter) sub(o usageCounter) usageCounter {
	return usageCounter{Uplink: max(0, c.Uplink-o.Uplink), Downlink: max(0, c.Downlink-o.Downlink)}
}

func (c usageCounter) capAt(o usageCounter) usageCounter {
	return usageCounter{Uplink: min(c.Uplink, o.Uplink), Downlink: min(c.Downlink, o.Downlink)}
}

// usageSubStoreRef is one Sub-Store graph record that selects a line: the
// record names an identity and the line's uuid is among its entry roots.
type usageSubStoreRef struct {
	RecordID   string
	IdentityID string
}

// usageLineFacts is everything attribution needs to know about one line,
// resolved once per ingestion or read.
type usageLineFacts struct {
	Line       Line
	Role       string
	Upstream   []string // hashes of lines whose chain lands here
	Downstream []string // hashes this line relays to
	// Named maps the on-box u_<hash> user names that live on this line to the
	// VpnUser they fold to.
	Named map[string]string
	// CredentialUser is set when the inbound carries exactly one credential
	// and exactly one VpnUser holds it.
	CredentialUser   string
	CredentialReason string
	Bound            []string // enabled bindings, sorted VpnUser ids
	SubStore         []usageSubStoreRef
}

func (f *usageLineFacts) hasDirectUsers() bool {
	return len(f.Named) > 0 || f.CredentialUser != "" || len(f.Bound) > 0 || len(f.SubStore) > 0
}

// usageAttributionContext is the fleet-wide fact set one call works from, so a
// read or an ingestion sees one consistent line graph and identity set.
type usageAttributionContext struct {
	byHash    map[string]*usageLineFacts
	byNodeTag map[string]map[string]*usageLineFacts
	byUUID    map[string]*usageLineFacts
	nodeName  map[string]string
	users     map[string]VpnUser
	// accounting maps a VpnUser id to the ProxyUser projection id that carries
	// its monotonic total (the legacy id for a migrated identity).
	accounting map[string]string
	vpnByAcct  map[string]string
	// nameIndex is the design-15 u_<hash> reverse index.
	nameIndex map[string]userLineNameTarget
	// reported holds the (line, user) pairs the latest snapshot of each node
	// actually carried a user counter for. The index above names every bound
	// user; only a reported counter makes a stored day row "named" at read
	// time rather than a rule's attribution.
	reported map[string]map[string]bool
	substore []usageSubStoreRecord
}

// usageSubStoreRecord is the slice of a Sub-Store subscription record the
// server needs: the identity it narrows to and the roots it selects. Read
// from the plugin's durable KV document; nothing else in the record is
// decoded.
type usageSubStoreRecord struct {
	ID          string   `json:"id"`
	Source      string   `json:"source,omitempty"`
	VPNIdentity string   `json:"vpn_identity,omitempty"`
	EntryRoots  []string `json:"entry_roots,omitempty"`
}

// subStoreGraphRecords reads the Sub-Store plugin's subscription document the
// same way the plugin does (plugin:latticenet.sub-store / subscriptions-v1)
// and keeps the vpn-core-graph records that name an identity.
func (s *Server) subStoreGraphRecords() []usageSubStoreRecord {
	entry, ok := s.store.KVEntry(usageSubStoreKVBucket, usageSubStoreRecordsKey)
	if !ok || len(entry.Value) == 0 || len(entry.Value) > usageMaxSubStoreRecordsLen {
		return nil
	}
	var doc struct {
		Records []usageSubStoreRecord `json:"records"`
	}
	if err := json.Unmarshal([]byte(entry.Value), &doc); err != nil {
		return nil
	}
	out := make([]usageSubStoreRecord, 0, len(doc.Records))
	for _, rec := range doc.Records {
		if rec.Source != usageSubStoreSourceGraph || strings.TrimSpace(rec.VPNIdentity) == "" || strings.TrimSpace(rec.ID) == "" {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// nodeNameIndex narrows the fleet-wide u_<hash> reverse index to the names one
// node can speak for. A counter is that node's own statement only when the line
// the name resolves to sits on that node; a name for a line the read model
// places elsewhere is another node's business. A name whose line the read model
// does not carry at all stays in, which is the stale-discovery degradation
// usageIngest's namedOnly loop already allows.
func (ctx *usageAttributionContext) nodeNameIndex(nodeID string) map[string]userLineNameTarget {
	if len(ctx.nameIndex) == 0 {
		return nil
	}
	out := make(map[string]userLineNameTarget, len(ctx.nameIndex))
	for name, target := range ctx.nameIndex {
		if f, ok := ctx.byHash[target.LineHashID]; ok && f.Line.NodeID != nodeID {
			continue
		}
		out[name] = target
	}
	return out
}

func (s *Server) usageAttributionContext() *usageAttributionContext {
	groups, _ := s.lineReadModel()
	ctx := &usageAttributionContext{
		byHash: map[string]*usageLineFacts{}, byNodeTag: map[string]map[string]*usageLineFacts{}, byUUID: map[string]*usageLineFacts{},
		nodeName: map[string]string{}, users: map[string]VpnUser{}, accounting: map[string]string{}, vpnByAcct: map[string]string{},
	}
	for _, g := range groups {
		ctx.nodeName[g.NodeID] = g.NodeName
		for _, ln := range g.Lines {
			f := &usageLineFacts{Line: ln, Named: map[string]string{}}
			ctx.byHash[ln.LineHashID] = f
			if ctx.byNodeTag[ln.NodeID] == nil {
				ctx.byNodeTag[ln.NodeID] = map[string]*usageLineFacts{}
			}
			if uuid := strings.ToLower(strings.TrimSpace(ln.LineUUID)); uuid != "" {
				ctx.byUUID[uuid] = f
			}
		}
	}
	// The counters arrive keyed by the tag the core loaded, which is the conf
	// file's name only by the helper script's convention. Index every tag a line
	// can be shown to own, not its name alone: a file holding a relay pair
	// carries two tags, and its name is not either of them.
	for key, ln := range lineInboundTagIndex(groups) {
		if f, ok := ctx.byHash[ln.LineHashID]; ok {
			ctx.byNodeTag[key.NodeID][key.Tag] = f
		}
	}

	// Identities: bindings, credential indexes, accounting ids.
	byUUID := map[string][]string{}
	byPassword := map[string][]string{}
	for _, u := range s.listVpnUsers() {
		ctx.users[u.ID] = u
		acct := strings.TrimSpace(u.MigratedFromProxyUser)
		if acct == "" {
			acct = u.ID
		}
		ctx.accounting[u.ID] = acct
		ctx.vpnByAcct[acct] = u.ID
		for _, b := range u.Bindings {
			if !b.Enabled {
				continue
			}
			if f, ok := ctx.byHash[b.LineHashID]; ok {
				f.Bound = append(f.Bound, u.ID)
			}
		}
		for _, c := range u.Credentials {
			if uuid := strings.ToLower(strings.TrimSpace(c.UUID)); uuid != "" {
				byUUID[uuid] = appendUniqueSorted(byUUID[uuid], u.ID)
			}
			if c.Password != "" {
				byPassword[c.Password] = appendUniqueSorted(byPassword[c.Password], u.ID)
			}
		}
	}
	for _, f := range ctx.byHash {
		sort.Strings(f.Bound)
	}

	// Named users: the on-box u_<hash> names, grouped by line.
	ctx.nameIndex = s.userLineNameIndex()
	for name, target := range ctx.nameIndex {
		if f, ok := ctx.byHash[target.LineHashID]; ok {
			f.Named[name] = target.VpnUserID
		}
	}
	ctx.reported = map[string]map[string]bool{}
	markReported := func(hash, userID string) {
		if ctx.reported[hash] == nil {
			ctx.reported[hash] = map[string]bool{}
		}
		ctx.reported[hash][userID] = true
	}
	for _, snap := range s.store.ProxyUsageSnapshots() {
		for name := range snap.UserTraffic {
			if target, ok := ctx.nameIndex[name]; ok {
				markReported(target.LineHashID, target.VpnUserID)
			}
		}
		for hash, byUser := range snap.LineUserBytes {
			for acct := range byUser {
				if vpnID := ctx.vpnByAcct[acct]; vpnID != "" {
					markReported(hash, vpnID)
				}
			}
		}
	}

	// Sub-Store records selecting lines through their entry roots.
	ctx.substore = s.subStoreGraphRecords()
	for _, rec := range ctx.substore {
		if _, ok := ctx.users[rec.VPNIdentity]; !ok {
			continue
		}
		for _, root := range rec.EntryRoots {
			if f, ok := ctx.byUUID[strings.ToLower(strings.TrimSpace(root))]; ok {
				f.SubStore = append(f.SubStore, usageSubStoreRef{RecordID: rec.ID, IdentityID: rec.VPNIdentity})
			}
		}
	}

	// Single-credential inbounds. Three sources, each exact: an overlay
	// definition names its user; a Lattice-rendered inbound with exactly one
	// eligible proxy user carries that user's uuid; a discovered single-user
	// line's share URL carries the credential the box accepts.
	shareURLs := map[string]map[string]string{} // node -> tag -> share url
	for _, inv := range s.liveSingBoxInventories(s.now()) {
		for _, n := range inv.Nodes {
			if n.UserKnown && n.UserCount == 1 && strings.TrimSpace(n.ShareURL) != "" {
				if shareURLs[inv.NodeID] == nil {
					shareURLs[inv.NodeID] = map[string]string{}
				}
				shareURLs[inv.NodeID][n.Name] = n.ShareURL
			}
		}
	}
	proxyUsers := s.store.ProxyUsers()
	for _, f := range ctx.byHash {
		ln := f.Line
		switch {
		case ln.Overlay && ln.OverlayUser != "":
			if _, ok := ctx.users[ln.OverlayUser]; ok {
				f.CredentialUser, f.CredentialReason = ln.OverlayUser, "overlay line definition names this user"
			}
		case ln.Managed:
			var single *model.ProxyUser
			count := 0
			for i := range proxyUsers {
				pu := proxyUsers[i]
				if !pu.Enabled || (len(pu.InboundIDs) > 0 && !proxyStringSliceContains(pu.InboundIDs, ln.Tag)) {
					continue
				}
				count++
				single = &proxyUsers[i]
			}
			if count == 1 {
				f.CredentialUser, f.CredentialReason = matchSingleCredential(byUUID, byPassword, single.UUID, single.Password, ln.Type)
			}
		default:
			if raw := shareURLs[ln.NodeID][ln.Tag]; raw != "" {
				uuid, password := shareURLCredential(raw)
				f.CredentialUser, f.CredentialReason = matchSingleCredential(byUUID, byPassword, uuid, password, ln.Type)
			}
		}
	}

	// Chain edges and roles. Declared edges already replaced inferred ones in
	// the read model, so JumpEdges is the authoritative downstream set.
	for _, f := range ctx.byHash {
		for _, target := range f.Line.JumpEdges {
			if target == f.Line.LineHashID {
				continue
			}
			t, ok := ctx.byHash[target]
			if !ok {
				continue
			}
			f.Downstream = appendUniqueSorted(f.Downstream, target)
			t.Upstream = appendUniqueSorted(t.Upstream, f.Line.LineHashID)
		}
	}
	for _, f := range ctx.byHash {
		f.Role = usageLineRole(len(f.Downstream) > 0, len(f.Upstream) > 0, f.hasDirectUsers())
	}
	return ctx
}

// usageLineRole derives the chain role from the two edge directions and
// whether anything reaches the line directly.
func usageLineRole(isSource, isTarget, hasDirect bool) string {
	switch {
	case isSource && isTarget:
		return usageRoleRelay
	case isSource:
		return usageRoleEntry
	case isTarget && hasDirect:
		return usageRoleShared
	case isTarget:
		return usageRoleExit
	default:
		return usageRoleDirect
	}
}

// matchSingleCredential resolves an inbound's single credential to the one
// VpnUser holding it. Two holders is no match: the rule is about exactness,
// and the binding rule follows for the ambiguous case.
func matchSingleCredential(byUUID, byPassword map[string][]string, uuid, password, protocol string) (string, string) {
	if uuid = strings.ToLower(strings.TrimSpace(uuid)); uuid != "" {
		if holders := byUUID[uuid]; len(holders) == 1 {
			return holders[0], "inbound " + firstNonEmpty(protocol, "credential") + " uuid is this user's credential"
		}
	}
	if password != "" {
		if holders := byPassword[password]; len(holders) == 1 {
			return holders[0], "inbound " + firstNonEmpty(protocol, "credential") + " password is this user's credential"
		}
	}
	return "", ""
}

// shareURLCredential pulls the credential out of a share link: the userinfo
// for the uuid- and password-bearing schemes, the JSON id for vmess, and the
// method:password pair for shadowsocks. Anything it cannot read yields empty
// values, which simply means the credential rule does not fire.
func shareURLCredential(raw string) (uuid, password string) {
	raw = strings.TrimSpace(raw)
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return "", ""
	}
	scheme = strings.ToLower(scheme)
	if scheme == "vmess" {
		payload := rest
		if i := strings.IndexAny(payload, "?#"); i >= 0 {
			payload = payload[:i]
		}
		decoded, ok := decodeLooseBase64(payload)
		if !ok {
			return "", ""
		}
		var v struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(decoded, &v) != nil || !proxyUUIDRe.MatchString(v.ID) {
			return "", ""
		}
		return strings.ToLower(v.ID), ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		if scheme == "ss" || scheme == "shadowsocks" {
			// ss://BASE64(method:password@host:port): the whole body is encoded.
			body := rest
			if i := strings.IndexAny(body, "#?/"); i >= 0 {
				body = body[:i]
			}
			if decoded, ok := decodeLooseBase64(body); ok {
				if creds, _, ok := strings.Cut(string(decoded), "@"); ok {
					if _, pw, ok := strings.Cut(creds, ":"); ok {
						return "", pw
					}
				}
			}
		}
		return "", ""
	}
	username := u.User.Username()
	pw, hasPassword := u.User.Password()
	switch scheme {
	case "ss", "shadowsocks":
		if hasPassword {
			return "", pw
		}
		if decoded, ok := decodeLooseBase64(username); ok {
			if _, p, ok := strings.Cut(string(decoded), ":"); ok {
				return "", p
			}
		}
		return "", ""
	case "tuic":
		if hasPassword {
			return strings.ToLower(username), pw
		}
	}
	if proxyUUIDRe.MatchString(username) {
		return strings.ToLower(username), ""
	}
	if hasPassword {
		return "", pw
	}
	return "", username
}

func decodeLooseBase64(value string) ([]byte, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if out, err := enc.DecodeString(value); err == nil {
			return out, true
		}
	}
	return nil, false
}

// usageLineRow is one attributed slice of one line's traffic. It is the wire
// row for /api/proxy/usage, the vpn-core usage RPC, and usage_query.
type usageLineRow struct {
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name,omitempty"`
	LineHashID string `json:"line_hash_id,omitempty"`
	Tag        string `json:"tag"`
	Role       string `json:"role"`
	// CountedAt names the upstream relay line(s) whose entry counter already
	// carries these bytes. Set on the relayed portion of a chain target, which
	// is excluded from user totals.
	CountedAt         string   `json:"counted_at,omitempty"`
	Uplink            int64    `json:"uplink"`
	Downlink          int64    `json:"downlink"`
	UsedBytes         int64    `json:"used_bytes"`
	Attribution       string   `json:"attribution"`
	AttributionProof  string   `json:"attribution_proof,omitempty"`
	AttributionReason string   `json:"attribution_reason,omitempty"`
	UserID            string   `json:"user_id,omitempty"`
	Email             string   `json:"email,omitempty"`
	Candidates        []string `json:"candidates,omitempty"`
	// Estimate marks a chain target's direct portion: the inbound counter
	// minus the upstream relay counters, floored at zero.
	Estimate bool `json:"estimate,omitempty"`
	// Counted says whether the row feeds the user's totals and quota.
	Counted bool `json:"counted"`
}

// usageLineTraffic is one line's traffic to attribute: the inbound counter,
// the named user counters that landed on it, and, for a chain target, the
// upstream relay counters over the same window. Upstream is nil when the
// caller cannot align windows (one ingestion of one node), in which case the
// whole non-named remainder of a chain target is treated as relayed.
type usageLineTraffic struct {
	Inbound  usageCounter
	Named    map[string]usageCounter // VpnUser id -> counter
	Upstream *usageCounter
}

func (ctx *usageAttributionContext) email(userID string) string {
	if u, ok := ctx.users[userID]; ok {
		return u.Email
	}
	return ""
}

// attributeLine turns one line's traffic into attributed rows. f is nil for
// an inbound tag the server cannot join to a line.
func (ctx *usageAttributionContext) attributeLine(nodeID, tag string, f *usageLineFacts, traffic usageLineTraffic) []usageLineRow {
	base := usageLineRow{NodeID: nodeID, NodeName: ctx.nodeName[nodeID], Tag: tag, Role: usageRoleDirect}
	if f == nil {
		if traffic.Inbound.zero() {
			return nil
		}
		row := base
		row.Uplink, row.Downlink, row.UsedBytes = traffic.Inbound.Uplink, traffic.Inbound.Downlink, traffic.Inbound.total()
		row.Attribution, row.AttributionReason = usageAttributionUnknownLine, "no line on this node carries this inbound tag"
		return []usageLineRow{row}
	}
	base.LineHashID, base.Role = f.Line.LineHashID, f.Role
	rows := []usageLineRow{}
	named := usageCounter{}
	namedUsers := make([]string, 0, len(traffic.Named))
	for userID := range traffic.Named {
		namedUsers = append(namedUsers, userID)
	}
	sort.Strings(namedUsers)
	for _, userID := range namedUsers {
		c := traffic.Named[userID]
		if c.zero() {
			continue
		}
		named.add(c)
		row := base
		row.Uplink, row.Downlink, row.UsedBytes = c.Uplink, c.Downlink, c.total()
		row.Attribution, row.AttributionProof = usageAttributionNamed, usageProofProof
		row.AttributionReason = "user counter on this line folds to this identity"
		row.UserID, row.Email, row.Counted = userID, ctx.email(userID), true
		rows = append(rows, row)
	}
	remainder := traffic.Inbound.sub(named)
	isTarget := len(f.Upstream) > 0
	if isTarget {
		relayed := remainder
		if traffic.Upstream != nil {
			relayed = remainder.capAt(*traffic.Upstream)
		}
		if !relayed.zero() {
			row := base
			row.Uplink, row.Downlink, row.UsedBytes = relayed.Uplink, relayed.Downlink, relayed.total()
			row.CountedAt = strings.Join(f.Upstream, ",")
			row.Attribution, row.AttributionReason = usageAttributionNone, "reached through a relay; counted at the entry line"
			rows = append(rows, row)
		}
		remainder = remainder.sub(relayed)
		if traffic.Upstream == nil {
			remainder = usageCounter{}
		}
	}
	if remainder.zero() {
		return rows
	}
	row := base
	row.Uplink, row.Downlink, row.UsedBytes = remainder.Uplink, remainder.Downlink, remainder.total()
	row.Estimate = isTarget
	switch {
	case len(namedUsers) > 0:
		// The line's rule is named; bytes the user counters did not claim stay
		// unattributed rather than being handed to a bound user by inference.
		row.Attribution, row.AttributionReason = usageAttributionNone, "inbound bytes beyond the named user counters"
		row.Candidates = namedUsers
	case f.CredentialUser != "":
		row.Attribution, row.AttributionProof, row.AttributionReason = usageAttributionCredential, usageProofProof, f.CredentialReason
		row.UserID, row.Email, row.Counted = f.CredentialUser, ctx.email(f.CredentialUser), !row.Estimate
	case len(f.Bound) == 1:
		row.Attribution, row.AttributionProof, row.AttributionReason = usageAttributionBinding, usageProofInferred, "only enabled binding on this line"
		row.UserID, row.Email, row.Counted = f.Bound[0], ctx.email(f.Bound[0]), !row.Estimate
	case len(f.SubStore) == 1:
		row.Attribution, row.AttributionProof = usageAttributionSubstore, usageProofInferred
		row.AttributionReason = "only Sub-Store record selecting this line (" + f.SubStore[0].RecordID + ")"
		row.UserID, row.Email = f.SubStore[0].IdentityID, ctx.email(f.SubStore[0].IdentityID)
	default:
		row.Attribution, row.AttributionReason = usageAttributionNone, unattributedLineReason(f)
		candidates := append([]string(nil), f.Bound...)
		for _, ref := range f.SubStore {
			candidates = appendUniqueSorted(candidates, ref.IdentityID)
		}
		row.Candidates = candidates
	}
	return append(rows, row)
}

// unattributedLineReason says why no rule claimed a line, distinguishing an
// attribution that failed from one that was never possible.
//
// sing-box builds its stats user allowlist by name, so a credential with no
// name has no per-user counter and its bytes stay inside the inbound total for
// as long as the config says so. No binding, no Sub-Store record and no future
// discovery changes that; only naming the credential on the box does. Reporting
// it as "no user" describes the symptom and leaves an operator unable to tell
// whether anything is theirs to fix. On this fleet it is also the ordinary case
// rather than the exception: 140 of 141 credentials carry no name.
//
// A named credential the server cannot place is the opposite and is worth
// naming separately. The node is counting it and the counter is being
// discarded, because only a u_<hash> name derived from an identity and a
// line_uuid reverses to a user; a name an operator set by hand does not, and
// guessing which identity it means is the one thing attribution must not do.
//
// A node that reports neither count says nothing here, which is every node
// until the helper script carrying the report is rolled.
// Every applicable cause is reported, not the first one matched. A line can
// carry unnamed credentials and named-but-unresolved ones at the same time, and
// a switch returning on first match reported only one of them.
//
// The ordering also picked the less actionable one. An unnamed credential is a
// permanent property of the config and nothing in the control plane fixes it; a
// named credential resolving to no identity means the node is counting
// something the server discards, which someone can act on.
//
// The failure that matters is not the missing half, it is that the half shown
// reads as a complete explanation. An operator would address the unnamed note,
// take the line as explained, and never learn a real counter was being thrown
// away underneath it.
func unattributedLineReason(f *usageLineFacts) string {
	const base = "line usage, no user"
	clauses := make([]string, 0, 2)
	switch {
	case f.Line.UnnamedUsers > 0 && f.Line.NamedUsers == 0:
		clauses = append(clauses, countedNoun(f.Line.UnnamedUsers, "credential")+" on this line "+
			agrees(f.Line.UnnamedUsers, "carries", "carry")+
			" no name, so the node cannot count them individually")
	case f.Line.UnnamedUsers > 0:
		clauses = append(clauses, countedNoun(f.Line.UnnamedUsers, "credential")+" on this line "+
			agrees(f.Line.UnnamedUsers, "carries", "carry")+
			" no name and "+agrees(f.Line.UnnamedUsers, "is", "are")+" counted only in the line total")
	}
	if f.Line.NamedUsers > 0 && len(f.Named) == 0 {
		clauses = append(clauses, countedNoun(f.Line.NamedUsers, "named credential")+" on this line "+
			agrees(f.Line.NamedUsers, "resolves", "resolve")+" to no identity the server knows")
	}
	if len(clauses) == 0 {
		return base
	}
	return base + "; " + strings.Join(clauses, "; ")
}

// countedNoun and agrees keep these reasons readable as sentences. They are for
// operator-facing text, where "1 credentials carry no name" reads as a bug in
// the thing reporting it and undermines the number next to it.
func countedNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

func agrees(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// diffTrafficCounters applies the monotonic rule to a counter family: a core
// restart (uptime went backwards) makes the current value the delta, a
// decrease without one is a new baseline that advances nothing, and a first
// report is a baseline only.
func diffTrafficCounters(current, previous map[string]model.ProxyTrafficCounter, hadPrevious, reset bool) map[string]usageCounter {
	if !hadPrevious || len(current) == 0 {
		return nil
	}
	out := map[string]usageCounter{}
	for key, cur := range current {
		prior := previous[key]
		delta := usageCounter{}
		switch {
		case reset:
			delta = usageCounter{Uplink: cur.Uplink, Downlink: cur.Downlink}
		default:
			if cur.Uplink >= prior.Uplink {
				delta.Uplink = cur.Uplink - prior.Uplink
			}
			if cur.Downlink >= prior.Downlink {
				delta.Downlink = cur.Downlink - prior.Downlink
			}
		}
		if delta.zero() {
			continue
		}
		out[key] = delta
	}
	return out
}

// usageCollectorState folds a profile's collector fields into one of four
// states: a node that never reported a collector is no_collector, not "ok".
func usageCollectorState(profile model.ProxyNodeProfile) string {
	if validProxyUsageCollectorStatus(profile.UsageCollectorStatus) {
		return profile.UsageCollectorStatus
	}
	if profile.UsageCollectorSource != "" || profile.UsageCollectorLastError != "" {
		return usageCollectorStateError
	}
	return usageCollectorStateNoCollector
}

// quotaPeriodBounds is the monthly window containing now for a reset day in
// 1..28: [start, end). The day bound keeps every month valid.
func quotaPeriodBounds(now time.Time, resetDay int) (start, end time.Time) {
	if resetDay < 1 || resetDay > 28 {
		resetDay = 1
	}
	now = now.UTC()
	y, m, _ := now.Date()
	start = time.Date(y, m, resetDay, 0, 0, 0, 0, time.UTC)
	if start.After(now) {
		start = time.Date(y, m-1, resetDay, 0, 0, 0, 0, time.UTC)
	}
	end = time.Date(start.Year(), start.Month()+1, resetDay, 0, 0, 0, 0, time.UTC)
	return start, end
}
