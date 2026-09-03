package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Line is the unified, node-grouped view of a proxy "line" — an inbound/endpoint
// regardless of origin: a Lattice-managed inbound rendered onto a node, or a proxy
// discovered on-box via `sb --json list`. It replaces the split between the old
// managed Inbounds view and the Discovered view (design-12). It is a DERIVED,
// read-model type computed on demand from the proxy store + live discovery
// inventory; it is not persisted and is never sent to the agent (so it lives in
// the server package, not the shared SDK). Secret-free: it carries only
// connection-shape metadata, never private keys or passwords.
type Line struct {
	ID                 string `json:"id"`           // == LineHashID (stable handle)
	LineHashID         string `json:"line_hash_id"` // stable across re-probes; see lineHash / stableLineHandle
	LineID             string `json:"line_id,omitempty"`
	NodeID             string `json:"node_id"`
	NodeIdentityUUID   string `json:"node_identity_uuid,omitempty"`
	LineUUID           string `json:"line_uuid,omitempty"`            // design-15 D1: durable control-plane identity (vpnmeta/lineuuid)
	DownstreamLineUUID string `json:"downstream_line_uuid,omitempty"` // design-15 §6: declared chain edge target
	Core               string `json:"core"`                           // sing-box | xray | mihomo
	Source             string `json:"source"`                         // managed | discovered | imported
	Managed            bool   `json:"managed"`                        // under Lattice config management
	Name               string `json:"name"`
	Tag                string `json:"tag,omitempty"`
	// InboundTags is every sing-box inbound tag the node reported for the conf
	// file this line stands for. Tag above is that file's name, which equals the
	// inbound tag only by the helper script's convention; a hand-written file, or
	// one holding a relay pair, carries tags of its own. Traffic counters and
	// connection records arrive keyed by the core's real inbound tags, so these
	// are what those joins have to run against. Empty when the node's sing-box
	// helper predates the field, which leaves the convention in force and every
	// existing join unchanged.
	InboundTags []string `json:"inbound_tags,omitempty"`
	// NamedUsers and UnnamedUsers count the credentials on this line's conf file
	// that the node can and cannot count individually. sing-box builds its stats
	// user allowlist by name, so an unnamed credential never gets a per-user
	// counter and its traffic stays inside the inbound total. That is a
	// permanent property of the config rather than a failed attribution, and the
	// two are worth telling apart on screen. Both zero means the node did not
	// report, which is not the same as a line with no credentials.
	NamedUsers   int    `json:"named_users,omitempty"`
	UnnamedUsers int    `json:"unnamed_users,omitempty"`
	Type         string `json:"type,omitempty"` // protocol
	Transport    string `json:"transport,omitempty"`
	Security     string `json:"security,omitempty"`
	ListenHost   string `json:"listen_host,omitempty"`
	ListenPort   int    `json:"listen_port,omitempty"`
	PublicHost   string `json:"public_host,omitempty"`
	// PublicPort is where the outside actually reaches this line, when that
	// differs from ListenPort. Declared by the node, because a mapping that
	// lives in a provider's router cannot be read from the config here. Zero
	// means the listen port is also the public one.
	PublicPort int `json:"public_port,omitempty"`
	// ProviderEdge is the hostname a provider forwards into this node from. A
	// relay names it as its outbound server, so it is the only host under which
	// a chain into a NAT node can be matched back to the line that ends it.
	ProviderEdge   string   `json:"provider_edge,omitempty"`
	Domain         string   `json:"domain,omitempty"`
	OutboundRef    string   `json:"outbound_ref,omitempty"`    // direct | <host/tag> | "" unknown
	OutboundServer string   `json:"outbound_server,omitempty"` // downstream server host the outbound routes to
	OutboundPort   int      `json:"outbound_port,omitempty"`   // downstream server port the outbound routes to
	JumpEdges      []string `json:"jump_edges,omitempty"`      // line_hash_ids this line relays to
	// DeclaredJumpEdges is the subset of JumpEdges resolved from the sidecar's
	// declared downstream_line_uuid (design-15 §6), not inferred from outbound
	// host/port — the UI badges these as orchestrated edges.
	DeclaredJumpEdges []string `json:"declared_jump_edges,omitempty"`
	// design-17: a line backed by a server-owned managed-line definition (the
	// overlay) carries the definition's state. The join is by line_hash_id —
	// the compiler pre-computes the hash discovery will assign, so a
	// rediscovered applied line lands on its definition exactly.
	Overlay       bool   `json:"overlay,omitempty"`
	OverlayStatus string `json:"overlay_status,omitempty"` // planned | applied | failed
	OverlayUser   string `json:"overlay_user,omitempty"`
	UserCount     int    `json:"user_count"`
	UserKnown     bool   `json:"user_known"`       // false ⇒ discovered line, count not yet inspected
	Status        string `json:"status,omitempty"` // ok | pending | error | stale
	LastError     string `json:"last_error,omitempty"`
	// design-19: what the service is doing, as opposed to what the config
	// says. Status above answers "does the configuration check out";
	// ServiceState answers "is anything actually running and holding this
	// line's port". They must never be merged back into one field: their
	// disagreement is exactly the incident signal.
	ServiceState     string    `json:"service_state,omitempty"` // running | down | restarting | unknown
	ServiceCheckedAt time.Time `json:"service_checked_at,omitempty"`
	// ServiceNote is the probe's own account of why the state is not
	// "running": the refused candidate and the rule it failed, or the command
	// that could not run. Empty when the service is proven running, so a
	// consumer that prints it prints only what needs a hand.
	ServiceNote string            `json:"service_note,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"` // sing-box `_lattice` block (future enrich)
}

// LineGroup is the set of lines on one node — the unit the dashboard renders.
type LineGroup struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name,omitempty"`
	Lines    []Line `json:"lines"`
}

// lineHash computes the stable identity of a line from its connection shape. It is
// stable across re-probes so the relay graph (jump_edges), dedup, and the future
// node-line map are deterministic. It is NOT a storage id and intentionally
// excludes volatile fields (status, timestamps, user counts).
func lineHash(nodeID, core, typ, listenHost string, listenPort int, tag, outbound string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		nodeID, core, typ, listenHost, strconv.Itoa(listenPort), tag, outbound,
	}, "\x00")))
	return "line_" + hex.EncodeToString(sum[:])[:24]
}

func stableLineHandle(lineID string) string {
	lineID = strings.ToLower(strings.TrimSpace(lineID))
	if lineID == "" || len(lineID) > 128 {
		return ""
	}
	for _, r := range lineID {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return ""
	}
	return "line_" + lineID
}

func effectiveDiscoveredLineID(node model.SingBoxNode) string {
	return firstNonEmpty(node.LineID, node.Metadata["line_id"])
}

// singBoxInboundTagsKey is the node-reported metadata entry carrying the sing-box
// inbound tags a conf file actually defines, JSON-encoded so a tag holding any
// character survives the trip. The helper script emits it from the config file
// itself, which is the only place the real tags exist: the discovery record names
// a line by its file name, and nothing else on the box states the difference.
const singBoxInboundTagsKey = "inbound_tags"

// maxDiscoveredInboundTags bounds what one reported line can claim. A conf file
// holding more inbounds than this is not a line, and the cap keeps a malformed
// or hostile report from turning the tag index into a scan.
const maxDiscoveredInboundTags = 64

// singBoxNamedUsersKey and singBoxUnnamedUsersKey are the node-reported counts
// of credentials sing-box can and cannot count on their own, across every
// inbound in the conf file. Absent when the node reports nothing or the file
// holds no credentials at all; those two are indistinguishable here and neither
// supports a claim, so both read as zero and no claim is made.
const (
	singBoxNamedUsersKey   = "named_users"
	singBoxUnnamedUsersKey = "unnamed_users"
)

// discoveredUserNaming decodes the reported credential-naming counts. A value
// it cannot read, or one past what a conf file could plausibly hold, yields
// zero, which simply leaves the line saying nothing about its credentials.
func discoveredUserNaming(node model.SingBoxNode) (named, unnamed int) {
	read := func(key string) int {
		v, err := strconv.Atoi(strings.TrimSpace(node.Metadata[key]))
		if err != nil || v < 0 || v > maxDiscoveredCredentials {
			return 0
		}
		return v
	}
	return read(singBoxNamedUsersKey), read(singBoxUnnamedUsersKey)
}

// maxDiscoveredCredentials bounds a reported credential count. It only has to
// be past anything a real conf file carries; the cap exists so a malformed or
// hostile report cannot put an absurd number on an operator's screen.
const maxDiscoveredCredentials = 100000

// discoveredInboundTags decodes the reported inbound tags of one discovered line.
// Anything it cannot read yields nothing, which simply leaves the line joined by
// its file name exactly as before.
func discoveredInboundTags(node model.SingBoxNode) []string {
	raw := strings.TrimSpace(node.Metadata[singBoxInboundTagsKey])
	if raw == "" {
		return nil
	}
	var decoded []string
	if json.Unmarshal([]byte(raw), &decoded) != nil || len(decoded) > maxDiscoveredInboundTags {
		return nil
	}
	var out []string
	for _, tag := range decoded {
		if tag = strings.TrimSpace(tag); tag != "" {
			out = appendUniqueSorted(out, tag)
		}
	}
	return out
}

// nodeTagKey is one (node, inbound tag) join key. A sing-box tag is unique only
// within one node, so the node id is half of the key everywhere.
type nodeTagKey struct {
	NodeID string
	Tag    string
}

// lineTagClaim ranks the evidence behind one line's claim on an inbound tag. A
// tag resolves to the line holding the strongest claim on it; two lines tied at
// that strength resolve to neither.
type lineTagClaim int

const (
	// claimFileName is a line's own name, standing on nothing but the helper
	// script's convention that create() writes the file name into the inbound's
	// tag field. It is what every join assumed before this index existed. A
	// conventional line's name is also a reported tag and is recorded again at
	// the stronger level, so what is left at this level alone is a name the node
	// either did not confirm or positively did not list.
	claimFileName lineTagClaim = iota
	// claimReported is a tag the node stated sing-box actually loaded. Counters
	// and connection records are keyed by these, so this is the only kind of
	// claim that is evidence about the thing being joined.
	claimReported
)

// lineInboundTagIndex maps every inbound tag the read model can vouch for to the
// line that owns it, for one fleet-wide set of groups. Both tag-keyed joins in
// the server (usage counters and connection records) run off this, so the rules
// live in one place.
//
// Claims are ranked, not ordered by pass. A line's own name used to win
// unconditionally, which is wrong in exactly the case this index was built for:
// when a line's name is not a tag sing-box loaded, and another line reports that
// same string as one it did load, the bytes are the second line's and were being
// credited to the first with nothing flagged. Silence is the problem there.
// An unattributed row is visible in the usage view; a misattributed one reads
// like a fact.
//
// Two lines tied at the strongest claim resolve to neither. Attribution is
// allowed to say it does not know; it is not allowed to guess, because a wrong
// attribution written once is indistinguishable from a right one forever after.
func lineInboundTagIndex(groups []LineGroup) map[nodeTagKey]Line {
	type claim struct {
		line      Line
		strength  lineTagClaim
		contested bool
	}
	claims := map[nodeTagKey]*claim{}
	record := func(nodeID, tag string, ln Line, strength lineTagClaim) {
		if tag = strings.TrimSpace(tag); tag == "" {
			return
		}
		key := nodeTagKey{NodeID: nodeID, Tag: tag}
		switch cur, ok := claims[key]; {
		case !ok, strength > cur.strength:
			// A stronger claim also clears any contest among weaker ones: those
			// were only tied with each other.
			claims[key] = &claim{line: ln, strength: strength}
		case strength == cur.strength && cur.line.LineHashID != ln.LineHashID:
			cur.contested = true
		}
	}
	for _, g := range groups {
		for _, ln := range g.Lines {
			// The line's own name, on the helper script's convention. A
			// conventional line also reports that same string below, which
			// records it again at the stronger level; nothing here needs to
			// special-case that, because the strongest claim on a key wins.
			record(ln.NodeID, ln.Tag, ln, claimFileName)
			for _, tag := range ln.InboundTags {
				record(ln.NodeID, tag, ln, claimReported)
			}
		}
	}
	index := make(map[nodeTagKey]Line, len(claims))
	for key, c := range claims {
		if c.contested {
			continue
		}
		index[key] = c.line
	}
	return index
}

func provesLineUUIDAuthorityHash(line Line) bool {
	if explicit := stableLineHandle(line.LineID); explicit != "" {
		return explicit == line.LineHashID
	}
	return lineHash(line.NodeID, line.Core, line.Type, line.ListenHost, line.ListenPort, line.Tag, line.OutboundRef) == line.LineHashID
}

// lineUUIDAuthorityResolver is the pure, immutable reverse authority used by
// every discovered-line projection. Construction scans the supplied authority
// exactly once. Empty values denote ambiguous UUIDs and never resolve.
type lineUUIDAuthorityResolver struct {
	hashByUUID  map[string]string
	uuidByHash  map[string]string
	ownerByHash map[string]string
}

func newLineUUIDAuthorityResolver(each func(func(hash, uuid, ownerNodeID string))) lineUUIDAuthorityResolver {
	resolver := lineUUIDAuthorityResolver{
		hashByUUID:  make(map[string]string),
		uuidByHash:  make(map[string]string),
		ownerByHash: make(map[string]string),
	}
	each(func(hash, uuid, ownerNodeID string) {
		resolver.add(hash, uuid, ownerNodeID)
	})
	return resolver
}

func (r lineUUIDAuthorityResolver) add(hash, uuid, ownerNodeID string) {
	hash = strings.TrimSpace(hash)
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	if hash == "" {
		return
	}
	r.uuidByHash[hash] = uuid
	r.ownerByHash[hash] = strings.TrimSpace(ownerNodeID)
	if !validLineUUIDv4(uuid) {
		return
	}
	if prior, exists := r.hashByUUID[uuid]; exists && prior != hash {
		r.hashByUUID[uuid] = ""
	} else if !exists {
		r.hashByUUID[uuid] = hash
	}
}

func (r lineUUIDAuthorityResolver) resolve(nodeID, lineID, reportedUUID string, fallback func() string) string {
	if explicit := stableLineHandle(lineID); explicit != "" {
		return explicit
	}
	reportedUUID = strings.ToLower(strings.TrimSpace(reportedUUID))
	if validLineUUIDv4(reportedUUID) {
		if hash := r.hashByUUID[reportedUUID]; hash != "" {
			owner := r.ownerByHash[hash]
			if owner == strings.TrimSpace(nodeID) {
				return hash
			}
			candidate := fallback()
			if owner == "" && candidate == hash {
				return hash
			}
			return candidate
		}
	}
	return fallback()
}

// uuid returns a UUID only when both directions uniquely identify the same
// hash. This round trip prevents a dynamically computed hash from re-admitting
// a duplicated UUID into compiler or read-model output.
func (r lineUUIDAuthorityResolver) uuid(hash string) (string, bool) {
	hash = strings.TrimSpace(hash)
	uuid := r.uuidByHash[hash]
	return uuid, uuid != "" && r.hashByUUID[uuid] == hash
}

func validLineUUIDv4(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if !proxyUUIDRe.MatchString(value) || value[14] != '4' {
		return false
	}
	return strings.ContainsRune("89ab", rune(value[19]))
}

// buildLineGroups merges Lattice-managed inbounds and on-box discovered nodes into
// one node-grouped Line set. Managed lines win a (node,type,port) collision (the
// managed view is richer and editable); the matching discovered entry is dropped
// so an applied-then-discovered inbound is not listed twice.
func (s *Server) buildLineGroups() []LineGroup {
	// A projection owns one immutable view of UUID authority. Holding the
	// authority lock across the batch prevents concurrent reattach from mixing
	// generations and lets all known lines resolve without per-line KV scans.
	s.lineUUIDMu.Lock()
	defer s.lineUUIDMu.Unlock()
	uuidByHash, ownerByHash := s.store.LineUUIDAuthoritySnapshot()
	uuidResolver := newLineUUIDAuthorityResolver(func(yield func(hash, uuid, ownerNodeID string)) {
		for hash, uuid := range uuidByHash {
			yield(hash, uuid, ownerByHash[hash])
		}
	})

	byNode := map[string][]Line{}
	// (nodeID|type|port) -> already have a managed line, so skip the discovered dup.
	managedKey := map[string]bool{}

	// (1) Managed lines: each node profile selects a subset of inbounds.
	inboundByID := map[string]model.ProxyInbound{}
	for _, ib := range s.store.ProxyInbounds() {
		inboundByID[ib.ID] = ib
	}
	users := s.store.ProxyUsers()
	for _, prof := range s.store.ProxyNodeProfiles() {
		applied := strings.TrimSpace(prof.AppliedSHA256) != ""
		for _, inboundID := range prof.InboundIDs {
			ib, ok := inboundByID[inboundID]
			if !ok || !ib.Enabled {
				continue
			}
			core := firstNonEmpty(ib.Core, prof.Core)
			listenHost := firstNonEmpty(ib.Listen, prof.ListenIP)
			domain := firstNonEmpty(ib.SNI, ib.Host)
			const outbound = "direct" // Lattice-rendered inbounds are terminal endpoints
			status := "pending"
			if applied {
				status = "ok"
			}
			if strings.TrimSpace(prof.LastError) != "" {
				status = "error"
			}
			ln := Line{
				NodeID:           prof.NodeID,
				NodeIdentityUUID: s.nodeIdentityUUID(prof.NodeID),
				Core:             core,
				Source:           "managed",
				Managed:          true,
				Name:             firstNonEmpty(ib.Name, ib.ID),
				Tag:              ib.ID,
				Type:             ib.Protocol,
				ListenHost:       listenHost,
				ListenPort:       ib.Port,
				PublicHost:       firstNonEmpty(prof.Hostname, s.nodePublicHost(prof.NodeID)),
				Domain:           domain,
				OutboundRef:      outbound,
				UserCount:        countInboundUsers(users, inboundID),
				UserKnown:        true,
				Status:           status,
				LastError:        prof.LastError,
			}
			ln.ServiceState, ln.ServiceCheckedAt, ln.ServiceNote = s.singBoxServiceState(prof.NodeID)
			ln.LineHashID = lineHash(ln.NodeID, ln.Core, ln.Type, ln.ListenHost, ln.ListenPort, ln.Tag, outbound)
			ln.ID = ln.LineHashID
			byNode[ln.NodeID] = append(byNode[ln.NodeID], ln)
			managedKey[managedDedupKey(ln.NodeID, ln.Type, ln.ListenPort)] = true
		}
	}

	// (2) Discovered lines: read-only `sb --json list` mirror. Connection shape is
	// known. Newer discovery sources also include listen_host / outbound_ref /
	// user_count from runtime config inspection; older agents leave them empty
	// and UserKnown=false.
	for _, inv := range s.liveSingBoxInventories(s.now()) {
		nodeSvcState, nodeSvcAt, nodeSvcNote := s.singBoxServiceState(inv.NodeID)
		for _, n := range inv.Nodes {
			port, _ := strconv.Atoi(strings.TrimSpace(n.Port))
			if managedKey[managedDedupKey(inv.NodeID, n.Protocol, port)] {
				continue // same line already shown from the managed side
			}
			status := "ok"
			lastErr := ""
			if inv.Status != "" && inv.Status != "ok" {
				status = "error"
				lastErr = inv.Error
			}
			lineID := effectiveDiscoveredLineID(n)
			nodeUUID := firstNonEmpty(n.NodeIdentityUUID, n.Metadata["node_uuid"], n.Metadata["lattice_identity_uuid"], s.nodeIdentityUUID(inv.NodeID))
			ln := Line{
				LineID:             lineID,
				LineUUID:           strings.TrimSpace(n.LineUUID),
				NodeID:             inv.NodeID,
				NodeIdentityUUID:   nodeUUID,
				DownstreamLineUUID: strings.TrimSpace(n.DownstreamLineUUID),
				Core:               "sing-box",
				Source:             "discovered",
				Managed:            false,
				Name:               n.Name,
				Tag:                n.Name,
				InboundTags:        discoveredInboundTags(n),
				Type:               n.Protocol,
				Transport:          n.Network,
				ListenHost:         n.ListenHost,
				ListenPort:         port,
				PublicHost:         n.Address,
				PublicPort:         atoiSafe(n.PublicPort),
				ProviderEdge:       strings.TrimSpace(inv.ProviderEdge),
				Domain:             firstNonEmpty(n.SNI, n.Host),
				OutboundRef:        n.OutboundRef,
				OutboundServer:     n.OutboundServer,
				OutboundPort:       atoiSafe(n.OutboundPort),
				UserCount:          n.UserCount,
				UserKnown:          n.UserKnown,
				Status:             status,
				LastError:          lastErr,
				Metadata:           n.Metadata,
				ServiceState:       refineLineServiceState(nodeSvcState, n.PortBound),
				ServiceCheckedAt:   nodeSvcAt,
				ServiceNote:        nodeSvcNote,
			}
			ln.NamedUsers, ln.UnnamedUsers = discoveredUserNaming(n)
			ln.LineHashID = uuidResolver.resolve(ln.NodeID, ln.LineID, ln.LineUUID, func() string {
				return lineHash(ln.NodeID, ln.Core, ln.Type, ln.ListenHost, ln.ListenPort, ln.Tag, ln.OutboundRef)
			})
			ln.ID = ln.LineHashID
			byNode[ln.NodeID] = append(byNode[ln.NodeID], ln)
		}
	}

	// (3) Fleet-wide relay (jump) edge resolver. A line whose outbound resolves to
	// a downstream server:port that matches another line's endpoint is a hub → exit
	// chain: record the downstream line's stable hash on the hub line's JumpEdges.
	// This is what lets the dashboard draw cross-node (A → B) relay edges.
	index := map[string]string{} // normHostPort(host,port) -> line_hash_id
	for _, lines := range byNode {
		for _, ln := range lines {
			for _, host := range []string{ln.PublicHost, ln.Domain, ln.ListenHost} {
				if strings.TrimSpace(host) == "" {
					continue
				}
				index[normHostPort(host, ln.ListenPort)] = ln.LineHashID
			}
		}
	}
	// A name a node answers to is not always a name it reports. A DDNS profile
	// publishes a record for a node, and a relay elsewhere names that record as
	// its outbound server, but the node itself may only ever report its bare
	// address, so the endpoint had no key and the edge was lost. The control
	// plane owns these records, so it can supply the missing names rather than
	// resolving anything.
	ddnsHosts := map[string][]string{} // node_id -> record names
	for _, profile := range s.store.DDNSProfiles() {
		node := strings.TrimSpace(profile.NodeID)
		if node == "" {
			continue
		}
		for _, d := range profile.Domains {
			if d = strings.TrimSpace(d); d != "" {
				ddnsHosts[node] = append(ddnsHosts[node], d)
			}
		}
	}

	// A node behind a provider is reached at the provider's edge hostname on a
	// forwarded port, and neither half of that pair is what the node listens on:
	// the relay names <provider edge>:<public port> while the loop above filed
	// the line under <own host>:<listen port>. Both have to be in the index or
	// the edge into a NAT node is lost outright, which is what hid four of one
	// hub's twenty-four relays. Filed second and without clobbering, so a line
	// reached directly always keeps the key it already owns.
	for _, lines := range byNode {
		for _, ln := range lines {
			port := ln.PublicPort
			if port <= 0 {
				port = ln.ListenPort
			}
			if port <= 0 {
				continue
			}
			hosts := append([]string{ln.ProviderEdge, ln.PublicHost, ln.Domain}, ddnsHosts[ln.NodeID]...)
			for _, host := range hosts {
				if strings.TrimSpace(host) == "" {
					continue
				}
				for _, p := range []int{port, ln.ListenPort} {
					if p <= 0 {
						continue
					}
					key := normHostPort(host, p)
					if _, taken := index[key]; !taken {
						index[key] = ln.LineHashID
					}
				}
			}
		}
	}
	for nodeID, lines := range byNode {
		for i := range lines {
			ln := &lines[i]
			if strings.TrimSpace(ln.OutboundServer) == "" || ln.OutboundPort <= 0 {
				continue
			}
			ref := strings.ToLower(strings.TrimSpace(ln.OutboundRef))
			if ref == "direct" || ref == "" {
				continue
			}
			target := index[normHostPort(ln.OutboundServer, ln.OutboundPort)]
			if target == "" || target == ln.LineHashID {
				continue
			}
			if !containsString(ln.JumpEdges, target) {
				ln.JumpEdges = append(ln.JumpEdges, target)
			}
		}
		byNode[nodeID] = lines
	}

	// (4) design-15 D1: attach the durable control-plane line_uuid to every line.
	// Allocation failure must degrade (uuid left empty + log) and never fail the
	// whole read model. Managed lines have no downstream metadata source yet, so
	// DownstreamLineUUID stays empty for them this slice.
	for nodeID, lines := range byNode {
		for i := range lines {
			if uuid, ok := uuidResolver.uuid(lines[i].LineHashID); ok {
				owner := uuidResolver.ownerByHash[lines[i].LineHashID]
				if owner == lines[i].NodeID {
					lines[i].LineUUID = uuid
					continue
				}
				if owner == "" && provesLineUUIDAuthorityHash(lines[i]) {
					if err := s.putLineUUIDAuthority(lines[i].LineHashID, uuid, lines[i].NodeID); err == nil {
						uuidResolver.ownerByHash[lines[i].LineHashID] = lines[i].NodeID
						lines[i].LineUUID = uuid
						continue
					}
				}
			}
			if persisted := uuidResolver.uuidByHash[lines[i].LineHashID]; persisted != "" {
				s.logger.Printf("linemeta: reject non-unique or invalid persisted line_uuid %s for %s", persisted, lines[i].LineHashID)
				lines[i].LineUUID = ""
				continue
			}
			uuid := strings.ToLower(strings.TrimSpace(lines[i].LineUUID))
			_, uuidKnown := uuidResolver.hashByUUID[uuid]
			if !validLineUUIDv4(uuid) || uuidKnown {
				var err error
				uuid, err = newProxyUUID()
				if err != nil {
					s.logger.Printf("linemeta: allocate line_uuid for %s: %v", lines[i].LineHashID, err)
					lines[i].LineUUID = ""
					continue
				}
			}
			if err := s.putLineUUIDAuthority(lines[i].LineHashID, uuid, lines[i].NodeID); err != nil {
				s.logger.Printf("linemeta: persist line_uuid for %s: %v", lines[i].LineHashID, err)
				lines[i].LineUUID = ""
				continue
			}
			lines[i].LineUUID = uuid
			uuidResolver.add(lines[i].LineHashID, uuid, lines[i].NodeID)
		}
		byNode[nodeID] = lines
	}

	// (4b) design-17: join the managed-line overlay definitions onto their
	// rediscovered lines. Defs are keyed by the planned line_hash_id; a
	// definition whose apply never landed simply has no line to join, and its
	// status surfaces through the lines service's "managed" listing instead.
	// Join failure degrades (no overlay flags) and never fails the read model.
	if defs, err := s.managedLineDefs(); err != nil {
		s.logger.Printf("linemeta: list managed line defs: %v", err)
	} else if len(defs) > 0 {
		byHash := map[string]managedLineDef{}
		for _, def := range defs {
			byHash[def.LineHashID] = def
		}
		for nodeID, lines := range byNode {
			for i := range lines {
				if def, ok := byHash[lines[i].LineHashID]; ok {
					lines[i].Overlay = true
					lines[i].OverlayStatus = def.Status
					lines[i].OverlayUser = def.UserID
					lines[i].Security = model.ProxySecurityReality
				}
			}
			byNode[nodeID] = lines
		}
	}

	// E3 committed chain authority overlays ordinary discovery before metadata is
	// rendered. Attempts are intentionally excluded: pending and failed
	// candidates must never leak into DownstreamLineUUID/JumpEdges. A committed
	// remove tombstone carries an empty target and therefore clears only the
	// source declaration while observation catches up.
	committedChains := s.store.LineChainSnapshot().Definitions
	for nodeID, lines := range byNode {
		for i := range lines {
			definition, ok := committedChains[strings.ToLower(strings.TrimSpace(lines[i].LineUUID))]
			if !ok {
				continue
			}
			lines[i].DownstreamLineUUID = strings.ToLower(strings.TrimSpace(definition.TargetLineUUID))
		}
		byNode[nodeID] = lines
	}

	// (5) design-15 §6: declared chain edges. A sidecar-declared
	// downstream_line_uuid resolves to the downstream line's hash fleet-wide —
	// exact across machines, immune to NAT and shared ports — and takes
	// provenance precedence over the inferred (host,port) edges from (3).
	uuidIndex := map[string]string{} // line_uuid -> unique line_hash_id; empty means ambiguous
	for _, lines := range byNode {
		for _, ln := range lines {
			uuid := strings.ToLower(strings.TrimSpace(ln.LineUUID))
			if uuid != "" {
				if prior, exists := uuidIndex[uuid]; exists && prior != ln.LineHashID {
					uuidIndex[uuid] = ""
				} else if !exists {
					uuidIndex[uuid] = ln.LineHashID
				}
			}
		}
	}
	for nodeID, lines := range byNode {
		for i := range lines {
			declared := strings.TrimSpace(lines[i].DownstreamLineUUID)
			if declared == "" {
				continue
			}
			target := uuidIndex[declared]
			if target == "" || target == lines[i].LineHashID {
				continue // downstream unknown to the fleet (deleted/down) or self
			}
			// Declared is authoritative when it resolves. Discard every inferred
			// candidate, including a conflicting host/port match: design-15's
			// first-match-wins rule is about the source, not merely de-duplication.
			lines[i].JumpEdges = []string{target}
			if !containsString(lines[i].DeclaredJumpEdges, target) {
				lines[i].DeclaredJumpEdges = append(lines[i].DeclaredJumpEdges, target)
			}
		}
		byNode[nodeID] = lines
	}

	// Group, name, and sort deterministically (nodes by id, lines by port then tag).
	groups := make([]LineGroup, 0, len(byNode))
	for nodeID, lines := range byNode {
		sort.Slice(lines, func(i, j int) bool {
			if lines[i].ListenPort != lines[j].ListenPort {
				return lines[i].ListenPort < lines[j].ListenPort
			}
			return lines[i].Tag < lines[j].Tag
		})
		groups = append(groups, LineGroup{NodeID: nodeID, NodeName: s.nodeDisplayName(nodeID), Lines: lines})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].NodeID < groups[j].NodeID })
	return groups
}

func managedDedupKey(nodeID, typ string, port int) string {
	return nodeID + "\x00" + typ + "\x00" + strconv.Itoa(port)
}

// atoiSafe parses a decimal port string, returning 0 on any failure.
func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// normHostPort is the case-insensitive host:port key used to match an outbound's
// downstream destination against another line's listening endpoint.
func normHostPort(host string, port int) string {
	return strings.ToLower(strings.TrimSpace(host)) + "|" + strconv.Itoa(port)
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// countInboundUsers counts enabled proxy users eligible for an inbound. An empty
// InboundIDs means "all inbounds" (the existing subscription semantics).
func countInboundUsers(users []model.ProxyUser, inboundID string) int {
	n := 0
	for _, u := range users {
		if !u.Enabled {
			continue
		}
		if len(u.InboundIDs) == 0 {
			n++
			continue
		}
		for _, id := range u.InboundIDs {
			if id == inboundID {
				n++
				break
			}
		}
	}
	return n
}

func (s *Server) nodePublicHost(nodeID string) string {
	if n, ok := s.store.Node(nodeID); ok {
		return strings.TrimSpace(n.PublicIP)
	}
	return ""
}

func (s *Server) nodeIdentityUUID(nodeID string) string {
	if n, ok := s.store.Node(nodeID); ok {
		return strings.TrimSpace(n.LatticeIdentityUUID)
	}
	return ""
}

func (s *Server) nodeDisplayName(nodeID string) string {
	if n, ok := s.store.Node(nodeID); ok {
		if name := strings.TrimSpace(n.Name); name != "" {
			return name
		}
	}
	return nodeID
}
