package server

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

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
	ID                 string            `json:"id"`           // == LineHashID (stable handle)
	LineHashID         string            `json:"line_hash_id"` // stable across re-probes; see lineHash / stableLineHandle
	LineID             string            `json:"line_id,omitempty"`
	NodeID             string            `json:"node_id"`
	NodeIdentityUUID   string            `json:"node_identity_uuid,omitempty"`
	LineUUID           string            `json:"line_uuid,omitempty"`            // design-15 D1: durable control-plane identity (vpnmeta/lineuuid)
	DownstreamLineUUID string            `json:"downstream_line_uuid,omitempty"` // design-15 §6: declared chain edge target
	Core               string            `json:"core"`                           // sing-box | xray | mihomo
	Source             string            `json:"source"`                         // managed | discovered | imported
	Managed            bool              `json:"managed"`                        // under Lattice config management
	Name               string            `json:"name"`
	Tag                string            `json:"tag,omitempty"`
	Type               string            `json:"type,omitempty"` // protocol
	ListenHost         string            `json:"listen_host,omitempty"`
	ListenPort         int               `json:"listen_port,omitempty"`
	PublicHost         string            `json:"public_host,omitempty"`
	Domain             string            `json:"domain,omitempty"`
	OutboundRef        string            `json:"outbound_ref,omitempty"`    // direct | <host/tag> | "" unknown
	OutboundServer     string            `json:"outbound_server,omitempty"` // downstream server host the outbound routes to
	OutboundPort       int               `json:"outbound_port,omitempty"`   // downstream server port the outbound routes to
	JumpEdges          []string          `json:"jump_edges,omitempty"`      // line_hash_ids this line relays to
	UserCount          int               `json:"user_count"`
	UserKnown          bool              `json:"user_known"`       // false ⇒ discovered line, count not yet inspected
	Status             string            `json:"status,omitempty"` // ok | pending | error | stale
	LastError          string            `json:"last_error,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"` // sing-box `_lattice` block (future enrich)
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

// buildLineGroups merges Lattice-managed inbounds and on-box discovered nodes into
// one node-grouped Line set. Managed lines win a (node,type,port) collision (the
// managed view is richer and editable); the matching discovered entry is dropped
// so an applied-then-discovered inbound is not listed twice.
func (s *Server) buildLineGroups() []LineGroup {
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
			lineID := firstNonEmpty(n.LineID, n.Metadata["line_id"])
			nodeUUID := firstNonEmpty(n.NodeIdentityUUID, n.Metadata["node_uuid"], n.Metadata["lattice_identity_uuid"], s.nodeIdentityUUID(inv.NodeID))
			ln := Line{
				LineID:             lineID,
				NodeID:             inv.NodeID,
				NodeIdentityUUID:   nodeUUID,
				DownstreamLineUUID: strings.TrimSpace(n.DownstreamLineUUID),
				Core:               "sing-box",
				Source:             "discovered",
				Managed:            false,
				Name:               n.Name,
				Tag:                n.Name,
				Type:               n.Protocol,
				ListenHost:         n.ListenHost,
				ListenPort:         port,
				PublicHost:         n.Address,
				Domain:             firstNonEmpty(n.SNI, n.Host),
				OutboundRef:        n.OutboundRef,
				OutboundServer:     n.OutboundServer,
				OutboundPort:       atoiSafe(n.OutboundPort),
				UserCount:          n.UserCount,
				UserKnown:          n.UserKnown,
				Status:             status,
				LastError:          lastErr,
				Metadata:           n.Metadata,
			}
			ln.LineHashID = stableLineHandle(ln.LineID)
			if ln.LineHashID == "" {
				ln.LineHashID = lineHash(ln.NodeID, ln.Core, ln.Type, ln.ListenHost, ln.ListenPort, ln.Tag, ln.OutboundRef)
			}
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
			uuid, err := s.ensureLineUUID(lines[i].LineHashID)
			if err != nil {
				s.logger.Printf("linemeta: allocate line_uuid for %s: %v", lines[i].LineHashID, err)
				continue
			}
			lines[i].LineUUID = uuid
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
