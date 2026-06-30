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
	ID          string            `json:"id"`           // == LineHashID (stable handle)
	LineHashID  string            `json:"line_hash_id"` // stable across re-probes; see lineHash
	NodeID      string            `json:"node_id"`
	Core        string            `json:"core"`    // sing-box | xray | mihomo
	Source      string            `json:"source"`  // managed | discovered | imported
	Managed     bool              `json:"managed"` // under Lattice config management
	Name        string            `json:"name"`
	Tag         string            `json:"tag,omitempty"`
	Type        string            `json:"type,omitempty"` // protocol
	ListenHost  string            `json:"listen_host,omitempty"`
	ListenPort  int               `json:"listen_port,omitempty"`
	PublicHost  string            `json:"public_host,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	OutboundRef string            `json:"outbound_ref,omitempty"` // direct | <host/tag> | "" unknown
	JumpEdges   []string          `json:"jump_edges,omitempty"`   // line_hash_ids this line relays to
	UserCount   int               `json:"user_count"`
	UserKnown   bool              `json:"user_known"`       // false ⇒ discovered line, count not yet inspected
	Status      string            `json:"status,omitempty"` // ok | pending | error | stale
	LastError   string            `json:"last_error,omitempty"`
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
				NodeID:      prof.NodeID,
				Core:        core,
				Source:      "managed",
				Managed:     true,
				Name:        firstNonEmpty(ib.Name, ib.ID),
				Tag:         ib.ID,
				Type:        ib.Protocol,
				ListenHost:  listenHost,
				ListenPort:  ib.Port,
				PublicHost:  firstNonEmpty(prof.Hostname, s.nodePublicHost(prof.NodeID)),
				Domain:      domain,
				OutboundRef: outbound,
				UserCount:   countInboundUsers(users, inboundID),
				UserKnown:   true,
				Status:      status,
				LastError:   prof.LastError,
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
			ln := Line{
				NodeID:      inv.NodeID,
				Core:        "sing-box",
				Source:      "discovered",
				Managed:     false,
				Name:        n.Name,
				Tag:         n.Name,
				Type:        n.Protocol,
				ListenHost:  n.ListenHost,
				ListenPort:  port,
				PublicHost:  n.Address,
				Domain:      firstNonEmpty(n.SNI, n.Host),
				OutboundRef: n.OutboundRef,
				UserCount:   n.UserCount,
				UserKnown:   n.UserKnown,
				Status:      status,
				LastError:   lastErr,
				Metadata:    n.Metadata,
			}
			ln.LineHashID = lineHash(ln.NodeID, ln.Core, ln.Type, ln.ListenHost, ln.ListenPort, ln.Tag, ln.OutboundRef)
			ln.ID = ln.LineHashID
			byNode[ln.NodeID] = append(byNode[ln.NodeID], ln)
		}
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

func (s *Server) nodeDisplayName(nodeID string) string {
	if n, ok := s.store.Node(nodeID); ok {
		if name := strings.TrimSpace(n.Name); name != "" {
			return name
		}
	}
	return nodeID
}
