package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/traceattr"
)

// Server-side attribution glue: it builds the immutable topology snapshot that
// traceattr works over, and expands a session filter into the node-local
// predicates an agent can evaluate.
//
// The snapshot is rebuilt per ingest batch rather than cached separately,
// because the two inputs it reads are already cached upstream: the line read
// model has its own TTL, and the user name index is a cheap walk. A stale or
// cold snapshot is expected and is handled by leaving records unresolved for a
// later retry, never by guessing.

// traceTopology assembles the (node, tag) -> line and u_<hex> -> user id maps.
func (s *Server) traceTopology() traceattr.Topology {
	groups, _ := s.lineReadModel()
	lines := map[traceattr.NodeTag]traceattr.LineRef{}
	// tagsByLineUUID is kept here rather than recomputed by callers because it
	// falls out of the same walk.
	for _, g := range groups {
		for _, ln := range g.Lines {
			if ln.Tag == "" {
				continue
			}
			lines[traceattr.NodeTag{NodeID: ln.NodeID, Tag: ln.Tag}] = traceattr.LineRef{
				LineUUID:   ln.LineUUID,
				LineHashID: ln.LineHashID,
			}
		}
	}
	users := map[string]string{}
	for name, target := range s.userLineNameIndex() {
		id := strings.TrimSpace(target.VpnUserID)
		if id == "" {
			id = strings.TrimSpace(target.ProxyUserID)
		}
		if id != "" {
			users[name] = id
		}
	}
	return traceattr.Topology{
		LinesByNodeTag: lines,
		UserIDByName:   users,
		BuiltAt:        s.now(),
	}
}

// attributeTraceRecords resolves line and user identity on an incoming batch.
// Records it cannot place are left explicitly unresolved rather than guessed;
// the retry sweep picks them up once the read model catches up.
func (s *Server) attributeTraceRecords(records []model.ConnRecord) {
	if len(records) == 0 {
		return
	}
	traceattr.New(s.traceTopology()).AttributeAll(records)
}

// traceUserNamesForNode turns the session's user ids into the on-box names that
// node actually renders. A user with no credential on this node contributes
// nothing, which is why the caller must treat an empty result for a non-empty
// filter as "this session does not apply here" rather than as "match all".
func (s *Server) traceUserNamesForNode(nodeID string, filter model.TraceFilter) []string {
	if len(filter.UserIDs) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, u := range filter.UserIDs {
		want[strings.TrimSpace(u)] = true
	}
	lineOnNode := map[string]bool{}
	groups, _ := s.lineReadModel()
	for _, g := range groups {
		if g.NodeID != nodeID {
			continue
		}
		for _, ln := range g.Lines {
			if ln.LineHashID != "" {
				lineOnNode[ln.LineHashID] = true
			}
		}
	}
	seen := map[string]bool{}
	out := []string{}
	for name, target := range s.userLineNameIndex() {
		if !lineOnNode[target.LineHashID] {
			continue
		}
		id := strings.TrimSpace(target.VpnUserID)
		if id == "" {
			id = strings.TrimSpace(target.ProxyUserID)
		}
		if !want[id] || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// traceInboundTagsForNode turns the session's line uuids into this node's
// inbound tags. Same emptiness rule as traceUserNamesForNode.
func (s *Server) traceInboundTagsForNode(nodeID string, filter model.TraceFilter) []string {
	if len(filter.LineUUIDs) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, u := range filter.LineUUIDs {
		want[strings.TrimSpace(u)] = true
	}
	out := []string{}
	groups, _ := s.lineReadModel()
	for _, g := range groups {
		if g.NodeID != nodeID {
			continue
		}
		for _, ln := range g.Lines {
			if ln.Tag != "" && want[ln.LineUUID] {
				out = append(out, ln.Tag)
			}
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// validateLoopbackHostPort accepts only host:port where host is a loopback
// literal or "localhost". A hostname that merely resolves to loopback today is
// refused, because resolution is not a property the control plane can pin, and
// this address is where an agent will send a bearer secret.
func validateLoopbackHostPort(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q must be host:port", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port %q is out of range", portStr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host %q must be a loopback literal or localhost", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("host %q is not a loopback address", host)
	}
	return nil
}
