package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/traceattr"
	"github.com/LatticeNet/lattice-server/internal/tracestore"
	"time"
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
	// Keyed by every inbound tag a line can be shown to own, not by its name
	// alone. sing-box logs the tag the core loaded, and a conf file whose
	// inbound tags differ from its file name would otherwise have none of its
	// connections placed. lineInboundTagIndex owns the precedence rules.
	for key, ln := range lineInboundTagIndex(groups) {
		lines[traceattr.NodeTag{NodeID: key.NodeID, Tag: key.Tag}] = traceattr.LineRef{
			LineUUID:   ln.LineUUID,
			LineHashID: ln.LineHashID,
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

// traceReattributeInterval is how often unresolved records are retried, and
// traceReattributeWindow is how far back a retry looks. The topology it waits
// for is a 60 second cache and an inventory that is rebuilt after a restart, so
// minutes is the right scale; looking back further would re-walk records whose
// identity was never going to arrive.
const (
	traceReattributeInterval = 5 * time.Minute
	traceReattributeWindow   = 24 * time.Hour
	traceReattributeBatch    = 500
)

// startTraceReattribution repairs records that were stored unresolved.
//
// A record ingested while the line read model was cold has no line and no user,
// and nothing ever looked at it again: the documented five minute self-heal did
// not exist, so a cold window at startup left records permanently unattributed
// and invisible to every user or line filter. This is that sweep.
func (s *Server) startTraceReattribution() {
	if s.traceStore == nil {
		return
	}
	go func() {
		for {
			time.Sleep(traceReattributeInterval)
			if n, err := s.reattributeUnresolved(); err != nil {
				s.logger.Printf("trace reattribution: %v", err)
			} else if n > 0 {
				s.logger.Printf("trace reattribution: resolved %d record(s) that arrived before their topology", n)
			}
		}
	}()
}

// reattributeUnresolved runs one pass and reports how many records it repaired.
func (s *Server) reattributeUnresolved() (int, error) {
	now := s.now()
	page, err := s.traceStore.QueryRecords(tracestore.Filter{
		Since:       now.Add(-traceReattributeWindow),
		Until:       now,
		UserKinds:   []string{model.UserKindUnresolved, model.UserKindUnnamed},
		IncludeOpen: false,
		Limit:       traceReattributeBatch,
	})
	if err != nil {
		return 0, err
	}
	if len(page.Records) == 0 {
		return 0, nil
	}
	attributor := traceattr.New(s.traceTopology())
	repaired := 0
	for _, rec := range page.Records {
		before := rec
		attributor.Attribute(&rec)
		if rec.UserID == before.UserID && rec.LineUUID == before.LineUUID && rec.UserKind == before.UserKind {
			continue
		}
		key := model.KeyOf(rec)
		if err := s.traceStore.Reattribute(key, rec.StartedAt, rec); err != nil {
			return repaired, err
		}
		repaired++
	}
	return repaired, nil
}
