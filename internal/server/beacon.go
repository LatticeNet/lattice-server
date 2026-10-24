package server

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The measurement beacon, control-plane side (lattice docs design 29 D3 and
// D12). The server holds one 32-byte key per target node and derives a path
// key per (source, target, epoch) from it. A target is handed its table and
// a source only its own key per target, through the authenticated config
// pull; nothing else ever carries a key. What runs is what an approved
// node.beacon plan said: the table holds the plan's approved sources that
// still use the beacon, and nobody else.

// Reachability check of a newly applied plan.
const (
	beaconReachPackets     = 3
	beaconReachIntervalSec = 60
	beaconReachTimeoutSec  = 2
)

// beaconErrorMax bounds the error text an agent reports.
const beaconErrorMax = 200

// beaconRuntime is the in-memory beacon state: each node's latest facts
// report. The egress addresses a plan depends on are durable
// (store.BeaconRegistry.Egress).
type beaconRuntime struct {
	mu    sync.Mutex
	facts map[string]model.BeaconFacts
	// reachMu serializes the reachability check's writes: a sync and a
	// verdict arriving together must not overwrite each other.
	reachMu sync.Mutex
}

func (b *beaconRuntime) noteFacts(nodeID string, f model.BeaconFacts) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.facts == nil {
		b.facts = map[string]model.BeaconFacts{}
	}
	b.facts[nodeID] = f
}

func (b *beaconRuntime) forgetFacts(nodeID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.facts, nodeID)
}

func (b *beaconRuntime) latestFacts(nodeID string) (model.BeaconFacts, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f, ok := b.facts[nodeID]
	return f, ok
}

// noteBeaconEgress records the address a node's agent connected from, kept
// only when it is a global IPv4 address: an agent reaching the control plane
// over WireGuard or a private network says nothing about where its probes
// leave. The record is durable and written only when the address moves, so
// a node.beacon plan rendered again after a restart admits the same
// addresses it was made with, before every source has pulled again.
func (s *Server) noteBeaconEgress(nodeID, ip string) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Unmap().Is4() {
		return
	}
	addr = addr.Unmap()
	if model.MonitorDestinationRefused(addr) || beacon.AddressRefused(addr) {
		return
	}
	if err := s.store.SetBeaconEgress(nodeID, addr.String()); err != nil {
		s.logger.Printf("beacon egress of node %s not recorded: %v", nodeID, err)
	}
}

// beaconFactsOf is a node's latest beacon report: the in-memory one when
// this server has heard it, else what the node record kept.
func (s *Server) beaconFactsOf(n model.Node) *model.BeaconFacts {
	if f, ok := s.beacon.latestFacts(n.ID); ok {
		return &f
	}
	if n.Beacon != nil {
		f := *n.Beacon
		return &f
	}
	return nil
}

// normalizeBeaconFacts keeps a report within its bounds; nil when there is
// none. It is the agent's own telemetry, so an out-of-vocabulary value is
// dropped rather than refused.
func normalizeBeaconFacts(in *model.BeaconFacts, now time.Time) *model.BeaconFacts {
	if in == nil {
		return nil
	}
	out := model.BeaconFacts{Responder: in.Responder}
	if in.Refusal == model.PathReasonRefusedByNode {
		out.Refusal = in.Refusal
	}
	switch in.State {
	case model.BeaconAgentOff, model.BeaconAgentListening, model.BeaconAgentBindFailed, model.BeaconAgentCircuitOpen, model.BeaconAgentRefused:
		out.State = in.State
	}
	if out.Refusal != "" {
		out.State = model.BeaconAgentRefused
	}
	if addr, err := beacon.ParseIPv4(strings.TrimSpace(in.Bind)); err == nil {
		out.Bind = addr.String()
	}
	if in.Port > 0 && in.Port <= 65535 {
		out.Port = in.Port
	}
	out.Epoch = in.Epoch
	if in.Sources > 0 && in.Sources <= 65535 {
		out.Sources = in.Sources
	}
	if !in.LastAuthAt.IsZero() && !in.LastAuthAt.After(now.Add(5*time.Minute)) {
		out.LastAuthAt = in.LastAuthAt.UTC()
	}
	msg := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(in.Error))
	if msg = strings.TrimSpace(msg); msg != "" {
		if len(msg) > beaconErrorMax {
			msg = msg[:beaconErrorMax]
		}
		out.Error = strings.ToValidUTF8(msg, "")
	}
	return &out
}

// beaconFactsDurable is the part of a report the node record keeps:
// everything but last_auth_at, which moves with every probe and lives in
// memory only, so the state file is written when the responder changes,
// never because it was probed.
func beaconFactsDurable(f *model.BeaconFacts) *model.BeaconFacts {
	if f == nil {
		return nil
	}
	out := *f
	out.LastAuthAt = time.Time{}
	return &out
}

// beaconFactsDurableChanged reports whether a report differs from the
// stored one in anything the node record keeps.
func beaconFactsDurableChanged(prev, next *model.BeaconFacts) bool {
	if (prev == nil) != (next == nil) {
		return true
	}
	if prev == nil {
		return false
	}
	return *beaconFactsDurable(prev) != *beaconFactsDurable(next)
}

// noteBeaconFacts takes a heartbeat's report: kept in memory always,
// written to the node record when it changed durably. A beat without one
// (an agent older than M2b, or one downgraded to it) clears the report, as
// a beat without probe_methods clears those. A change to where a target
// listens (its state, bind address or port) starts its pending reachability
// check: a change plan that moves the port leaves the agent reporting
// listening before and after, and only the port says it moved.
func (s *Server) noteBeaconFacts(nodeID string, stored *model.BeaconFacts, reported *model.BeaconFacts) {
	facts := normalizeBeaconFacts(reported, s.now())
	if facts == nil {
		s.beacon.forgetFacts(nodeID)
		if stored != nil {
			if err := s.store.SetNodeBeaconFacts(nodeID, nil); err != nil {
				s.logger.Printf("beacon facts for node %s not cleared: %v", nodeID, err)
			}
		}
		return
	}
	s.beacon.noteFacts(nodeID, *facts)
	if !beaconFactsDurableChanged(stored, facts) {
		return
	}
	if err := s.store.SetNodeBeaconFacts(nodeID, beaconFactsDurable(facts)); err != nil {
		s.logger.Printf("beacon facts for node %s not stored: %v", nodeID, err)
		return
	}
	if beaconListenMoved(stored, facts) {
		if t, ok := s.store.BeaconTarget(nodeID); ok && t.ReachArmed {
			s.syncBeaconReach(s.now())
		}
	}
}

// beaconListenMoved reports whether a report changes where the agent says
// it listens: its state, its bind address or its port.
func beaconListenMoved(prev, next *model.BeaconFacts) bool {
	if prev == nil || next == nil {
		return prev != next
	}
	return prev.State != next.State || prev.Bind != next.Bind || prev.Port != next.Port
}

// beaconListening reports whether a node's agent says it listens where its
// applied plan put it.
func beaconListening(facts *model.BeaconFacts, t store.BeaconTarget) bool {
	return facts != nil && facts.State == model.BeaconAgentListening &&
		facts.Bind == t.Settings.Bind && facts.Port == t.Settings.Port
}

// beaconTargetGate is why no source may probe target now, "" when sources
// may: the target has an applied, enabled beacon with a key, and its agent
// has a responder and does not refuse it.
func beaconTargetGate(t store.BeaconTarget, exists bool, facts *model.BeaconFacts) string {
	if !exists || !t.Settings.Enabled || t.Key == "" || t.Epoch == 0 {
		return model.PathReasonBeaconNotEnabled
	}
	if t.CompanionPending {
		return model.PathReasonFirewallPending
	}
	if facts != nil && facts.Refusal != "" {
		return model.PathReasonRefusedByNode
	}
	if facts == nil || !facts.Responder {
		return model.PathReasonBeaconNotListening
	}
	return ""
}

// beaconNodeAddresses are the IPv4 addresses a node is known to answer on:
// its public and primary interface addresses and the hosts of the public
// line endpoints the latency port rule accepted for it (which include a
// provider edge it declares). An advertised endpoint must be one of them.
func beaconNodeAddresses(n model.Node, endpoints map[string]latencyNodeEndpoints) map[string]bool {
	out := map[string]bool{}
	for _, raw := range []string{n.PublicIP, n.InternalIP} {
		if addr, err := beacon.ParseIPv4(strings.TrimSpace(raw)); err == nil {
			out[addr.String()] = true
		}
	}
	for _, c := range endpoints[n.ID].candidates {
		if host, _, err := net.SplitHostPort(c.target); err == nil {
			if addr, err := beacon.ParseIPv4(host); err == nil {
				out[addr.String()] = true
			}
		}
	}
	return out
}

// beaconEndpointCurrent reports whether an advertised endpoint is still one
// of the node's addresses. A node that moved leaves its old address to
// whoever holds it next, so sources must not keep sending there.
func beaconEndpointCurrent(n model.Node, endpoint string, endpoints map[string]latencyNodeEndpoints) bool {
	ap, err := beacon.ParseEndpoint(endpoint)
	if err != nil {
		return false
	}
	return beaconNodeAddresses(n, endpoints)[ap.Addr().String()]
}

// beaconSourceGate is why source may not probe target by beacon, given the
// target is usable: it must be in the applied plan's approved set.
func beaconSourceGate(t store.BeaconTarget, sourceID string) string {
	for _, src := range t.Approved {
		if src.NodeID == sourceID {
			return ""
		}
	}
	if t.Exposure == model.BeaconExposureNetGuard {
		return model.PathReasonFirewallPending
	}
	return model.PathReasonBeaconSourcePending
}

// beaconTargetKey decodes a target's key.
func beaconTargetKey(t store.BeaconTarget) (beacon.Key, bool) {
	var key beacon.Key
	raw, err := base64.StdEncoding.DecodeString(t.Key)
	if err != nil || len(raw) != beacon.KeyLen {
		return key, false
	}
	copy(key[:], raw)
	return key, true
}

func newBeaconTargetKey() (string, error) {
	var key beacon.Key
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// beaconSendEpoch is the epoch sources sign with now: the previous one
// until the target has held the new one for model.BeaconSourceSwitchDelay.
func beaconSendEpoch(t store.BeaconTarget, now time.Time) uint32 {
	if t.PrevEpoch != 0 && (t.AckedAt.IsZero() || now.Before(t.AckedAt.Add(model.BeaconSourceSwitchDelay))) {
		return t.PrevEpoch
	}
	return t.Epoch
}

// beaconPrevEpochState says what the target's table does with PrevEpoch
// now: accept it, hold it retired, or drop it.
func beaconPrevEpochState(t store.BeaconTarget, now time.Time) (include, retired bool) {
	if t.PrevEpoch == 0 {
		return false, false
	}
	if t.AckedAt.IsZero() || now.Before(t.AckedAt.Add(model.BeaconEpochOverlap)) {
		return true, false
	}
	if now.Before(t.AckedAt.Add(model.BeaconEpochOverlap + model.BeaconRetiredGrace)) {
		return true, true
	}
	return false, false
}

// rotateBeaconEpoch moves t to a new epoch. A table holds at most two epochs
// per source, so the oldest goes at once.
func rotateBeaconEpoch(t *store.BeaconTarget, now time.Time) {
	t.PrevEpoch = t.Epoch
	t.Epoch++
	t.RotatedAt = now.UTC()
	t.AckedAt = time.Time{}
}

// beaconCurrentSources are the sources that use target's beacon now: the
// candidates planned names for it (beaconPlanned: the path set's and every
// enabled auto check definition's whose target set holds it) and every
// source of an enabled operator beacon check naming it, less nodes that are
// gone, disabled, or whose agent does not run the beacon client.
func (s *Server) beaconCurrentSources(target string, planned latencyPlan, monitors []model.Monitor, nodes map[string]model.Node) map[string]bool {
	out := map[string]bool{}
	add := func(sourceID string) {
		n, ok := nodes[sourceID]
		if !ok || n.Disabled || sourceID == target || latencyProbeGate(n, model.MonitorTypeBeacon) != "" {
			return
		}
		out[sourceID] = true
	}
	for _, sourceID := range planned.beaconCandidates[target] {
		add(sourceID)
	}
	targets := monitorTargets{nodes: nodes}
	for _, mon := range monitors {
		if !store.MonitorOwnerOf(mon).Authored() || !mon.Enabled || mon.Type != model.MonitorTypeBeacon || mon.TargetNode != target {
			continue
		}
		for _, sourceID := range targets.monitorSources(mon) {
			add(sourceID)
		}
	}
	return out
}

// beaconTableSources are the node ids target's table holds: approved by the
// applied plan and current, sorted.
func beaconTableSources(t store.BeaconTarget, current map[string]bool) []string {
	var out []string
	for _, src := range t.Approved {
		if current[src.NodeID] {
			out = append(out, src.NodeID)
		}
	}
	sort.Strings(out)
	return out
}

// agentBeaconConfig is AgentConfig.Beacon for node: its source id, its path
// key for every target whose table holds it, and its own responder when an
// applied plan enables one. Pulling it is also when the node's own target
// state advances: a source that left the table rotates the epoch, and the
// first pull of a new epoch starts the switch-over clock.
func (s *Server) agentBeaconConfig(node model.Node, now time.Time) *model.AgentBeaconConfig {
	targets := s.store.BeaconTargets()
	if len(targets) == 0 {
		return nil
	}
	ids := s.store.BeaconSourceIDs()
	if _, isTarget := targets[node.ID]; !isTarget && ids[node.ID] == 0 {
		// Neither a target nor a source of any plan: nothing to compute.
		return nil
	}
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	planned := s.beaconPlanned(now, nodes)
	monitors := s.store.Monitors()
	out := &model.AgentBeaconConfig{SourceID: ids[node.ID]}

	if t, ok := targets[node.ID]; ok {
		if responder := s.beaconResponderFor(node, t, planned, monitors, nodes, ids, now); responder != nil {
			out.Responder = responder
		}
	}
	if out.SourceID != 0 && latencyProbeGate(node, model.MonitorTypeBeacon) == "" {
		targetIDs := make([]string, 0, len(targets))
		for id := range targets {
			targetIDs = append(targetIDs, id)
		}
		sort.Strings(targetIDs)
		for _, targetID := range targetIDs {
			t := targets[targetID]
			tn, ok := nodes[targetID]
			if !ok || targetID == node.ID {
				continue
			}
			if beaconTargetGate(t, true, s.beaconFactsOf(tn)) != "" || beaconSourceGate(t, node.ID) != "" ||
				!beaconEndpointCurrent(tn, t.Settings.Endpoint, planned.endpoints) {
				continue
			}
			current := s.beaconCurrentSources(targetID, planned, monitors, nodes)
			if !current[node.ID] {
				continue
			}
			key, ok := beaconTargetKey(t)
			if !ok {
				continue
			}
			epoch := beaconSendEpoch(t, now)
			pathKey := beacon.DerivePathKey(&key, out.SourceID, epoch)
			out.Keys = append(out.Keys, model.BeaconPathKey{TargetNode: targetID, Epoch: epoch, Key: slices.Clone(pathKey[:])})
		}
	}
	if out.SourceID == 0 && out.Responder == nil && len(out.Keys) == 0 {
		return nil
	}
	return out
}

// beaconResponderFor is node's responder configuration, nil when it has
// none. It writes the target state when the table's source set lost a
// member (rotation), when the node first holds a new epoch, or when the
// retired epoch's grace has ended.
func (s *Server) beaconResponderFor(node model.Node, t store.BeaconTarget, planned latencyPlan, monitors []model.Monitor, nodes map[string]model.Node, ids map[string]uint32, now time.Time) *model.BeaconResponderConfig {
	facts := s.beaconFactsOf(node)
	if beaconTargetGate(t, true, facts) != "" {
		return nil
	}
	current := s.beaconCurrentSources(node.ID, planned, monitors, nodes)
	tableSources := beaconTableSources(t, current)
	updated, err := s.store.UpdateBeaconTarget(node.ID, func(next *store.BeaconTarget, exists bool) (bool, error) {
		if !exists || !next.Settings.Enabled || next.Key == "" {
			return false, nil
		}
		// From the state being written, so an approval that committed after
		// the snapshot above is the one the table follows.
		tableSources = beaconTableSources(*next, current)
		changed := false
		removed := false
		for _, prior := range next.TableSources {
			if !slices.Contains(tableSources, prior) {
				removed = true
				break
			}
		}
		if removed {
			rotateBeaconEpoch(next, now)
			changed = true
		}
		if !slices.Equal(next.TableSources, tableSources) {
			next.TableSources = slices.Clone(tableSources)
			changed = true
		}
		if next.AckedAt.IsZero() {
			next.AckedAt = now.UTC()
			changed = true
		}
		if include, _ := beaconPrevEpochState(*next, now); !include && next.PrevEpoch != 0 {
			next.PrevEpoch = 0
			changed = true
		}
		return changed, nil
	})
	if err != nil {
		// Fail closed: serve the current source set even though the rotation
		// could not be recorded, so a source that left is out of the table
		// now; the next pull records the rotation.
		s.logger.Printf("beacon state of node %s not advanced: %v", node.ID, err)
		updated = t
		updated.TableSources = tableSources
	}
	if updated.Key == "" {
		return nil
	}
	key, ok := beaconTargetKey(updated)
	if !ok {
		return nil
	}
	cfg := &model.BeaconResponderConfig{
		Bind:   updated.Settings.Bind,
		Port:   updated.Settings.Port,
		Limits: updated.Settings.Limits,
		Table:  []model.BeaconTableKey{},
	}
	include, retired := beaconPrevEpochState(updated, now)
	for _, sourceNode := range updated.TableSources {
		id := ids[sourceNode]
		if id == 0 {
			continue
		}
		k := beacon.DerivePathKey(&key, id, updated.Epoch)
		cfg.Table = append(cfg.Table, model.BeaconTableKey{SourceID: id, Epoch: updated.Epoch, Key: slices.Clone(k[:])})
		if include {
			k := beacon.DerivePathKey(&key, id, updated.PrevEpoch)
			cfg.Table = append(cfg.Table, model.BeaconTableKey{SourceID: id, Epoch: updated.PrevEpoch, Key: slices.Clone(k[:]), Retired: retired})
		}
	}
	return cfg
}

// beaconRotate moves a node's key to a new epoch (the audited rotate
// route).
func (s *Server) beaconRotate(nodeID string, now time.Time) (store.BeaconTarget, error) {
	return s.store.UpdateBeaconTarget(nodeID, func(next *store.BeaconTarget, exists bool) (bool, error) {
		if !exists || !next.Settings.Enabled || next.Key == "" {
			return false, errBeaconNotEnabled
		}
		rotateBeaconEpoch(next, now)
		return true, nil
	})
}

// beaconMonitorGate is why source is not handed a beacon check to target
// now, "" when it is.
func (s *Server) beaconMonitorGate(source model.Node, target string, now time.Time) string {
	t, exists := s.store.BeaconTarget(target)
	tn, ok := s.store.Node(target)
	if !ok {
		return model.PathReasonBeaconNotEnabled
	}
	if reason := beaconTargetGate(t, exists, s.beaconFactsOf(tn)); reason != "" {
		return reason
	}
	if !beaconEndpointCurrent(tn, t.Settings.Endpoint, s.pathPlanned(now).endpoints) {
		return model.PathReasonNotProbeable
	}
	return beaconSourceGate(t, source.ID)
}

// syncBeaconReach writes the reachability checks that are due: one per
// target whose applied plan armed one and whose agent now listens where the
// plan put it, run by the first approved, current, online source with the
// beacon client. A target with no such source gets the no_source verdict.
func (s *Server) syncBeaconReach(now time.Time) {
	s.beacon.reachMu.Lock()
	defer s.beacon.reachMu.Unlock()
	targets := s.store.BeaconTargets()
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	planned := s.beaconPlanned(now, nodes)
	monitors := s.store.Monitors()
	var desired []model.Monitor
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, targetID := range ids {
		t := targets[targetID]
		tn, ok := nodes[targetID]
		if !ok || !t.ReachArmed || !t.Settings.Enabled || t.CompanionPending {
			continue
		}
		if !beaconListening(s.beaconFactsOf(tn), t) {
			continue
		}
		source := ""
		for _, candidate := range beaconTableSources(t, s.beaconCurrentSources(targetID, planned, monitors, nodes)) {
			if n := nodes[candidate]; n.Online && !n.Disabled {
				source = candidate
				break
			}
		}
		if source == "" {
			_, _ = s.store.UpdateBeaconTarget(targetID, func(next *store.BeaconTarget, exists bool) (bool, error) {
				if !exists || !next.ReachArmed {
					return false, nil
				}
				next.ReachArmed = false
				next.Reach = model.BeaconReachability{State: model.BeaconReachNoSource, CheckedAt: now.UTC()}
				return true, nil
			})
			continue
		}
		desired = append(desired, model.Monitor{
			ID:          model.BeaconReachMonitorPrefix + targetID,
			Name:        "Beacon reachability of " + latencyNodeLabel(tn),
			Type:        model.MonitorTypeBeacon,
			Target:      t.Settings.Endpoint,
			TargetNode:  targetID,
			IntervalSec: beaconReachIntervalSec,
			TimeoutSec:  beaconReachTimeoutSec,
			Packets:     beaconReachPackets,
			NodeIDs:     []string{source},
			Enabled:     true,
			Alert:       model.MonitorAlertOff,
			CreatedAt:   now.UTC(),
		})
		if t.Reach.Source != source || t.Reach.State != model.BeaconReachPending {
			_, _ = s.store.UpdateBeaconTarget(targetID, func(next *store.BeaconTarget, exists bool) (bool, error) {
				if !exists || !next.ReachArmed {
					return false, nil
				}
				next.Reach = model.BeaconReachability{State: model.BeaconReachPending, Source: source, MonitorID: model.BeaconReachMonitorPrefix + targetID}
				return true, nil
			})
		}
	}
	if _, err := s.store.SyncManagedMonitors(model.MonitorManagedBeacon, desired, now); err != nil {
		s.logger.Printf("beacon reachability checks not synced: %v", err)
	}
}

// noteBeaconReachResult turns a reachability check's first telling result
// into the target's verdict and retires the check. A result that only says
// the source's key or clock has not caught up keeps the check running.
func (s *Server) noteBeaconReachResult(result model.MonitorResult, now time.Time) {
	targetID, ok := strings.CutPrefix(result.MonitorID, model.BeaconReachMonitorPrefix)
	if !ok {
		return
	}
	verdict := ""
	switch {
	case result.Success:
		verdict = model.BeaconReachReachable
	case result.Reason == model.PathReasonBeaconNotListening:
		verdict = model.BeaconReachNotListening
	case result.Reason == "":
		verdict = model.BeaconReachFiltered
	default:
		return
	}
	s.beacon.reachMu.Lock()
	_, err := s.store.UpdateBeaconTarget(targetID, func(next *store.BeaconTarget, exists bool) (bool, error) {
		// Only the source the check was handed to may decide it.
		if !exists || !next.ReachArmed || next.Reach.Source != result.NodeID {
			return false, nil
		}
		next.ReachArmed = false
		next.Reach = model.BeaconReachability{State: verdict, Source: result.NodeID, MonitorID: result.MonitorID, CheckedAt: now.UTC()}
		return true, nil
	})
	s.beacon.reachMu.Unlock()
	if err != nil {
		s.logger.Printf("beacon reachability of node %s not stored: %v", targetID, err)
		return
	}
	s.syncBeaconReach(now)
}

// beaconSuggestedPort is the node's assigned random port, assigned and kept
// on first need.
func (s *Server) beaconSuggestedPort(nodeID string) (int, error) {
	if t, ok := s.store.BeaconTarget(nodeID); ok && t.SuggestedPort != 0 {
		return t.SuggestedPort, nil
	}
	port, err := randomBeaconPort()
	if err != nil {
		return 0, err
	}
	t, err := s.store.UpdateBeaconTarget(nodeID, func(next *store.BeaconTarget, exists bool) (bool, error) {
		if next.SuggestedPort != 0 {
			return false, nil
		}
		next.SuggestedPort = port
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	return t.SuggestedPort, nil
}

func randomBeaconPort() (int, error) {
	var b [2]byte
	span := beacon.PortRandomMax - beacon.PortRandomMin + 1
	// Rejection sampling keeps the draw uniform over the range.
	limit := (65536 / span) * span
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		v := int(b[0])<<8 | int(b[1])
		if v < limit {
			return beacon.PortRandomMin + v%span, nil
		}
	}
}

// beaconPlanned is the path set's plan with the beacon candidates of the
// enabled auto check definitions added, each definition's sets resolved once
// for every target the caller walks. The cached plan is not changed.
func (s *Server) beaconPlanned(now time.Time, nodes map[string]model.Node) latencyPlan {
	planned := s.pathPlanned(now)
	checks := s.checkBeaconCandidates(nodes)
	if len(checks) == 0 {
		return planned
	}
	merged := make(map[string][]string, len(planned.beaconCandidates)+len(checks))
	for target, sources := range planned.beaconCandidates {
		merged[target] = sources
	}
	for target, sources := range checks {
		merged[target] = append(slices.Clone(merged[target]), sources...)
	}
	planned.beaconCandidates = merged
	return planned
}

// checkBeaconCandidates are, per target node, the sources of every enabled
// auto check definition that measures it, less its excluded pairs: an auto
// pair takes the beacon only once the target's applied plan approves its
// source, so a node.beacon plan for the target approves them, as it did the
// path set's auto sources (design 29 D12, design 32 R1).
func (s *Server) checkBeaconCandidates(nodes map[string]model.Node) map[string][]string {
	var defs []model.CheckDefinition
	for _, def := range s.store.CheckDefinitions() {
		if def.Enabled && def.Type == model.CheckMethodAuto {
			defs = append(defs, def)
		}
	}
	if len(defs) == 0 {
		return nil
	}
	list := make([]model.Node, 0, len(nodes))
	for _, n := range nodes {
		list = append(list, n)
	}
	groupList := s.store.Groups()
	out := map[string][]string{}
	for _, def := range defs {
		sources := groups.ResolveTargets(def.Sources, list, groupList)
		for _, target := range groups.ResolveTargets(def.Targets, list, groupList) {
			for _, sourceID := range sources {
				if sourceID != target && !slices.Contains(def.ExcludedPairs, model.LatencyPair{Source: sourceID, Target: target}) {
					out[target] = append(out[target], sourceID)
				}
			}
		}
	}
	return out
}
