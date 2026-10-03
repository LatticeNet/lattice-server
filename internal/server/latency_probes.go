package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Latency and reachability probes between nodes. The operator's answer of
// 2026-10-02: probes run from the domestic node cd-hs-sh to the overseas
// nodes by default, and any node can be set to probe any other.
//
// The operator keeps one configuration. syncLatencyProbes turns it, against
// the fleet as it is now, into ordinary tcp monitors: one per target, assigned
// to the sources that probe it, marked ManagedBy "latency". Agents fetch them
// through /api/agent/monitors and report through the monitor result routes
// like any other monitor, so a probe needs nothing beyond the tcp monitor
// every agent has run since v0.3.3, and its results land in the hot store and
// its rollups. Results are never audited; only configuration saves and the
// rare sync that changes a generated monitor are.
//
// The port rule: which endpoint a probe dials
//
// A probe is a TCP connect, so it may only dial a port the target already
// serves to the public for its own reasons, and it must never touch a port
// whose exposure is guarded. From the target's current line inventory:
//
//  1. Protocols carried over TCP only: vless, vmess, trojan, anytls,
//     shadowsocks, shadowtls and naive. hysteria, hysteria2, tuic, wireguard
//     and the QUIC transport are UDP, which a connect cannot measure. direct,
//     socks, http and mixed inbounds are relays or proxies, not lines, and
//     are never dialled.
//  2. No loopback listener. A line behind the node's own TLS front listens
//     on 127.0.0.1 and reports the front's port, so a probe would measure the
//     front and whatever CDN sits before it, not the line.
//  3. Never SSH and never a knock-gated port. Port 22, every port sshd
//     reports, the SSH Guard plan's SSH port and every port its knock table
//     covers are refused, as the dialled port and as the listen port behind
//     it, even when a line claims them.
//  4. The port the world dials: the declared public port when the node sits
//     behind a provider, else the listen port.
//  5. The host: the provider edge when the node declares one and the line a
//     public port; else the line's published address when it is a public
//     IPv4 literal; else the node's public IPv4 unless the node declares NAT;
//     else the published host name. Private, loopback, link-local, CGNAT
//     and multicast addresses are never dialled.
//  6. Among what is left: a line sing-box was seen holding its port, then
//     one nobody checked, then one seen not listening; a raw TCP transport
//     before ws, http, h2, httpupgrade and grpc (those can sit behind a CDN);
//     then the lowest port, then the line name. The pick is sticky: a target
//     keeps its endpoint while that endpoint still passes the rule, so a
//     probe does not hop between lines and restart on every sweep.
//
// A target left with nothing is shown as not probeable, with the reason. A
// target whose inventory is not current (the node is offline, or the control
// plane has just started) keeps the endpoint its monitor already had: a node
// that went dark is exactly what the probe has to keep measuring.

const (
	// latencyDefaultSourceName is the node the defaults probe from.
	latencyDefaultSourceName = "cd-hs-sh"
	// latencyMonitorPrefix starts every generated monitor id; the rest is
	// the target node id, so a target has at most one generated monitor.
	latencyMonitorPrefix = "mon_lat_"
	// latencyProbeSyncInterval is how often the fleet is planned again. A
	// new node or a changed line inventory reaches the probes within it.
	latencyProbeSyncInterval = 2 * time.Minute

	latencyConfigMaxSources = 32
	latencyConfigMaxTargets = 512
	latencyConfigMaxPairs   = 4096
)

var (
	latencyTCPProtocols = map[string]bool{
		"vless": true, "vmess": true, "trojan": true, "anytls": true,
		"shadowsocks": true, "shadowtls": true, "naive": true,
	}
	latencyUDPProtocols    = map[string]bool{"hysteria": true, "hysteria2": true, "tuic": true, "wireguard": true}
	latencyUDPNetworks     = map[string]bool{"quic": true, "hysteria2": true, "tuic": true}
	latencyLayeredNetworks = map[string]bool{"ws": true, "http": true, "h2": true, "httpupgrade": true, "grpc": true}
	latencyCGNAT           = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
)

func latencyMonitorID(targetNodeID string) string { return latencyMonitorPrefix + targetNodeID }

// latencyRegion classifies a node for the default target rule by its
// Geo.Country (ISO alpha-2): CN is mainland China; HK, MO, TW and every other
// country are outside it; no country is unknown and never a default target.
func latencyRegion(n model.Node) (country, region string) {
	if n.Geo != nil {
		country = strings.ToUpper(strings.TrimSpace(n.Geo.Country))
	}
	switch country {
	case "":
		return "", model.LatencyRegionUnknown
	case "CN":
		return country, model.LatencyRegionMainland
	default:
		return country, model.LatencyRegionOutside
	}
}

// defaultLatencyProbeConfig is what is in force until an operator saves:
// probes on, every 60 s, from every node named cd-hs-sh to every node
// outside mainland China.
func defaultLatencyProbeConfig(nodes []model.Node) model.LatencyProbeConfig {
	cfg := model.LatencyProbeConfig{
		Enabled:     true,
		IntervalSec: model.LatencyProbeDefaultIntervalSec,
		TimeoutSec:  model.LatencyProbeDefaultTimeoutSec,
		AutoTargets: true,
	}
	for _, n := range nodes {
		if strings.EqualFold(strings.TrimSpace(n.Name), latencyDefaultSourceName) {
			cfg.Sources = append(cfg.Sources, n.ID)
		}
	}
	sort.Strings(cfg.Sources)
	return cfg
}

// latencyEndpoint is one dialable endpoint the port rule accepted.
type latencyEndpoint struct {
	target   string
	protocol string
	line     string
	rank     [3]int
}

func latencyLoopback(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// latencyPublicIPv4 returns raw as a dialable public IPv4 address.
func latencyPublicIPv4(raw string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", false
	}
	v4 := ip.To4()
	if v4 == nil || v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() ||
		v4.IsUnspecified() || v4.IsMulticast() || v4.Equal(net.IPv4bcast) || latencyCGNAT.Contains(v4) {
		return "", false
	}
	return v4.String(), true
}

// latencyHostname reports whether raw is a DNS name a probe may dial: not an
// address literal, not localhost, and only the characters a host name holds.
func latencyHostname(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 253 || net.ParseIP(strings.Trim(raw, "[]")) != nil || !strings.Contains(raw, ".") {
		return false
	}
	if strings.EqualFold(raw, "localhost") || strings.HasSuffix(strings.ToLower(raw), ".localhost") {
		return false
	}
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// latencyHost is step 5 of the port rule.
func latencyHost(node model.Node, inv model.SingBoxInventory, line model.SingBoxNode, publicPort int) string {
	if publicPort > 0 {
		edge := strings.TrimSpace(inv.ProviderEdge)
		if ip, ok := latencyPublicIPv4(edge); ok {
			return ip
		}
		if latencyHostname(edge) {
			return edge
		}
	}
	addr := strings.TrimSpace(line.Address)
	if ip, ok := latencyPublicIPv4(addr); ok {
		return ip
	}
	if !strings.EqualFold(strings.TrimSpace(inv.Network), "nat") {
		if ip, ok := latencyPublicIPv4(node.PublicIP); ok {
			return ip
		}
	}
	if latencyHostname(addr) {
		return addr
	}
	return ""
}

func latencyBoundRank(bound *bool) int {
	switch {
	case bound == nil:
		return 1
	case *bound:
		return 0
	default:
		return 2
	}
}

// latencyEndpoints applies steps 1 to 6 of the port rule to one inventory.
// With nothing accepted, the note says why (a model.LatencyEndpoint* code).
func latencyEndpoints(node model.Node, inv model.SingBoxInventory, refused map[int]bool) ([]latencyEndpoint, string) {
	var out []latencyEndpoint
	seen := map[string]bool{}
	sawUDP, sawTCPProtocol, sawAddressless := false, false, false
	for _, line := range inv.Nodes {
		protocol := strings.ToLower(strings.TrimSpace(line.Protocol))
		network := strings.ToLower(strings.TrimSpace(line.Network))
		if latencyUDPProtocols[protocol] || (latencyTCPProtocols[protocol] && latencyUDPNetworks[network]) {
			sawUDP = true
			continue
		}
		if !latencyTCPProtocols[protocol] {
			continue
		}
		sawTCPProtocol = true
		if latencyLoopback(line.ListenHost) {
			continue
		}
		listen, _ := strconv.Atoi(strings.TrimSpace(line.Port))
		public, _ := strconv.Atoi(strings.TrimSpace(line.PublicPort))
		port := listen
		if public > 0 {
			port = public
		}
		if port < 1 || port > 65535 || refused[port] || refused[listen] {
			continue
		}
		host := latencyHost(node, inv, line, public)
		if host == "" {
			sawAddressless = true
			continue
		}
		target := net.JoinHostPort(host, strconv.Itoa(port))
		if seen[target] {
			continue
		}
		seen[target] = true
		layered := 0
		if latencyLayeredNetworks[network] {
			layered = 1
		}
		out = append(out, latencyEndpoint{
			target:   target,
			protocol: protocol,
			line:     line.Name,
			rank:     [3]int{latencyBoundRank(line.PortBound), layered, port},
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return slices.Compare(out[i].rank[:], out[j].rank[:]) < 0
		}
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		return out[i].target < out[j].target
	})
	if len(out) > 0 {
		return out, ""
	}
	switch {
	case sawAddressless:
		return nil, model.LatencyEndpointNoAddress
	case sawUDP && !sawTCPProtocol:
		return nil, model.LatencyEndpointUDPOnly
	default:
		return nil, model.LatencyEndpointNoLine
	}
}

// latencyRefusedPorts is step 3 of the port rule for one node. approvals is
// the approval list, read once per plan.
func (s *Server) latencyRefusedPorts(nodeID string, approvals []model.Approval) map[int]bool {
	refused := map[int]bool{22: true}
	if reality := s.guardRealityForLint(nodeID); reality != nil && reality.SSHD != nil {
		for _, port := range reality.SSHD.Ports {
			refused[port] = true
		}
	}
	knock := s.sshGuardKnockStateIn(nodeID, approvals)
	if knock.SSHPort > 0 {
		refused[knock.SSHPort] = true
	}
	for _, port := range knock.GatedPorts {
		refused[port] = true
	}
	return refused
}

func latencyTargetPort(target string) int {
	_, raw, err := net.SplitHostPort(target)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(raw)
	return port
}

func latencyPairKey(source, target string) string { return source + "\x00" + target }

// latencyPlan is the configuration applied to the fleet: the plan the API
// returns and the generated monitors the store should hold.
type latencyPlan struct {
	plan    model.LatencyProbePlan
	desired []model.Monitor
}

// planLatencyProbes applies the configuration (or the defaults) to the fleet
// as it is now. It reads and never writes.
func (s *Server) planLatencyProbes(now time.Time) latencyPlan {
	nodes := s.store.Nodes()
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Name != nodes[j].Name {
			return nodes[i].Name < nodes[j].Name
		}
		return nodes[i].ID < nodes[j].ID
	})
	byID := make(map[string]model.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	cfg, stored := s.store.LatencyProbeConfig()
	if !stored {
		cfg = defaultLatencyProbeConfig(nodes)
	}
	out := latencyPlan{plan: model.LatencyProbePlan{
		Config:            cfg,
		Stored:            stored,
		DefaultSourceName: latencyDefaultSourceName,
		Nodes:             []model.LatencyProbeNode{},
		Pairs:             []model.LatencyProbePairState{},
	}}

	configured := map[string]bool{}
	var sources []string
	for _, sourceID := range cfg.Sources {
		if configured[sourceID] {
			continue
		}
		configured[sourceID] = true
		n, ok := byID[sourceID]
		switch {
		case !ok:
			out.plan.SourceNotes = latencyNote(out.plan.SourceNotes, sourceID, model.LatencySourceUnknownNode)
		case n.Disabled:
			out.plan.SourceNotes = latencyNote(out.plan.SourceNotes, sourceID, model.LatencySourceDisabled)
		default:
			sources = append(sources, sourceID)
		}
	}
	sort.Strings(sources)
	included, excluded := map[string]bool{}, map[string]bool{}
	for _, nodeID := range cfg.IncludeTargets {
		included[nodeID] = true
	}
	for _, nodeID := range cfg.ExcludeTargets {
		excluded[nodeID] = true
	}
	disabledPairs := map[string]bool{}
	for _, pair := range cfg.DisabledPairs {
		disabledPairs[latencyPairKey(pair.Source, pair.Target)] = true
	}
	existing := map[string]model.Monitor{}
	for _, mon := range s.store.Monitors() {
		if mon.ManagedBy == model.MonitorManagedLatency {
			existing[mon.ID] = mon
		}
	}
	inventories := map[string]model.SingBoxInventory{}
	for _, inv := range s.liveSingBoxInventories(now) {
		inventories[inv.NodeID] = inv
	}
	approvals := s.store.Approvals()
	interval := cfg.IntervalSec
	if interval <= 0 {
		interval = model.LatencyProbeDefaultIntervalSec
	}
	timeout := cfg.TimeoutSec
	if timeout <= 0 {
		timeout = model.LatencyProbeDefaultTimeoutSec
	}

	for _, n := range nodes {
		country, region := latencyRegion(n)
		pn := model.LatencyProbeNode{
			NodeID:  n.ID,
			Name:    n.Name,
			Country: country,
			Region:  region,
			Source:  configured[n.ID],
			Target:  model.LatencyTargetNone,
		}
		switch {
		case excluded[n.ID]:
			pn.TargetReason = model.LatencyReasonExcluded
		case n.Disabled:
			pn.TargetReason = model.LatencyReasonNodeDisabled
		case included[n.ID]:
			pn.Target, pn.TargetReason = model.LatencyTargetProbed, model.LatencyReasonIncluded
		case !cfg.AutoTargets:
			pn.TargetReason = model.LatencyReasonAutoOff
		case region == model.LatencyRegionOutside:
			pn.Target, pn.TargetReason = model.LatencyTargetProbed, model.LatencyReasonAuto
		case region == model.LatencyRegionMainland:
			pn.TargetReason = model.LatencyReasonMainland
		default:
			pn.TargetReason = model.LatencyReasonRegionUnknown
		}
		monitorID := latencyMonitorID(n.ID)
		prior, hadPrior := existing[monitorID]
		if pn.Target == model.LatencyTargetNone {
			if hadPrior {
				// Out of the set: the monitor stays, paused, with its history.
				paused := prior
				paused.Enabled = false
				out.desired = append(out.desired, paused)
				pn.MonitorID = monitorID
			}
			out.plan.Nodes = append(out.plan.Nodes, pn)
			continue
		}

		var chosen *latencyEndpoint
		refused := s.latencyRefusedPorts(n.ID, approvals)
		inv, live := inventories[n.ID]
		if live && (inv.Status == "" || inv.Status == "ok") {
			endpoints, note := latencyEndpoints(n, inv, refused)
			for i := range endpoints {
				if hadPrior && endpoints[i].target == prior.Target {
					chosen = &endpoints[i]
					break
				}
			}
			if chosen == nil && len(endpoints) > 0 {
				chosen = &endpoints[0]
			}
			pn.EndpointNote = note
		} else if hadPrior && prior.Target != "" && !refused[latencyTargetPort(prior.Target)] {
			chosen = &latencyEndpoint{target: prior.Target}
			pn.EndpointNote = model.LatencyEndpointLastKnown
		} else {
			pn.EndpointNote = model.LatencyEndpointNoInventory
		}

		var active []string
		firstPair := len(out.plan.Pairs)
		for _, sourceID := range sources {
			if sourceID == n.ID {
				continue
			}
			enabled := !disabledPairs[latencyPairKey(sourceID, n.ID)]
			pair := model.LatencyProbePairState{Source: sourceID, Target: n.ID, Enabled: enabled}
			if chosen != nil && enabled && cfg.Enabled {
				pair.Active = true
				active = append(active, sourceID)
			}
			out.plan.Pairs = append(out.plan.Pairs, pair)
		}
		// A monitor exists for the target while something probes it or a
		// history was already taken; nothing is created just to sit paused.
		if hadPrior || (chosen != nil && len(active) > 0) {
			for i := firstPair; i < len(out.plan.Pairs); i++ {
				out.plan.Pairs[i].MonitorID = monitorID
			}
		}

		if chosen == nil {
			pn.Target = model.LatencyTargetNotProbeable
			if hadPrior {
				paused := prior
				paused.Enabled = false
				out.desired = append(out.desired, paused)
				pn.MonitorID = monitorID
			}
			out.plan.Nodes = append(out.plan.Nodes, pn)
			continue
		}
		pn.Endpoint, pn.Protocol, pn.LineName = chosen.target, chosen.protocol, chosen.line
		if len(active) == 0 {
			pn.Target = model.LatencyTargetPaused
			switch {
			case !cfg.Enabled:
				pn.TargetReason = model.LatencyReasonConfigOff
			case !latencyHasOtherSource(sources, n.ID):
				pn.TargetReason = model.LatencyReasonNoSource
			default:
				pn.TargetReason = model.LatencyReasonPairsOff
			}
		}
		mon := model.Monitor{
			ID:          monitorID,
			Name:        "Latency to " + latencyNodeLabel(n),
			Type:        model.MonitorTypeTCP,
			Target:      chosen.target,
			IntervalSec: interval,
			TimeoutSec:  timeout,
			NodeIDs:     active,
			Enabled:     len(active) > 0,
			ManagedBy:   model.MonitorManagedLatency,
		}
		switch {
		case len(active) > 0:
		case hadPrior:
			// Paused: keep the sources the history was taken from, so the
			// monitors list still shows their last readings.
			mon.NodeIDs = slices.Clone(prior.NodeIDs)
		default:
			out.plan.Nodes = append(out.plan.Nodes, pn)
			continue
		}
		pn.MonitorID = monitorID
		out.desired = append(out.desired, mon)
		out.plan.Nodes = append(out.plan.Nodes, pn)
	}
	return out
}

func latencyNote(notes map[string]string, key, value string) map[string]string {
	if notes == nil {
		notes = map[string]string{}
	}
	notes[key] = value
	return notes
}

func latencyHasOtherSource(sources []string, target string) bool {
	for _, sourceID := range sources {
		if sourceID != target {
			return true
		}
	}
	return false
}

func latencyNodeLabel(n model.Node) string {
	if name := strings.TrimSpace(n.Name); name != "" {
		return name
	}
	return n.ID
}

// syncLatencyProbes plans the fleet and brings the generated monitors in line
// with the plan. The store writes only when a generated monitor changed, and
// only then is the sync audited.
func (s *Server) syncLatencyProbes(now time.Time) (model.LatencyProbePlan, store.ManagedMonitorChanges, error) {
	s.latencySync.Lock()
	defer s.latencySync.Unlock()
	planned := s.planLatencyProbes(now)
	changes, err := s.store.SyncManagedMonitors(model.MonitorManagedLatency, planned.desired, now)
	if err != nil {
		return planned.plan, changes, err
	}
	if changes.Changed() {
		s.recordAudit(model.AuditEvent{
			ID:       id.New("audit"),
			At:       now.UTC(),
			ActorID:  systemActorID,
			Action:   "monitor.latency.sync",
			Scope:    "monitor:admin",
			Decision: "allow",
			Metadata: map[string]string{
				"created":     latencyIDList(changes.Created),
				"updated":     latencyIDList(changes.Updated),
				"deleted":     latencyIDList(changes.Deleted),
				"config":      strconv.FormatInt(planned.plan.Config.Version, 10),
				"config_kind": map[bool]string{true: "stored", false: "defaults"}[planned.plan.Stored],
			},
		})
	}
	return planned.plan, changes, nil
}

// latencyIDList joins ids for an audit field, bounded so a fleet-wide change
// cannot grow one audit row without limit.
func latencyIDList(ids []string) string {
	const max = 40
	if len(ids) <= max {
		return strings.Join(ids, ",")
	}
	return strings.Join(ids[:max], ",") + fmt.Sprintf(",+%d", len(ids)-max)
}

// startLatencyProbeSync plans the fleet again every latencyProbeSyncInterval.
// The first run waits one interval, so agents have reported their line
// inventories since the control plane started; until then every target keeps
// the endpoint its monitor already had.
func (s *Server) startLatencyProbeSync() {
	s.runLatencyProbeSync(latencyProbeSyncInterval, func() {
		if _, _, err := s.syncLatencyProbes(s.now()); err != nil {
			s.logger.Printf("latency probes: %v", err)
		}
	})
}

// runLatencyProbeSync calls sync on every tick until Close stops it. A tick
// that lands after Close does not sync.
func (s *Server) runLatencyProbeSync(every time.Duration, sync func()) {
	s.latencySyncLoops.Add(1)
	go func() {
		defer s.latencySyncLoops.Done()
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-s.latencySyncStop:
				return
			case <-ticker.C:
			}
			select {
			case <-s.latencySyncStop:
				return
			default:
			}
			sync()
		}
	}()
}

// normalizeLatencyProbeConfig validates a configuration an operator sent:
// bounds, existing nodes, no node both included and excluded, no pair from a
// node to itself. Lists come back deduplicated and sorted, so two saves of
// the same intent store the same bytes.
func (s *Server) normalizeLatencyProbeConfig(in model.LatencyProbeConfig) (model.LatencyProbeConfig, error) {
	nodes := map[string]bool{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = true
	}
	out := model.LatencyProbeConfig{Enabled: in.Enabled, AutoTargets: in.AutoTargets, IntervalSec: in.IntervalSec, TimeoutSec: in.TimeoutSec}
	if out.IntervalSec == 0 {
		out.IntervalSec = model.LatencyProbeDefaultIntervalSec
	}
	if out.TimeoutSec == 0 {
		out.TimeoutSec = model.LatencyProbeDefaultTimeoutSec
	}
	if out.IntervalSec < model.LatencyProbeMinIntervalSec || out.IntervalSec > model.LatencyProbeMaxIntervalSec {
		return out, fmt.Errorf("interval_sec must be %d to %d", model.LatencyProbeMinIntervalSec, model.LatencyProbeMaxIntervalSec)
	}
	if out.TimeoutSec < 1 || out.TimeoutSec > model.LatencyProbeMaxTimeoutSec || out.TimeoutSec >= out.IntervalSec {
		return out, fmt.Errorf("timeout_sec must be 1 to %d and shorter than interval_sec", model.LatencyProbeMaxTimeoutSec)
	}
	ids := func(field string, list []string, limit int) ([]string, error) {
		set := map[string]bool{}
		for _, raw := range list {
			nodeID := strings.TrimSpace(raw)
			if !nodes[nodeID] {
				return nil, fmt.Errorf("%s names %q, which is not a node", field, raw)
			}
			set[nodeID] = true
		}
		if len(set) > limit {
			return nil, fmt.Errorf("%s holds %d nodes, at most %d", field, len(set), limit)
		}
		outIDs := make([]string, 0, len(set))
		for nodeID := range set {
			outIDs = append(outIDs, nodeID)
		}
		sort.Strings(outIDs)
		return outIDs, nil
	}
	var err error
	if out.Sources, err = ids("sources", in.Sources, latencyConfigMaxSources); err != nil {
		return out, err
	}
	if out.IncludeTargets, err = ids("include_targets", in.IncludeTargets, latencyConfigMaxTargets); err != nil {
		return out, err
	}
	if out.ExcludeTargets, err = ids("exclude_targets", in.ExcludeTargets, latencyConfigMaxTargets); err != nil {
		return out, err
	}
	for _, nodeID := range out.IncludeTargets {
		if slices.Contains(out.ExcludeTargets, nodeID) {
			return out, fmt.Errorf("node %q is both included and excluded", nodeID)
		}
	}
	pairs := map[string]model.LatencyPair{}
	for _, pair := range in.DisabledPairs {
		pair.Source, pair.Target = strings.TrimSpace(pair.Source), strings.TrimSpace(pair.Target)
		if !nodes[pair.Source] || !nodes[pair.Target] {
			return out, fmt.Errorf("disabled pair %q to %q names a node that does not exist", pair.Source, pair.Target)
		}
		if pair.Source == pair.Target {
			return out, fmt.Errorf("disabled pair %q names one node twice", pair.Source)
		}
		pairs[latencyPairKey(pair.Source, pair.Target)] = pair
	}
	if len(pairs) > latencyConfigMaxPairs {
		return out, fmt.Errorf("disabled_pairs holds %d pairs, at most %d", len(pairs), latencyConfigMaxPairs)
	}
	for _, pair := range pairs {
		out.DisabledPairs = append(out.DisabledPairs, pair)
	}
	sort.Slice(out.DisabledPairs, func(i, j int) bool {
		a, b := out.DisabledPairs[i], out.DisabledPairs[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Target < b.Target
	})
	return out, nil
}

// latencyNodeVisible is whether a principal may read latency data about a
// node: monitor:read on it.
func latencyNodeVisible(p principal, nodeID string) bool {
	return rbac.Allows(p.Principal, "monitor:read", nodeID)
}

// latencyPlanForPrincipal narrows a plan to the nodes the principal may read.
// A pair needs both of its nodes; the configuration's lists are narrowed the
// same way, so a node-confined token learns nothing about other nodes.
func latencyPlanForPrincipal(plan model.LatencyProbePlan, p principal) model.LatencyProbePlan {
	if !principalHasNodeRestriction(p) {
		return plan
	}
	visible := func(nodeID string) bool { return latencyNodeVisible(p, nodeID) }
	filter := func(list []string) []string {
		out := []string{}
		for _, nodeID := range list {
			if visible(nodeID) {
				out = append(out, nodeID)
			}
		}
		return out
	}
	narrowed := plan
	narrowed.Config.Sources = filter(plan.Config.Sources)
	narrowed.Config.IncludeTargets = filter(plan.Config.IncludeTargets)
	narrowed.Config.ExcludeTargets = filter(plan.Config.ExcludeTargets)
	narrowed.Config.DisabledPairs = nil
	for _, pair := range plan.Config.DisabledPairs {
		if visible(pair.Source) && visible(pair.Target) {
			narrowed.Config.DisabledPairs = append(narrowed.Config.DisabledPairs, pair)
		}
	}
	narrowed.Nodes = []model.LatencyProbeNode{}
	for _, n := range plan.Nodes {
		if visible(n.NodeID) {
			narrowed.Nodes = append(narrowed.Nodes, n)
		}
	}
	narrowed.Pairs = []model.LatencyProbePairState{}
	for _, pair := range plan.Pairs {
		if visible(pair.Source) && visible(pair.Target) {
			narrowed.Pairs = append(narrowed.Pairs, pair)
		}
	}
	narrowed.SourceNotes = nil
	for nodeID, note := range plan.SourceNotes {
		if visible(nodeID) {
			narrowed.SourceNotes = latencyNote(narrowed.SourceNotes, nodeID, note)
		}
	}
	return narrowed
}

// handleLatencyProbes reads the plan (GET, monitor:read) or saves the
// configuration (PUT, monitor:admin on the whole fleet). A save names the
// version it was made from; a stale one is refused with 409 so two operators
// cannot overwrite each other. The answer to a save is the new plan, after
// the generated monitors were brought in line with it.
func (s *Server) handleLatencyProbes(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "monitor:read") {
			return
		}
		writeJSON(w, http.StatusOK, latencyPlanForPrincipal(s.planLatencyProbes(s.now()).plan, p))
	case http.MethodPut:
		if !s.requireScope(w, p, "monitor:admin") {
			return
		}
		if principalHasNodeRestriction(p) {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "restricted token cannot change fleet-wide latency probes"))
			return
		}
		var req model.LatencyProbeConfig
		if !decodeClientJSON(w, r, &req) {
			return
		}
		cfg, err := s.normalizeLatencyProbeConfig(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		now := s.now()
		stored, err := s.store.SetLatencyProbeConfig(cfg, req.Version, p.ActorID, now)
		if errors.Is(err, store.ErrLatencyProbeVersion) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			At:       now.UTC(),
			Action:   "monitor.latency.config",
			Scope:    "monitor:admin",
			Decision: "allow",
			Metadata: map[string]string{
				"version":         strconv.FormatInt(stored.Version, 10),
				"enabled":         strconv.FormatBool(stored.Enabled),
				"interval_sec":    strconv.Itoa(stored.IntervalSec),
				"timeout_sec":     strconv.Itoa(stored.TimeoutSec),
				"sources":         latencyIDList(stored.Sources),
				"auto_targets":    strconv.FormatBool(stored.AutoTargets),
				"include_targets": latencyIDList(stored.IncludeTargets),
				"exclude_targets": latencyIDList(stored.ExcludeTargets),
				"disabled_pairs":  strconv.Itoa(len(stored.DisabledPairs)),
			},
		})
		plan, _, err := s.syncLatencyProbes(now)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("configuration saved; the probes follow on the next sweep: %w", err))
			return
		}
		writeJSON(w, http.StatusOK, latencyPlanForPrincipal(plan, p))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}
