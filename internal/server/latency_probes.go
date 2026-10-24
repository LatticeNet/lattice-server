package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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
//  5. The host is the node's own address or the provider edge it declares,
//     never an address a line merely publishes: a line's address comes from
//     the node and could name any host, including one inside the source's
//     network. When the node declares a provider edge and the line a public
//     port, the edge, as a public IPv4 literal or as a name the control
//     plane resolved to public addresses only (latency_edges.go; the probe
//     dials the address, never the name). Else the node's public IPv4,
//     unless the node declares NAT and the line does not publish that same
//     address. A line's host name is never dialled. Private, loopback,
//     link-local, CGNAT, benchmark (fake-ip) and multicast addresses are
//     never dialled. The node reports its public IPv4 too, so a compromised
//     node can still aim the probe of itself at another public address on a
//     port its inventory names; it cannot aim it into the source's network.
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
	// latencyBenchmark is 198.18.0.0/15, which proxy clients hand out as
	// fake-ip DNS answers: never a real host.
	latencyBenchmark = &net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)}
)

func latencyMonitorID(targetNodeID string) string { return latencyMonitorPrefix + targetNodeID }

// latencyICMPMonitorPrefix starts the generated icmp check of a target
// (design 29 D2); tcp keeps latencyMonitorPrefix and its history.
const latencyICMPMonitorPrefix = "mon_lati_"

func latencyICMPMonitorID(targetNodeID string) string { return latencyICMPMonitorPrefix + targetNodeID }

// latencyBeaconMonitorID is the generated beacon check of a target (design
// 29 D2, D12).
func latencyBeaconMonitorID(targetNodeID string) string {
	return model.LatencyMonitorPrefixBeacon + targetNodeID
}

// latencyGeneratedTarget is the target node of a generated check id, from
// any of the prefixes.
func latencyGeneratedTarget(monitorID string) (string, bool) {
	if target, ok := strings.CutPrefix(monitorID, latencyICMPMonitorPrefix); ok {
		return target, true
	}
	if target, ok := strings.CutPrefix(monitorID, model.LatencyMonitorPrefixBeacon); ok {
		return target, true
	}
	return strings.CutPrefix(monitorID, latencyMonitorPrefix)
}

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
// probes on, every 60 s, from the cd-hs-sh node to every node outside
// mainland China. The node matches by id or by name: production enrolled it
// with the id cd-hs-sh and a display name of its own, so matching the name
// alone left the defaults with no source and every target paused.
func defaultLatencyProbeConfig(nodes []model.Node) model.LatencyProbeConfig {
	cfg := model.LatencyProbeConfig{
		Enabled:     true,
		IntervalSec: model.LatencyProbeDefaultIntervalSec,
		TimeoutSec:  model.LatencyProbeDefaultTimeoutSec,
		AutoTargets: true,
	}
	for _, n := range nodes {
		if strings.EqualFold(strings.TrimSpace(n.ID), latencyDefaultSourceName) ||
			strings.EqualFold(strings.TrimSpace(n.Name), latencyDefaultSourceName) {
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
		v4.IsUnspecified() || v4.IsMulticast() || v4.Equal(net.IPv4bcast) || latencyCGNAT.Contains(v4) ||
		latencyBenchmark.Contains(v4) {
		return "", false
	}
	// The monitor destination rule too: a node target is exempt from the
	// agent's own refusal, so this is the only judge of where it points.
	if addr, ok := netip.AddrFromSlice(v4); !ok || model.MonitorDestinationRefused(addr) {
		return "", false
	}
	return v4.String(), true
}

// latencyHostname reports whether raw is a DNS name the control plane may
// resolve for a probe: not an address literal, not localhost, and only the
// characters a host name holds.
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

// latencyHosts is step 5 of the port rule: the addresses a probe of this line
// may dial, all IPv4 literals. edges maps each edge name to the public
// addresses the control plane resolved for it (latencyEdgeCache.snapshot).
// A declared edge is the only host for a line with a public port: a NAT
// node's public port lives on the edge, not on the node.
func latencyHosts(node model.Node, inv model.SingBoxInventory, line model.SingBoxNode, publicPort int, edges map[string][]string) []string {
	if edge := strings.TrimSpace(inv.ProviderEdge); publicPort > 0 && edge != "" {
		if ip, ok := latencyPublicIPv4(edge); ok {
			return []string{ip}
		}
		if latencyHostname(edge) {
			return edges[latencyEdgeKey(edge)]
		}
		return nil
	}
	own, ok := latencyPublicIPv4(node.PublicIP)
	if !ok {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(inv.Network), "nat") {
		return []string{own}
	}
	if addr, ok := latencyPublicIPv4(line.Address); ok && addr == own {
		return []string{own}
	}
	return nil
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
func latencyEndpoints(node model.Node, inv model.SingBoxInventory, refused map[int]bool, edges map[string][]string) ([]latencyEndpoint, string) {
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
		hosts := latencyHosts(node, inv, line, public, edges)
		if len(hosts) == 0 {
			sawAddressless = true
			continue
		}
		layered := 0
		if latencyLayeredNetworks[network] {
			layered = 1
		}
		for _, host := range hosts {
			target := net.JoinHostPort(host, strconv.Itoa(port))
			if seen[target] {
				continue
			}
			seen[target] = true
			out = append(out, latencyEndpoint{
				target:   target,
				protocol: protocol,
				line:     line.Name,
				rank:     [3]int{latencyBoundRank(line.PortBound), layered, port},
			})
		}
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

// latencyDialableTarget reports whether a stored target is one the port rule
// can produce: a public IPv4 literal and a port.
func latencyDialableTarget(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	_, ok := latencyPublicIPv4(host)
	port := latencyTargetPort(target)
	return ok && port > 0 && port <= 65535
}

func latencyPairKey(source, target string) string { return source + "\x00" + target }

// latencyPlan is the configuration applied to the fleet: the plan the API
// returns, the generated monitors the store should hold, and every node's
// tcp endpoints, which operator checks that name a node resolve against.
type latencyPlan struct {
	plan      model.LatencyProbePlan
	desired   []model.Monitor
	endpoints map[string]latencyNodeEndpoints
	// beaconCandidates are, per target node, the path set sources whose
	// method for it is auto or beacon, whose agent runs the beacon client
	// and whose pair is enabled: the sources a node.beacon plan for the
	// target approves, and that keep a key while approved (design 29 D12).
	beaconCandidates map[string][]string
}

// latencyNodeEndpoints is what the port rule found on one node: the
// endpoints it accepted, best first, when the node's line inventory is
// current, and the ports it refuses either way.
type latencyNodeEndpoints struct {
	live       bool
	candidates []latencyEndpoint
	note       string
	refused    map[int]bool
}

// choose picks the endpoint a check that dialled prior dials now: prior
// while the rule still accepts it, else the best one. A node whose
// inventory is not current keeps prior when the rule could have produced
// it; note is a model.LatencyEndpoint* code, empty when the pick is fresh.
func (e latencyNodeEndpoints) choose(prior string) (*latencyEndpoint, string) {
	if e.live {
		for i := range e.candidates {
			if prior != "" && e.candidates[i].target == prior {
				return &e.candidates[i], e.note
			}
		}
		if len(e.candidates) > 0 {
			return &e.candidates[0], e.note
		}
		return nil, e.note
	}
	if prior != "" && latencyDialableTarget(prior) && !e.refused[latencyTargetPort(prior)] {
		return &latencyEndpoint{target: prior}, model.LatencyEndpointLastKnown
	}
	return nil, model.LatencyEndpointNoInventory
}

// latencyProbeGate is why a source cannot run kind now: "" when it can,
// the refusal its agent reported, or agent_too_old.
func latencyProbeGate(source model.Node, kind string) string {
	if model.ProbeMethodSupported(source.ProbeMethods, kind) {
		return ""
	}
	if reason := source.ProbeRefusals[kind]; reason != "" {
		return reason
	}
	return model.PathReasonAgentTooOld
}

// monitorProbeGate is latencyProbeGate for a whole check: beyond its kind,
// a check that uses a field only M2a agents read (an http status set other
// than the default, or request headers) needs an agent that reports its
// methods. An older agent would judge such a check by the old rule and
// send it without its headers, so it reads a check it cannot run as down.
func monitorProbeGate(source model.Node, mon model.Monitor) string {
	if reason := latencyProbeGate(source, mon.Type); reason != "" {
		return reason
	}
	if len(source.ProbeMethods) == 0 && monitorNeedsCurrentAgent(mon) {
		return model.PathReasonAgentTooOld
	}
	return ""
}

// monitorNeedsCurrentAgent reports whether a check uses a field agents
// older than design 29 M2a ignore.
func monitorNeedsCurrentAgent(mon model.Monitor) bool {
	if mon.Type != model.MonitorTypeHTTP {
		return false
	}
	if len(mon.Headers) > 0 {
		return true
	}
	if mon.ExpectStatus == "" {
		return false
	}
	set, err := model.ParseMonitorStatusSet(mon.ExpectStatus)
	return err != nil || set.String() != model.MonitorExpectStatusDefault
}

// latencySourceMethod is the method setting in force for one source: its
// pin, else the configuration's, else tcp.
func latencySourceMethod(cfg model.LatencyProbeConfig, sourceID string) string {
	if m := cfg.SourceMethods[sourceID]; m != "" {
		return m
	}
	if cfg.Method != "" {
		return cfg.Method
	}
	return model.LatencyMethodTCP
}

// latencyTargetCaps is what one target offers one source.
type latencyTargetCaps struct {
	// tcpOK and icmpOK say whether the target has a tcp endpoint and a
	// public IPv4.
	tcpOK, icmpOK bool
	// icmpFiltered says icmp reads icmp_filtered for this pair now (its
	// latest icmp result failed on a path that has never had an echo back).
	icmpFiltered bool
	// beaconGate is why this source may not use the target's beacon, ""
	// when it may (beaconTargetGate, then beaconSourceGate);
	// beaconListening says the target's agent listens where its plan put it.
	beaconGate      string
	beaconListening bool
}

// latencyTargetFacts is what one target offers every source for the auto
// choice, before the per-source beacon approval (caps): its icmp address and
// its beacon. The path set planner and auto check definitions share it, so
// both choose a method by the same facts.
type latencyTargetFacts struct {
	icmpTarget string
	icmpOK     bool
	// beaconEndpoint is the endpoint the target's enabled beacon
	// advertises, empty when it has none.
	beaconEndpoint string
	bt             store.BeaconTarget
	// targetGate is why no source may use the beacon (beaconTargetGate,
	// or not_probeable when the node moved off the advertised address);
	// listening says the target's agent listens where its plan put it.
	targetGate string
	listening  bool
}

func (s *Server) latencyTargetFactsOf(n model.Node, endpoints map[string]latencyNodeEndpoints, beacons map[string]store.BeaconTarget) latencyTargetFacts {
	var f latencyTargetFacts
	f.icmpTarget, f.icmpOK = latencyPublicIPv4(n.PublicIP)
	bt, btOK := beacons[n.ID]
	f.bt = bt
	if btOK && bt.Settings.Enabled {
		f.beaconEndpoint = bt.Settings.Endpoint
	}
	facts := s.beaconFactsOf(n)
	f.targetGate = beaconTargetGate(bt, btOK, facts)
	if f.targetGate == "" && !beaconEndpointCurrent(n, f.beaconEndpoint, endpoints) {
		// The node moved off the address its plan advertises.
		f.targetGate = model.PathReasonNotProbeable
	}
	f.listening = f.targetGate == "" && beaconListening(facts, bt)
	return f
}

// caps is what the target offers sourceID, with tcpOK saying whether it has
// a tcp endpoint.
func (f latencyTargetFacts) caps(tcpOK bool, sourceID string) latencyTargetCaps {
	caps := latencyTargetCaps{tcpOK: tcpOK, icmpOK: f.icmpOK, beaconGate: f.targetGate, beaconListening: f.listening}
	if caps.beaconGate == "" {
		caps.beaconGate = beaconSourceGate(f.bt, sourceID)
	}
	return caps
}

// latencyPairMethod is the kind a source probes a target with and, when it
// cannot, why (a model.PathReason* code). auto takes, in D2's order, the
// beacon when the target's applied plan approved the source and the target
// listens, else icmp when the source runs it, the target can be pinged and
// icmp does not read icmp_filtered for the pair (the console design review
// decision of 2026-10-16), else tcp. A pin never falls back.
func latencyPairMethod(setting string, source model.Node, caps latencyTargetCaps) (method, reason string) {
	tcpOK, icmpOK := caps.tcpOK, caps.icmpOK
	switch setting {
	case model.LatencyMethodBeacon:
		if reason := latencyProbeGate(source, model.MonitorTypeBeacon); reason != "" {
			return model.MonitorTypeBeacon, reason
		}
		return model.MonitorTypeBeacon, caps.beaconGate
	case model.LatencyMethodICMP:
		if !icmpOK {
			return model.MonitorTypeICMP, model.PathReasonNotProbeable
		}
		return model.MonitorTypeICMP, latencyProbeGate(source, model.MonitorTypeICMP)
	case model.LatencyMethodAuto:
		if caps.beaconGate == "" && caps.beaconListening && latencyProbeGate(source, model.MonitorTypeBeacon) == "" {
			return model.MonitorTypeBeacon, ""
		}
		if icmpOK && !caps.icmpFiltered && latencyProbeGate(source, model.MonitorTypeICMP) == "" {
			return model.MonitorTypeICMP, ""
		}
		if tcpOK {
			return model.MonitorTypeTCP, latencyProbeGate(source, model.MonitorTypeTCP)
		}
		if icmpOK {
			return model.MonitorTypeICMP, latencyProbeGate(source, model.MonitorTypeICMP)
		}
		return model.MonitorTypeTCP, model.PathReasonNotProbeable
	default:
		if !tcpOK {
			return model.MonitorTypeTCP, model.PathReasonNotProbeable
		}
		return model.MonitorTypeTCP, latencyProbeGate(source, model.MonitorTypeTCP)
	}
}

// latencyMethodResolvable reports whether a method setting can reach a
// target at all, whatever the source.
func latencyMethodResolvable(setting string, tcpOK, icmpOK, beaconOK bool) bool {
	switch setting {
	case model.LatencyMethodBeacon:
		return beaconOK
	case model.LatencyMethodICMP:
		return icmpOK
	case model.LatencyMethodAuto:
		return tcpOK || icmpOK || beaconOK
	default:
		return tcpOK
	}
}

// latencyICMPRecheck is how long auto keeps a pair on tcp after its icmp
// read icmp_filtered. Once the pair is on tcp nothing runs icmp for it, so
// the verdict would otherwise stand forever; after this the pair tries icmp
// again, and one more filtered run puts it back on tcp for another day.
const latencyICMPRecheck = 24 * time.Hour

// latencyICMPFiltered reports whether a pair's icmp path reads
// icmp_filtered now, from its generated icmp check's latest result, and
// that result is less than latencyICMPRecheck old.
func (s *Server) latencyICMPFiltered(icmpMonitorID, sourceID string, now time.Time) bool {
	latest, ok, err := s.store.MonitorLatest(icmpMonitorID, sourceID)
	if err != nil || !ok || latest.Unknown != nil {
		return false
	}
	if now.Sub(latest.At) >= latencyICMPRecheck {
		return false
	}
	return icmpFiltered(model.MonitorTypeICMP, latest)
}

// planLatencyProbes applies the stored configuration (or the defaults) to
// the fleet as it is now. It reads and never writes.
func (s *Server) planLatencyProbes(now time.Time) latencyPlan {
	nodes := s.store.Nodes()
	cfg, stored := s.store.LatencyProbeConfig()
	if !stored {
		cfg = defaultLatencyProbeConfig(nodes)
	}
	return s.planLatencyProbesFor(cfg, stored, nodes, now)
}

// planLatencyProbesFor applies cfg to the fleet as it is now, so a save can
// see what it would generate before it is stored.
func (s *Server) planLatencyProbesFor(cfg model.LatencyProbeConfig, stored bool, nodes []model.Node, now time.Time) latencyPlan {
	nodes = slices.Clone(nodes)
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
	out := latencyPlan{
		plan: model.LatencyProbePlan{
			Config:            cfg,
			Stored:            stored,
			DefaultSourceName: latencyDefaultSourceName,
			Nodes:             []model.LatencyProbeNode{},
			Pairs:             []model.LatencyProbePairState{},
		},
		endpoints:        make(map[string]latencyNodeEndpoints, len(nodes)),
		beaconCandidates: map[string][]string{},
	}
	beaconTargets := s.store.BeaconTargets()

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
		if store.MonitorOwnerOf(mon) == store.MonitorOwnerPathSet {
			existing[mon.ID] = mon
		}
	}
	inventories := map[string]model.SingBoxInventory{}
	for _, inv := range s.liveSingBoxInventories(now) {
		inventories[inv.NodeID] = inv
	}
	approvals := s.store.Approvals()
	edges := s.latencyEdges.snapshot()
	interval := cfg.IntervalSec
	if interval <= 0 {
		interval = model.LatencyProbeDefaultIntervalSec
	}
	timeout := cfg.TimeoutSec
	if timeout <= 0 {
		timeout = model.LatencyProbeDefaultTimeoutSec
	}
	keepPaused := func(prior model.Monitor, targetNode string) {
		paused := prior
		paused.Enabled = false
		paused.TargetNode = targetNode
		out.desired = append(out.desired, paused)
	}

	for _, n := range nodes {
		// Every node's tcp endpoints, target or not: an operator's check
		// that names the node resolves against them.
		info := latencyNodeEndpoints{refused: s.latencyRefusedPorts(n.ID, approvals)}
		if inv, live := inventories[n.ID]; live && (inv.Status == "" || inv.Status == "ok") {
			info.live = true
			info.candidates, info.note = latencyEndpoints(n, inv, info.refused, edges)
		}
		out.endpoints[n.ID] = info

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
		tcpID, icmpID, beaconID := latencyMonitorID(n.ID), latencyICMPMonitorID(n.ID), latencyBeaconMonitorID(n.ID)
		priorTCP, hadTCP := existing[tcpID]
		priorICMP, hadICMP := existing[icmpID]
		priorBeacon, hadBeacon := existing[beaconID]
		facts := s.latencyTargetFactsOf(n, out.endpoints, beaconTargets)
		beaconEndpoint := facts.beaconEndpoint
		pn.BeaconTarget = beaconEndpoint
		if pn.Target == model.LatencyTargetNone {
			// Out of the set: the monitors stay, paused, with their history.
			if hadTCP {
				keepPaused(priorTCP, n.ID)
				pn.MonitorID = tcpID
			}
			if hadICMP {
				keepPaused(priorICMP, n.ID)
				pn.ICMPMonitorID = icmpID
			}
			if hadBeacon {
				keepPaused(priorBeacon, n.ID)
				pn.BeaconMonitorID = beaconID
			}
			out.plan.Nodes = append(out.plan.Nodes, pn)
			continue
		}

		prior := ""
		if hadTCP {
			prior = priorTCP.Target
		}
		chosen, note := info.choose(prior)
		pn.EndpointNote = note
		icmpTarget, icmpOK := facts.icmpTarget, facts.icmpOK
		pn.ICMPTarget = icmpTarget
		tcpOK := chosen != nil
		beaconOK := facts.targetGate == ""

		var activeTCP, activeICMP, activeBeacon []string
		firstPair := len(out.plan.Pairs)
		probeable, methodBlocked, plainInactive := false, false, false
		for _, sourceID := range sources {
			if sourceID == n.ID {
				continue
			}
			enabled := !disabledPairs[latencyPairKey(sourceID, n.ID)]
			setting := latencySourceMethod(cfg, sourceID)
			caps := facts.caps(tcpOK, sourceID)
			if setting == model.LatencyMethodAuto && icmpOK && hadICMP {
				caps.icmpFiltered = s.latencyICMPFiltered(icmpID, sourceID, now)
			}
			if (setting == model.LatencyMethodAuto || setting == model.LatencyMethodBeacon) && enabled && cfg.Enabled &&
				latencyProbeGate(byID[sourceID], model.MonitorTypeBeacon) == "" {
				out.beaconCandidates[n.ID] = append(out.beaconCandidates[n.ID], sourceID)
			}
			method, reason := latencyPairMethod(setting, byID[sourceID], caps)
			if reason != model.PathReasonNotProbeable {
				probeable = true
			}
			pair := model.LatencyProbePairState{Source: sourceID, Target: n.ID, Enabled: enabled, Method: method}
			if enabled {
				pair.Reason = reason
			}
			switch {
			case enabled && cfg.Enabled && reason == "":
				pair.Active = true
				switch method {
				case model.MonitorTypeICMP:
					activeICMP = append(activeICMP, sourceID)
				case model.MonitorTypeBeacon:
					activeBeacon = append(activeBeacon, sourceID)
				default:
					activeTCP = append(activeTCP, sourceID)
				}
			case enabled && reason != "" && reason != model.PathReasonNotProbeable:
				methodBlocked = true
			default:
				plainInactive = true
			}
			out.plan.Pairs = append(out.plan.Pairs, pair)
		}
		if len(sources) == 0 || !latencyHasOtherSource(sources, n.ID) {
			probeable = latencyMethodResolvable(latencySourceMethod(cfg, ""), tcpOK, icmpOK, beaconOK)
		}
		// A monitor exists for each kind while something probes with it or
		// a history was already taken; nothing is created just to sit
		// paused.
		tcpMonitor := tcpOK && (hadTCP || len(activeTCP) > 0)
		icmpMonitor := icmpOK && (hadICMP || len(activeICMP) > 0)
		beaconMonitor := beaconEndpoint != "" && (hadBeacon || len(activeBeacon) > 0)
		for i := firstPair; i < len(out.plan.Pairs); i++ {
			pair := &out.plan.Pairs[i]
			switch {
			case pair.Method == model.MonitorTypeICMP && (icmpMonitor || hadICMP):
				pair.MonitorID = icmpID
			case pair.Method == model.MonitorTypeTCP && (tcpMonitor || hadTCP):
				pair.MonitorID = tcpID
			case pair.Method == model.MonitorTypeBeacon && (beaconMonitor || hadBeacon):
				pair.MonitorID = beaconID
			}
		}

		if chosen != nil {
			pn.Endpoint, pn.Protocol, pn.LineName = chosen.target, chosen.protocol, chosen.line
		}
		if !probeable {
			pn.Target = model.LatencyTargetNotProbeable
			if !tcpOK && latencySourceMethod(cfg, "") == model.LatencyMethodICMP {
				pn.EndpointNote = model.LatencyEndpointNoAddress
			}
		} else if len(activeTCP)+len(activeICMP)+len(activeBeacon) == 0 {
			pn.Target = model.LatencyTargetPaused
			switch {
			case !cfg.Enabled:
				pn.TargetReason = model.LatencyReasonConfigOff
			case !latencyHasOtherSource(sources, n.ID):
				pn.TargetReason = model.LatencyReasonNoSource
			case methodBlocked && !plainInactive:
				pn.TargetReason = model.LatencyReasonSourceMethod
			default:
				pn.TargetReason = model.LatencyReasonPairsOff
			}
		}

		switch {
		case tcpMonitor:
			mon := model.Monitor{
				ID:          tcpID,
				Name:        "Latency to " + latencyNodeLabel(n),
				Type:        model.MonitorTypeTCP,
				Target:      chosen.target,
				TargetNode:  n.ID,
				IntervalSec: interval,
				TimeoutSec:  timeout,
				NodeIDs:     activeTCP,
				Enabled:     len(activeTCP) > 0,
				ManagedBy:   model.MonitorManagedLatency,
			}
			if len(activeTCP) == 0 {
				// Paused: keep the sources the history was taken from, so
				// the monitors list still shows their last readings.
				mon.NodeIDs = slices.Clone(priorTCP.NodeIDs)
			}
			out.desired = append(out.desired, mon)
			pn.MonitorID = tcpID
		case hadTCP:
			keepPaused(priorTCP, n.ID)
			pn.MonitorID = tcpID
		}
		switch {
		case icmpMonitor:
			mon := model.Monitor{
				ID:          icmpID,
				Name:        "Ping to " + latencyNodeLabel(n),
				Type:        model.MonitorTypeICMP,
				Target:      icmpTarget,
				TargetNode:  n.ID,
				IntervalSec: interval,
				TimeoutSec:  timeout,
				Packets:     model.MonitorPacketsDefault,
				NodeIDs:     activeICMP,
				Enabled:     len(activeICMP) > 0,
				ManagedBy:   model.MonitorManagedLatency,
			}
			if len(activeICMP) == 0 {
				mon.NodeIDs = slices.Clone(priorICMP.NodeIDs)
			}
			out.desired = append(out.desired, mon)
			pn.ICMPMonitorID = icmpID
		case hadICMP:
			keepPaused(priorICMP, n.ID)
			pn.ICMPMonitorID = icmpID
		}
		switch {
		case beaconMonitor:
			mon := model.Monitor{
				ID:          beaconID,
				Name:        "Beacon to " + latencyNodeLabel(n),
				Type:        model.MonitorTypeBeacon,
				Target:      beaconEndpoint,
				TargetNode:  n.ID,
				IntervalSec: interval,
				TimeoutSec:  timeout,
				Packets:     model.MonitorPacketsDefault,
				NodeIDs:     activeBeacon,
				Enabled:     len(activeBeacon) > 0,
				ManagedBy:   model.MonitorManagedLatency,
			}
			if len(activeBeacon) == 0 {
				mon.NodeIDs = slices.Clone(priorBeacon.NodeIDs)
			}
			out.desired = append(out.desired, mon)
			pn.BeaconMonitorID = beaconID
		case hadBeacon:
			keepPaused(priorBeacon, n.ID)
			pn.BeaconMonitorID = beaconID
		}
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

// syncLatencyProbes resolves the provider edge names, plans the fleet and
// brings the generated monitors in line with the plan. The store writes only
// when a generated monitor changed, and only then is the sync audited.
func (s *Server) syncLatencyProbes(now time.Time) (model.LatencyProbePlan, store.ManagedMonitorChanges, error) {
	s.latencySync.Lock()
	defer s.latencySync.Unlock()
	s.latencyEdges.refresh(latencyEdgeNames(s.liveSingBoxInventories(now)), now)
	planned := s.planLatencyProbes(now)
	s.monitorPaths.notePlan(planned, now)
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

// latencyMethodList is the per-source method pins for an audit field,
// "source=method" sorted by source.
func latencyMethodList(pins map[string]string) string {
	list := make([]string, 0, len(pins))
	for sourceID, method := range pins {
		list = append(list, sourceID+"="+method)
	}
	sort.Strings(list)
	return latencyIDList(list)
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
		now := s.now()
		if _, _, err := s.syncLatencyProbes(now); err != nil {
			s.logger.Printf("latency probes: %v", err)
		}
		// Check definitions follow on the same sweep, reusing the endpoint
		// picks the path set just made (design 32 D1).
		if _, err := s.syncCheckDefinitions(now, "sweep"); err != nil {
			s.logger.Printf("check definitions: %v", err)
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
	// The method: empty stays empty and reads as tcp, so a configuration
	// saved before methods existed keeps its paths and history.
	validMethod := func(m string) bool {
		switch m {
		case model.LatencyMethodTCP, model.LatencyMethodICMP, model.LatencyMethodBeacon, model.LatencyMethodAuto:
			return true
		}
		return false
	}
	out.Method = strings.TrimSpace(in.Method)
	if out.Method != "" && !validMethod(out.Method) {
		return out, fmt.Errorf("method must be %q, %q, %q or %q", model.LatencyMethodTCP, model.LatencyMethodICMP, model.LatencyMethodBeacon, model.LatencyMethodAuto)
	}
	for raw, method := range in.SourceMethods {
		sourceID, method := strings.TrimSpace(raw), strings.TrimSpace(method)
		if !slices.Contains(out.Sources, sourceID) {
			return out, fmt.Errorf("source_methods names %q, which is not one of the sources", raw)
		}
		if !validMethod(method) {
			return out, fmt.Errorf("source_methods[%s] must be %q, %q, %q or %q", sourceID, model.LatencyMethodTCP, model.LatencyMethodICMP, model.LatencyMethodBeacon, model.LatencyMethodAuto)
		}
		if out.SourceMethods == nil {
			out.SourceMethods = map[string]string{}
		}
		out.SourceMethods[sourceID] = method
	}
	// The alert policy and the degraded thresholds (design 29 D13). The
	// output is built field by field, so each is copied here or a save
	// drops it. An empty policy stays empty and reads as off.
	out.Alert = strings.TrimSpace(in.Alert)
	degraded, err := validMonitorAlertFor(model.MonitorTypeTCP, out.Alert, in.Degraded)
	if err != nil {
		return out, err
	}
	out.Degraded = degraded
	if err := validMonitorAlertAfter(in.AlertAfter); err != nil {
		return out, err
	}
	out.AlertAfter = in.AlertAfter
	return out, nil
}

// latencyConfigChanged names the path set fields a save changed, for its
// audit record.
func latencyConfigChanged(prior, next model.LatencyProbeConfig) []string {
	var out []string
	note := func(field string, differs bool) {
		if differs {
			out = append(out, field)
		}
	}
	note("enabled", prior.Enabled != next.Enabled)
	note("interval_sec", prior.IntervalSec != next.IntervalSec)
	note("timeout_sec", prior.TimeoutSec != next.TimeoutSec)
	note("sources", !slices.Equal(prior.Sources, next.Sources))
	note("auto_targets", prior.AutoTargets != next.AutoTargets)
	note("include_targets", !slices.Equal(prior.IncludeTargets, next.IncludeTargets))
	note("exclude_targets", !slices.Equal(prior.ExcludeTargets, next.ExcludeTargets))
	note("disabled_pairs", !slices.Equal(prior.DisabledPairs, next.DisabledPairs))
	note("method", prior.Method != next.Method)
	note("source_methods", latencyMethodList(prior.SourceMethods) != latencyMethodList(next.SourceMethods))
	note("alert", model.EffectiveMonitorAlert(prior.Alert, true) != model.EffectiveMonitorAlert(next.Alert, true))
	note("alert_after", pathSetPolicy(prior).after != pathSetPolicy(next).after)
	note("degraded", !degradedRulesEqual(prior.Degraded, next.Degraded))
	return out
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
	narrowed.Config.SourceMethods = nil
	for sourceID, method := range plan.Config.SourceMethods {
		if visible(sourceID) {
			if narrowed.Config.SourceMethods == nil {
				narrowed.Config.SourceMethods = map[string]string{}
			}
			narrowed.Config.SourceMethods[sourceID] = method
		}
	}
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
		s.monitorSaves.Lock()
		defer s.monitorSaves.Unlock()
		cfg, err := s.normalizeLatencyProbeConfig(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		now := s.now()
		// The generated icmp checks count against the same per (source,
		// target) packet budget as the operator's own.
		nodes := s.store.Nodes()
		planned := s.planLatencyProbesFor(cfg, true, nodes, now)
		var generated []model.Monitor
		for _, mon := range planned.desired {
			if model.MonitorKindSendsPackets(mon.Type) {
				generated = append(generated, mon)
			}
		}
		if len(generated) > 0 {
			if err := s.monitorTargetsAt(now).checkPacketBudget(s.store.Monitors(), generated...); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		prior, _ := s.store.LatencyProbeConfig()
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
				"method":          stored.Method,
				"source_methods":  latencyMethodList(stored.SourceMethods),
				"alert":           model.EffectiveMonitorAlert(stored.Alert, true),
				"alert_after":     strconv.Itoa(pathSetPolicy(stored).after),
				"degraded":        degradedRuleSummary(stored.Degraded),
				"changed":         strings.Join(latencyConfigChanged(prior, stored), ","),
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
