package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Checks of design 29 M2a: node targets resolved per kind, icmp with
// several packets per run, http expectations and request headers whose
// values may be write-only secrets, and the destinations a check may name.
// The rules shared with the agents (status sets, header rules, origins,
// destination refusal) live in lattice-sdk model/monitor_checks.go.

// monitorPacketKinds are the kinds that send several packets a run and take
// packets (model.MonitorKindSendsPackets); monitorNodeTargetKinds are the
// kinds whose target may be a node, which monitorTargets.resolve resolves.
var (
	monitorPacketKinds     = []string{model.MonitorTypeICMP, model.MonitorTypeBeacon}
	monitorNodeTargetKinds = []string{model.MonitorTypeICMP, model.MonitorTypeTCP, model.MonitorTypeBeacon}
)

// The answers to a field on a kind that does not take it, naming the kinds
// that do.
var (
	errMonitorPacketsKinds    = fmt.Errorf("packets applies to %s checks only", monitorKindList(monitorPacketKinds))
	errMonitorTargetNodeKinds = fmt.Errorf("an http check takes a URL; target_node applies to %s checks", monitorKindList(monitorNodeTargetKinds))
)

// monitorKindList names kinds in prose: "icmp and beacon", "icmp, tcp and
// beacon".
func monitorKindList(kinds []string) string {
	if len(kinds) < 2 {
		return strings.Join(kinds, "")
	}
	return strings.Join(kinds[:len(kinds)-1], ", ") + " and " + kinds[len(kinds)-1]
}

// monitorTargets resolves the node a check names into what its kind dials,
// against the fleet as the latency plan last saw it.
type monitorTargets struct {
	nodes     map[string]model.Node
	endpoints map[string]latencyNodeEndpoints
	// beacons are the nodes' beacon states, which beacon checks resolve
	// against (design 29 D12).
	beacons map[string]store.BeaconTarget
}

// monitorTargetsAt is the resolver for now: the cached latency plan's node
// endpoints (pathPlanned) and the node records.
func (s *Server) monitorTargetsAt(now time.Time) monitorTargets {
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	return monitorTargets{nodes: nodes, endpoints: s.pathPlanned(now).endpoints, beacons: s.store.BeaconTargets()}
}

// resolve is what a check of kind that names nodeID dials now, given the
// target it dialled before (a tcp endpoint stays while the port rule still
// accepts it). reason says why there is nothing: a model.LatencyEndpoint*
// code for tcp, model.LatencyEndpointNoAddress for icmp, or "unknown_node".
func (t monitorTargets) resolve(kind, nodeID, prior string) (target, reason string) {
	n, ok := t.nodes[nodeID]
	if !ok {
		return "", "unknown_node"
	}
	switch kind {
	case model.MonitorTypeICMP:
		ip, ok := latencyPublicIPv4(n.PublicIP)
		if !ok {
			return "", model.LatencyEndpointNoAddress
		}
		return ip, ""
	case model.MonitorTypeTCP:
		info, ok := t.endpoints[nodeID]
		if !ok {
			info = latencyNodeEndpoints{}
		}
		chosen, note := info.choose(prior)
		if chosen == nil {
			if note == "" {
				note = model.LatencyEndpointNoLine
			}
			return "", note
		}
		return chosen.target, ""
	case model.MonitorTypeBeacon:
		t, ok := t.beacons[nodeID]
		if !ok || !t.Settings.Enabled || t.Settings.Endpoint == "" {
			return "", model.PathReasonBeaconNotEnabled
		}
		return t.Settings.Endpoint, ""
	}
	return "", "unsupported_kind"
}

// resolved is mon with its target resolved now, and false when a check that
// names a node cannot be resolved for its kind. Checks the path set or a
// beacon plan generated are resolved by their planner and come back as they
// are.
func (t monitorTargets) resolved(mon model.Monitor) (model.Monitor, bool) {
	if mon.TargetNode == "" || !store.MonitorOwnerOf(mon).Authored() {
		return mon, true
	}
	target, reason := t.resolve(mon.Type, mon.TargetNode, mon.Target)
	if reason != "" {
		return mon, false
	}
	mon.Target = target
	return mon, true
}

// redactMonitorHeaders is the read form of a check's headers: a secret
// header keeps its name and says it is set; its value never leaves.
func redactMonitorHeaders(in []model.MonitorHeader) []model.MonitorHeader {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.MonitorHeader, len(in))
	for i, h := range in {
		if h.Secret {
			out[i] = model.MonitorHeader{Name: h.Name, Secret: true, Set: h.Value != ""}
			continue
		}
		out[i] = model.MonitorHeader{Name: h.Name, Value: h.Value}
	}
	return out
}

// monitorHeaderNames names a check's headers for an audit record, secret
// ones marked, never a value.
func monitorHeaderNames(in []model.MonitorHeader) string {
	names := make([]string, 0, len(in))
	for _, h := range in {
		if h.Secret {
			names = append(names, h.Name+"(secret)")
		} else {
			names = append(names, h.Name)
		}
	}
	return strings.Join(names, ",")
}

// errDestination is the answer to a target the destination rules refuse.
func errDestination(host string) error {
	return fmt.Errorf("target %s is a loopback, link-local, metadata, multicast or private address; name the node instead (target_node) or use a public address", host)
}

// checkMonitorHost applies the destination rules to a host a check names:
// a literal must be a public address, and localhost is refused. A name is
// judged by the agent at dial time, against every address it resolves to.
func checkMonitorHost(host string) error {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return errors.New("target has no host")
	}
	if strings.ContainsAny(host, "% \t") {
		// A zone or a space is never part of a name a check may dial.
		return fmt.Errorf("target host %q is not a host name or an address", host)
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return errDestination(host)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if model.MonitorDestinationRefused(addr) {
			return errDestination(host)
		}
		return nil
	}
	// A host whose last label is a number is an address in a form some
	// resolvers read and netip does not (2130706433, 127.1, 0x7f.1): no
	// DNS name ends in a number, so it is refused rather than judged.
	label := lower[strings.LastIndexByte(lower, '.')+1:]
	if monitorNumericLabel(label) {
		return fmt.Errorf("target %s is an address in a numeric form; write it as a dotted IPv4 or an IPv6 literal", host)
	}
	return nil
}

// monitorNumericLabel reports whether a host label is all decimal digits or
// a 0x hexadecimal number.
func monitorNumericLabel(label string) bool {
	if rest, ok := strings.CutPrefix(label, "0x"); ok {
		label = rest
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	if label == "" {
		return false
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}

// normalizeHTTPMonitor checks an http check's URL, expectations and
// headers, and binds its secrets to the URL's origin. checkHost applies
// the destination rules to the URL's host: a create does, an edit does
// not, since the target cannot change and a check saved before the rules
// existed must stay editable (an agent still refuses its destination at
// dial time).
func normalizeHTTPMonitor(mon *model.Monitor, checkHost bool) error {
	if mon.TargetNode != "" {
		return errMonitorTargetNodeKinds
	}
	if mon.Packets != 0 {
		return errMonitorPacketsKinds
	}
	u, err := url.Parse(strings.TrimSpace(mon.Target))
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errors.New("an http check's target is an absolute http or https URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("an http check's target is an absolute http or https URL")
	}
	if u.User != nil {
		return errors.New("an http check's URL cannot carry a user name or password; send it as a secret header")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("an http check's URL has port %q; it must be 1 to 65535", port)
		}
	}
	if checkHost {
		if err := checkMonitorHost(u.Hostname()); err != nil {
			return err
		}
	}
	mon.Target = strings.TrimSpace(mon.Target)
	set, err := model.ParseMonitorStatusSet(mon.ExpectStatus)
	if err != nil {
		return err
	}
	mon.ExpectStatus = set.String()
	if len(mon.Headers) > model.MonitorHeadersMax {
		return fmt.Errorf("an http check carries at most %d headers", model.MonitorHeadersMax)
	}
	seen := map[string]bool{}
	headers := make([]model.MonitorHeader, 0, len(mon.Headers))
	for _, h := range mon.Headers {
		name := model.CanonicalMonitorHeaderName(h.Name)
		if err := model.ValidateMonitorHeader(name, h.Value); err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("header %s is named twice", name)
		}
		seen[name] = true
		headers = append(headers, model.MonitorHeader{Name: name, Value: h.Value, Secret: h.Secret})
	}
	mon.Headers = headers
	if len(mon.Headers) == 0 {
		mon.Headers = nil
	}
	mon.SecretsOrigin = ""
	if model.MonitorHasSecrets(*mon) {
		if scheme != "https" {
			return errors.New("a check with secret headers must use https, so the secrets travel encrypted to a verified host")
		}
		origin, err := model.MonitorOrigin(mon.Target)
		if err != nil {
			return err
		}
		mon.SecretsOrigin = origin
	}
	return nil
}

// canonicalMonitorExpectStatus is a stored status set in canonical form, so an
// edit that leaves it alone does not read as a change; a check saved
// before the field existed reads as the default.
func canonicalMonitorExpectStatus(raw string) string {
	set, err := model.ParseMonitorStatusSet(raw)
	if err != nil {
		return raw
	}
	return set.String()
}

// applyMonitorHeaderEdits applies an edit's header operations in order to
// the stored headers (design 29 D1). A header the edit does not name is
// kept, so an edit that echoes the read form neither wipes nor leaks a
// secret. The result is validated by normalizeHTTPMonitor afterwards.
func applyMonitorHeaderEdits(stored []model.MonitorHeader, edits []model.MonitorHeaderEdit) ([]model.MonitorHeader, error) {
	out := slices.Clone(stored)
	index := func(name string) int {
		for i, h := range out {
			if h.Name == name {
				return i
			}
		}
		return -1
	}
	named := map[string]bool{}
	for _, e := range edits {
		name := model.CanonicalMonitorHeaderName(e.Name)
		if name == "" {
			return nil, errors.New("a header edit names no header")
		}
		if named[name] {
			return nil, fmt.Errorf("header %s is named twice in one edit", name)
		}
		named[name] = true
		i := index(name)
		switch e.Op {
		case model.MonitorHeaderKeep:
			if i < 0 {
				return nil, fmt.Errorf("header %s is not on the check; read it again before editing", name)
			}
		case model.MonitorHeaderSet:
			if e.Value == "" {
				return nil, fmt.Errorf("header %s needs a value to be set", name)
			}
			h := model.MonitorHeader{Name: name, Value: e.Value, Secret: e.Secret}
			if i < 0 {
				out = append(out, h)
			} else {
				out[i] = h
			}
		case model.MonitorHeaderDelete:
			if i >= 0 {
				out = slices.Delete(out, i, i+1)
			}
		default:
			return nil, fmt.Errorf("header %s: op must be %q, %q or %q", name, model.MonitorHeaderKeep, model.MonitorHeaderSet, model.MonitorHeaderDelete)
		}
	}
	return out, nil
}

// monitorHeadersEqual compares two header lists, values included.
func monitorHeadersEqual(a, b []model.MonitorHeader) bool {
	return slices.EqualFunc(a, b, func(x, y model.MonitorHeader) bool {
		return x.Name == y.Name && x.Value == y.Value && x.Secret == y.Secret
	})
}

// monitorRunSpan is how long one run of mon can take: an icmp run sends
// its echoes MonitorPacketSpacingMs apart and each waits the timeout.
func monitorRunSpan(mon model.Monitor) time.Duration {
	span := time.Duration(mon.TimeoutSec) * time.Second
	if model.MonitorKindSendsPackets(mon.Type) {
		span += time.Duration(model.MonitorPackets(mon)-1) * model.MonitorPacketSpacingMs * time.Millisecond
	}
	return span
}

// validMonitorRun checks that a run ends before the next one starts.
func validMonitorRun(mon model.Monitor) error {
	if span := monitorRunSpan(mon); span >= time.Duration(mon.IntervalSec)*time.Second {
		return fmt.Errorf("a run of %d echoes %d ms apart, each waiting %d s, takes up to %s, which does not end before the next run %d s later; lengthen interval_sec or lower packets or timeout_sec",
			model.MonitorPackets(mon), model.MonitorPacketSpacingMs, mon.TimeoutSec, span, mon.IntervalSec)
	}
	return nil
}

// normalizeICMPMonitor checks an icmp check's target and packets. A node
// target resolves to the node's public IPv4; a literal must be a public
// IPv4 address.
func (t monitorTargets) normalizeICMPMonitor(mon *model.Monitor) error {
	if mon.ExpectStatus != "" || len(mon.Headers) > 0 {
		return errors.New("expect_status and headers apply to http checks only")
	}
	if mon.Packets == 0 {
		mon.Packets = model.MonitorPacketsDefault
	}
	if mon.Packets < 1 || mon.Packets > model.MonitorPacketsMax {
		return fmt.Errorf("packets must be 1 to %d", model.MonitorPacketsMax)
	}
	if mon.TargetNode != "" {
		target, reason := t.resolve(model.MonitorTypeICMP, mon.TargetNode, "")
		if reason != "" {
			return fmt.Errorf("node %s cannot be pinged: %s", mon.TargetNode, monitorResolveNote(reason))
		}
		mon.Target = target
		return nil
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(mon.Target))
	if err != nil || !addr.Unmap().Is4() {
		return errors.New("an icmp check's target is a node (target_node) or an IPv4 address")
	}
	if model.MonitorDestinationRefused(addr) {
		return errDestination(addr.String())
	}
	mon.Target = addr.Unmap().String()
	return nil
}

// normalizeTCPMonitor checks a tcp check's target: a node resolves to its
// public line port by the latency probes' port rule; host:port otherwise.
func (t monitorTargets) normalizeTCPMonitor(mon *model.Monitor) error {
	if mon.ExpectStatus != "" || len(mon.Headers) > 0 {
		return errors.New("expect_status and headers apply to http checks only")
	}
	if mon.Packets != 0 {
		return errMonitorPacketsKinds
	}
	if mon.TargetNode != "" {
		target, reason := t.resolve(model.MonitorTypeTCP, mon.TargetNode, "")
		if reason != "" {
			return fmt.Errorf("node %s has no public tcp line to connect to: %s", mon.TargetNode, monitorResolveNote(reason))
		}
		mon.Target = target
		return nil
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(mon.Target))
	if err != nil {
		return errors.New("a tcp check's target is a node (target_node) or host:port")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("a tcp check's port %q must be 1 to 65535", port)
	}
	if err := checkMonitorHost(host); err != nil {
		return err
	}
	mon.Target = net.JoinHostPort(host, port)
	return nil
}

// monitorResolveNote says in words why a node target cannot be resolved.
func monitorResolveNote(reason string) string {
	switch reason {
	case "unknown_node":
		return "no such node"
	case model.LatencyEndpointNoAddress:
		return "it has no public IPv4 address"
	case model.LatencyEndpointUDPOnly:
		return "every line it serves is UDP"
	case model.LatencyEndpointNoLine:
		return "it serves no public TCP line the probe may dial (never SSH or a knock-gated port)"
	case model.LatencyEndpointNoInventory:
		return "it has not reported its lines yet"
	case model.PathReasonBeaconNotEnabled:
		return "it has no enabled beacon; enable one through a node.beacon plan"
	}
	return reason
}

// normalizeBeaconMonitor checks a beacon check: it names a node and never
// an address, and the node has an applied, enabled beacon whose advertised
// endpoint the check resolves to.
func (t monitorTargets) normalizeBeaconMonitor(mon *model.Monitor) error {
	if mon.ExpectStatus != "" || len(mon.Headers) > 0 {
		return errors.New("expect_status and headers apply to http checks only")
	}
	if mon.TargetNode == "" {
		return errors.New("a beacon check names its target with target_node; it never takes an address")
	}
	if mon.Packets == 0 {
		mon.Packets = model.MonitorPacketsDefault
	}
	if mon.Packets < 1 || mon.Packets > model.MonitorPacketsMax {
		return fmt.Errorf("packets must be 1 to %d", model.MonitorPacketsMax)
	}
	if mon.IntervalSec < model.LatencyProbeMinIntervalSec {
		return fmt.Errorf("a beacon check runs at most every %d s", model.LatencyProbeMinIntervalSec)
	}
	target, reason := t.resolve(model.MonitorTypeBeacon, mon.TargetNode, "")
	if reason != "" {
		return fmt.Errorf("node %s cannot be probed by beacon: %s", mon.TargetNode, monitorResolveNote(reason))
	}
	mon.Target = target
	return nil
}

// monitorPacketKey is one (source, target address) a packet budget counts.
type monitorPacketKey struct{ source, target string }

// monitorPacketLoad sums, per (source, target address), the packets per
// second of every enabled multi-packet check in monitors. Every node is a
// source of an all-nodes check; paused sources send nothing.
func (t monitorTargets) monitorPacketLoad(monitors []model.Monitor) map[monitorPacketKey]float64 {
	load := map[monitorPacketKey]float64{}
	for _, mon := range monitors {
		if !mon.Enabled || !model.MonitorKindSendsPackets(mon.Type) || mon.IntervalSec <= 0 {
			continue
		}
		resolved, ok := t.resolved(mon)
		if !ok {
			continue
		}
		rate := float64(model.MonitorPackets(mon)) / float64(mon.IntervalSec)
		for _, source := range t.monitorSources(mon) {
			load[monitorPacketKey{source: source, target: resolved.Target}] += rate
		}
	}
	return load
}

// monitorSources are the nodes that run mon now.
func (t monitorTargets) monitorSources(mon model.Monitor) []string {
	var sources []string
	if mon.AssignAll {
		for nodeID := range t.nodes {
			sources = append(sources, nodeID)
		}
		sort.Strings(sources)
	} else {
		sources = slices.Clone(mon.NodeIDs)
	}
	return slices.DeleteFunc(sources, func(nodeID string) bool { return slices.Contains(mon.PausedNodeIDs, nodeID) })
}

// checkPacketBudget refuses a save that would let one source send more
// than model.MonitorPacketsPerSecondMax packets a second to one address,
// counting every enabled multi-packet check, operator and generated, with
// changed in place of the checks of the same id. Only the pairs a changed
// check sends on are judged, so an older excess elsewhere does not block an
// unrelated save.
func (t monitorTargets) checkPacketBudget(stored []model.Monitor, changed ...model.Monitor) error {
	byID := map[string]bool{}
	for _, mon := range changed {
		byID[mon.ID] = true
	}
	all := make([]model.Monitor, 0, len(stored)+len(changed))
	for _, mon := range stored {
		if !byID[mon.ID] {
			all = append(all, mon)
		}
	}
	all = append(all, changed...)
	load := t.monitorPacketLoad(all)
	touched := t.monitorPacketLoad(changed)
	keys := make([]monitorPacketKey, 0, len(touched))
	for key := range touched {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		return keys[i].target < keys[j].target
	})
	for _, key := range keys {
		if load[key] > model.MonitorPacketsPerSecondMax+1e-9 {
			return fmt.Errorf("node %s would send %.2f packets a second to %s across its checks; at most %d: lengthen an interval or lower packets",
				key.source, load[key], key.target, model.MonitorPacketsPerSecondMax)
		}
	}
	return nil
}
