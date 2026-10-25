package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Check definitions (design 32 D1). A definition holds a method, a source
// selector, a target selector and addresses, and the shared fields every
// monitor it expands into carries. The planner here turns each definition,
// against the fleet as it is now, into managed monitors, one per (target,
// method), marked ManagedBy "check:<definition id>", and the store writes
// them through the same managed sync the path set uses. Expanded monitors
// are authored checks everywhere (store.MonitorOwner.Authored): matrix rows,
// paging, visibility, beacon sources and node target resolution, which goes
// through monitorTargets.resolve and so through the path set planner's port
// rule and sticky endpoint choice.
//
// Rules the planner keeps:
//
//   - A target that leaves the set keeps its monitor, paused, with its
//     history; only a target node removed from the fleet loses its monitor.
//     The operator deletes history by deleting the definition or forgetting
//     its paused targets.
//   - Nothing is created to sit paused: a disabled definition, or a target no
//     source can run, creates no monitor, and pauses the ones it has.
//   - A target in the set that its method cannot dial still has its monitor,
//     so the matrix reads the pair unknown with the reason.
//   - A definition monitor's PausedNodeIDs are only ever packet budget
//     pauses: a source that would send one address more than
//     model.MonitorPacketsPerSecondMax across its checks is paused at every
//     sync and resumes when the budget has room. The load of every check a
//     definition did not expand is charged first; then the pairs that already
//     run keep their share, and only then do new or paused pairs take what is
//     left, each pass in definition order. So the pair whose arrival pushed a
//     source over the budget is the one paused, never an older pair that was
//     running, and a stable fleet never flaps.

// checkDefinitionMonitorID is an expanded monitor's id: "mon_", the
// definition id, and a short hash of the method and the normalized target,
// so an entry's id never depends on its position and a method change
// starts a new series. Nothing parses it.
func checkDefinitionMonitorID(definitionID, method, target string) string {
	sum := sha256.Sum256([]byte(method + "\x00" + target))
	return "mon_" + definitionID + "_" + hex.EncodeToString(sum[:5])
}

// checkDefinitionPreviewID stands in for a definition's id in the dry run
// of a create, which has none yet.
const checkDefinitionPreviewID = model.CheckDefinitionIDPrefix + "preview"

// checkDefinitionError is a refused save: the status to answer and why.
type checkDefinitionError struct {
	status int
	err    error
}

func (e *checkDefinitionError) Error() string { return e.err.Error() }

func checkBadRequest(format string, args ...any) *checkDefinitionError {
	return &checkDefinitionError{status: http.StatusBadRequest, err: fmt.Errorf(format, args...)}
}

// checkFieldRefusal is a 400 about the request field at path (design 32 R6).
func checkFieldRefusal(path string, err error) *checkDefinitionError {
	return &checkDefinitionError{status: http.StatusBadRequest, err: fieldError(path, err)}
}

func checkFieldf(path, format string, args ...any) *checkDefinitionError {
	return checkFieldRefusal(path, fmt.Errorf(format, args...))
}

func checkForbidden(path, msg string) *checkDefinitionError {
	return &checkDefinitionError{status: http.StatusForbidden, err: fieldError(path, apiError(model.APIErrorCapabilityDenied, msg))}
}

// checkSelectorBroad reports whether a selector names a group or the whole
// fleet, which grows as the fleet does.
func checkSelectorBroad(sel model.TargetSelector) bool {
	return sel.All || len(sel.Groups) > 0
}

func checkSelectorEmpty(sel model.TargetSelector) bool {
	return !sel.All && len(sel.Nodes) == 0 && len(sel.Groups) == 0
}

// aCheck is "a tcp check", "an auto check": a method's check with its article.
func aCheck(kind string) string {
	switch kind {
	case model.CheckMethodAuto, model.MonitorTypeICMP, model.MonitorTypeHTTP:
		return "an " + kind + " check"
	}
	return "a " + kind + " check"
}

// checkKindTakesNodes and checkKindTakesAddresses say which targets a
// method takes.
func checkKindTakesNodes(kind string) bool {
	return kind == model.MonitorTypeTCP || kind == model.MonitorTypeICMP || kind == model.MonitorTypeBeacon || kind == model.CheckMethodAuto
}

func checkKindTakesAddresses(kind string) bool {
	return kind != model.MonitorTypeBeacon && kind != model.CheckMethodAuto
}

// checkKindSendsPackets reports whether a definition's packets apply: an
// auto definition's icmp and beacon pairs send them.
func checkKindSendsPackets(kind string) bool {
	return model.MonitorKindSendsPackets(kind) || kind == model.CheckMethodAuto
}

// normalizeCheckSelector cleans a selector: ids trimmed, repeats dropped,
// lists sorted, bounded, and every id an existing node or group, or one the
// stored definition already named (a node removed since stays editable).
func normalizeCheckSelector(field string, in model.TargetSelector, prior *model.TargetSelector, nodes map[string]bool, groupIDs map[string]bool) (model.TargetSelector, error) {
	priorHas := func(list func(model.TargetSelector) []string, id string) bool {
		return prior != nil && slices.Contains(list(*prior), id)
	}
	clean := func(name string, raw []string, limit int, exists map[string]bool, list func(model.TargetSelector) []string) ([]string, error) {
		out := cleanNodeList(raw)
		path := field + "." + name
		if len(out) > limit {
			return nil, fieldErrorf(path, "%s holds %d entries, at most %d", path, len(out), limit)
		}
		for _, id := range out {
			if !exists[id] && !priorHas(list, id) {
				kind := "node"
				if name == "groups" {
					kind = "group"
				}
				return nil, fieldErrorf(rawIndexPath(path, raw, id), "%s names %q, which is not a %s", path, id, kind)
			}
		}
		if len(out) == 0 {
			return nil, nil
		}
		return out, nil
	}
	var out model.TargetSelector
	var err error
	if out.Nodes, err = clean("nodes", in.Nodes, model.CheckDefinitionNodesMax, nodes, func(s model.TargetSelector) []string { return s.Nodes }); err != nil {
		return out, err
	}
	if out.Groups, err = clean("groups", in.Groups, model.CheckDefinitionGroupsMax, groupIDs, func(s model.TargetSelector) []string { return s.Groups }); err != nil {
		return out, err
	}
	if out.Exclude, err = clean("exclude", in.Exclude, model.CheckDefinitionNodesMax, nodes, func(s model.TargetSelector) []string { return s.Exclude }); err != nil {
		return out, err
	}
	out.All = in.All
	// One canonical form that resolves to the same nodes (groups.ResolveTargets):
	// the whole fleet needs nothing named, an exclusion wins over a named
	// node, and an exclusion with no group or whole fleet to subtract from
	// says nothing. The console edits this form, so it never changes what a
	// selector sent through the API measures.
	if out.All {
		out.Nodes, out.Groups = nil, nil
	}
	if len(out.Exclude) > 0 {
		out.Nodes = slices.DeleteFunc(out.Nodes, func(id string) bool { return slices.Contains(out.Exclude, id) })
		if len(out.Nodes) == 0 {
			out.Nodes = nil
		}
		if !out.All && len(out.Groups) == 0 {
			out.Exclude = nil
		}
	}
	return out, nil
}

// normalizeCheckAddress is one external target in canonical form, which is
// also what its monitor id hashes: an http URL with its scheme and host in
// lower case and no fragment, host:port for tcp and tls, an IPv4 address
// for icmp, and a resolver endpoint for dns (model.DNSResolver.String). It applies the same rules a single check's create does.
func normalizeCheckAddress(kind, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch kind {
	case model.MonitorTypeHTTP:
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Host == "" {
			return "", fmt.Errorf("address %q is not an absolute http or https URL", raw)
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Fragment, u.RawFragment = "", ""
		mon := model.Monitor{Type: kind, Target: u.String()}
		if err := normalizeHTTPMonitor(&mon, true); err != nil {
			return "", fmt.Errorf("address %q: %w", raw, err)
		}
		return mon.Target, nil
	case model.MonitorTypeTCP:
		host, port, err := net.SplitHostPort(raw)
		if err != nil {
			return "", fmt.Errorf("address %q: a tcp target is host:port", raw)
		}
		mon := model.Monitor{Type: kind, Target: net.JoinHostPort(strings.ToLower(strings.TrimSpace(host)), port)}
		if err := (monitorTargets{}).normalizeTCPMonitor(&mon); err != nil {
			return "", fmt.Errorf("address %q: %w", raw, err)
		}
		return mon.Target, nil
	case model.MonitorTypeICMP:
		mon := model.Monitor{Type: kind, Target: raw}
		if err := (monitorTargets{}).normalizeICMPMonitor(&mon); err != nil {
			return "", fmt.Errorf("address %q: %w", raw, err)
		}
		return mon.Target, nil
	case model.MonitorTypeTLS:
		host, port, err := splitTLSTarget(raw)
		if err != nil {
			return "", fmt.Errorf("address %q: %w", raw, err)
		}
		return net.JoinHostPort(strings.ToLower(host), port), nil
	case model.MonitorTypeDNS:
		target, err := normalizeDNSTarget(raw, true)
		if err != nil {
			return "", fmt.Errorf("address %q: %w", raw, err)
		}
		return target, nil
	}
	return "", fmt.Errorf("%s takes no addresses", aCheck(kind))
}

// normalizeCheckDefinition validates a save against the fleet now and
// returns the definition to store. prior is the stored definition for an
// edit, nil for a create. A refusal carries its status: 403 for scope, 400
// for everything else. Scope is judged first, on the ids as sent, so a
// restricted principal cannot tell from the answer whether an id it may not
// read exists.
func (s *Server) normalizeCheckDefinition(p principal, req model.CheckDefinitionSave, prior *model.CheckDefinition) (model.CheckDefinition, *checkDefinitionError) {
	spec := req.CheckDefinitionSpec
	out := model.CheckDefinition{}
	if prior != nil {
		out.ID = prior.ID
	}
	out.Name = strings.TrimSpace(spec.Name)
	if out.Name == "" {
		return out, checkFieldf("name", "name is required")
	}
	if len(out.Name) > model.CheckDefinitionNameMax {
		return out, checkFieldf("name", "name is at most %d bytes", model.CheckDefinitionNameMax)
	}
	out.Type = strings.TrimSpace(spec.Type)
	switch out.Type {
	case model.MonitorTypeTCP, model.MonitorTypeICMP, model.MonitorTypeBeacon, model.MonitorTypeHTTP, model.MonitorTypeTLS, model.MonitorTypeDNS, model.CheckMethodAuto:
	default:
		return out, checkFieldf("type", "type must be tcp, icmp, beacon, http, tls, dns or auto")
	}
	if failure := checkDefinitionScope(p, out.Type, spec.Sources, spec.Targets, spec.ExcludedPairs); failure != nil {
		return out, failure
	}
	if failure := s.normalizeCheckTargets(&out, spec, prior); failure != nil {
		return out, failure
	}
	if failure := s.normalizeExcludedPairs(&out, spec.ExcludedPairs, prior); failure != nil {
		return out, failure
	}
	if prior != nil {
		// Written once by the migration, never by a save.
		out.Adopted = slices.Clone(prior.Adopted)
	}
	if failure := normalizeCheckTiming(&out, spec); failure != nil {
		return out, failure
	}
	if failure := normalizeCheckHTTP(&out, req, prior); failure != nil {
		return out, failure
	}
	if failure := normalizeCheckDNS(&out, spec); failure != nil {
		return out, failure
	}
	out.Alert = strings.TrimSpace(spec.Alert)
	degraded, err := validMonitorAlertFor(out.Type, out.Alert, spec.Degraded)
	if err != nil {
		return out, checkFieldRefusal("alert", err)
	}
	out.Degraded = degraded
	if out.Alert == "" {
		out.Alert = model.MonitorAlertDown
	}
	if err := validMonitorAlertAfter(spec.AlertAfter); err != nil {
		return out, checkFieldRefusal("alert_after", err)
	}
	out.AlertAfter = spec.AlertAfter
	out.Enabled = spec.Enabled
	return out, nil
}

// checkDefinitionScope is who may store these selectors. Expansion runs as
// the system, so a stored group or whole-fleet selector would let a
// restricted principal's targets grow to nodes it cannot read, as the path
// set refuses for the same reason. A restricted principal may name explicit
// nodes: sources it administers, targets and exclusions it can read.
func checkDefinitionScope(p principal, kind string, sources, targets model.TargetSelector, excludedPairs []model.LatencyPair) *checkDefinitionError {
	restricted := principalHasNodeRestriction(p)
	if restricted && checkSelectorBroad(sources) {
		return checkForbidden("sources", "a group or whole-fleet selector needs a token with no node allowlist; name the nodes instead")
	}
	if restricted && checkSelectorBroad(targets) {
		return checkForbidden("targets", "a group or whole-fleet selector needs a token with no node allowlist; name the nodes instead")
	}
	if restricted && kind == model.MonitorTypeTLS {
		return checkForbidden("type", "restricted token cannot create a server-evaluated monitor")
	}
	for _, nodeID := range cleanNodeList(sources.Nodes) {
		if !rbac.Allows(p.Principal, "monitor:admin", nodeID) {
			return checkForbidden(rawIndexPath("sources.nodes", sources.Nodes, nodeID), "forbidden: sources names a node this token may not administer")
		}
	}
	for _, list := range []struct {
		path string
		ids  []string
	}{{"targets.nodes", targets.Nodes}, {"sources.exclude", sources.Exclude}, {"targets.exclude", targets.Exclude}} {
		for _, nodeID := range cleanNodeList(list.ids) {
			if !latencyNodeVisible(p, nodeID) {
				return checkForbidden(rawIndexPath(list.path, list.ids, nodeID), "forbidden: the check names a node this token may not read")
			}
		}
	}
	for i, pair := range excludedPairs {
		if !latencyNodeVisible(p, strings.TrimSpace(pair.Source)) || !latencyNodeVisible(p, strings.TrimSpace(pair.Target)) {
			return checkForbidden(fieldIndex("excluded_pairs", i), "forbidden: the check names a node this token may not read")
		}
	}
	return nil
}

// normalizeCheckTargets cleans the selectors and addresses and checks the
// shape the method takes.
func (s *Server) normalizeCheckTargets(out *model.CheckDefinition, spec model.CheckDefinitionSpec, prior *model.CheckDefinition) *checkDefinitionError {
	nodes := map[string]bool{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = true
	}
	groupIDs := map[string]bool{}
	for _, g := range s.store.Groups() {
		groupIDs[g.ID] = true
	}
	var priorSources, priorTargets *model.TargetSelector
	if prior != nil {
		priorSources, priorTargets = &prior.Sources, &prior.Targets
	}
	var err error
	if out.Sources, err = normalizeCheckSelector("sources", spec.Sources, priorSources, nodes, groupIDs); err != nil {
		return checkFieldRefusal("sources", err)
	}
	if out.Targets, err = normalizeCheckSelector("targets", spec.Targets, priorTargets, nodes, groupIDs); err != nil {
		return checkFieldRefusal("targets", err)
	}
	seen := map[string]bool{}
	for i, raw := range spec.Addresses {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		addr, err := normalizeCheckAddress(out.Type, raw)
		if err != nil {
			return checkFieldRefusal(fieldIndex("addresses", i), err)
		}
		if !seen[addr] {
			seen[addr] = true
			out.Addresses = append(out.Addresses, addr)
		}
	}
	sort.Strings(out.Addresses)
	if len(out.Addresses) > model.CheckDefinitionAddressesMax {
		return checkFieldf("addresses", "addresses holds %d entries, at most %d", len(out.Addresses), model.CheckDefinitionAddressesMax)
	}
	tls := out.Type == model.MonitorTypeTLS
	switch {
	case tls && (!checkSelectorEmpty(out.Sources) || len(out.Sources.Exclude) > 0):
		return checkFieldf("sources", "a tls check runs on the control plane: it takes no sources")
	case !tls && checkSelectorEmpty(out.Sources):
		return checkFieldf("sources", "sources selects no node: name nodes, groups or the whole fleet")
	case !checkKindTakesNodes(out.Type) && (!checkSelectorEmpty(out.Targets) || len(out.Targets.Exclude) > 0):
		return checkFieldf("targets", "%s takes addresses, not target nodes", aCheck(out.Type))
	case !checkKindTakesAddresses(out.Type) && len(out.Addresses) > 0:
		return checkFieldf("addresses", "%s names target nodes; it never takes an address", aCheck(out.Type))
	case checkSelectorEmpty(out.Targets) && len(out.Addresses) == 0:
		return checkFieldf("targets", "the check has no target: name target nodes or addresses")
	}
	return nil
}

// normalizeExcludedPairs cleans the excluded pairs: trimmed, without
// repeats, sorted and bounded, each naming two different nodes that exist
// (or that the stored definition already excluded, so a node removed since
// stays editable). A pair whose source is not one of the definition's
// sources says nothing, so it is refused rather than kept.
func (s *Server) normalizeExcludedPairs(out *model.CheckDefinition, pairs []model.LatencyPair, prior *model.CheckDefinition) *checkDefinitionError {
	if len(pairs) == 0 {
		return nil
	}
	if !checkKindTakesNodes(out.Type) {
		return checkFieldf("excluded_pairs", "%s has no node pairs to exclude", aCheck(out.Type))
	}
	nodes := map[string]bool{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = true
	}
	known := func(pair model.LatencyPair) bool {
		if nodes[pair.Source] && nodes[pair.Target] {
			return true
		}
		return prior != nil && slices.Contains(prior.ExcludedPairs, pair)
	}
	sourceSet := map[string]bool{}
	for _, nodeID := range out.Sources.Nodes {
		sourceSet[nodeID] = true
	}
	broad := checkSelectorBroad(out.Sources)
	seen := map[string]bool{}
	for i, raw := range pairs {
		pair := model.LatencyPair{Source: strings.TrimSpace(raw.Source), Target: strings.TrimSpace(raw.Target)}
		field := fieldIndex("excluded_pairs", i)
		switch {
		case pair.Source == "" || pair.Target == "":
			return checkFieldf(field, "an excluded pair names a source and a target node")
		case pair.Source == pair.Target:
			return checkFieldf(field, "an excluded pair names two different nodes")
		case !known(pair):
			return checkFieldf(field, "excluded pair %s to %s names a node that does not exist", pair.Source, pair.Target)
		case !broad && !sourceSet[pair.Source]:
			return checkFieldf(field, "excluded pair %s to %s names a node that is not a source of this check", pair.Source, pair.Target)
		}
		key := latencyPairKey(pair.Source, pair.Target)
		if seen[key] {
			continue
		}
		seen[key] = true
		out.ExcludedPairs = append(out.ExcludedPairs, pair)
	}
	if len(out.ExcludedPairs) > model.CheckDefinitionExcludedPairsMax {
		return checkFieldf("excluded_pairs", "excluded_pairs holds %d entries, at most %d", len(out.ExcludedPairs), model.CheckDefinitionExcludedPairsMax)
	}
	sortLatencyPairs(out.ExcludedPairs)
	return nil
}

// sortLatencyPairs orders pairs by source, then target.
func sortLatencyPairs(pairs []model.LatencyPair) {
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Source != pairs[j].Source {
			return pairs[i].Source < pairs[j].Source
		}
		return pairs[i].Target < pairs[j].Target
	})
}

// normalizeCheckTiming fills and checks the interval, the timeout, the
// packets and the tls warning window.
func normalizeCheckTiming(out *model.CheckDefinition, spec model.CheckDefinitionSpec) *checkDefinitionError {
	tls := out.Type == model.MonitorTypeTLS
	out.IntervalSec, out.TimeoutSec = spec.IntervalSec, spec.TimeoutSec
	if out.IntervalSec <= 0 {
		out.IntervalSec = 30
		if tls {
			out.IntervalSec = int(tlsMonitorDefaultInterval / time.Second)
		}
	}
	if out.TimeoutSec <= 0 {
		out.TimeoutSec = 5
		if tls {
			out.TimeoutSec = int(tlsMonitorDefaultTimeout / time.Second)
		}
	}
	if err := validMonitorTiming(out.IntervalSec, out.TimeoutSec); err != nil {
		return checkFieldRefusal("interval_sec", err)
	}
	if checkKindSendsPackets(out.Type) {
		out.Packets = spec.Packets
		if out.Packets == 0 {
			out.Packets = model.MonitorPacketsDefault
		}
		if out.Packets < 1 || out.Packets > model.MonitorPacketsMax {
			return checkFieldf("packets", "packets must be 1 to %d", model.MonitorPacketsMax)
		}
		kind := out.Type
		if kind == model.CheckMethodAuto {
			// Judged as the longest run its pairs can make, an icmp one.
			kind = model.MonitorTypeICMP
		}
		if err := validMonitorRun(model.Monitor{Type: kind, IntervalSec: out.IntervalSec, TimeoutSec: out.TimeoutSec, Packets: out.Packets}); err != nil {
			return checkFieldRefusal("interval_sec", err)
		}
	} else if spec.Packets != 0 {
		return checkFieldRefusal("packets", errMonitorPacketsKinds)
	}
	if tls {
		out.ThresholdDays = spec.ThresholdDays
		if out.ThresholdDays == 0 {
			out.ThresholdDays = tlsMonitorDefaultThresholdDays
		}
		if out.ThresholdDays < 1 || out.ThresholdDays > tlsMonitorMaxThresholdDays {
			return checkFieldf("threshold_days", "threshold_days must be between 1 and %d", tlsMonitorMaxThresholdDays)
		}
	} else if spec.ThresholdDays != 0 {
		return checkFieldf("threshold_days", "threshold_days applies to tls checks only")
	}
	return nil
}

// normalizeCheckHTTP checks an http definition's expectations and headers.
// Header edits apply to the stored headers in order, as a check's edit
// does; secrets need explicit source nodes and https everywhere, and stay
// bound to the origins they were saved for.
func normalizeCheckHTTP(out *model.CheckDefinition, req model.CheckDefinitionSave, prior *model.CheckDefinition) *checkDefinitionError {
	if out.Type != model.MonitorTypeHTTP {
		if strings.TrimSpace(req.ExpectStatus) != "" {
			return checkFieldf("expect_status", "expect_status and headers apply to http checks only")
		}
		if len(req.Headers) > 0 {
			return checkFieldf("headers", "expect_status and headers apply to http checks only")
		}
		return nil
	}
	var stored []model.MonitorHeader
	if prior != nil && prior.Type == model.MonitorTypeHTTP {
		stored = prior.Headers
	}
	headers, err := applyMonitorHeaderEdits(stored, req.Headers)
	if err != nil {
		return checkFieldRefusal("headers", err)
	}
	probe := model.Monitor{Type: out.Type, Target: "https://example.invalid/", ExpectStatus: req.ExpectStatus, Headers: headers}
	if len(out.Addresses) > 0 {
		probe.Target = out.Addresses[0]
	}
	if err := normalizeHTTPMonitor(&probe, false); err != nil {
		// The probe's headers are the stored ones with the edits applied,
		// so their positions are not the request's: name the list.
		path := apiErrorField(err)
		switch {
		case path == "target":
			path = "addresses"
		case strings.HasPrefix(path, "headers"):
			path = "headers"
		}
		return &checkDefinitionError{status: http.StatusBadRequest, err: refieldError(path, err)}
	}
	out.ExpectStatus, out.Headers = probe.ExpectStatus, probe.Headers
	if !model.MonitorHasSecrets(probe) {
		return nil
	}
	if checkSelectorBroad(out.Sources) {
		return checkFieldf("sources", "a check with secret headers names its sources as nodes, never a group or the whole fleet: a node that joined would receive the secrets")
	}
	origins := map[string]bool{}
	for i, addr := range out.Addresses {
		origin, err := model.MonitorOrigin(addr)
		if err != nil {
			return checkFieldRefusal(fieldIndex("addresses", i), err)
		}
		if !strings.HasPrefix(origin, "https://") {
			return checkFieldf(fieldIndex("addresses", i), "a check with secret headers must use https for every address, so the secrets travel encrypted to a verified host")
		}
		origins[origin] = true
	}
	for origin := range origins {
		out.SecretsOrigins = append(out.SecretsOrigins, origin)
	}
	sort.Strings(out.SecretsOrigins)
	if err := checkSecretsRebound(prior, out.SecretsOrigins, req.Headers); err != nil {
		return checkFieldRefusal("headers", err)
	}
	return nil
}

// normalizeCheckDNS checks a dns definition's question and judgement, which
// every expanded monitor carries, and refuses them on another method.
func normalizeCheckDNS(out *model.CheckDefinition, spec model.CheckDefinitionSpec) *checkDefinitionError {
	probe := model.Monitor{Type: out.Type, DNSName: spec.DNSName, DNSType: spec.DNSType, DNSExpect: spec.DNSExpect, DNSExpectRcode: spec.DNSExpectRcode}
	if out.Type != model.MonitorTypeDNS {
		if err := refuseDNSFields(probe); err != nil {
			return &checkDefinitionError{status: http.StatusBadRequest, err: err}
		}
		return nil
	}
	if err := normalizeDNSQuestion(&probe); err != nil {
		return &checkDefinitionError{status: http.StatusBadRequest, err: err}
	}
	out.DNSName, out.DNSType, out.DNSExpect, out.DNSExpectRcode = probe.DNSName, probe.DNSType, probe.DNSExpect, probe.DNSExpectRcode
	return nil
}

// checkSecretsRebound refuses an edit that would send stored secrets to an
// origin they were not saved for (design 29 D1 binds secrets to their
// origin): an edit that adds such an origin must set every secret header
// again in the same edit, or delete it.
func checkSecretsRebound(prior *model.CheckDefinition, origins []string, edits []model.MonitorHeaderEdit) error {
	if prior == nil || prior.Type != model.MonitorTypeHTTP {
		return nil
	}
	var added []string
	for _, origin := range origins {
		if !slices.Contains(prior.SecretsOrigins, origin) {
			added = append(added, origin)
		}
	}
	if len(added) == 0 {
		return nil
	}
	settled := map[string]bool{}
	for _, e := range edits {
		if e.Op == model.MonitorHeaderSet || e.Op == model.MonitorHeaderDelete {
			settled[model.CanonicalMonitorHeaderName(e.Name)] = true
		}
	}
	for _, h := range prior.Headers {
		if h.Secret && !settled[h.Name] {
			return fmt.Errorf("secret header %s was saved for %s; adding %s needs it set again in the same edit", h.Name, strings.Join(prior.SecretsOrigins, ", "), strings.Join(added, ", "))
		}
	}
	return nil
}

// checkPlanContext is the fleet as one planning pass sees it. Plans made
// from one context share one packet budget, so a sweep and a save allocate
// it the same way.
type checkPlanContext struct {
	now     time.Time
	nodes   []model.Node
	byID    map[string]model.Node
	groups  []model.Group
	targets monitorTargets
	// existing are the stored monitors of each definition owner.
	existing map[string]map[string]model.Monitor
	// load is the packets a second each (source, address) already sends,
	// starting from every check a definition did not expand.
	load map[monitorPacketKey]float64
	// facts is what a target offers every source for an auto definition's
	// choice, the path set planner's facts (latencyTargetFactsOf), and
	// icmpFiltered whether a pair's icmp check reads icmp_filtered now.
	facts        func(n model.Node) latencyTargetFacts
	icmpFiltered func(monitorID, sourceID string) bool
}

func (s *Server) checkPlanContextAt(now time.Time) *checkPlanContext {
	nodes := s.store.Nodes()
	byID := make(map[string]model.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	endpoints := s.pathPlanned(now).endpoints
	beacons := s.store.BeaconTargets()
	c := &checkPlanContext{
		now:      now,
		nodes:    nodes,
		byID:     byID,
		groups:   s.store.Groups(),
		targets:  monitorTargets{nodes: byID, endpoints: endpoints, beacons: beacons},
		existing: map[string]map[string]model.Monitor{},
		facts: func(n model.Node) latencyTargetFacts {
			return s.latencyTargetFactsOf(n, endpoints, beacons)
		},
		icmpFiltered: func(monitorID, sourceID string) bool {
			return s.latencyICMPFiltered(monitorID, sourceID, now)
		},
	}
	var others []model.Monitor
	for _, mon := range s.store.Monitors() {
		if store.MonitorOwnerOf(mon) == store.MonitorOwnerDefinition {
			owner := store.MonitorOwnerKey(mon)
			if c.existing[owner] == nil {
				c.existing[owner] = map[string]model.Monitor{}
			}
			c.existing[owner][mon.ID] = mon
			continue
		}
		others = append(others, mon)
	}
	c.load = c.targets.monitorPacketLoad(others)
	return c
}

// checkDefinitionPlan is one definition applied to the fleet: the monitors
// the store should hold for it, and what the dry run reports.
type checkDefinitionPlan struct {
	def     model.CheckDefinition
	owner   string
	desired []model.Monitor
	// entries are the targets in the set, in order, with their monitor
	// when one exists or would.
	entries []checkPlanEntry
	sources []string
	notes   map[string]string
}

// checkPlanEntry is one target in a definition's set, with one method: an
// auto definition's target has an entry for each method its sources use.
type checkPlanEntry struct {
	key        string
	targetNode string
	kind       string
	// sources are the definition's sources that measure this target with
	// kind now.
	sources   []string
	monitorID string
	// adopted says monitorID is one the definition adopted from the path
	// set (CheckDefinition.Adopted).
	adopted bool
	// target is what the method dials now, empty when nothing can be.
	target string
	// desired is the index of its monitor in the plan's desired list, -1
	// when none is created.
	desired int
	// reason and note say why nothing can be dialled: a PathReason* code
	// and a LatencyEndpoint* detail.
	reason, note string
	// budget are the sources the packet budget pauses.
	budget map[string]bool
}

// targetKeys are the targets in the set, by the key an entry and a
// monitor share (checkMonitorKey).
func (p *checkDefinitionPlan) targetKeys() map[string]bool {
	out := make(map[string]bool, len(p.entries))
	for _, e := range p.entries {
		out[e.key] = true
	}
	return out
}

// checkMonitorKey is the target a definition monitor measures, as its plan
// entry names it: the target node, else the address.
func checkMonitorKey(mon model.Monitor) string {
	if mon.TargetNode != "" {
		return mon.TargetNode
	}
	return mon.Target
}

// monitorOf is an entry's desired monitor, nil when none is created.
func (p *checkDefinitionPlan) monitorOf(e checkPlanEntry) *model.Monitor {
	if e.desired < 0 {
		return nil
	}
	return &p.desired[e.desired]
}

// planAll plans every definition in defs, oldest first, with override in
// place of the definition of the same id (or after the others when it is
// new), so the packet budget is shared out in the same order whichever
// call plans. It charges the context's budget, so a context plans once.
func (c *checkPlanContext) planAll(defs []model.CheckDefinition, override *model.CheckDefinition) []checkDefinitionPlan {
	defs = slices.Clone(defs)
	if override != nil {
		next := *override
		if next.CreatedAt.IsZero() {
			next.CreatedAt = c.now.UTC()
		}
		replaced := false
		for i := range defs {
			if defs[i].ID == next.ID {
				next.CreatedAt = defs[i].CreatedAt
				defs[i] = next
				replaced = true
			}
		}
		if !replaced {
			defs = append(defs, next)
		}
	}
	sort.SliceStable(defs, func(i, j int) bool {
		if !defs[i].CreatedAt.Equal(defs[j].CreatedAt) {
			return defs[i].CreatedAt.Before(defs[j].CreatedAt)
		}
		return defs[i].ID < defs[j].ID
	})
	out := make([]checkDefinitionPlan, 0, len(defs))
	for _, def := range defs {
		out = append(out, c.plan(def))
	}
	c.shareBudget(out)
	return out
}

// shareBudget pauses the definition pairs that would push a source over
// the packet budget to one address: the pairs that already run keep their
// share first, then the rest, each pass in definition order.
func (c *checkPlanContext) shareBudget(plans []checkDefinitionPlan) {
	type pair struct {
		plan, entry int
		source      string
	}
	var incumbents, newcomers []pair
	for pi := range plans {
		plan := &plans[pi]
		for ei, e := range plan.entries {
			mon := plan.monitorOf(e)
			if mon == nil || !mon.Enabled || e.reason != "" || !model.MonitorKindSendsPackets(mon.Type) || mon.IntervalSec <= 0 {
				continue
			}
			prior, had := c.existing[plan.owner][mon.ID]
			running := map[string]bool{}
			if had && prior.Enabled && prior.Target == mon.Target {
				for _, sourceID := range prior.NodeIDs {
					running[sourceID] = true
				}
				for _, sourceID := range prior.PausedNodeIDs {
					delete(running, sourceID)
				}
			}
			for _, sourceID := range mon.NodeIDs {
				if running[sourceID] {
					incumbents = append(incumbents, pair{pi, ei, sourceID})
				} else {
					newcomers = append(newcomers, pair{pi, ei, sourceID})
				}
			}
		}
	}
	for _, p := range append(incumbents, newcomers...) {
		plan := &plans[p.plan]
		e := &plan.entries[p.entry]
		mon := plan.monitorOf(*e)
		rate := float64(model.MonitorPackets(*mon)) / float64(mon.IntervalSec)
		key := monitorPacketKey{source: p.source, target: mon.Target}
		if c.load[key]+rate > model.MonitorPacketsPerSecondMax+1e-9 {
			if e.budget == nil {
				e.budget = map[string]bool{}
			}
			e.budget[p.source] = true
			mon.PausedNodeIDs = append(mon.PausedNodeIDs, p.source)
			continue
		}
		c.load[key] += rate
	}
	for pi := range plans {
		for i := range plans[pi].desired {
			slices.Sort(plans[pi].desired[i].PausedNodeIDs)
		}
	}
}

// checkNodeLabel names a node target in a monitor's name.
func (c *checkPlanContext) checkNodeLabel(nodeID string) string {
	if n, ok := c.byID[nodeID]; ok {
		return latencyNodeLabel(n)
	}
	return nodeID
}

// plan applies one definition to the fleet. The packet budget is shared out
// afterwards, over every plan at once (shareBudget).
func (c *checkPlanContext) plan(def model.CheckDefinition) checkDefinitionPlan {
	owner := store.CheckDefinitionOwner(def.ID)
	existing := c.existing[owner]
	out := checkDefinitionPlan{def: def, owner: owner, notes: map[string]string{}}
	tls := def.Type == model.MonitorTypeTLS

	// Sources: the selector resolved, less disabled nodes. An explicit id
	// that names no node is noted, as the path set notes it.
	usable := func(sel model.TargetSelector) []string {
		var ids []string
		for _, nodeID := range groups.ResolveTargets(sel, c.nodes, c.groups) {
			if c.byID[nodeID].Disabled {
				out.notes[nodeID] = model.LatencySourceDisabled
				continue
			}
			ids = append(ids, nodeID)
		}
		for _, nodeID := range sel.Nodes {
			if _, ok := c.byID[nodeID]; !ok {
				out.notes[nodeID] = model.LatencySourceUnknownNode
			}
		}
		return ids
	}
	if !tls {
		out.sources = usable(def.Sources)
	}
	excluded := make(map[string]bool, len(def.ExcludedPairs))
	for _, pair := range def.ExcludedPairs {
		excluded[latencyPairKey(pair.Source, pair.Target)] = true
	}
	adopted := make(map[string]string, len(def.Adopted))
	for _, a := range def.Adopted {
		adopted[a.Method+"\x00"+a.TargetNode] = a.MonitorID
	}
	// idOf is the monitor of a (method, target): the adopted one for
	// exactly the adopted keys, else the hashed one.
	idOf := func(kind, key string) (string, bool) {
		if monitorID, ok := adopted[kind+"\x00"+key]; ok {
			return monitorID, true
		}
		return checkDefinitionMonitorID(def.ID, kind, key), false
	}
	for _, nodeID := range usable(def.Targets) {
		var sources []string
		for _, sourceID := range out.sources {
			if sourceID != nodeID && !excluded[latencyPairKey(sourceID, nodeID)] {
				sources = append(sources, sourceID)
			}
		}
		if def.Type != model.CheckMethodAuto {
			out.entries = append(out.entries, checkPlanEntry{key: nodeID, targetNode: nodeID, kind: def.Type, sources: sources})
			continue
		}
		out.entries = append(out.entries, c.autoEntries(nodeID, sources, existing, idOf)...)
	}
	for _, addr := range def.Addresses {
		out.entries = append(out.entries, checkPlanEntry{key: addr, kind: def.Type, sources: slices.Clone(out.sources)})
	}

	inSet := map[string]bool{}
	for i := range out.entries {
		e := &out.entries[i]
		e.desired = -1
		e.monitorID, e.adopted = idOf(e.kind, e.key)
		inSet[e.monitorID] = true
		prior, had := existing[e.monitorID]
		sources := e.sources
		target := e.key
		if e.targetNode != "" {
			target = ""
			resolved, why := c.targets.resolve(e.kind, e.targetNode, prior.Target)
			switch {
			case why == "":
				target = resolved
			case e.kind == model.MonitorTypeBeacon:
				e.reason, e.note = model.PathReasonBeaconNotEnabled, why
			default:
				e.reason, e.note = model.PathReasonNotProbeable, why
			}
			if target == "" && had {
				// Keep what it dialled last; the agent is handed nothing
				// until the node resolves again.
				target = prior.Target
			}
		}
		e.target = target
		if e.reason != "" {
			e.target = ""
		}
		runs := tls || len(sources) > 0
		if !had && (!def.Enabled || !runs) {
			// Nothing is created to sit paused.
			continue
		}
		mon := model.Monitor{
			ID:             e.monitorID,
			Type:           e.kind,
			Target:         target,
			TargetNode:     e.targetNode,
			IntervalSec:    def.IntervalSec,
			TimeoutSec:     def.TimeoutSec,
			ThresholdDays:  def.ThresholdDays,
			ExpectStatus:   def.ExpectStatus,
			Headers:        slices.Clone(def.Headers),
			DNSName:        def.DNSName,
			DNSType:        def.DNSType,
			DNSExpect:      slices.Clone(def.DNSExpect),
			DNSExpectRcode: def.DNSExpectRcode,
			Alert:          def.Alert,
			AlertAfter:     def.AlertAfter,
			Degraded:       def.Degraded,
			NodeIDs:        sources,
			Enabled:        def.Enabled && runs,
			ManagedBy:      owner,
		}
		if model.MonitorKindSendsPackets(e.kind) {
			mon.Packets = def.Packets
			if mon.Packets == 0 {
				mon.Packets = model.MonitorPacketsDefault
			}
		}
		if e.adopted {
			// It keeps the path set's mark, so the release before the
			// migration re-owns it after a rollback (store.MigratePathSet).
			mon.ManagedBy, mon.CheckDefinitionID = model.MonitorManagedLatency, def.ID
		}
		if e.targetNode != "" {
			mon.Name = def.Name + " to " + c.checkNodeLabel(e.targetNode)
		} else {
			mon.Name = def.Name + " to " + e.key
		}
		if def.Type == model.CheckMethodAuto {
			mon.Name += " (" + e.kind + ")"
		}
		if len(mon.Headers) == 0 {
			mon.Headers = nil
		}
		if model.MonitorHasSecrets(mon) {
			mon.SecretsOrigin, _ = model.MonitorOrigin(target)
		}
		if !runs && had {
			// No source left: keep the ones the history was taken from.
			mon.NodeIDs = slices.Clone(prior.NodeIDs)
		}
		e.desired = len(out.desired)
		out.desired = append(out.desired, mon)
	}

	// Targets that left the set keep their monitors, paused, unless the
	// target node left the fleet. A paused monitor keeps no secret value.
	ids := make([]string, 0, len(existing))
	for monitorID := range existing {
		ids = append(ids, monitorID)
	}
	sort.Strings(ids)
	for _, monitorID := range ids {
		if inSet[monitorID] {
			continue
		}
		prior := existing[monitorID]
		if prior.TargetNode != "" {
			if _, ok := c.byID[prior.TargetNode]; !ok {
				continue
			}
		}
		paused := prior
		paused.Enabled = false
		paused.PausedNodeIDs = nil
		paused.NodeIDs = slices.Clone(prior.NodeIDs)
		paused.Headers = slices.DeleteFunc(slices.Clone(prior.Headers), func(h model.MonitorHeader) bool { return h.Secret })
		if len(paused.Headers) == 0 {
			paused.Headers = nil
		}
		paused.SecretsOrigin = ""
		out.desired = append(out.desired, paused)
	}
	return out
}

// autoEntries are an auto definition's entries for one target node: one for
// each method its sources use now, by the path set planner's choice
// (latencyPairMethod over latencyTargetFacts), so a pair is measured the way
// it was before the path set became a definition. A target nothing can
// reach reads as a tcp entry nothing can dial, as the path set read it.
func (c *checkPlanContext) autoEntries(nodeID string, sources []string, existing map[string]model.Monitor, idOf func(kind, key string) (string, bool)) []checkPlanEntry {
	tcpID, _ := idOf(model.MonitorTypeTCP, nodeID)
	_, why := c.targets.resolve(model.MonitorTypeTCP, nodeID, existing[tcpID].Target)
	facts := c.facts(c.byID[nodeID])
	icmpID, _ := idOf(model.MonitorTypeICMP, nodeID)
	_, hadICMP := existing[icmpID]
	byKind := map[string][]string{}
	for _, sourceID := range sources {
		caps := facts.caps(why == "", sourceID)
		if facts.icmpOK && hadICMP {
			caps.icmpFiltered = c.icmpFiltered(icmpID, sourceID)
		}
		kind, _ := latencyPairMethod(model.LatencyMethodAuto, c.byID[sourceID], caps)
		byKind[kind] = append(byKind[kind], sourceID)
	}
	var out []checkPlanEntry
	for _, kind := range []string{model.MonitorTypeTCP, model.MonitorTypeICMP, model.MonitorTypeBeacon} {
		if len(byKind[kind]) > 0 {
			out = append(out, checkPlanEntry{key: nodeID, targetNode: nodeID, kind: kind, sources: byKind[kind]})
		}
	}
	if len(out) == 0 {
		out = append(out, checkPlanEntry{key: nodeID, targetNode: nodeID, kind: model.MonitorTypeTCP})
	}
	return out
}

// sets is every plan's desired monitors by owner, with an empty set for
// each definition owner whose definition is gone, so its monitors go too.
func (c *checkPlanContext) sets(plans []checkDefinitionPlan) map[string][]model.Monitor {
	out := make(map[string][]model.Monitor, len(plans))
	for _, plan := range plans {
		out[plan.owner] = plan.desired
	}
	for owner := range c.existing {
		if _, ok := out[owner]; !ok {
			out[owner] = nil
		}
	}
	return out
}

// pairReason is why one pair of a plan reads unknown now, "" when it is
// measured: the order the matrix judges in (pathStateOf), so the dry run
// and the matrix name the same reason.
func (s *Server) checkPairReason(c *checkPlanContext, e checkPlanEntry, mon *model.Monitor, sourceID string) string {
	if e.reason != "" {
		return e.reason
	}
	if sourceID != "" {
		source := c.byID[sourceID]
		if gate := monitorProbeGate(source, *mon); gate != "" {
			return gate
		}
		if mon.Type == model.MonitorTypeBeacon && mon.TargetNode != "" {
			if gate := s.beaconMonitorGate(source, mon.TargetNode, c.now); gate != "" {
				return gate
			}
			if gate := s.beaconTargetListenGate(mon.TargetNode, c.byID); gate != "" {
				return gate
			}
		}
		if mon.Enabled && e.budget[sourceID] {
			return model.PathReasonPacketBudget
		}
	}
	if !mon.Enabled {
		return model.PathReasonSourcePaused
	}
	if sourceID != "" {
		if n, ok := c.byID[sourceID]; !ok || n.Disabled || !n.Online {
			return model.PathReasonAgentOffline
		}
	}
	return ""
}

// checkPreview is the dry run of one plan among plans: what a save writes
// and measures, judged by the store's own sync rule over every
// definition's set, as the save writes them.
func (s *Server) checkPreview(c *checkPlanContext, plans []checkDefinitionPlan, plan checkDefinitionPlan) (model.CheckDefinitionPreview, error) {
	out := model.CheckDefinitionPreview{
		Sources: slices.Clone(plan.sources),
		Targets: []model.CheckPreviewTarget{},
		Pairs:   []model.CheckPreviewPair{},
	}
	if out.Sources == nil {
		out.Sources = []string{}
	}
	for _, e := range plan.entries {
		t := model.CheckPreviewTarget{Target: e.target, TargetNode: e.targetNode, Reason: e.reason, Note: e.note}
		if mon := plan.monitorOf(e); mon != nil {
			t.MonitorID = e.monitorID
			sources := mon.NodeIDs
			if mon.Type == model.MonitorTypeTLS {
				sources = []string{""}
			}
			for _, sourceID := range sources {
				pair := model.CheckPreviewPair{Source: sourceID, MonitorID: e.monitorID, Reason: s.checkPairReason(c, e, mon, sourceID)}
				if pair.Reason == "" {
					out.Measured++
				}
				out.Pairs = append(out.Pairs, pair)
			}
		}
		out.Targets = append(out.Targets, t)
	}
	out.Paths = len(out.Pairs)
	changes, err := s.store.DiffManagedMonitorSets(c.sets(plans), plan.def.ID)
	if err != nil {
		return out, err
	}
	diff := changes[plan.owner]
	for owner, ch := range changes {
		if owner != plan.owner && ch.Changed() {
			out.AlsoChanges = append(out.AlsoChanges, strings.TrimPrefix(owner, store.MonitorManagedCheckPrefix))
		}
	}
	sort.Strings(out.AlsoChanges)
	inSet := map[string]bool{}
	for _, e := range plan.entries {
		inSet[e.monitorID] = true
	}
	out.Writes = model.CheckPreviewWrites{Created: emptyIfNil(diff.Created), Updated: []string{}, Paused: []string{}, Deleted: emptyIfNil(diff.Deleted)}
	for _, monitorID := range diff.Updated {
		if inSet[monitorID] {
			out.Writes.Updated = append(out.Writes.Updated, monitorID)
		} else {
			out.Writes.Paused = append(out.Writes.Paused, monitorID)
		}
	}
	if len(plan.notes) > 0 {
		out.Notes = plan.notes
	}
	return out, nil
}

func emptyIfNil(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

// syncCheckDefinitions plans every definition against the fleet now and
// writes every one that changed in one store write, audited like the path
// set's sync with bounded id lists. trigger names what asked (sweep, group,
// node, beacon) for the audit record.
func (s *Server) syncCheckDefinitions(now time.Time, trigger string) (map[string]store.ManagedMonitorChanges, error) {
	s.checkDefSync.Lock()
	defer s.checkDefSync.Unlock()
	defs := s.store.CheckDefinitions()
	if len(defs) == 0 && !s.store.AnyDefinitionMonitor() {
		return nil, nil
	}
	c := s.checkPlanContextAt(now)
	plans := c.planAll(defs, nil)
	sets := c.sets(plans)
	if len(sets) == 0 {
		return nil, nil
	}
	changes, err := s.store.SyncManagedMonitorSets(sets, now)
	if err != nil {
		return changes, err
	}
	s.auditCheckSync(now, trigger, changes)
	return changes, nil
}

// auditCheckSync records a sync that changed monitors, as
// monitor.latency.sync does: system actor, bounded id lists.
func (s *Server) auditCheckSync(now time.Time, trigger string, changes map[string]store.ManagedMonitorChanges) {
	var created, updated, deleted, definitions []string
	for owner, c := range changes {
		if !c.Changed() {
			continue
		}
		definitions = append(definitions, strings.TrimPrefix(owner, store.MonitorManagedCheckPrefix))
		created = append(created, c.Created...)
		updated = append(updated, c.Updated...)
		deleted = append(deleted, c.Deleted...)
	}
	if len(definitions) == 0 {
		return
	}
	for _, list := range [][]string{created, updated, deleted, definitions} {
		sort.Strings(list)
	}
	s.recordAudit(model.AuditEvent{
		ID:       id.New("audit"),
		At:       now.UTC(),
		ActorID:  systemActorID,
		Action:   "monitor.check.sync",
		Scope:    "monitor:admin",
		Decision: "allow",
		Metadata: map[string]string{
			"trigger":     trigger,
			"definitions": latencyIDList(definitions),
			"created":     latencyIDList(created),
			"updated":     latencyIDList(updated),
			"deleted":     latencyIDList(deleted),
		},
	})
}

// resyncCheckDefinitions follows a fleet change (a group edit, a node
// removal, a beacon approval) at once rather than at the next sweep. A
// failure is logged; the sweep tries again.
func (s *Server) resyncCheckDefinitions(trigger string) {
	if _, err := s.syncCheckDefinitions(s.now(), trigger); err != nil {
		s.logger.Printf("check definitions not synced after %s: %v", trigger, err)
	}
}
