package server

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/netguard"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// design-13 G1: read-only netguard views. Stored security groups, zones, and
// bindings are served as-is; nodes that only have a legacy NFTInputs baseline
// are served as an on-the-fly converted view marked source:"legacy". Nothing
// here mutates the store or touches any apply path.

const (
	netGuardSourceStored = "stored"
	netGuardSourceLegacy = "legacy"
	// netGuardSourceUnbound marks a review compiled from the empty observe-only
	// binding the store synthesises for a node with no stored binding.
	netGuardSourceUnbound = "unbound"
)

type securityGroupView struct {
	model.SecurityGroup
	Source string `json:"source"`
	NodeID string `json:"node_id,omitempty"` // set for node-private legacy groups
}

type nodeGuardView struct {
	NodeID   string                 `json:"node_id"`
	NodeName string                 `json:"node_name,omitempty"`
	Source   string                 `json:"source"`
	Binding  model.NodeGuardBinding `json:"binding"`
	Groups   []securityGroupView    `json:"groups"`
	Zones    []model.GuardZone      `json:"zones"`
}

type netGuardReplanInput struct {
	NodeID            string `json:"node_id"`
	AcceptLockoutRisk bool   `json:"accept_lockout_risk"`
}

type netGuardReview struct {
	Node        nodeGuardView         `json:"node"`
	Reality     guardRealityDetail    `json:"reality"`
	Suggestions []netguard.Suggestion `json:"suggestions"`
	DriftState  string                `json:"drift_state"`
	ReplanInput netGuardReplanInput   `json:"replan_input"`
	// Findings is what Lint would say about the plan this node's current intent
	// compiles to. Serving it from a read method is what lets an operator see a
	// lockout risk before creating an approval instead of after.
	Findings []netguard.Finding `json:"findings"`
	// Ruleset is the nft text this intent renders to right now. It is the
	// escape hatch behind the zone and group model, and the left side of the
	// diff an operator reads before approving anything.
	Ruleset string `json:"ruleset,omitempty"`
	// CompileError explains why Ruleset is empty. An unmanaged or unresolvable
	// node still gets its reality rendered; refusing the whole review because
	// intent does not compile would hide the evidence the operator came for.
	CompileError string `json:"compile_error,omitempty"`
}

type netGuardReviewResponse struct {
	Review netGuardReview `json:"review"`
}

const (
	netGuardDriftUnknown  = "unknown"
	netGuardDriftInSync   = "in_sync"
	netGuardDriftDetected = "drift"

	// Keep the historical apply-ruleset prefix so existing opt-in
	// auto-approval policies continue to match, while the exact suffix keeps
	// NetGuard writeback/capability handling distinct from legacy plain nft.
	netGuardApprovalAction         = "apply-ruleset:netguard-v1"
	netGuardManagedSHAResultPrefix = "lattice netguard: managed_sha="
)

// guardIDRe bounds operator-chosen group and zone ids to a charset that is
// safe wherever they surface (nft comments, routes, audit metadata).
var guardIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func (s *Server) handleNetGuardGroups(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireGlobalNetGuardScope(w, p, "netguard:read") {
			return
		}
	case http.MethodPost:
		s.handleUpsertSecurityGroup(w, r, p)
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	views := make([]securityGroupView, 0)
	for _, group := range s.store.SecurityGroups() {
		views = append(views, securityGroupView{SecurityGroup: group, Source: netGuardSourceStored})
	}
	for _, inputs := range s.store.AllNFTInputs() {
		if !rbac.Allows(p.Principal, "netguard:read", inputs.NodeID) {
			continue
		}
		if _, ok := s.store.SecurityGroup(netguard.LegacyGroupPrefix + inputs.NodeID); ok {
			continue // an adopted stored group supersedes the legacy view
		}
		converted := netguard.LegacyBaseline(inputs)
		views = append(views, securityGroupView{
			SecurityGroup: converted.Group,
			Source:        netGuardSourceLegacy,
			NodeID:        inputs.NodeID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": views})
}

func (s *Server) handleNetGuardZones(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireGlobalNetGuardScope(w, p, "netguard:read") {
			return
		}
	case http.MethodPost:
		s.handleUpsertGuardZone(w, r, p)
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	builtin := []model.GuardZone{
		{ID: model.GuardZonePublic, Name: "public", Builtin: true},
		{ID: model.GuardZoneLoopback, Name: "loopback", Builtin: true, Interfaces: []string{"lo"}},
		{ID: model.GuardZoneWireGuard, Name: "wireguard", Builtin: true},
		{ID: model.GuardZoneTailscale, Name: "tailscale", Builtin: true},
	}
	zones := make([]model.GuardZone, 0, len(builtin))
	seen := map[string]bool{}
	for _, zone := range s.store.GuardZones() {
		zones = append(zones, zone)
		seen[zone.ID] = true
	}
	for _, zone := range builtin {
		if !seen[zone.ID] {
			zones = append(zones, zone)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones})
}

func (s *Server) handleNetGuardNodes(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	views := make([]nodeGuardView, 0)
	covered := map[string]bool{}
	for _, binding := range s.store.NodeGuardBindings() {
		if !rbac.Allows(p.Principal, "netguard:read", binding.NodeID) {
			continue
		}
		covered[binding.NodeID] = true
		views = append(views, s.storedNodeGuardView(binding))
	}
	for _, inputs := range s.store.AllNFTInputs() {
		if covered[inputs.NodeID] {
			continue
		}
		if !rbac.Allows(p.Principal, "netguard:read", inputs.NodeID) {
			continue
		}
		converted := netguard.LegacyBaseline(inputs)
		views = append(views, nodeGuardView{
			NodeID:   inputs.NodeID,
			NodeName: s.nodeName(inputs.NodeID),
			Source:   netGuardSourceLegacy,
			Binding:  converted.Binding,
			Groups: []securityGroupView{{
				SecurityGroup: converted.Group,
				Source:        netGuardSourceLegacy,
				NodeID:        inputs.NodeID,
			}},
			Zones: converted.Zones,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": views})
}

func (s *Server) handleNetGuardReview(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "node_id is required"))
		return
	}
	if !rbac.Allows(p.Principal, "netguard:read", nodeID) {
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "not found"))
		return
	}
	input, snapshot, resolver, err := s.compileInputSnapshotFor(p, nodeID)
	if err != nil {
		if errors.Is(err, store.ErrNetGuardCompileNodeNotFound) {
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "not found"))
			return
		}
		writeError(w, http.StatusConflict, apiError(model.APIErrorBadRequest, err.Error()))
		return
	}
	reality := s.guardRealityDetailForNode(nodeID, s.now().UTC())
	suggestions := make([]netguard.Suggestion, 0)
	if reality.Reality != nil {
		suggestions, err = netguard.Suggest(netguard.SuggestInput{
			Binding: input.Binding,
			Groups:  input.Groups,
			Zones:   input.Zones,
			Reality: *reality.Reality,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	review := netGuardReview{
		Node:        netGuardViewFromCompileInput(input, snapshot.Node.Name),
		Reality:     reality,
		Suggestions: suggestions,
		DriftState:  netGuardDriftState(input.Binding, reality.Reality),
		ReplanInput: netGuardReplanInput{NodeID: nodeID},
		Findings:    make([]netguard.Finding, 0),
	}
	if !snapshot.HasBinding {
		review.Node.Source = netGuardSourceUnbound
	}
	ruleset, findings, compileErr := s.netGuardPreview(input, reality.Reality)
	// Checked before compileErr: a denied remote makes the compiler fail with a
	// message that names the node, which is what the refusal exists to withhold.
	if refused := resolver.Refused(); refused != nil {
		writeError(w, http.StatusForbidden, refused)
		return
	}
	if compileErr != nil {
		review.CompileError = compileErr.Error()
	} else {
		review.Ruleset = ruleset
		review.Findings = findings
	}
	writeJSON(w, http.StatusOK, netGuardReviewResponse{Review: review})
}

func netGuardViewFromCompileInput(input netguard.CompileInput, nodeName string) nodeGuardView {
	groups := make([]securityGroupView, 0, len(input.Groups))
	for _, group := range input.Groups {
		groups = append(groups, securityGroupView{SecurityGroup: group, Source: netGuardSourceStored})
	}
	zoneIDs := map[string]bool{
		model.GuardZonePublic:    true,
		model.GuardZoneWireGuard: true,
	}
	for _, zoneID := range input.Binding.ZoneIDs {
		zoneIDs[zoneID] = true
	}
	collectRuleZoneIDs := func(rules []model.GuardRule) {
		for _, rule := range rules {
			if rule.Remote.Kind == model.NetRefZone && rule.Remote.ZoneID != "" {
				zoneIDs[rule.Remote.ZoneID] = true
			}
		}
	}
	collectRuleZoneIDs(input.Binding.Overrides)
	for _, group := range input.Groups {
		collectRuleZoneIDs(group.Rules)
	}
	orderedZoneIDs := make([]string, 0, len(zoneIDs))
	for zoneID := range zoneIDs {
		orderedZoneIDs = append(orderedZoneIDs, zoneID)
	}
	sort.Strings(orderedZoneIDs)
	zones := make([]model.GuardZone, 0, len(orderedZoneIDs))
	for _, zoneID := range orderedZoneIDs {
		if zone, ok := input.Zones[zoneID]; ok {
			zones = append(zones, zone)
		}
	}
	return nodeGuardView{
		NodeID:   input.Binding.NodeID,
		NodeName: nodeName,
		Binding:  input.Binding,
		Source:   netGuardSourceStored,
		Groups:   groups,
		Zones:    zones,
	}
}

// netGuardPreview renders the ruleset this intent compiles to and lints it,
// without creating an approval or touching any node. It is the read-side twin
// of the first half of handleNetGuardPlan, and the two must stay identical: a
// preview that lints differently from the plan is worse than no preview.
func (s *Server) netGuardPreview(input netguard.CompileInput, reality *model.GuardNodeReality) (string, []netguard.Finding, error) {
	compiled, err := netguard.Compile(input)
	if err != nil {
		return "", nil, err
	}
	ruleset, err := network.GenerateNFTPlan(compiled)
	if err != nil {
		return "", nil, err
	}
	findings := netguard.Lint(compiled, netguard.LintOptions{
		PublicURLConfigured: s.publicURL != "",
		Reality:             reality,
	})
	if findings == nil {
		findings = make([]netguard.Finding, 0)
	}
	return ruleset, findings, nil
}

func netGuardDriftState(binding model.NodeGuardBinding, reality *model.GuardNodeReality) string {
	if reality == nil || strings.TrimSpace(binding.AppliedTableSHA) == "" || strings.TrimSpace(reality.ManagedSHA) == "" {
		return netGuardDriftUnknown
	}
	if strings.EqualFold(binding.AppliedTableSHA, reality.ManagedSHA) {
		return netGuardDriftInSync
	}
	return netGuardDriftDetected
}

func (s *Server) storedNodeGuardView(binding model.NodeGuardBinding) nodeGuardView {
	groups := make([]securityGroupView, 0, len(binding.GroupIDs))
	for _, groupID := range binding.GroupIDs {
		if group, ok := s.store.SecurityGroup(groupID); ok {
			groups = append(groups, securityGroupView{SecurityGroup: group, Source: netGuardSourceStored})
		}
	}
	zones := make([]model.GuardZone, 0, len(binding.ZoneIDs))
	for _, zoneID := range binding.ZoneIDs {
		if zone, ok := s.store.GuardZone(zoneID); ok {
			zones = append(zones, zone)
		}
	}
	return nodeGuardView{
		NodeID:   binding.NodeID,
		NodeName: s.nodeName(binding.NodeID),
		Source:   netGuardSourceStored,
		Binding:  binding,
		Groups:   groups,
		Zones:    zones,
	}
}

func (s *Server) nodeName(nodeID string) string {
	if node, ok := s.store.Node(nodeID); ok {
		return node.Name
	}
	return ""
}

func (s *Server) requireGlobalNetGuardScope(w http.ResponseWriter, p principal, scope string) bool {
	if !s.requireScope(w, p, scope) {
		return false
	}
	if !principalHasNodeRestriction(p) {
		return true
	}
	s.recordAudit(model.AuditEvent{
		ID:            id.New("audit"),
		ActorID:       p.ActorID,
		TokenID:       p.TokenID,
		Action:        "authorize.scope",
		Scope:         scope,
		Decision:      "deny",
		Reason:        "global netguard objects require an unrestricted server allowlist",
		CorrelationID: p.CorrelationID,
	})
	writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
	return false
}

// resolveNodeZones builds the zone map used to compile one node. Zones are
// fleet-scoped by name but resolve per-node facts: the "public" zone means
// *this* node's public interface, the "wireguard" zone means *this* node's
// mesh CIDR. Operator-authored zones (e.g. a tailscale zone pinning
// tailscale0) are used verbatim.
func (s *Server) resolveNodeZones(nodeID string) map[string]model.GuardZone {
	inputs, hasInputs := s.store.NFTInputs(nodeID)
	return resolveNodeZonesFrom(s.store.GuardZones(), inputs, hasInputs)
}

func resolveNodeZonesFrom(guardZones []model.GuardZone, inputs model.NFTInputs, hasInputs bool) map[string]model.GuardZone {
	zones := netguard.ZoneMap(guardZones)
	if zones == nil {
		zones = map[string]model.GuardZone{}
	}

	public := zones[model.GuardZonePublic]
	public.ID, public.Name, public.Builtin = model.GuardZonePublic, "public", true
	if len(public.Interfaces) == 0 {
		iface := "eth0"
		if hasInputs && inputs.InterfaceName != "" {
			iface = inputs.InterfaceName
		}
		public.Interfaces = []string{iface}
	}
	zones[model.GuardZonePublic] = public

	wg := zones[model.GuardZoneWireGuard]
	wg.ID, wg.Name, wg.Builtin = model.GuardZoneWireGuard, "wireguard", true
	if len(wg.CIDRs) == 0 {
		cidr := "10.66.0.0/24"
		if hasInputs && inputs.WireGuardCIDR != "" {
			cidr = inputs.WireGuardCIDR
		}
		wg.CIDRs = []string{cidr}
	}
	zones[model.GuardZoneWireGuard] = wg

	if _, ok := zones[model.GuardZoneLoopback]; !ok {
		zones[model.GuardZoneLoopback] = model.GuardZone{
			ID: model.GuardZoneLoopback, Name: "loopback", Builtin: true, Interfaces: []string{"lo"},
		}
	}
	return zones
}

func (s *Server) compileInputFor(p principal, nodeID string) (netguard.CompileInput, *scopedNodeResolver, error) {
	input, _, resolver, err := s.compileInputSnapshotFor(p, nodeID)
	return input, resolver, err
}

// compileInputSnapshotFor builds the netguard compile input for one node and
// returns the resolver alongside it, so the caller can refuse before it looks
// at the compiler's error.
//
// The snapshot's Nodes map holds every node in the fleet, so resolving straight
// out of it was the unscoped lookup in another coat. That mattered: a per-node
// override rule on a binding may name any node as its remote, and the compiler
// turns that into the remote's WireGuard IP /32 and public IP /32 inside the
// ruleset that /api/netguard/review and /api/netguard/plan return. An operator
// with netguard:admin on one node could write such an override and read another
// node's addresses straight back out.
//
// Refused rather than filtered: a firewall ruleset silently missing the rules
// whose remotes the caller cannot read is a wrong firewall, not a shorter one,
// and here it would silently drop a deny rule.
func (s *Server) compileInputSnapshotFor(p principal, nodeID string) (netguard.CompileInput, store.NetGuardCompileSnapshot, *scopedNodeResolver, error) {
	snapshot, err := s.store.NetGuardCompileSnapshot(nodeID)
	if err != nil {
		return netguard.CompileInput{}, store.NetGuardCompileSnapshot{}, nil, err
	}
	nodes := snapshot.Nodes
	resolver := s.nodeResolverOver(func(id string) (model.Node, bool) {
		node, ok := nodes[id]
		return node, ok
	}, p, "netguard:read", "compiling this node's guard", nodeID)
	return netguard.CompileInput{
		Binding: snapshot.Binding,
		Groups:  snapshot.Groups,
		Zones:   resolveNodeZonesFrom(snapshot.GuardZones, snapshot.NFTInputs, snapshot.HasNFTInput),
		Resolve: resolver.Resolve,
	}, snapshot, resolver, nil
}

// compileInputForSystem is compileInputFor without a principal, for the
// approve-time freshness recompute whose only output is a hash compared in
// memory. See currentGroupDerivedPolicyPlanSHA for the same reasoning.
func (s *Server) compileInputForSystem(nodeID string) (netguard.CompileInput, error) {
	snapshot, err := s.store.NetGuardCompileSnapshot(nodeID)
	if err != nil {
		return netguard.CompileInput{}, err
	}
	nodes := snapshot.Nodes
	resolver := s.systemNodeResolverOver(func(id string) (model.Node, bool) {
		node, ok := nodes[id]
		return node, ok
	}, "freshness hash only; never returned to the caller")
	return netguard.CompileInput{
		Binding: snapshot.Binding,
		Groups:  snapshot.Groups,
		Zones:   resolveNodeZonesFrom(snapshot.GuardZones, snapshot.NFTInputs, snapshot.HasNFTInput),
		Resolve: resolver.Resolve,
	}, nil
}

func (s *Server) handleUpsertSecurityGroup(w http.ResponseWriter, r *http.Request, p principal) {
	if !s.requireGlobalNetGuardScope(w, p, "netguard:admin") {
		return
	}
	var req model.SecurityGroup
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.ID == "" {
		req.ID = id.New("sg")
	}
	if !guardIDRe.MatchString(req.ID) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid security group id %q", req.ID))
		return
	}
	if strings.HasPrefix(req.ID, netguard.LegacyGroupPrefix) {
		if _, ok := s.store.SecurityGroup(req.ID); !ok {
			writeError(w, http.StatusBadRequest, errors.New("legacy group ids are reserved; adopt the node instead"))
			return
		}
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}
	// Validate rules by compiling them in isolation: an unrenderable rule must
	// never reach the store, so a later plan cannot fail on stored garbage.
	if err := s.validateGuardRules(p, req.Rules); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.store.UpsertSecurityGroup(req)
	if err != nil {
		if errors.Is(err, store.ErrGuardVersionConflict) {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "netguard.group.upsert", Scope: "netguard:admin",
		Metadata: map[string]string{"group_id": saved.ID},
	})
	writeJSON(w, http.StatusOK, securityGroupView{SecurityGroup: saved, Source: netGuardSourceStored})
}

// validateGuardRules compiles a candidate rule set against a permissive
// synthetic node so unsupported or malformed shapes are rejected at write
// time rather than at plan time.
//
// It takes the principal because a rule may name a remote node, and the
// compiler's rejection message names it back: "remote node %q not found"
// against "remote node %q has no resolvable address" against acceptance told a
// caller whether a guessed node id existed and whether it had an address. The
// node-binding path reaches this with only per-node netguard:admin, so that was
// a live existence oracle for a node-restricted operator. Under the scoped
// resolver an unreadable remote is indistinguishable from an absent one.
func (s *Server) validateGuardRules(p principal, rules []model.GuardRule) error {
	if len(rules) == 0 {
		return nil
	}
	zones := map[string]model.GuardZone{
		model.GuardZonePublic:    {ID: model.GuardZonePublic, Interfaces: []string{"eth0"}},
		model.GuardZoneWireGuard: {ID: model.GuardZoneWireGuard, CIDRs: []string{"10.66.0.0/24"}},
	}
	for _, zone := range s.store.GuardZones() {
		zones[zone.ID] = zone
	}
	resolver := s.nodeResolverFor(p, "netguard:read", "validating these rules")
	_, err := netguard.Compile(netguard.CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "validate", Managed: true},
		Groups:  []model.SecurityGroup{{ID: "validate", Rules: rules}},
		Zones:   zones,
		Resolve: resolver.Resolve,
	})
	// Checked before err: the compiler names the node it could not resolve.
	if refused := resolver.Refused(); refused != nil {
		return refused
	}
	return err
}

func (s *Server) handleDeleteSecurityGroup(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireGlobalNetGuardScope(w, p, "netguard:admin") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	// A group still attached to a node would leave that binding uncompilable.
	for _, binding := range s.store.NodeGuardBindings() {
		for _, groupID := range binding.GroupIDs {
			if groupID == req.ID {
				writeError(w, http.StatusConflict, fmt.Errorf("security group %q is still attached to node %q", req.ID, binding.NodeID))
				return
			}
		}
	}
	if err := s.store.DeleteSecurityGroup(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "netguard.group.delete", Scope: "netguard:admin",
		Metadata: map[string]string{"group_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUpsertGuardZone(w http.ResponseWriter, r *http.Request, p principal) {
	if !s.requireGlobalNetGuardScope(w, p, "netguard:admin") {
		return
	}
	var req model.GuardZone
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if !guardIDRe.MatchString(req.ID) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid zone id %q", req.ID))
		return
	}
	if req.ID == model.GuardZoneLoopback {
		writeError(w, http.StatusBadRequest, errors.New("the loopback zone is not editable"))
		return
	}
	if len(req.Interfaces) == 0 && len(req.CIDRs) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("a zone needs at least one interface or cidr"))
		return
	}
	// Canonicalize by rendering a throwaway trusted-zone accept: the same
	// interface-name and CIDR validation the compiler enforces.
	if _, err := netguard.Compile(netguard.CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "validate", Managed: true, ZoneIDs: []string{req.ID}},
		Zones:   map[string]model.GuardZone{req.ID: req},
		// No rules, so no remote is ever resolved; the compiler only requires a
		// non-nil resolver. Scoped anyway so the guard test has nothing to
		// carve an exception for.
		Resolve: s.nodeResolverFor(p, "netguard:read", "validating this zone").Resolve,
	}); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Builtin = false
	if err := s.store.UpsertGuardZone(req); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "netguard.zone.upsert", Scope: "netguard:admin",
		Metadata: map[string]string{"zone_id": req.ID},
	})
	stored, _ := s.store.GuardZone(req.ID)
	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) handleDeleteGuardZone(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireGlobalNetGuardScope(w, p, "netguard:admin") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	for _, binding := range s.store.NodeGuardBindings() {
		for _, zoneID := range binding.ZoneIDs {
			if zoneID == req.ID {
				writeError(w, http.StatusConflict, fmt.Errorf("zone %q is still trusted by node %q", req.ID, binding.NodeID))
				return
			}
		}
	}
	if err := s.store.DeleteGuardZone(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "netguard.zone.delete", Scope: "netguard:admin",
		Metadata: map[string]string{"zone_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleNetGuardBindings(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req model.NodeGuardBinding
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	// Scope first, then existence. The other order answered "does node X
	// exist" with a 404-against-403 difference before any check ran, which is
	// the same oracle the plan endpoints were closed against.
	if !s.requireNodeScope(w, p, "netguard:admin", req.NodeID) {
		return
	}
	if _, ok := s.store.Node(req.NodeID); !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	for _, groupID := range req.GroupIDs {
		if _, ok := s.store.SecurityGroup(groupID); !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("security group %q not found", groupID))
			return
		}
	}
	if err := s.validateGuardRules(p, req.Overrides); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req = s.serverAuthoritativeGuardBinding(req)
	saved, err := s.store.UpsertNodeGuardBinding(req)
	if err != nil {
		if errors.Is(err, store.ErrGuardVersionConflict) {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "netguard.binding.upsert", Scope: "netguard:admin",
		Metadata: map[string]string{"node_id": req.NodeID},
	})
	writeJSON(w, http.StatusOK, s.storedNodeGuardView(saved))
}

// handleDeleteNodeGuardBinding is the undo for an observe-only binding
// written by mistake; until it existed such a record could only be parked at
// managed=false. A managed binding is refused with 409: managed means the
// guard table this binding compiled may be live on the node, and dropping the
// record would leave that table with no owner. The operator unmanages first
// (a binding upsert with managed=false, which touches nothing on the node: the
// applied table stays until a new plan replaces it), and only then can the
// record go. Deleting a binding likewise changes nothing on the node.
func (s *Server) handleDeleteNodeGuardBinding(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	// Scope before existence, as in the binding upsert: a 404-against-403
	// difference must not tell a restricted token which nodes have bindings.
	if !s.requireNodeScope(w, p, "netguard:admin", req.NodeID) {
		return
	}
	binding, ok := s.store.NodeGuardBinding(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node has no guard binding"))
		return
	}
	if binding.Managed {
		writeError(w, http.StatusConflict, errors.New("guard binding is managed; set managed=false before deleting it"))
		return
	}
	deleted, ok, err := s.store.DeleteNodeGuardBinding(req.NodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node has no guard binding"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "netguard.binding.delete", Scope: "netguard:admin",
		Metadata: map[string]string{"node_id": req.NodeID},
	})
	writeJSON(w, http.StatusOK, deleted)
}

func (s *Server) serverAuthoritativeGuardBinding(req model.NodeGuardBinding) model.NodeGuardBinding {
	existing, ok := s.store.NodeGuardBinding(req.NodeID)
	if !ok {
		req.LastPlanSHA = ""
		req.LastAppliedAt = time.Time{}
		req.LastError = ""
		req.AppliedTableSHA = ""
		return req
	}
	intentChanged := !guardBindingIntentEqual(existing, req)
	req.LastPlanSHA = existing.LastPlanSHA
	req.LastAppliedAt = existing.LastAppliedAt
	req.LastError = existing.LastError
	req.AppliedTableSHA = existing.AppliedTableSHA
	if intentChanged {
		req.LastPlanSHA = ""
		req.LastError = "binding changed since the last plan; create a new plan before applying"
	}
	return req
}

func guardBindingIntentEqual(a, b model.NodeGuardBinding) bool {
	if a.Managed != b.Managed || !slices.Equal(a.GroupIDs, b.GroupIDs) || !slices.Equal(a.ZoneIDs, b.ZoneIDs) || len(a.Overrides) != len(b.Overrides) {
		return false
	}
	for i := range a.Overrides {
		if !reflect.DeepEqual(a.Overrides[i], b.Overrides[i]) {
			return false
		}
	}
	return true
}

// handleNetGuardAdopt materializes a node's converted legacy baseline into
// stored records and marks it managed. Until a node is adopted its converted
// view stays observe-only and cannot be planned.
func (s *Server) handleNetGuardAdopt(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "netguard:admin", req.NodeID) {
		return
	}
	if _, ok := s.store.NodeGuardBinding(req.NodeID); ok {
		writeError(w, http.StatusConflict, errors.New("node is already adopted"))
		return
	}
	inputs, ok := s.store.NFTInputs(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node has no legacy baseline to adopt"))
		return
	}
	view := netguard.LegacyBaseline(inputs)
	group := view.Group
	group.Version = 0
	saved, err := s.store.UpsertSecurityGroup(group)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	binding := view.Binding
	binding.Version = 0
	binding.Managed = true
	binding.GroupIDs = []string{saved.ID}
	storedBinding, err := s.store.UpsertNodeGuardBinding(binding)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "netguard.node.adopt", Scope: "netguard:admin",
		Metadata: map[string]string{"node_id": req.NodeID, "group_id": saved.ID},
	})
	writeJSON(w, http.StatusOK, s.storedNodeGuardView(storedBinding))
}

// handleNetGuardPlan compiles a node's guard model, lints it, and records a
// pending approval. The plan text is the same `table inet lattice_guard`
// ruleset the legacy Network Guard path produces, so it rides the existing
// `nft` apply script — validate, snapshot, dead-man watchdog, commit,
// control-plane selfcheck — with no new apply branch.
func (s *Server) handleNetGuardPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID            string `json:"node_id"`
		AcceptLockoutRisk bool   `json:"accept_lockout_risk"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "netguard:admin", req.NodeID) {
		return
	}
	if !s.requireNodeScope(w, p, "network:plan", req.NodeID) {
		return
	}
	input, resolver, err := s.compileInputFor(p, req.NodeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	compiled, err := netguard.Compile(input)
	if s.writeRefusal(w, p, resolver) {
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// The lockout lint is the only thing standing between a default-drop plan
	// and a permanently unreachable node, so it gets the node's reported reality
	// rather than the tcp/22 assumption whenever one exists.
	findings := netguard.Lint(compiled, netguard.LintOptions{
		PublicURLConfigured: s.publicURL != "",
		Reality:             s.guardRealityForLint(req.NodeID),
	})
	if netguard.Blocking(findings) && !req.AcceptLockoutRisk {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":    "plan blocked by lint findings",
			"findings": findings,
		})
		return
	}
	ruleset, err := network.GenerateNFTPlan(compiled)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    req.NodeID,
		Plugin:    "nft",
		Action:    netGuardApprovalAction,
		Plan:      ruleset,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	binding := input.Binding
	binding.LastPlanSHA = approvalPlanSHA(approval)
	binding.LastError = ""
	if _, err := s.store.UpsertNodeGuardBinding(binding); err != nil {
		if errors.Is(err, store.ErrGuardVersionConflict) {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	approval, err = s.submitApproval(r.Context(), approval)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	metadata := map[string]string{"approval_id": approval.ID, "source": "netguard"}
	if netguard.Blocking(findings) {
		metadata["lockout_risk_accepted"] = "true"
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), NodeID: req.NodeID, Action: "netguard.lockout_risk.accepted", Scope: "netguard:admin",
			Metadata: map[string]string{"node_id": req.NodeID, "approval_id": approval.ID},
		})
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "netguard.plan", Scope: "network:plan", Metadata: metadata,
	})
	writeJSON(w, http.StatusOK, map[string]any{"approval": approval, "findings": findings})
}

func (s *Server) requireCurrentNetGuardApproval(approval model.Approval) error {
	if !isNetGuardApproval(approval) {
		return nil
	}
	binding, ok := s.store.NodeGuardBinding(approval.NodeID)
	if !ok {
		return fmt.Errorf("netguard binding %q not found; re-plan before approving", approval.NodeID)
	}
	planSHA := approvalPlanSHA(approval)
	if binding.LastPlanSHA == "" || !strings.EqualFold(binding.LastPlanSHA, planSHA) {
		return errors.New("netguard binding changed since this plan was created; re-plan before approving")
	}
	currentSHA, err := s.currentNetGuardPlanSHA(approval.NodeID)
	if err != nil {
		return fmt.Errorf("current netguard intent cannot be compiled: %w", err)
	}
	if !strings.EqualFold(currentSHA, planSHA) {
		return errors.New("netguard binding dependencies changed since this plan was created; re-plan before approving")
	}
	return nil
}

func isNetGuardApproval(approval model.Approval) bool {
	return approval.Plugin == "nft" && approval.Action == netGuardApprovalAction
}

func (s *Server) currentNetGuardPlanSHA(nodeID string) (string, error) {
	input, err := s.compileInputForSystem(nodeID)
	if err != nil {
		return "", err
	}
	compiled, err := netguard.Compile(input)
	if err != nil {
		return "", err
	}
	ruleset, err := network.GenerateNFTPlan(compiled)
	if err != nil {
		return "", err
	}
	return approvalPlanSHA(model.Approval{Plan: ruleset}), nil
}

func (s *Server) handleNetGuardTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	const maxTransitionAttempts = 4
	for attempt := 0; attempt < maxTransitionAttempts; attempt++ {
		currentApproval, ok := s.store.Approval(approval.ID)
		if !ok || !isNetGuardApproval(currentApproval) {
			return store.ErrTaskNotFound
		}
		binding, ok := s.store.NodeGuardBinding(currentApproval.NodeID)
		if !ok {
			return store.ErrGuardVersionConflict
		}
		planSHA := approvalPlanSHA(currentApproval)
		metadata := map[string]string{
			"approval_id": currentApproval.ID,
			"task_id":     task.ID,
			"plan_sha":    planSHA,
		}

		reason := ""
		if binding.LastPlanSHA == "" || !strings.EqualFold(binding.LastPlanSHA, planSHA) {
			if strings.Contains(binding.LastError, "dependency changed") {
				reason = "task result belongs to a stale netguard plan after a binding dependency changed; re-plan before applying"
			} else {
				reason = "task result belongs to a stale netguard plan; re-plan before applying the current binding"
			}
		} else if currentSHA, err := s.currentNetGuardPlanSHA(currentApproval.NodeID); err != nil {
			reason = "task result belongs to stale netguard intent that no longer compiles: " + err.Error()
		} else if !strings.EqualFold(currentSHA, planSHA) {
			reason = "task result belongs to a stale netguard plan after a binding dependency changed; re-plan before applying"
		} else if result.Error != "" || result.ExitCode != 0 {
			reason = taskFailureSummary(result)
		}

		managedSHA := ""
		if reason == "" {
			var err error
			managedSHA, err = netGuardManagedSHAFromTaskResult(result.Stdout)
			if err != nil {
				reason = err.Error()
			}
		}
		if result.FinishedAt.IsZero() {
			result.FinishedAt = time.Now().UTC()
		}
		if reason == "" {
			binding.LastAppliedAt = result.FinishedAt
			binding.LastError = ""
			binding.AppliedTableSHA = managedSHA
			currentApproval.Status = model.ApprovalApplied
			currentApproval.Reason = ""
			metadata["managed_sha"] = managedSHA
		} else {
			reason = strings.TrimSpace(reason)
			if reason == "" {
				reason = "netguard apply failed"
			}
			binding.LastError = reason
			currentApproval.Status = model.ApprovalRejected
			currentApproval.Reason = truncateMetadataValue(reason, 240)
		}

		committed, err := s.store.CompleteNetGuardTaskResult(result, currentApproval, binding)
		if committed {
			if err != nil {
				s.logger.Printf("netguard task result committed with degraded durability: %v", err)
				// The exact transition is visible for idempotent retry, but the agent
				// must retain its result journal until a later request confirms the
				// state-file directory entry and receives HTTP 200.
				return err
			}
			action, decision := "netguard.apply.applied", "allow"
			if reason != "" {
				action, decision = "netguard.apply.failed", "deny"
			}
			s.recordRequestAudit(r, model.AuditEvent{
				ID: id.New("audit"), NodeID: currentApproval.NodeID, Action: action,
				Decision: decision, Reason: reason, Metadata: metadata,
			})
			return nil
		}
		if errors.Is(err, store.ErrGuardVersionConflict) {
			continue
		}
		return err
	}
	return fmt.Errorf("netguard binding changed repeatedly while recording task result: %w", store.ErrGuardVersionConflict)
}

func netGuardManagedSHAFromTaskResult(stdout string) (string, error) {
	managedSHA := ""
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, netGuardManagedSHAResultPrefix) {
			continue
		}
		candidate := strings.TrimSpace(strings.TrimPrefix(line, netGuardManagedSHAResultPrefix))
		if managedSHA != "" {
			return "", errors.New("successful netguard task returned multiple canonical managed-table hashes")
		}
		managedSHA = candidate
	}
	if managedSHA == "" {
		return "", errors.New("successful netguard task did not return the canonical managed-table hash")
	}
	if !isLowerHex64(managedSHA) {
		return "", errors.New("successful netguard task returned an invalid canonical managed-table hash")
	}
	return managedSHA, nil
}
