package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
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
	zones := netguard.ZoneMap(s.store.GuardZones())
	if zones == nil {
		zones = map[string]model.GuardZone{}
	}
	inputs, hasInputs := s.store.NFTInputs(nodeID)

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

func (s *Server) compileInputFor(nodeID string) (netguard.CompileInput, error) {
	binding, ok := s.store.NodeGuardBinding(nodeID)
	if !ok {
		return netguard.CompileInput{}, fmt.Errorf("node %q has no guard binding; adopt it first", nodeID)
	}
	groups := make([]model.SecurityGroup, 0, len(binding.GroupIDs))
	for _, groupID := range binding.GroupIDs {
		group, ok := s.store.SecurityGroup(groupID)
		if !ok {
			return netguard.CompileInput{}, fmt.Errorf("security group %q not found", groupID)
		}
		groups = append(groups, group)
	}
	return netguard.CompileInput{
		Binding: binding,
		Groups:  groups,
		Zones:   s.resolveNodeZones(nodeID),
		Resolve: s.resolveNode,
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
	if err := s.validateGuardRules(req.Rules); err != nil {
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
func (s *Server) validateGuardRules(rules []model.GuardRule) error {
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
	_, err := netguard.Compile(netguard.CompileInput{
		Binding: model.NodeGuardBinding{NodeID: "validate", Managed: true},
		Groups:  []model.SecurityGroup{{ID: "validate", Rules: rules}},
		Zones:   zones,
		Resolve: s.resolveNode,
	})
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
		Resolve: s.resolveNode,
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
	if _, ok := s.store.Node(req.NodeID); !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if !s.requireNodeScope(w, p, "netguard:admin", req.NodeID) {
		return
	}
	for _, groupID := range req.GroupIDs {
		if _, ok := s.store.SecurityGroup(groupID); !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("security group %q not found", groupID))
			return
		}
	}
	if err := s.validateGuardRules(req.Overrides); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
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
	input, err := s.compileInputFor(req.NodeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	compiled, err := netguard.Compile(input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	findings := netguard.Lint(compiled, netguard.LintOptions{PublicURLConfigured: s.publicURL != ""})
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
		Action:    "apply-ruleset",
		Plan:      ruleset,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
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
