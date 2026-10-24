package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/netpolicy"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/selfdns"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/wireguard"
)

// Design 32 D4: the node's effective network. One read answers "what applies
// to this node": the inbound firewall and what feeds it, every outbound
// policy that reaches the node in the order expansion merges them, SSH Guard,
// the mesh facts the server holds, and the node groups. For each nftables
// table Lattice writes it names every owner, the last writer from the last
// applied approval, and two rulesets: what would compile now and what was
// last applied.
//
// It uses only the side-effect-free layer. The plan handlers store the
// expanded policy and the NetGuard plan SHA before they submit an approval,
// so composing through them would write on every read. Everything here is
// netGuardPreview, ExpandGroupPolicies, NormalizePolicy, CompileEgressPlan
// and the legacy and self-host DNS composers, none of which touches the
// store.
//
// Scope is refused, not filtered. The node itself needs node:read. Each
// section needs the scope that reads its own data elsewhere and is refused
// whole, naming that scope, when the caller lacks it. A ruleset whose
// compile needs a remote node the caller cannot read is refused, never shown
// without the rules it would lose.

const (
	nodeNetworkOK      = "ok"
	nodeNetworkRefused = "refused"
	// A ruleset column that has nothing to show: no composer writes the
	// table now, or no approval ever applied it.
	nodeNetworkNone  = "none"
	nodeNetworkError = "error"

	nodeNetworkGuardTable  = "inet lattice_guard"
	nodeNetworkPolicyTable = "inet lattice_policy"
	nodeNetworkKnockTable  = "inet lattice_knock"

	// Who writes or feeds a table.
	ownerNetGuard       = "netguard"
	ownerBeacon         = "beacon"
	ownerSelfDNS        = "selfdns"
	ownerLegacyFirewall = "legacy_firewall"
	ownerOutboundPolicy = "outbound_policy"
	ownerManualPolicy   = "manual_policy"
	ownerSSHGuard       = "sshguard"

	// What an owner does to the table on this node.
	ownerWrites      = "writes"
	ownerContributes = "contributes"
	ownerObserves    = "observes"
	ownerRefused     = "refused"
	ownerIdle        = "idle"
	ownerOrphan      = "orphan"
)

// nodeNetworkSection says whether the caller may read a section. A refused
// section carries nothing else.
type nodeNetworkSection struct {
	State string `json:"state"`
	// Scope is the scope the caller lacks on this node.
	Scope  string `json:"scope,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func sectionOK() nodeNetworkSection { return nodeNetworkSection{State: nodeNetworkOK} }

func sectionRefused(scope string) nodeNetworkSection {
	return nodeNetworkSection{State: nodeNetworkRefused, Scope: scope, Reason: "reading this needs " + scope + " on this node"}
}

type nodeNetworkRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type nodeNetworkSecurityGroup struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Rules int    `json:"rules"`
	// Via names the node group a derived binding comes through (S4).
	Via *nodeNetworkRef `json:"via,omitempty"`
}

// nodeNetworkPort is a port another feature opens in lattice_guard.
type nodeNetworkPort struct {
	Source string `json:"source"` // selfdns | beacon
	// Label names the deployment for a reader who may read it.
	Label     string   `json:"label,omitempty"`
	Protocols []string `json:"protocols"`
	Port      int      `json:"port"`
	Exposure  string   `json:"exposure,omitempty"`
	// Sources counts the beacon sources the applied plan admits.
	Sources int `json:"sources,omitempty"`
}

// nodeNetworkLegacyIngress is the ingress rules a manual outbound policy
// still holds (design 32 D3). The policy's own plan never applies them; the
// legacy firewall route folds them into lattice_guard on a node NetGuard does
// not manage.
type nodeNetworkLegacyIngress struct {
	Rules int `json:"rules"`
	// State is applies_legacy or ignored_netguard.
	State string `json:"state"`
}

type nodeNetworkInbound struct {
	nodeNetworkSection
	// Firewall names who writes lattice_guard here now: netguard on a node
	// NetGuard manages, legacy where it does not, none when nothing does.
	Firewall string `json:"firewall,omitempty"`
	// Binding is managed, observe (the observe-only record) or none.
	Binding        string                     `json:"binding,omitempty"`
	BindingVersion int64                      `json:"binding_version,omitempty"`
	Zones          []nodeNetworkRef           `json:"zones"`
	SecurityGroups []nodeNetworkSecurityGroup `json:"security_groups"`
	// DerivedSecurityGroups is the place for security groups bound to a
	// node group the node belongs to. Empty until S4 stores such bindings.
	DerivedSecurityGroups []nodeNetworkSecurityGroup `json:"derived_security_groups"`
	ExtraPorts            []nodeNetworkPort          `json:"extra_ports"`
	LegacyIngress         *nodeNetworkLegacyIngress  `json:"legacy_ingress,omitempty"`
	DriftState            string                     `json:"drift_state,omitempty"`
}

// nodeNetworkPolicy is one outbound policy whose target names the node.
type nodeNetworkPolicy struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Label    string `json:"label"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
	// Reach says how the target names the node: named, group, fleet. A
	// policy that names the node and excludes it reads excluded.
	Reach     string           `json:"reach"`
	ViaGroups []nodeNetworkRef `json:"via_groups,omitempty"`
	// State is applies, disabled, excluded, blocked (a manual policy owns
	// the node) or empty (no rule of it reaches this node).
	State string `json:"state"`
	// Rules counts what the policy contributes to this node after
	// expansion; a group remote counts once per member.
	Rules             int `json:"rules"`
	Allow             int `json:"allow"`
	Deny              int `json:"deny"`
	HiddenTargetNodes int `json:"hidden_target_nodes,omitempty"`
}

type nodeNetworkNodePolicy struct {
	Enabled       bool      `json:"enabled"`
	Rules         int       `json:"rules"`
	LastAppliedAt time.Time `json:"last_applied_at,omitzero"`
}

type nodeNetworkOutbound struct {
	nodeNetworkSection
	// Source is what writes lattice_policy here: policies (expanded from
	// outbound policies), manual (a node document of its own), orphan (a
	// group-derived document no policy reaches any more) or none.
	Source      string              `json:"source,omitempty"`
	DefaultDrop bool                `json:"default_drop"`
	Policies    []nodeNetworkPolicy `json:"policies"`
	// Manual is the node's own document, which blocks every policy.
	Manual *nodeNetworkNodePolicy `json:"manual,omitempty"`
	// Orphan is the group-derived document still on the node after it left
	// every policy's target (server_group_policy.go reports these and
	// leaves them for explicit cleanup).
	Orphan *nodeNetworkNodePolicy `json:"orphan,omitempty"`
}

type nodeNetworkAccess struct {
	nodeNetworkSection
	Enrolled bool   `json:"enrolled"`
	Posture  string `json:"posture,omitempty"`
	// KnockRequired is true while the node's report lists the knock table:
	// SSH answers only after a knock. The sequence and its ports are never
	// part of this view.
	KnockRequired  bool   `json:"knock_required"`
	Stage          string `json:"stage,omitempty"`
	StageIsHistory bool   `json:"stage_is_history"`
	RevertArmed    bool   `json:"revert_armed"`
}

type nodeNetworkApplied struct {
	ApprovalID string    `json:"approval_id,omitempty"`
	AppliedAt  time.Time `json:"applied_at"`
}

type nodeNetworkMesh struct {
	nodeNetworkSection
	Address    string `json:"address,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	PublicKey  bool   `json:"public_key"`
	Ready      bool   `json:"ready"`
	// Missing names what keeps the node out of the mesh: address,
	// public_key.
	Missing []string `json:"missing"`
	// Peers is how many peers a WireGuard plan for this node renders now.
	Peers       int                 `json:"peers"`
	LastApplied *nodeNetworkApplied `json:"last_applied,omitempty"`
	// NotReported names what only the node knows and no agent reports to
	// the server, so this view cannot show it.
	NotReported []string `json:"not_reported"`
}

type nodeNetworkGroup struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Slug  string `json:"slug,omitempty"`
	Color string `json:"color,omitempty"`
}

type nodeNetworkGroups struct {
	nodeNetworkSection
	Items []nodeNetworkGroup `json:"items"`
}

type nodeNetworkOwner struct {
	Kind  string `json:"kind"`
	State string `json:"state"`
}

type nodeNetworkWriter struct {
	Kind string `json:"kind"`
	// ApprovalID is set when the caller may read that approval.
	ApprovalID string    `json:"approval_id,omitempty"`
	AppliedAt  time.Time `json:"applied_at"`
	// deploymentID is the self-host DNS deployment a selfdns writer names.
	deploymentID string
}

// nodeNetworkRuleset is one column of Show rules.
type nodeNetworkRuleset struct {
	State string `json:"state"`
	// Composer names what produced the ruleset: for compile_now the
	// composer that would write the table next, for last_applied the kind
	// of the last writer.
	Composer string `json:"composer,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	// Ruleset is the text, only when the request asks for rules.
	Ruleset string `json:"ruleset,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type nodeNetworkTable struct {
	nodeNetworkSection
	Table      string             `json:"table"`
	Owners     []nodeNetworkOwner `json:"owners"`
	LastWriter *nodeNetworkWriter `json:"last_writer,omitempty"`
	CompileNow nodeNetworkRuleset `json:"compile_now"`
	// LastApplied is the ruleset of the newest applied approval that wrote
	// the table.
	LastApplied nodeNetworkRuleset `json:"last_applied"`
	// ReplanPending is true when both rulesets exist and differ: the table
	// on the node is not what its writer would plan now.
	ReplanPending bool   `json:"replan_pending"`
	DriftState    string `json:"drift_state,omitempty"`
	// RulesWithheld says why this table never serves rules: knock, for the
	// SSH Guard table, whose rules are the knock sequence.
	RulesWithheld string `json:"rules_withheld,omitempty"`
}

type nodeNetworkView struct {
	NodeID      string              `json:"node_id"`
	NodeName    string              `json:"node_name,omitempty"`
	GeneratedAt time.Time           `json:"generated_at"`
	Inbound     nodeNetworkInbound  `json:"inbound"`
	Outbound    nodeNetworkOutbound `json:"outbound"`
	Access      nodeNetworkAccess   `json:"access"`
	Mesh        nodeNetworkMesh     `json:"mesh"`
	Groups      nodeNetworkGroups   `json:"groups"`
	Tables      []nodeNetworkTable  `json:"tables"`
}

// handleNodeNetwork answers GET /api/nodes/network?node_id=&rules=1.
func (s *Server) handleNodeNetwork(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, apiError(model.APIErrorBadRequest, "node_id is required"))
		return
	}
	// Scope first, so an id outside the caller's allowlist reads the same
	// whether or not a node has it.
	if !s.requireNodeScope(w, p, "node:read", nodeID) {
		return
	}
	node, ok := s.store.Node(nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "node not found"))
		return
	}
	withRules := r.URL.Query().Get("rules") == "1"
	writeJSON(w, http.StatusOK, s.nodeNetworkFor(p, node, withRules))
}

// nodeNetworkFor composes the view. It reads and never writes.
func (s *Server) nodeNetworkFor(p principal, node model.Node, withRules bool) nodeNetworkView {
	now := s.now().UTC()
	nodes := s.store.Nodes()
	groupList := s.store.Groups()
	resolved := groups.ResolveAll(groupList, nodes)
	view := nodeNetworkView{NodeID: node.ID, NodeName: node.Name, GeneratedAt: now}

	applied := s.store.NodeAppliedApprovals(node.ID, "nft", "selfdns", model.BeaconApprovalPlugin, "nftpolicy", sshGuardPlugin, "wireguard")
	reality := s.guardRealityForLint(node.ID)
	binding, hasBinding := s.store.NodeGuardBinding(node.ID)
	managed := hasBinding && binding.Managed

	view.Inbound = s.nodeNetworkInbound(p, node, binding, hasBinding, reality)
	outbound, policyCompile := s.nodeNetworkOutbound(p, node, nodes, groupList, resolved)
	view.Outbound = outbound
	view.Access = s.nodeNetworkAccess(p, node.ID, now)
	view.Mesh = s.nodeNetworkMesh(p, node, nodes, applied)
	view.Groups = nodeNetworkGroupsFor(p, node.ID, groupList, resolved)

	view.Tables = []nodeNetworkTable{
		s.nodeNetworkGuardTable(p, node, binding, hasBinding, managed, reality, applied, withRules),
		s.nodeNetworkPolicyTable(p, node.ID, view.Outbound, policyCompile, applied, withRules),
		s.nodeNetworkKnockTable(p, node.ID, view.Access, applied),
	}
	return view
}

func (s *Server) nodeNetworkInbound(p principal, node model.Node, binding model.NodeGuardBinding, hasBinding bool, reality *model.GuardNodeReality) nodeNetworkInbound {
	if !rbac.Allows(p.Principal, "netguard:read", node.ID) {
		return nodeNetworkInbound{nodeNetworkSection: sectionRefused("netguard:read")}
	}
	in := nodeNetworkInbound{
		nodeNetworkSection:    sectionOK(),
		Zones:                 []nodeNetworkRef{},
		SecurityGroups:        []nodeNetworkSecurityGroup{},
		DerivedSecurityGroups: []nodeNetworkSecurityGroup{},
		ExtraPorts:            []nodeNetworkPort{},
	}
	_, hasInputs := s.store.NFTInputs(node.ID)
	switch {
	case hasBinding && binding.Managed:
		in.Firewall, in.Binding = "netguard", "managed"
	case hasBinding:
		in.Binding = "observe"
	default:
		in.Binding = "none"
	}
	if in.Firewall == "" {
		in.Firewall = "none"
		if hasInputs {
			in.Firewall = "legacy"
		}
	}
	if hasBinding {
		in.BindingVersion = binding.Version
		for _, zoneID := range binding.ZoneIDs {
			ref := nodeNetworkRef{ID: zoneID}
			if zone, ok := s.store.GuardZone(zoneID); ok {
				ref.Name = zone.Name
			}
			in.Zones = append(in.Zones, ref)
		}
		// Binding order is compile order: one deny rule turns off the fast
		// path, so the position of a group changes behaviour.
		for _, groupID := range binding.GroupIDs {
			sg := nodeNetworkSecurityGroup{ID: groupID}
			if group, ok := s.store.SecurityGroup(groupID); ok {
				sg.Name, sg.Rules = group.Name, len(group.Rules)
			}
			in.SecurityGroups = append(in.SecurityGroups, sg)
		}
		in.DriftState = netGuardDriftState(binding, reality)
	}

	for _, dep := range s.store.DNSDeployments() {
		if dep.NodeID != node.ID || dep.Engine == model.DNSEngineExternal || dep.Disabled {
			continue
		}
		port := nodeNetworkPort{Source: ownerSelfDNS, Port: dep.ListenPort, Exposure: dep.Exposure, Protocols: []string{}}
		if dep.EnableUDP {
			port.Protocols = append(port.Protocols, network.NFTProtoUDP)
		}
		if dep.EnableTCP {
			port.Protocols = append(port.Protocols, network.NFTProtoTCP)
		}
		// The ports are firewall facts the ruleset already shows; the
		// deployment's name is read under dns:admin.
		if rbac.Allows(p.Principal, "dns:admin", node.ID) {
			port.Label = dep.Name
		}
		in.ExtraPorts = append(in.ExtraPorts, port)
	}
	if t, ok := s.store.BeaconTarget(node.ID); ok && t.Settings.Enabled && t.Settings.Port > 0 {
		in.ExtraPorts = append(in.ExtraPorts, nodeNetworkPort{
			Source:    ownerBeacon,
			Protocols: []string{network.NFTProtoUDP},
			Port:      t.Settings.Port,
			Exposure:  t.Exposure,
			Sources:   len(t.Approved),
		})
	}

	if policy, ok := s.store.NetPolicy(node.ID); ok && policy.Enabled && !policy.GroupDerived {
		ingress := 0
		for _, rule := range policy.Rules {
			if strings.EqualFold(rule.Direction, model.NetDirIngress) {
				ingress++
			}
		}
		if ingress > 0 {
			state := "applies_legacy"
			if hasBinding && binding.Managed {
				state = "ignored_netguard"
			}
			in.LegacyIngress = &nodeNetworkLegacyIngress{Rules: ingress, State: state}
		}
	}
	return in
}

// nodeNetworkPolicyCompile is what the outbound section learned that the
// policy table compiles: the per-node document that would be planned now.
type nodeNetworkPolicyCompile struct {
	policy model.NetPolicy
	ok     bool
}

func (s *Server) nodeNetworkOutbound(p principal, node model.Node, nodes []model.Node, groupList []model.Group, resolved map[string][]string) (nodeNetworkOutbound, nodeNetworkPolicyCompile) {
	if !rbac.Allows(p.Principal, "netpolicy:read", node.ID) {
		return nodeNetworkOutbound{nodeNetworkSection: sectionRefused("netpolicy:read")}, nodeNetworkPolicyCompile{}
	}
	out := nodeNetworkOutbound{nodeNetworkSection: sectionOK(), Policies: []nodeNetworkPolicy{}}
	policies := s.store.GroupPolicies()
	effective := netpolicy.ExpandGroupPolicies(policies, netpolicy.PolicyTargets(policies, nodes, groupList), resolved)
	eff, covered := effective[node.ID]

	stored, hasStored := s.store.NetPolicy(node.ID)
	// The clobber guard of handleGroupPolicyPlan, read the same way.
	manual := hasStored && !stored.GroupDerived && len(stored.Rules) > 0
	if manual {
		out.Manual = &nodeNetworkNodePolicy{Enabled: stored.Enabled, Rules: len(stored.Rules), LastAppliedAt: stored.LastAppliedAt}
	}
	if hasStored && stored.GroupDerived && !covered {
		out.Orphan = &nodeNetworkNodePolicy{Enabled: stored.Enabled, Rules: len(stored.Rules), LastAppliedAt: stored.LastAppliedAt}
	}

	groupNames, nodeNames := groupNamesOf(groupList), nodeNamesOf(nodes)
	sorted := append([]model.GroupNetPolicy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})
	for _, gp := range sorted {
		sel := gp.TargetScope()
		named := slices.Contains(sel.Nodes, node.ID)
		via := make([]nodeNetworkRef, 0)
		for _, groupID := range sel.Groups {
			if slices.Contains(resolved[groupID], node.ID) {
				via = append(via, nodeNetworkRef{ID: groupID, Name: groupNames[groupID]})
			}
		}
		if !named && len(via) == 0 && !sel.All {
			continue
		}
		entry := nodeNetworkPolicy{ID: gp.ID, Name: gp.Name, Priority: gp.Priority, Enabled: gp.Enabled, ViaGroups: via}
		switch {
		case named:
			entry.Reach = "named"
		case len(via) > 0:
			entry.Reach = "group"
		default:
			entry.Reach = "fleet"
		}
		target, hidden := viewerTarget(p, sel)
		entry.Label = outboundPolicyLabel(gp.Name, target, hidden, groupNames, nodeNames)
		entry.HiddenTargetNodes = hidden
		// Counted as expansion would merge it, whether or not it is on, so a
		// disabled policy says what turning it on would add.
		probe := gp
		probe.Enabled = true
		contributed := netpolicy.ExpandGroupPolicies([]model.GroupNetPolicy{probe}, map[string][]string{gp.ID: {node.ID}}, resolved)[node.ID]
		entry.Rules = len(contributed.Rules)
		for _, rule := range contributed.Rules {
			if strings.EqualFold(rule.Action, model.NetRuleDeny) {
				entry.Deny++
			} else {
				entry.Allow++
			}
		}
		switch {
		case slices.Contains(sel.Exclude, node.ID):
			entry.Reach, entry.State = "excluded", "excluded"
		case !gp.Enabled:
			entry.State = "disabled"
		case manual:
			entry.State = "blocked"
		case entry.Rules == 0:
			entry.State = "empty"
		default:
			entry.State = "applies"
		}
		out.Policies = append(out.Policies, entry)
	}

	compile := nodeNetworkPolicyCompile{}
	switch {
	case manual:
		out.Source = "manual"
		out.DefaultDrop = stored.Enabled
		compile = nodeNetworkPolicyCompile{policy: stored, ok: stored.Enabled}
	case covered:
		out.Source = "policies"
		out.DefaultDrop = true
		compile = nodeNetworkPolicyCompile{policy: eff, ok: true}
	case out.Orphan != nil:
		out.Source = "orphan"
		out.DefaultDrop = stored.Enabled && !stored.LastAppliedAt.IsZero()
	default:
		out.Source = "none"
	}
	return out, compile
}

func (s *Server) nodeNetworkAccess(p principal, nodeID string, now time.Time) nodeNetworkAccess {
	// The pair the knock state and the SSH Guard board require per node.
	for _, scope := range []string{"sshguard:read", "network:plan"} {
		if !rbac.Allows(p.Principal, scope, nodeID) {
			return nodeNetworkAccess{nodeNetworkSection: sectionRefused(scope)}
		}
	}
	row := s.sshGuardNodeStatusFor(nodeID, now)
	return nodeNetworkAccess{
		nodeNetworkSection: sectionOK(),
		Enrolled:           row.Enrolled,
		Posture:            string(row.Posture.State),
		KnockRequired:      row.KnockGate,
		Stage:              string(row.Stage),
		StageIsHistory:     row.StageIsHistory,
		RevertArmed:        row.RevertArmed,
	}
}

func (s *Server) nodeNetworkMesh(p principal, node model.Node, nodes []model.Node, applied []store.AppliedApproval) nodeNetworkMesh {
	if !rbac.Allows(p.Principal, "wireguard:read", node.ID) {
		return nodeNetworkMesh{nodeNetworkSection: sectionRefused("wireguard:read")}
	}
	mesh := nodeNetworkMesh{
		nodeNetworkSection: sectionOK(),
		Address:            node.WireGuardIP,
		ListenPort:         node.WireGuardPort,
		Endpoint:           node.WireGuardEndpoint,
		PublicKey:          node.WireGuardPublicKey != "",
		Missing:            []string{},
		// The agent reports the node's address, key, port and endpoint and
		// nothing about the live interface.
		NotReported: []string{"handshakes", "transfer", "live_peers"},
	}
	if node.WireGuardIP == "" {
		mesh.Missing = append(mesh.Missing, "address")
	}
	if node.WireGuardPublicKey == "" {
		mesh.Missing = append(mesh.Missing, "public_key")
	}
	mesh.Ready = len(mesh.Missing) == 0
	if node.WireGuardIP != "" {
		// The rule a WireGuard plan applies, so the count is what a plan for
		// this node would render now.
		if _, peers, err := wireguard.BuildMesh(nodes, node, 0); err == nil {
			mesh.Peers = len(peers)
		}
	}
	for _, a := range applied {
		if a.Approval.Plugin != "wireguard" {
			continue
		}
		last := &nodeNetworkApplied{AppliedAt: a.AppliedAt}
		if s.approvalVisibleToPrincipal(p, a.Approval) {
			last.ApprovalID = a.Approval.ID
		}
		mesh.LastApplied = last
		break
	}
	return mesh
}

func nodeNetworkGroupsFor(p principal, nodeID string, groupList []model.Group, resolved map[string][]string) nodeNetworkGroups {
	if !rbac.Allows(p.Principal, "group:read", "") {
		return nodeNetworkGroups{nodeNetworkSection: sectionRefused("group:read")}
	}
	out := nodeNetworkGroups{nodeNetworkSection: sectionOK(), Items: []nodeNetworkGroup{}}
	member := map[string]bool{}
	for _, groupID := range groups.GroupIDsForNode(nodeID, resolved) {
		member[groupID] = true
	}
	for _, g := range groupList {
		if member[g.ID] {
			out.Items = append(out.Items, nodeNetworkGroup{ID: g.ID, Name: g.Name, Slug: g.Slug, Color: g.Color})
		}
	}
	return out
}

// guardWriteOf says whether an approval wrote lattice_guard, as which kind,
// and with which ruleset. It mirrors approvalWritesLegacyGuard and the
// beacon companion: NetGuard's own plans, the legacy route's, a self-host
// DNS plan that carries a ruleset, and a beacon plan under NetGuard.
func guardWriteOf(a model.Approval) (kind, ruleset, deploymentID string, ok bool) {
	switch {
	case isNetGuardApproval(a):
		return ownerNetGuard, a.Plan, "", true
	case a.Plugin == "nft":
		return ownerLegacyFirewall, a.Plan, "", true
	case a.Plugin == "selfdns":
		artifacts, err := selfdns.ParseApprovalPlan(a.Plan)
		if err != nil || artifacts.NFTRuleset == "" {
			return "", "", "", false
		}
		return ownerSelfDNS, artifacts.NFTRuleset, selfDNSDeploymentOf(a.Action), true
	case isBeaconApproval(a):
		plan, err := beaconPlanOf(a)
		if err != nil || plan.NetGuard == nil {
			return "", "", "", false
		}
		return ownerBeacon, plan.NetGuard.Ruleset, "", true
	}
	return "", "", "", false
}

// selfDNSDeploymentOf reads the deployment id selfDNSApprovalAction encoded.
func selfDNSDeploymentOf(action string) string {
	encoded, ok := strings.CutPrefix(action, selfDNSApplyActionPrefix)
	if !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return string(raw)
}

// rulesetDigest hashes a ruleset as text, trimmed, so the copy a self-host
// DNS plan fences and the one the composer returns compare equal.
func rulesetDigest(ruleset string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(ruleset)))
	return hex.EncodeToString(sum[:])
}

func rulesetColumn(composer, ruleset string, withRules bool) nodeNetworkRuleset {
	col := nodeNetworkRuleset{State: nodeNetworkOK, Composer: composer, SHA256: rulesetDigest(ruleset)}
	if withRules {
		col.Ruleset = ruleset
	}
	return col
}

func rulesetRefused(composer, scope, reason string) nodeNetworkRuleset {
	return nodeNetworkRuleset{State: nodeNetworkRefused, Composer: composer, Scope: scope, Reason: reason}
}

// lastAppliedColumn is the last-applied column for one applied approval:
// its ruleset when the caller may read the approval, otherwise a refusal
// naming the scope the approval reads under.
func (s *Server) lastAppliedColumn(p principal, a store.AppliedApproval, kind, ruleset string, withRules bool) nodeNetworkRuleset {
	if !s.approvalVisibleToPrincipal(p, a.Approval) {
		return rulesetRefused(kind, approvalReadScope(a.Approval), "reading this plan needs the scope its approval is read under")
	}
	return rulesetColumn(kind, ruleset, withRules)
}

// approvalReadScope names the scope approvalPrimaryScopeAllows checks for the
// plugins whose approvals write the tables this view shows.
func approvalReadScope(a model.Approval) string {
	switch a.Plugin {
	case "nftpolicy":
		return "netpolicy:admin"
	case "selfdns":
		return "dns:admin"
	case model.BeaconApprovalPlugin:
		return "monitor:read"
	case sshGuardPlugin:
		return "sshguard:read"
	}
	return "network:plan"
}

func (s *Server) nodeNetworkGuardTable(p principal, node model.Node, binding model.NodeGuardBinding, hasBinding, managed bool, reality *model.GuardNodeReality, applied []store.AppliedApproval, withRules bool) nodeNetworkTable {
	table := nodeNetworkTable{Table: nodeNetworkGuardTable}
	if !rbac.Allows(p.Principal, "netguard:read", node.ID) {
		table.nodeNetworkSection = sectionRefused("netguard:read")
		return table
	}
	table.nodeNetworkSection = sectionOK()

	var lastRuleset string
	var last *store.AppliedApproval
	for i := range applied {
		kind, ruleset, deploymentID, ok := guardWriteOf(applied[i].Approval)
		if !ok {
			continue
		}
		last, lastRuleset = &applied[i], ruleset
		table.LastWriter = &nodeNetworkWriter{Kind: kind, AppliedAt: applied[i].AppliedAt, deploymentID: deploymentID}
		if s.approvalVisibleToPrincipal(p, applied[i].Approval) {
			table.LastWriter.ApprovalID = applied[i].Approval.ID
		}
		break
	}

	_, hasInputs := s.store.NFTInputs(node.ID)
	hasDNS := false
	for _, dep := range s.store.DNSDeployments() {
		if dep.NodeID == node.ID && dep.Engine != model.DNSEngineExternal {
			hasDNS = true
			break
		}
	}
	if managed {
		beacon := ownerIdle
		if s.beaconCompanionFor(node.ID) != nil {
			beacon = ownerContributes
		}
		table.Owners = []nodeNetworkOwner{
			{Kind: ownerNetGuard, State: ownerWrites},
			{Kind: ownerBeacon, State: beacon},
			{Kind: ownerSelfDNS, State: ownerRefused},
			{Kind: ownerLegacyFirewall, State: ownerRefused},
		}
		table.DriftState = netGuardDriftState(binding, reality)
	} else {
		netguardState := ownerIdle
		if hasBinding {
			netguardState = ownerObserves
		}
		legacy := ownerIdle
		if hasInputs || (table.LastWriter != nil && table.LastWriter.Kind == ownerLegacyFirewall) {
			legacy = ownerWrites
		}
		dns := ownerIdle
		if hasDNS {
			dns = ownerWrites
		}
		table.Owners = []nodeNetworkOwner{
			{Kind: ownerNetGuard, State: netguardState},
			{Kind: ownerBeacon, State: ownerIdle},
			{Kind: ownerSelfDNS, State: dns},
			{Kind: ownerLegacyFirewall, State: legacy},
		}
	}

	table.CompileNow = s.guardCompileNow(p, node.ID, managed, hasInputs, table.LastWriter, reality, withRules)
	if last == nil {
		table.LastApplied = nodeNetworkRuleset{State: nodeNetworkNone}
	} else {
		table.LastApplied = s.lastAppliedColumn(p, *last, table.LastWriter.Kind, lastRuleset, withRules)
		// Decided on the digests the server holds, so a caller who may read
		// what would compile now learns that the node differs from it even
		// when the applied plan is not theirs to read.
		if table.CompileNow.State == nodeNetworkOK {
			table.ReplanPending = table.CompileNow.SHA256 != rulesetDigest(lastRuleset)
		}
	}
	return table
}

// guardCompileNow is the ruleset the composer that would write lattice_guard
// next renders now. On a node NetGuard manages that is NetGuard's preview,
// which carries the applied beacon companion. Elsewhere it is the composer of
// the last writer: the self-host DNS composer for the deployment it named, or
// the legacy firewall route.
func (s *Server) guardCompileNow(p principal, nodeID string, managed, hasInputs bool, writer *nodeNetworkWriter, reality *model.GuardNodeReality, withRules bool) nodeNetworkRuleset {
	if managed {
		input, _, resolver, err := s.compileInputSnapshotFor(p, nodeID)
		if err != nil {
			return nodeNetworkRuleset{State: nodeNetworkError, Composer: ownerNetGuard, Reason: err.Error()}
		}
		ruleset, _, compileErr := s.netGuardPreview(input, reality)
		// Before compileErr: the compiler names the node it could not
		// resolve, which is what the refusal withholds.
		if refused := resolver.Refused(); refused != nil {
			return rulesetRefused(ownerNetGuard, "netguard:read", refused.Error())
		}
		if compileErr != nil {
			return nodeNetworkRuleset{State: nodeNetworkError, Composer: ownerNetGuard, Reason: compileErr.Error()}
		}
		return rulesetColumn(ownerNetGuard, ruleset, withRules)
	}
	if !rbac.Allows(p.Principal, "network:plan", nodeID) {
		return rulesetRefused(ownerLegacyFirewall, "network:plan", "the legacy firewall route composes under network:plan")
	}
	plan := network.NFTPlan{}
	if stored, ok := s.store.NFTInputs(nodeID); ok {
		plan = nftPlanFromStoredInputs(stored)
	}
	ingress, err := s.composeNFTIngressPolicy(nodeID, &plan, p)
	switch {
	case errors.Is(err, errNFTIngressPolicyReadRequired):
		return rulesetRefused(ownerLegacyFirewall, "netpolicy:read", err.Error())
	case errors.Is(err, errUnreadableNodes):
		return rulesetRefused(ownerLegacyFirewall, "netpolicy:read", err.Error())
	case err != nil:
		return nodeNetworkRuleset{State: nodeNetworkError, Composer: ownerLegacyFirewall, Reason: err.Error()}
	}
	composer := ownerLegacyFirewall
	if writer != nil && writer.Kind == ownerSelfDNS && writer.deploymentID != "" {
		if dep, ok := s.store.DNSDeployment(writer.deploymentID); ok && dep.NodeID == nodeID && dep.Engine != model.DNSEngineExternal {
			composed, _, err := selfdns.ComposeFirewallPlan(dep, plan)
			if err != nil {
				return nodeNetworkRuleset{State: nodeNetworkError, Composer: ownerSelfDNS, Reason: err.Error()}
			}
			plan, composer = composed, ownerSelfDNS
		}
	}
	// Nothing composes this table: no stored inputs, no ingress rule and no
	// writer. The legacy route would still render a drop-all ruleset if
	// someone planned it, which is not what the node runs.
	if !hasInputs && ingress == 0 && writer == nil {
		return nodeNetworkRuleset{State: nodeNetworkNone, Composer: composer}
	}
	ruleset, err := network.GenerateNFTPlan(plan)
	if err != nil {
		return nodeNetworkRuleset{State: nodeNetworkError, Composer: composer, Reason: err.Error()}
	}
	return rulesetColumn(composer, ruleset, withRules)
}

func (s *Server) nodeNetworkPolicyTable(p principal, nodeID string, outbound nodeNetworkOutbound, compile nodeNetworkPolicyCompile, applied []store.AppliedApproval, withRules bool) nodeNetworkTable {
	table := nodeNetworkTable{Table: nodeNetworkPolicyTable}
	if outbound.State != nodeNetworkOK {
		table.nodeNetworkSection = outbound.nodeNetworkSection
		return table
	}
	table.nodeNetworkSection = sectionOK()
	switch outbound.Source {
	case "manual":
		table.Owners = []nodeNetworkOwner{{Kind: ownerManualPolicy, State: ownerWrites}, {Kind: ownerOutboundPolicy, State: ownerRefused}}
	case "policies":
		table.Owners = []nodeNetworkOwner{{Kind: ownerOutboundPolicy, State: ownerWrites}}
	case "orphan":
		table.Owners = []nodeNetworkOwner{{Kind: ownerOutboundPolicy, State: ownerOrphan}}
	default:
		table.Owners = []nodeNetworkOwner{{Kind: ownerOutboundPolicy, State: ownerIdle}}
	}

	var last *store.AppliedApproval
	for i := range applied {
		if applied[i].Approval.Plugin == "nftpolicy" {
			last = &applied[i]
			break
		}
	}
	if last != nil {
		table.LastWriter = &nodeNetworkWriter{Kind: table.Owners[0].Kind, AppliedAt: last.AppliedAt}
		if s.approvalVisibleToPrincipal(p, last.Approval) {
			table.LastWriter.ApprovalID = last.Approval.ID
		}
	}

	composer := table.Owners[0].Kind
	switch {
	case !compile.ok:
		table.CompileNow = nodeNetworkRuleset{State: nodeNetworkNone, Composer: composer}
	default:
		table.CompileNow = s.policyCompileNow(p, nodeID, composer, compile, withRules)
	}
	if last == nil {
		table.LastApplied = nodeNetworkRuleset{State: nodeNetworkNone}
		return table
	}
	table.LastApplied = s.lastAppliedColumn(p, *last, composer, last.Approval.Plan, withRules)
	if table.CompileNow.State == nodeNetworkOK {
		table.ReplanPending = table.CompileNow.SHA256 != rulesetDigest(last.Approval.Plan)
	}
	return table
}

// policyCompileNow compiles the node document the outbound plan would
// compile: the manual one as handleNetPolicyPlan does, or the expanded one as
// handleGroupPolicyPlan does, through a resolver scoped to the caller.
func (s *Server) policyCompileNow(p principal, nodeID, composer string, compile nodeNetworkPolicyCompile, withRules bool) nodeNetworkRuleset {
	opts, err := s.netPolicyCompileOptions()
	if err != nil {
		return nodeNetworkRuleset{State: nodeNetworkError, Composer: composer, Reason: err.Error()}
	}
	resolver := s.nodeResolverFor(p, "netpolicy:read", "this node's outbound policy", nodeID)
	policy := compile.policy
	if composer == ownerOutboundPolicy {
		normalized, err := netpolicy.NormalizePolicy(policy, resolver.Resolve)
		if refused := resolver.Refused(); refused != nil {
			return rulesetRefused(composer, "netpolicy:read", refused.Error())
		}
		if err != nil {
			return nodeNetworkRuleset{State: nodeNetworkError, Composer: composer, Reason: err.Error()}
		}
		normalized.GroupDerived = true
		policy = normalized
	}
	plan, err := netpolicy.CompileEgressPlan(policy, resolver.Resolve, opts)
	if refused := resolver.Refused(); refused != nil {
		return rulesetRefused(composer, "netpolicy:read", refused.Error())
	}
	if err != nil {
		return nodeNetworkRuleset{State: nodeNetworkError, Composer: composer, Reason: err.Error()}
	}
	return rulesetColumn(composer, plan.Ruleset, withRules)
}

// nodeNetworkKnockTable names SSH Guard's table and its last writer. Its
// rules are the knock sequence, a credential, so no column ever carries
// them.
func (s *Server) nodeNetworkKnockTable(p principal, nodeID string, access nodeNetworkAccess, applied []store.AppliedApproval) nodeNetworkTable {
	table := nodeNetworkTable{Table: nodeNetworkKnockTable, RulesWithheld: "knock"}
	if access.State != nodeNetworkOK {
		table.nodeNetworkSection = access.nodeNetworkSection
		return table
	}
	table.nodeNetworkSection = sectionOK()
	state := ownerIdle
	if access.KnockRequired {
		state = ownerWrites
	}
	table.Owners = []nodeNetworkOwner{{Kind: ownerSSHGuard, State: state}}
	table.CompileNow = nodeNetworkRuleset{State: nodeNetworkNone, Composer: ownerSSHGuard}
	table.LastApplied = nodeNetworkRuleset{State: nodeNetworkNone}
	for i := range applied {
		if applied[i].Approval.Plugin != sshGuardPlugin {
			continue
		}
		table.LastWriter = &nodeNetworkWriter{Kind: ownerSSHGuard, AppliedAt: applied[i].AppliedAt}
		if s.approvalVisibleToPrincipal(p, applied[i].Approval) {
			table.LastWriter.ApprovalID = applied[i].Approval.ID
		}
		table.LastApplied = nodeNetworkRuleset{State: nodeNetworkRefused, Composer: ownerSSHGuard, Reason: "the knock table's rules are the knock sequence"}
		break
	}
	return table
}
