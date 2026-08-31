package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Node capability enrolment: which capabilities may act on which nodes.
//
// The control plane already answered this question in four different shapes
// before this file existed - AgentLaunchConfig's switches, NodeGuardBinding's
// Managed flag, AgentUpdatePolicy's Enabled flag, and StorageBinding - each
// with its own endpoint and its own default, and none of them consulted by task
// dispatch. SSH Guard had no record at all, which is why "which nodes are in
// scope for hardening" was answered by whoever happened to be selecting rows.
//
// This is the fifth shape only in the sense that it is meant to absorb the
// other four: they stay authoritative for their own area and become inputs to
// resolveNodeCapability, so each can be folded in independently instead of
// migrating anything.
//
// The identity of a capability is the Plugin field already carried on
// approvals. That field is always set from a server-side constant and never
// decoded from a client body, so it is safe to make an authorization decision
// on. Reusing it also means no second vocabulary to keep in sync.

// capabilitySingBox gates the sing-box management surface: adding, removing and
// reconfiguring lines on a node. Named apart from the read-only
// "singbox:discover" because they default differently - looking at a node's
// sing-box needs no paperwork, changing it does.
const capabilitySingBox = "singbox"

// capabilitySingBoxDiscover is the read half: inventorying what a node already
// runs. Split from the write half because they default differently, and because
// a rediscovery follows every successful apply - blocking the read would leave
// the control plane's picture stale exactly when it had just changed.
const capabilitySingBoxDiscover = "singbox:discover"

// capabilitySpec declares how one capability is defaulted and whether the
// enrolment gate is live for it yet.
type capabilitySpec struct {
	// Mutates decides the default, and it is the only axis that does.
	//
	// Reading a node needs no paperwork; changing one does. Defaulting
	// everything to deny would mean a freshly enrolled node reports no metrics
	// until someone grants it, which nobody would accept and which would push
	// operators toward granting everything up front. Defaulting everything to
	// allow is the behaviour that produced a fleet-wide SSH hardening run
	// against machines that were never meant to be in it.
	Mutates bool

	// Enforced turns the gate on for this capability. It exists so capabilities
	// can be adopted one at a time: an unenforced capability records enrolment
	// decisions and shows them in the console without refusing anything, which
	// is what makes it safe to populate the table before flipping the switch.
	Enforced bool

	// Derive reads the per-node record this capability already had, for nodes
	// with no explicit enrolment. This is what makes a capability safe to turn
	// on: without it, flipping Enforced would refuse every node in the fleet,
	// because nothing has a new-style enrolment yet.
	//
	// It returns (enrolled, known). known=false means the old record says
	// nothing about this node either, and the capability default decides.
	// Only consulted when there is no explicit record, so an operator decision
	// always wins over an inferred one.
	Derive func(s *Server, nodeID string) (enrolled bool, known bool)
}

// launchIntent is the operator's configured intent for a node's agent, which
// is the right input for these derivations: what the agent currently reports is
// evidence about the machine, but what may act on it is a decision, and the
// decision lives in AgentLaunch.
func launchIntent(s *Server, nodeID string) (model.AgentLaunchConfig, bool) {
	node, ok := s.store.Node(nodeID)
	if !ok || node.AgentLaunch == nil {
		return model.AgentLaunchConfig{}, false
	}
	return *node.AgentLaunch, true
}

// deriveSingBox answers "does this node run sing-box" the way the operator
// already told us: the discover switch on the node's agent launch config. A
// node that was never set up for sing-box has no business receiving sing-box
// management tasks, which is the whole point.
func deriveSingBox(s *Server, nodeID string) (bool, bool) {
	launch, ok := launchIntent(s, nodeID)
	if !ok {
		return false, false
	}
	return launch.SingBoxDiscover, true
}

func deriveTerminal(s *Server, nodeID string) (bool, bool) {
	launch, ok := launchIntent(s, nodeID)
	if !ok {
		return false, false
	}
	return launch.AllowTerminal, true
}

// deriveAgentUpdate reads the per-node update policy. Absent policy is not
// "disabled": it is "nobody has configured updates here", which is exactly the
// undecided case the capability default is for.
func deriveAgentUpdate(s *Server, nodeID string) (bool, bool) {
	policy, ok := s.store.AgentUpdatePolicy(nodeID)
	if !ok {
		return false, false
	}
	return policy.Enabled, true
}

// deriveNetGuard reads the netguard adoption record, which is the closest thing
// the control plane already had to an enrolment: Managed means an operator
// adopted this node into firewall management.
func deriveNetGuard(s *Server, nodeID string) (bool, bool) {
	binding, ok := s.store.NodeGuardBinding(nodeID)
	if !ok {
		return false, false
	}
	return binding.Managed, true
}

// capabilitySpecs is keyed by the approval Plugin value, except where one
// plugin spans both a read and a write surface and therefore needs two entries
// (sing-box discovery is a read; sing-box apply changes the machine).
var capabilitySpecs = map[string]capabilitySpec{
	// The two the operator asked for, and the two that ship OFF.
	//
	// Not a retreat from enforcing them: a compiled default decides what a fleet
	// does the moment this version starts, and on that morning the enrolment
	// table is empty. sshguard has nothing to derive from, so enforcing it on
	// arrival would refuse hardening for every node until someone enrolled them
	// - and the API to do the enrolling arrives in the same release. sing-box
	// derives, but from a switch that may be off on nodes an operator has been
	// managing by hand for a year.
	//
	// So the mechanism ships, the gates page shows what turning each one on
	// would refuse against the real fleet, and the operator flips them when the
	// numbers look right. That is the whole reason enforcement became stored
	// policy rather than a constant; using it here is the point, not a
	// concession.
	sshGuardPlugin:    {Mutates: true},
	capabilitySingBox: {Mutates: true, Derive: deriveSingBox},

	// Declared, not yet enforced. Each of these already has a per-node record
	// of its own; turning one on means teaching resolveNodeCapability to read
	// that record, then flipping Enforced. Until then they behave exactly as
	// they do today.
	"nft":              {Mutates: true, Derive: deriveNetGuard},
	"nftpolicy":        {Mutates: true},
	"wireguard":        {Mutates: true},
	"selfdns":          {Mutates: true},
	"agentupdate":      {Mutates: true, Derive: deriveAgentUpdate},
	"proxycore":        {Mutates: true},
	"cftunnel":         {Mutates: true},
	"acme-dns":         {Mutates: true},
	"singbox-linemeta": {Mutates: true},
	"singbox:discover": {Mutates: false, Derive: deriveSingBox},
	"terminal":         {Mutates: true, Derive: deriveTerminal},
	"metrics":          {Mutates: false},
	"inventory":        {Mutates: false},
	"trace":            {Mutates: false},
	"logs":             {Mutates: false},
}

// KnownCapability describes one declared capability to the console.
//
// Enforced and Mutates are both exported because they answer different
// questions an operator asks: whether a decision here currently bites, and
// whether this capability is one that changes the machine (which is what makes
// it opt-in in the first place). Without Enforced the console would render
// fourteen inert capabilities beside the one live one and imply they all matter
// equally.
type KnownCapability struct {
	ID       string `json:"id"`
	Enforced bool   `json:"enforced"`
	Mutates  bool   `json:"mutates"`
	// Derived is whether this capability can answer for a node that has no
	// explicit enrolment. Enforcing one that cannot refuses the whole fleet on
	// the first request, so the console has to be able to say so.
	Derived bool `json:"derived"`
}

// KnownCapabilities lists every capability this fleet has, compiled-in and
// plugin-provided, with the enforcement each one currently has.
func (s *Server) KnownCapabilities() []KnownCapability {
	seen := map[string]capabilitySpec{}
	for id, spec := range capabilitySpecs {
		seen[id] = spec
	}
	for _, loaded := range s.plugins {
		if _, ok := seen[loaded.Manifest.ID]; !ok {
			seen[loaded.Manifest.ID] = capabilitySpec{Mutates: true}
		}
	}
	out := make([]KnownCapability, 0, len(seen))
	for id, spec := range seen {
		out = append(out, KnownCapability{
			ID:       id,
			Enforced: s.capabilityEnforced(id),
			Mutates:  spec.Mutates,
			Derived:  spec.Derive != nil,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// capabilityDecision is why a node was allowed or refused, in words an operator
// can act on. An exclusion and a missing enrolment are both refusals, but they
// call for opposite actions, so they never collapse into one message.
type capabilityDecision struct {
	Allowed bool
	// Reason is empty when allowed by default and there is nothing to say.
	Reason string
	// Source is where the answer came from: an operator's explicit record, the
	// node's own older configuration, or the capability default. The console
	// needs this to avoid showing "not decided" for a node that is in fact
	// allowed because of how it was already set up - which reads as blocked
	// when it is not.
	Source string
}

const (
	capabilitySourceRecord  = "record"
	capabilitySourceDerived = "derived"
	capabilitySourceDefault = "default"
	// capabilitySourceNotEnforced means the gate is off for this fleet, so the
	// scope answer, whatever it is, did not apply.
	capabilitySourceNotEnforced = "not-enforced"
)

// resolveNodeCapability is the decision: may this capability act on this node,
// right now, on this fleet.
//
// It includes whether the gate is even live. An earlier version answered only
// the scope question and left every caller to check enforcement separately,
// which meant the same answer meant different things depending on who asked and
// put the burden on each new call site to remember. Three sites remembered; the
// tests written against it did not, which is the tell.
//
// The scope question on its own is still available as resolveCapabilityScope,
// for the impact preview and for showing an operator what a gate would do.
func (s *Server) resolveNodeCapability(nodeID, capability string) capabilityDecision {
	if !s.capabilityEnforced(capability) {
		return capabilityDecision{Allowed: true, Source: capabilitySourceNotEnforced}
	}
	return s.resolveCapabilityScope(nodeID, capability)
}

// resolveCapabilityScope answers the scope question alone, as if the gate were
// live. Order matters: an explicit decision always beats a derived one, and an
// exclusion beats an enrolment, so revoking is never ambiguous when both
// records somehow exist.
func (s *Server) resolveCapabilityScope(nodeID, capability string) capabilityDecision {
	spec, declared := s.capabilitySpecFor(capability)
	if !declared {
		// An undeclared capability is not gated. Refusing here would break every
		// flow that has not been onboarded yet, which is the opposite of a
		// staged rollout.
		return capabilityDecision{Allowed: true, Source: capabilitySourceDefault}
	}
	if record, ok := s.store.NodeCapability(nodeID, capability); ok {
		switch record.State {
		case store.CapabilityExcluded:
			return capabilityDecision{Allowed: false, Reason: excludedReason(record), Source: capabilitySourceRecord}
		case store.CapabilityEnrolled:
			return capabilityDecision{Allowed: true, Source: capabilitySourceRecord}
		}
	}
	// No explicit decision. Fall back to whatever record this capability
	// already kept for the node, so turning a capability on does not refuse a
	// fleet that has been correctly configured for years under the old shape.
	if spec.Derive != nil {
		if enrolled, known := spec.Derive(s, nodeID); known {
			if enrolled {
				return capabilityDecision{Allowed: true, Source: capabilitySourceDerived}
			}
			return capabilityDecision{
				Allowed: false,
				Source:  capabilitySourceDerived,
				Reason: fmt.Sprintf(
					"node is not configured for %q; enable it on the node, or enrol the node explicitly",
					capability),
			}
		}
	}
	if !spec.Mutates {
		return capabilityDecision{Allowed: true, Source: capabilitySourceDefault}
	}
	return capabilityDecision{
		Allowed: false,
		Source:  capabilitySourceDefault,
		Reason: fmt.Sprintf(
			"node is not enrolled in %q, which changes the node and is opt-in; enrol it or pick a different target",
			capability),
	}
}

func excludedReason(record store.NodeCapability) string {
	if record.Reason == "" {
		return fmt.Sprintf("node is excluded from %q", record.Capability)
	}
	return fmt.Sprintf("node is excluded from %q: %s", record.Capability, record.Reason)
}

// capabilitySpecFor resolves a capability's declaration, including ones that
// are not compiled in.
//
// Every installed plugin is a capability. A plugin operation mints an approval
// carrying the plugin's manifest id and queues a task against a node, which is
// the same shape as any built-in capability and deserves the same gate - and
// until this existed, third-party plugins were the one family that could act on
// any node in the fleet unscoped, which is backwards. They are declared as
// mutating with nothing to derive from, and start unenforced so an operator
// turns them on deliberately after seeing what it would refuse.
func (s *Server) capabilitySpecFor(capability string) (capabilitySpec, bool) {
	if spec, ok := capabilitySpecs[capability]; ok {
		return spec, true
	}
	if capability == "" {
		return capabilitySpec{}, false
	}
	if _, ok := s.loadedPlugin(capability); ok {
		return capabilitySpec{Mutates: true}, true
	}
	return capabilitySpec{}, false
}

// capabilityEnforced reports whether the gate is live.
//
// The operator's stored policy wins over the compiled default. The default is
// what a fresh install should do; the policy is what this fleet has decided,
// and only the operator knows when their nodes have been curated enough for a
// capability to start refusing work.
func (s *Server) capabilityEnforced(capability string) bool {
	if policy, ok := s.store.CapabilityPolicy(capability); ok {
		return policy.Enforced
	}
	spec, ok := s.capabilitySpecFor(capability)
	return ok && spec.Enforced
}

// requireNodeCapability refuses the request when the capability may not act on
// the node, and reports whether the caller should continue.
func (s *Server) requireNodeCapability(w http.ResponseWriter, nodeID, capability string) bool {
	decision := s.resolveNodeCapability(nodeID, capability)
	if decision.Allowed {
		return true
	}
	writeError(w, http.StatusForbidden, fmt.Errorf("%s", decision.Reason))
	return false
}

// nodeCapabilityEffectiveView is one capability's answer for one node: what
// the gate would decide right now, and why. State/RecordReason describe the
// explicit record when there is one; Allowed/Source describe the decision,
// which may come from the node's older configuration instead.
type nodeCapabilityEffectiveView struct {
	Capability string `json:"capability"`
	Enforced   bool   `json:"enforced"`
	Mutates    bool   `json:"mutates"`
	Allowed    bool   `json:"allowed"`
	Source     string `json:"source"`
	Reason     string `json:"reason,omitempty"`

	State        string    `json:"state,omitempty"`
	RecordReason string    `json:"record_reason,omitempty"`
	ActorID      string    `json:"actor_id,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

type nodeCapabilityView struct {
	NodeID     string    `json:"node_id"`
	Capability string    `json:"capability"`
	State      string    `json:"state"`
	Reason     string    `json:"reason,omitempty"`
	ActorID    string    `json:"actor_id,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
	// Enforced tells the console whether this decision currently bites, so a
	// recorded-but-not-yet-live capability cannot be mistaken for a guarantee.
	Enforced bool `json:"enforced"`
}

// handleNodeCapabilities lists enrolment decisions (GET) and records one
// (POST). Reading needs node:read; changing scope is an administrative act on
// the node, so it needs node:admin and the node must be one the caller may
// actually administer.
func (s *Server) handleNodeCapabilities(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "node:read") {
			return
		}
		// ?node_id= asks the question the node page actually has: for this one
		// node, what is the effective answer for each capability, and where did
		// it come from. Listing only stored records would show "not decided"
		// for a node that is allowed because of how it was already configured,
		// which reads as blocked when it is not.
		if nodeID := strings.TrimSpace(r.URL.Query().Get("node_id")); nodeID != "" {
			if !rbac.Allows(p.Principal, "node:read", nodeID) {
				writeError(w, http.StatusForbidden, errors.New("forbidden"))
				return
			}
			effective := make([]nodeCapabilityEffectiveView, 0, len(capabilitySpecs))
			for _, known := range s.KnownCapabilities() {
				decision := s.resolveCapabilityScope(nodeID, known.ID)
				view := nodeCapabilityEffectiveView{
					Capability: known.ID,
					Enforced:   known.Enforced,
					Mutates:    known.Mutates,
					Allowed:    decision.Allowed,
					Source:     decision.Source,
					Reason:     decision.Reason,
				}
				if record, ok := s.store.NodeCapability(nodeID, known.ID); ok {
					view.State = record.State
					view.RecordReason = record.Reason
					view.ActorID = record.ActorID
					view.UpdatedAt = record.UpdatedAt
				}
				effective = append(effective, view)
			}
			writeJSON(w, http.StatusOK, map[string]any{"node_id": nodeID, "effective": effective})
			return
		}
		records := s.store.NodeCapabilities()
		out := make([]nodeCapabilityView, 0, len(records))
		for _, record := range records {
			if !rbac.Allows(p.Principal, "node:read", record.NodeID) {
				continue
			}
			out = append(out, nodeCapabilityView{
				NodeID: record.NodeID, Capability: record.Capability, State: record.State,
				Reason: record.Reason, ActorID: record.ActorID, UpdatedAt: record.UpdatedAt,
				Enforced: s.capabilityEnforced(record.Capability),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"capabilities": out,
			"known":        s.KnownCapabilities(),
		})
	case http.MethodPost:
		if !s.requireScope(w, p, "node:admin") {
			return
		}
		var req struct {
			NodeID     string `json:"node_id"`
			Capability string `json:"capability"`
			State      string `json:"state"`
			Reason     string `json:"reason"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.NodeID = strings.TrimSpace(req.NodeID)
		req.Capability = strings.TrimSpace(req.Capability)
		req.State = strings.TrimSpace(req.State)
		req.Reason = strings.TrimSpace(req.Reason)
		if req.NodeID == "" || req.Capability == "" {
			writeError(w, http.StatusBadRequest, errors.New("node_id and capability are required"))
			return
		}
		// Scope is not enough: changing what may act on a node is a change to
		// that node, so the caller has to be able to reach it.
		if !s.requireReadableNodes(w, p, "node:admin", "this node", []string{req.NodeID}) {
			return
		}
		if _, ok := s.store.Node(req.NodeID); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		if _, ok := capabilitySpecs[req.Capability]; !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("unknown capability %q", req.Capability))
			return
		}
		switch req.State {
		case store.CapabilityEnrolled:
		case store.CapabilityExcluded:
			// The reason is the whole point of excluded: without it the record
			// says "not this one" and nothing about why, which is exactly the
			// state this was built to replace.
			if req.Reason == "" {
				writeError(w, http.StatusBadRequest, errors.New("a reason is required to exclude a node"))
				return
			}
		case "":
			// Clears the record, returning the node to the capability default.
		default:
			writeError(w, http.StatusBadRequest, fmt.Errorf("state must be %q, %q, or empty to clear",
				store.CapabilityEnrolled, store.CapabilityExcluded))
			return
		}
		record := store.NodeCapability{
			NodeID: req.NodeID, Capability: req.Capability, State: req.State,
			Reason: req.Reason, ActorID: p.ActorID, UpdatedAt: s.now(),
		}
		if err := s.store.SetNodeCapability(record); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID:      id.New("audit"),
			ActorID: p.ActorID,
			NodeID:  req.NodeID,
			Action:  "node.capability." + firstNonEmpty(req.State, "cleared"),
			Scope:   "node:admin",
			Reason:  req.Reason,
			Metadata: map[string]string{
				"capability": req.Capability,
				"state":      req.State,
			},
		})
		writeJSON(w, http.StatusOK, nodeCapabilityView{
			NodeID: record.NodeID, Capability: record.Capability, State: record.State,
			Reason: record.Reason, ActorID: record.ActorID, UpdatedAt: record.UpdatedAt,
			Enforced: s.capabilityEnforced(record.Capability),
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// capabilityImpactView is what turning one capability's gate on would do to
// this fleet right now.
//
// Enforcement is the one setting here that can break working operations: a
// capability with nothing to derive from refuses every node that has no
// explicit enrolment, which on a fresh table is the entire fleet. Nobody should
// have to discover that by flipping it and watching the failures, so the answer
// is available before the decision.
type capabilityImpactView struct {
	Capability  string `json:"capability"`
	Enforced    bool   `json:"enforced"`
	Mutates     bool   `json:"mutates"`
	Derived     bool   `json:"derived"`
	AllowCount  int    `json:"allow_count"`
	RefuseCount int    `json:"refuse_count"`
	// Refused names the first few, because a count alone does not tell an
	// operator whether the answer is "the three I excluded" or "everything".
	Refused []capabilityImpactNode `json:"refused,omitempty"`
}

type capabilityImpactNode struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason,omitempty"`
}

const capabilityImpactSample = 10

// capabilityImpact resolves the capability against every node the caller can
// see, as if it were enforced.
func (s *Server) capabilityImpact(p principal, capability string) capabilityImpactView {
	spec, _ := s.capabilitySpecFor(capability)
	out := capabilityImpactView{
		Capability: capability,
		Enforced:   s.capabilityEnforced(capability),
		Mutates:    spec.Mutates,
		Derived:    spec.Derive != nil,
	}
	for _, node := range s.store.Nodes() {
		if !rbac.Allows(p.Principal, "node:read", node.ID) {
			continue
		}
		decision := s.resolveCapabilityScope(node.ID, capability)
		if decision.Allowed {
			out.AllowCount++
			continue
		}
		out.RefuseCount++
		if len(out.Refused) < capabilityImpactSample {
			out.Refused = append(out.Refused, capabilityImpactNode{
				NodeID: node.ID, Name: node.Name, Reason: decision.Reason,
			})
		}
	}
	return out
}

// handleCapabilityPolicies lists every capability with the impact of its gate
// (GET), and turns one on or off (POST).
func (s *Server) handleCapabilityPolicies(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "node:read") {
			return
		}
		known := s.KnownCapabilities()
		out := make([]capabilityImpactView, 0, len(known))
		for _, k := range known {
			out = append(out, s.capabilityImpact(p, k.ID))
		}
		writeJSON(w, http.StatusOK, map[string]any{"capabilities": out})
	case http.MethodPost:
		// Turning a gate off is a security downgrade, so it needs the scope that
		// administers nodes rather than the one that reads them. It is offered
		// at all because an operator who needs the lever during an incident will
		// otherwise reach for something worse, and because the audit trail
		// records who did it and when.
		if !s.requireScope(w, p, "node:admin") {
			return
		}
		var req struct {
			Capability string `json:"capability"`
			Enforced   bool   `json:"enforced"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.Capability = strings.TrimSpace(req.Capability)
		if req.Capability == "" {
			writeError(w, http.StatusBadRequest, errors.New("capability is required"))
			return
		}
		if _, ok := s.capabilitySpecFor(req.Capability); !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("unknown capability %q", req.Capability))
			return
		}
		policy := store.CapabilityPolicy{
			Capability: req.Capability, Enforced: req.Enforced,
			ActorID: p.ActorID, UpdatedAt: s.now(),
		}
		if err := s.store.SetCapabilityPolicy(policy); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		decision := "allow"
		if !req.Enforced {
			// A gate being switched off is the event worth finding later.
			decision = "warn"
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID:       id.New("audit"),
			ActorID:  p.ActorID,
			Action:   "capability.policy",
			Scope:    "node:admin",
			Decision: decision,
			Reason:   fmt.Sprintf("enforcement %v for %q", req.Enforced, req.Capability),
			Metadata: map[string]string{"capability": req.Capability},
		})
		writeJSON(w, http.StatusOK, s.capabilityImpact(p, req.Capability))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}
