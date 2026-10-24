package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The measurement beacon's control-plane state (lattice docs design 29 D3
// and D12): one source id per node, assigned once and never reused, and per
// target node the settings its last applied node.beacon plan set, the
// sources that plan approved, the 32-byte target key and the epoch the path
// keys are derived for. The target key is a reversible credential: crypto.go
// encrypts it at rest, and nothing outside the server's beacon code reads it.
//
// Like the latency configuration this is operator intent plus a few
// low-frequency transitions (a rotation, the target's first pull of a new
// epoch, a reachability verdict, a node's egress address moving), so it
// lives in the JSON state and is mirrored into the hot store's meta bucket.
// Nothing here is written per heartbeat or per config pull: an egress
// address is written only when it changes.

// BeaconRegistry is State.Beacon.
type BeaconRegistry struct {
	// NextSourceID is the source id the next node is given; ids start at 1.
	NextSourceID uint32            `json:"next_source_id"`
	SourceIDs    map[string]uint32 `json:"source_ids,omitempty"`
	// Targets are keyed by node id. A node appears once a plan for it has
	// been applied or a port has been suggested for it.
	Targets map[string]BeaconTarget `json:"targets,omitempty"`
	// Egress is the global IPv4 address each node's agent last pulled its
	// config from, keyed by node id. A NetGuard companion admits a source
	// from it when it is neither of the source's pinned addresses, so a
	// node.beacon plan depends on it; it is kept here so a plan rendered
	// again after a restart reads what the plan was made from.
	Egress map[string]string `json:"egress,omitempty"`
}

// BeaconTarget is one node's beacon as the control plane holds it.
type BeaconTarget struct {
	NodeID string `json:"node_id"`
	// Version counts applied plans; a plan names the version it was made
	// from and is stale once another one is applied.
	Version int64 `json:"version"`
	// Settings are what the last applied plan set (Enabled false after a
	// disable, or before any plan).
	Settings model.BeaconSettings `json:"settings"`
	// Approved is the source set of the last applied plan.
	Approved          []model.BeaconPlanSource `json:"approved,omitempty"`
	Exposure          string                   `json:"exposure,omitempty"`
	Companion         *BeaconCompanion         `json:"companion,omitempty"`
	AppliedApprovalID string                   `json:"applied_approval_id,omitempty"`
	AppliedAt         time.Time                `json:"applied_at,omitzero"`
	AppliedBy         string                   `json:"applied_by,omitempty"`
	// SuggestedPort is the random listen port the node was assigned, kept so
	// every enable without a port takes the same one.
	SuggestedPort int `json:"suggested_port,omitempty"`
	// Key is the base64 target key, empty while the beacon is disabled.
	Key string `json:"key,omitempty"`
	// Epoch is the newest epoch (N) and PrevEpoch the one before it (N-1)
	// while it is still accepted or retired; zero when there is none.
	Epoch     uint32    `json:"epoch,omitempty"`
	PrevEpoch uint32    `json:"prev_epoch,omitempty"`
	RotatedAt time.Time `json:"rotated_at,omitzero"`
	// AckedAt is when the target first pulled a table holding Epoch.
	AckedAt time.Time `json:"acked_at,omitzero"`
	// TableSources are the node ids the target's table last held, so a
	// source leaving it is noticed and rotates the epoch.
	TableSources []string                 `json:"table_sources,omitempty"`
	Reach        model.BeaconReachability `json:"reach,omitzero"`
	// ReachArmed means a reachability check is due once the target reports
	// listening on the applied address and port.
	ReachArmed bool `json:"reach_armed,omitempty"`
	// CompanionPending means the applied plan's NetGuard companion has not
	// applied yet (or failed): until it does, no source probes the beacon,
	// which reads firewall_pending, and no reachability check runs.
	CompanionPending bool `json:"companion_pending,omitempty"`
}

// BeaconCompanion is the NetGuard companion rule set in force for a node:
// UDP Port admitted from Allow, and Bind:Port marked notrack both ways.
type BeaconCompanion struct {
	Bind  string   `json:"bind"`
	Port  int      `json:"port"`
	Allow []string `json:"allow"`
}

// ErrBeaconVersion is returned when an apply names a beacon version other
// than the stored one.
var ErrBeaconVersion = errors.New("beacon state changed since the plan was made")

func cloneBeaconTarget(t BeaconTarget) BeaconTarget {
	t.Approved = slices.Clone(t.Approved)
	for i := range t.Approved {
		t.Approved[i].Allow = slices.Clone(t.Approved[i].Allow)
	}
	if t.Companion != nil {
		c := *t.Companion
		c.Allow = slices.Clone(c.Allow)
		t.Companion = &c
	}
	t.TableSources = slices.Clone(t.TableSources)
	return t
}

func cloneBeaconRegistry(r *BeaconRegistry) *BeaconRegistry {
	if r == nil {
		return nil
	}
	out := &BeaconRegistry{NextSourceID: r.NextSourceID, SourceIDs: maps.Clone(r.SourceIDs), Egress: maps.Clone(r.Egress)}
	if r.Targets != nil {
		out.Targets = make(map[string]BeaconTarget, len(r.Targets))
		for id, t := range r.Targets {
			out.Targets[id] = cloneBeaconTarget(t)
		}
	}
	return out
}

// BeaconTarget returns one node's beacon state.
func (s *Store) BeaconTarget(nodeID string) (BeaconTarget, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Beacon == nil {
		return BeaconTarget{}, false
	}
	t, ok := s.state.Beacon.Targets[nodeID]
	if !ok {
		return BeaconTarget{}, false
	}
	return cloneBeaconTarget(t), true
}

// BeaconTargets returns every node's beacon state, keyed by node id.
func (s *Store) BeaconTargets() map[string]BeaconTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]BeaconTarget{}
	if s.state.Beacon == nil {
		return out
	}
	for id, t := range s.state.Beacon.Targets {
		out[id] = cloneBeaconTarget(t)
	}
	return out
}

// BeaconSourceIDs returns the assigned source ids, keyed by node id.
func (s *Store) BeaconSourceIDs() map[string]uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Beacon == nil {
		return map[string]uint32{}
	}
	return maps.Clone(s.state.Beacon.SourceIDs)
}

// BeaconEgress returns the egress address last recorded for a node, empty
// when none is.
func (s *Store) BeaconEgress(nodeID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Beacon == nil {
		return ""
	}
	return s.state.Beacon.Egress[nodeID]
}

// SetBeaconEgress records the address a node's agent pulled its config
// from, writing the state only when it differs from the recorded one. The
// caller validates the address. The node must exist.
func (s *Store) SetBeaconEgress(nodeID, addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Beacon != nil && s.state.Beacon.Egress[nodeID] == addr {
		return nil
	}
	if _, ok := s.state.Nodes[nodeID]; !ok {
		return fmt.Errorf("node %q not found", nodeID)
	}
	reg := cloneBeaconRegistry(s.state.Beacon)
	if reg == nil {
		reg = &BeaconRegistry{NextSourceID: 1}
	}
	if reg.Egress == nil {
		reg.Egress = map[string]string{}
	}
	reg.Egress[nodeID] = addr
	prior := s.state.Beacon
	s.state.Beacon = reg
	if err := s.Save(); err != nil {
		s.state.Beacon = prior
		return err
	}
	return nil
}

// EnsureBeaconSourceIDs gives every node in nodeIDs a source id it does not
// have yet and returns the ids of all of them. An id number is never given
// out twice. Deleting a node drops its id and its place in every approved
// set, so a machine enrolled later under the same node id is a new source
// that needs its own approval.
func (s *Store) EnsureBeaconSourceIDs(nodeIDs []string) (map[string]uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg := cloneBeaconRegistry(s.state.Beacon)
	if reg == nil {
		reg = &BeaconRegistry{}
	}
	if reg.SourceIDs == nil {
		reg.SourceIDs = map[string]uint32{}
	}
	if reg.NextSourceID == 0 {
		reg.NextSourceID = 1
	}
	out := make(map[string]uint32, len(nodeIDs))
	assigned := false
	for _, nodeID := range nodeIDs {
		if nodeID == "" {
			continue
		}
		id, ok := reg.SourceIDs[nodeID]
		if !ok {
			if _, exists := s.state.Nodes[nodeID]; !exists {
				continue
			}
			if reg.NextSourceID == 0 {
				return nil, errors.New("beacon source ids exhausted")
			}
			id = reg.NextSourceID
			reg.NextSourceID++
			reg.SourceIDs[nodeID] = id
			assigned = true
		}
		out[nodeID] = id
	}
	if !assigned {
		return out, nil
	}
	prior := s.state.Beacon
	s.state.Beacon = reg
	if err := s.Save(); err != nil {
		s.state.Beacon = prior
		return nil, err
	}
	return out, nil
}

// UpdateBeaconTarget runs fn on a copy of nodeID's beacon state (a zero one
// with exists false when there is none) and stores the copy when fn reports
// a change. The node must exist.
func (s *Store) UpdateBeaconTarget(nodeID string, fn func(t *BeaconTarget, exists bool) (bool, error)) (BeaconTarget, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Nodes[nodeID]; !ok {
		return BeaconTarget{}, fmt.Errorf("node %q not found", nodeID)
	}
	var current BeaconTarget
	exists := false
	if s.state.Beacon != nil {
		current, exists = s.state.Beacon.Targets[nodeID]
	}
	next := cloneBeaconTarget(current)
	next.NodeID = nodeID
	changed, err := fn(&next, exists)
	if err != nil || !changed {
		return cloneBeaconTarget(current), err
	}
	reg := cloneBeaconRegistry(s.state.Beacon)
	if reg == nil {
		reg = &BeaconRegistry{NextSourceID: 1}
	}
	if reg.Targets == nil {
		reg.Targets = map[string]BeaconTarget{}
	}
	reg.Targets[nodeID] = next
	prior := s.state.Beacon
	s.state.Beacon = reg
	if err := s.Save(); err != nil {
		s.state.Beacon = prior
		return BeaconTarget{}, err
	}
	return cloneBeaconTarget(next), nil
}

// ApplyBeaconApproval decides a node.beacon approval in one commit: the
// approval becomes approved, the node's beacon state becomes target (whose
// Version must be one above the stored one), the apply task of its NetGuard
// companion is queued when there is one, and the node's guard binding
// records the companion ruleset as its latest plan so NetGuard's own
// freshness checks agree with what is about to run. bindingVersion is the
// binding version the companion was compiled against.
func (s *Store) ApplyBeaconApproval(approval model.Approval, target BeaconTarget, task *model.Task, ruleset string, bindingVersion int64) (committed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	currentApproval, ok := s.state.Approvals[approval.ID]
	if !ok || currentApproval.Status != model.ApprovalPending ||
		currentApproval.NodeID != approval.NodeID || currentApproval.Plugin != approval.Plugin ||
		currentApproval.Action != approval.Action || currentApproval.Plan != approval.Plan {
		return false, ErrTaskTransitionConflict
	}
	if _, ok := s.state.Nodes[approval.NodeID]; !ok || target.NodeID != approval.NodeID {
		return false, ErrTaskTransitionConflict
	}
	var stored BeaconTarget
	if s.state.Beacon != nil {
		stored = s.state.Beacon.Targets[approval.NodeID]
	}
	if target.Version != stored.Version+1 {
		return false, ErrBeaconVersion
	}
	now := time.Now().UTC()
	staged := s.state
	if task != nil {
		if task.ID == "" || task.ApprovalID != approval.ID || len(task.Targets) != 1 || task.Targets[0] != approval.NodeID {
			return false, ErrTaskTransitionConflict
		}
		if _, exists := s.state.Tasks[task.ID]; exists {
			return false, ErrTaskTransitionConflict
		}
		binding, ok := s.state.GuardBindings[approval.NodeID]
		if !ok || !binding.Managed || binding.Version != bindingVersion || ruleset == "" {
			return false, ErrGuardVersionConflict
		}
		binding = cloneNodeGuardBinding(binding)
		binding.LastPlanSHA = fmt.Sprintf("%x", sha256.Sum256([]byte(ruleset)))
		binding.LastError = ""
		binding.Version++
		binding.UpdatedAt = now
		staged.GuardBindings = maps.Clone(s.state.GuardBindings)
		staged.GuardBindings[approval.NodeID] = binding
		t := *task
		if t.CreatedAt.IsZero() {
			t.CreatedAt = now
		}
		if t.Status == "" {
			t.Status = model.TaskQueued
		}
		staged.Tasks = maps.Clone(s.state.Tasks)
		staged.Tasks[t.ID] = t
	}
	approval.CreatedAt = currentApproval.CreatedAt
	approval.UpdatedAt = now
	staged.Approvals = maps.Clone(s.state.Approvals)
	staged.Approvals[approval.ID] = approval
	reg := cloneBeaconRegistry(s.state.Beacon)
	if reg == nil {
		reg = &BeaconRegistry{NextSourceID: 1}
	}
	if reg.Targets == nil {
		reg.Targets = map[string]BeaconTarget{}
	}
	reg.Targets[approval.NodeID] = cloneBeaconTarget(target)
	staged.Beacon = reg
	committed, err = s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return committed, err
}

// CompleteBeaconCompanionTask records the outcome of a node.beacon
// approval's NetGuard companion task: the approval becomes applied (or
// rejected with reason), and on success the guard binding records the
// managed table hash the agent reported, as a NetGuard apply does.
func (s *Store) CompleteBeaconCompanionTask(approvalID, rulesetSHA, managedSHA, reason string, finishedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	approval, ok := s.state.Approvals[approvalID]
	if !ok || approval.Plugin != model.BeaconApprovalPlugin {
		return ErrTaskNotFound
	}
	if approval.Status != model.ApprovalApproved {
		return nil
	}
	now := time.Now().UTC()
	staged := s.state
	staged.Approvals = maps.Clone(s.state.Approvals)
	if reason == "" {
		approval.Status = model.ApprovalApplied
		approval.Reason = ""
	} else {
		approval.Status = model.ApprovalRejected
		if len(reason) > 240 {
			reason = reason[:240]
		}
		approval.Reason = reason
	}
	approval.UpdatedAt = now
	staged.Approvals[approvalID] = approval
	if s.state.Beacon != nil {
		if t, ok := s.state.Beacon.Targets[approval.NodeID]; ok && t.AppliedApprovalID == approvalID && reason == "" && t.CompanionPending {
			reg := cloneBeaconRegistry(s.state.Beacon)
			t = cloneBeaconTarget(t)
			t.CompanionPending = false
			reg.Targets[approval.NodeID] = t
			staged.Beacon = reg
		}
	}
	if binding, ok := s.state.GuardBindings[approval.NodeID]; ok && strings.EqualFold(binding.LastPlanSHA, rulesetSHA) {
		binding = cloneNodeGuardBinding(binding)
		if reason == "" {
			binding.LastAppliedAt = finishedAt
			binding.AppliedTableSHA = managedSHA
			binding.LastError = ""
			// The companion recompiled the whole table, derived groups included.
			if node, ok := s.state.Nodes[approval.NodeID]; ok && binding.Managed {
				binding.AppliedDerived = derivedOf(s.derivedGuardGroupsLocked(node, binding.GroupIDs))
			}
		} else {
			binding.LastError = approval.Reason
		}
		binding.Version++
		binding.UpdatedAt = now
		staged.GuardBindings = maps.Clone(s.state.GuardBindings)
		staged.GuardBindings[approval.NodeID] = binding
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}

// SetNodeBeaconFacts stores the beacon report of a node's agent.
func (s *Store) SetNodeBeaconFacts(nodeID string, facts *model.BeaconFacts) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.state.Nodes[nodeID]
	if !ok {
		return fmt.Errorf("node %q not found", nodeID)
	}
	if facts == nil {
		n.Beacon = nil
	} else {
		f := *facts
		n.Beacon = &f
	}
	s.state.Nodes[nodeID] = n
	return s.Save()
}
