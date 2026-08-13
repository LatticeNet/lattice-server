package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	LineChainOperationSet    = "set"
	LineChainOperationRemove = "remove"

	LineChainStatusPlanned           = "planned"
	LineChainStatusApplying          = "applying"
	LineChainStatusAppliedUnobserved = "applied_unobserved"
	LineChainStatusConverged         = "converged"
	LineChainStatusDrifted           = "drifted"
	LineChainStatusFailed            = "failed"
)

var (
	ErrLineChainRevisionConflict = errors.New("line chain graph revision conflict")
	ErrLineChainCycle            = errors.New("line chain cycle")
	ErrLineChainSourceBusy       = errors.New("line chain source already has an active attempt")
	ErrLineChainAttemptNotFound  = errors.New("line chain attempt not found")
)

// LineChainDefinition is the committed host baseline. Target fields are empty
// only for a committed remove tombstone awaiting scheduled observation.
type LineChainDefinition struct {
	SourceLineUUID             string    `json:"source_line_uuid"`
	SourceNodeID               string    `json:"source_node_id"`
	SourceLineHashID           string    `json:"source_line_hash_id"`
	SourceInboundTag           string    `json:"source_inbound_tag"`
	TargetLineUUID             string    `json:"target_line_uuid,omitempty"`
	TargetNodeID               string    `json:"target_node_id,omitempty"`
	TargetDefinitionDigest     string    `json:"target_definition_digest,omitempty"`
	TargetPublicMaterialDigest string    `json:"target_public_material_digest,omitempty"`
	TargetCredentialDigest     string    `json:"target_credential_digest,omitempty"`
	OutboundTag                string    `json:"outbound_tag"`
	FragmentPath               string    `json:"fragment_path"`
	FragmentSHA256             string    `json:"fragment_sha256"`
	SidecarSHA256              string    `json:"sidecar_sha256"`
	ArtifactSHA256             string    `json:"artifact_sha256"`
	ApprovalID                 string    `json:"approval_id"`
	Status                     string    `json:"status"`
	DriftCode                  string    `json:"drift_code,omitempty"`
	Generation                 uint64    `json:"generation"`
	CreatedAt                  time.Time `json:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at"`
}

// LineChainAttempt is an in-flight candidate, stored separately so a failed
// replace/remove cannot overwrite the active committed edge.
type LineChainAttempt struct {
	ApprovalID              string              `json:"approval_id"`
	Operation               string              `json:"operation"`
	SourceLineUUID          string              `json:"source_line_uuid"`
	SourceNodeID            string              `json:"source_node_id"`
	CandidateTargetLineUUID string              `json:"candidate_target_line_uuid,omitempty"`
	CandidateTargetNodeID   string              `json:"candidate_target_node_id,omitempty"`
	BaseGeneration          uint64              `json:"base_generation"`
	BaseArtifactSHA256      string              `json:"base_artifact_sha256,omitempty"`
	CandidateArtifactSHA256 string              `json:"candidate_artifact_sha256,omitempty"`
	CandidateDefinition     LineChainDefinition `json:"candidate_definition"`
	RequestSHA256           string              `json:"request_sha256"`
	PlanGraphRevision       uint64              `json:"plan_graph_revision"`
	QueuedGraphRevision     uint64              `json:"queued_graph_revision,omitempty"`
	FirstLeaseGraphRevision uint64              `json:"first_lease_graph_revision,omitempty"`
	IssuedTaskID            string              `json:"issued_task_id,omitempty"`
	IssuedLeaseID           string              `json:"issued_lease_id,omitempty"`
	IssuedScriptSHA256      string              `json:"issued_script_sha256,omitempty"`
	IssuedArtifactSHA256    string              `json:"issued_artifact_sha256,omitempty"`
	Status                  string              `json:"status"`
	LastErrorCode           string              `json:"last_error_code,omitempty"`
	LastError               string              `json:"last_error,omitempty"`
	CreatedAt               time.Time           `json:"created_at"`
	UpdatedAt               time.Time           `json:"updated_at"`
}

type LineChainSnapshot struct {
	Definitions map[string]LineChainDefinition
	Attempts    map[string]LineChainAttempt
	Revision    uint64
}

// LineChainCompileStateSnapshot is the persistent half of the compiler input.
// It is copied under one store lock and is safe for server-side projection
// without further store reads or identity allocation.
type LineChainCompileStateSnapshot struct {
	Nodes              map[string]model.Node
	LineUUIDByHash     map[string]string
	VpnUsers           map[string]VpnUserPublicRecord
	VpnUserSecrets     map[string]VpnUserSecretRecord
	ManagedLines       map[string]ManagedLinePublicRecord
	ManagedLineSecrets map[string]ManagedLineSecretRecord
	Chains             LineChainSnapshot
}

func (s *Store) LineChainCompileStateSnapshot() LineChainCompileStateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lineChainCompileStateSnapshotLocked()
}

func (s *Store) lineChainCompileStateSnapshotLocked() LineChainCompileStateSnapshot {
	nodes := make(map[string]model.Node, len(s.state.Nodes))
	for id, node := range s.state.Nodes {
		nodes[id] = cloneNode(node)
	}
	uuidByHash := make(map[string]string)
	for _, entry := range s.state.KV {
		if entry.Bucket == "vpnmeta/lineuuid" {
			uuidByHash[entry.Key] = entry.Value
		}
	}
	return LineChainCompileStateSnapshot{
		Nodes: nodes, LineUUIDByHash: uuidByHash,
		VpnUsers: cloneVpnUserPublicRecords(s.state.VpnUsers), VpnUserSecrets: cloneVpnUserSecretRecords(s.state.VpnUserSecrets),
		ManagedLines: cloneManagedLinePublicRecords(s.state.ManagedLines), ManagedLineSecrets: cloneManagedLineSecretRecords(s.state.ManagedLineSecrets),
		Chains: LineChainSnapshot{Definitions: cloneLineChainDefinitions(s.state.LineChainDefinitions), Attempts: cloneLineChainAttempts(s.state.LineChainAttempts), Revision: s.state.LineChainGraphRevision},
	}
}

// WouldCreateLineChainCycle evaluates a candidate against every committed edge
// and every already-reserved applying candidate from the supplied immutable
// snapshot. Planned attempts do not reserve graph membership.
func WouldCreateLineChainCycle(snapshot LineChainSnapshot, sourceLineUUID, targetLineUUID string) bool {
	attempts := cloneLineChainAttempts(snapshot.Attempts)
	attempts["candidate"] = LineChainAttempt{
		ApprovalID: "candidate", SourceLineUUID: sourceLineUUID,
		CandidateTargetLineUUID: targetLineUUID, Operation: LineChainOperationSet,
		Status: LineChainStatusApplying,
	}
	return lineChainGraphHasCycle(snapshot.Definitions, attempts)
}

func cloneLineChainDefinitions(in map[string]LineChainDefinition) map[string]LineChainDefinition {
	out := make(map[string]LineChainDefinition, len(in))
	for id, definition := range in {
		out[id] = definition
	}
	return out
}

func cloneLineChainAttempts(in map[string]LineChainAttempt) map[string]LineChainAttempt {
	out := make(map[string]LineChainAttempt, len(in))
	for id, attempt := range in {
		out[id] = attempt
	}
	return out
}

func (s *Store) LineChainSnapshot() LineChainSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return LineChainSnapshot{
		Definitions: cloneLineChainDefinitions(s.state.LineChainDefinitions),
		Attempts:    cloneLineChainAttempts(s.state.LineChainAttempts),
		Revision:    s.state.LineChainGraphRevision,
	}
}

func validateLineChainAttempt(attempt LineChainAttempt) error {
	if strings.TrimSpace(attempt.ApprovalID) == "" || strings.TrimSpace(attempt.SourceLineUUID) == "" {
		return errors.New("line chain approval_id and source_line_uuid are required")
	}
	if attempt.Operation != LineChainOperationSet && attempt.Operation != LineChainOperationRemove {
		return fmt.Errorf("unsupported line chain operation %q", attempt.Operation)
	}
	if attempt.Operation == LineChainOperationSet && strings.TrimSpace(attempt.CandidateTargetLineUUID) == "" {
		return errors.New("set line chain requires a target")
	}
	if attempt.Operation == LineChainOperationRemove && strings.TrimSpace(attempt.CandidateTargetLineUUID) != "" {
		return errors.New("remove line chain must not carry a target")
	}
	if attempt.SourceLineUUID == attempt.CandidateTargetLineUUID {
		return ErrLineChainCycle
	}
	return nil
}

// PlanLineChain persists one planned attempt without reserving graph membership
// or incrementing the global revision.
func (s *Store) PlanLineChain(attempt LineChainAttempt) (LineChainAttempt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planLineChainLocked(attempt, nil)
}

// PlanLineChainApproval persists the typed approval and candidate together.
func (s *Store) PlanLineChainApproval(attempt LineChainAttempt, approval model.Approval) (LineChainAttempt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planLineChainLocked(attempt, &approval)
}

func (s *Store) planLineChainLocked(attempt LineChainAttempt, approval *model.Approval) (LineChainAttempt, bool, error) {
	if err := validateLineChainAttempt(attempt); err != nil {
		return LineChainAttempt{}, false, err
	}
	if attempt.PlanGraphRevision != s.state.LineChainGraphRevision {
		return LineChainAttempt{}, false, ErrLineChainRevisionConflict
	}
	current := s.state.LineChainDefinitions[attempt.SourceLineUUID]
	if current.Generation != attempt.BaseGeneration || current.ArtifactSHA256 != attempt.BaseArtifactSHA256 {
		return LineChainAttempt{}, false, ErrLineChainRevisionConflict
	}
	for approvalID, current := range s.state.LineChainAttempts {
		if current.SourceLineUUID != attempt.SourceLineUUID || current.Status == LineChainStatusFailed {
			continue
		}
		if current.RequestSHA256 == attempt.RequestSHA256 && current.Operation == attempt.Operation &&
			current.CandidateTargetLineUUID == attempt.CandidateTargetLineUUID {
			return current, true, nil
		}
		return LineChainAttempt{}, false, fmt.Errorf("%w: source %s has approval %s", ErrLineChainSourceBusy, attempt.SourceLineUUID, approvalID)
	}
	now := time.Now().UTC()
	attempt.Status = LineChainStatusPlanned
	if attempt.CreatedAt.IsZero() {
		attempt.CreatedAt = now
	}
	attempt.UpdatedAt = now
	staged := s.state
	staged.LineChainAttempts = cloneLineChainAttempts(s.state.LineChainAttempts)
	staged.LineChainAttempts[attempt.ApprovalID] = attempt
	if approval != nil {
		if approval.ID != attempt.ApprovalID || approval.Status != model.ApprovalPending {
			return LineChainAttempt{}, false, errors.New("line chain approval does not match planned attempt")
		}
		staged.Approvals = make(map[string]model.Approval, len(s.state.Approvals)+1)
		for id, current := range s.state.Approvals {
			staged.Approvals[id] = current
		}
		staged.Approvals[approval.ID] = *approval
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return attempt, false, err
}

// ReserveLineChain performs the exact approval-time R -> R+1 graph CAS.
func (s *Store) ReserveLineChain(approvalID string, expectedRevision uint64) (LineChainAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.LineChainGraphRevision != expectedRevision {
		return LineChainAttempt{}, ErrLineChainRevisionConflict
	}
	attempt, ok := s.state.LineChainAttempts[approvalID]
	if !ok || attempt.Status != LineChainStatusPlanned || attempt.PlanGraphRevision != expectedRevision {
		return LineChainAttempt{}, ErrLineChainAttemptNotFound
	}
	definitions := cloneLineChainDefinitions(s.state.LineChainDefinitions)
	attempts := cloneLineChainAttempts(s.state.LineChainAttempts)
	attempt.Status = LineChainStatusApplying
	attempt.QueuedGraphRevision = expectedRevision + 1
	attempt.UpdatedAt = time.Now().UTC()
	attempts[approvalID] = attempt
	if lineChainGraphHasCycle(definitions, attempts) {
		return LineChainAttempt{}, ErrLineChainCycle
	}
	staged := s.state
	staged.LineChainAttempts = attempts
	staged.LineChainGraphRevision = expectedRevision + 1
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return attempt, err
}

// ApproveLineChain atomically changes the reviewed approval and attempt to
// applying, reserves the candidate graph edge, queues exactly one bound task,
// and advances R to R+1 in one persistence transaction.
func (s *Store) ApproveLineChain(approval model.Approval, task model.Task) (LineChainAttempt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	currentApproval, ok := s.state.Approvals[approval.ID]
	if !ok || currentApproval.Status != model.ApprovalPending || approval.Status != model.ApprovalApproved ||
		currentApproval.Plugin != approval.Plugin || currentApproval.Service != approval.Service || currentApproval.Method != approval.Method ||
		currentApproval.Action != approval.Action || currentApproval.Plan != approval.Plan || currentApproval.RequestSHA256 != approval.RequestSHA256 {
		return LineChainAttempt{}, false, ErrTaskTransitionConflict
	}
	attempt, ok := s.state.LineChainAttempts[approval.ID]
	if !ok || attempt.Status != LineChainStatusPlanned || attempt.PlanGraphRevision != s.state.LineChainGraphRevision {
		return LineChainAttempt{}, false, ErrLineChainRevisionConflict
	}
	currentDefinition := s.state.LineChainDefinitions[attempt.SourceLineUUID]
	if currentDefinition.Generation != attempt.BaseGeneration || currentDefinition.ArtifactSHA256 != attempt.BaseArtifactSHA256 {
		return LineChainAttempt{}, false, ErrLineChainRevisionConflict
	}
	if task.ID == "" || task.ApprovalID != approval.ID || len(task.Targets) != 1 || task.Targets[0] != attempt.SourceNodeID ||
		strings.TrimSpace(task.Script) == "" || approval.ArtifactDigest == "" || approval.ArtifactDigest != attempt.CandidateArtifactSHA256 {
		return LineChainAttempt{}, false, ErrTaskTransitionConflict
	}
	for _, existing := range s.state.Tasks {
		if existing.ApprovalID == approval.ID {
			return LineChainAttempt{}, false, ErrTaskTransitionConflict
		}
	}
	attempts := cloneLineChainAttempts(s.state.LineChainAttempts)
	attempt.Status = LineChainStatusApplying
	attempt.QueuedGraphRevision = s.state.LineChainGraphRevision + 1
	attempt.UpdatedAt = time.Now().UTC()
	attempts[approval.ID] = attempt
	if lineChainGraphHasCycle(s.state.LineChainDefinitions, attempts) {
		return LineChainAttempt{}, false, ErrLineChainCycle
	}
	staged := s.state
	staged.LineChainAttempts = attempts
	staged.LineChainGraphRevision = attempt.QueuedGraphRevision
	staged.Approvals = make(map[string]model.Approval, len(s.state.Approvals))
	for id, value := range s.state.Approvals {
		staged.Approvals[id] = value
	}
	approval.CreatedAt = currentApproval.CreatedAt
	approval.UpdatedAt = attempt.UpdatedAt
	staged.Approvals[approval.ID] = approval
	staged.Tasks = make(map[string]model.Task, len(s.state.Tasks)+1)
	for id, value := range s.state.Tasks {
		staged.Tasks[id] = value
	}
	if task.CreatedAt.IsZero() {
		task.CreatedAt = attempt.UpdatedAt
	}
	if task.Status == "" {
		task.Status = model.TaskQueued
	}
	staged.Tasks[task.ID] = task
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return attempt, committed, err
}

// CompleteLineChainTaskResult durably records the exact issued lease result and
// promotes (or fails) its candidate in one graph revision transition.
func (s *Store) CompleteLineChainTaskResult(r model.TaskResult, approval model.Approval, terminalStatus, errorCode, terminalError string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	task, ok := s.state.Tasks[r.TaskID]
	if !ok || task.ApprovalID != approval.ID || !taskLeaseMatches(task, r.NodeID, r.LeaseID) {
		return false, ErrTaskLeaseMismatch
	}
	attempt, ok := s.state.LineChainAttempts[approval.ID]
	if !ok || attempt.Status != LineChainStatusApplying || attempt.IssuedTaskID != task.ID || attempt.IssuedLeaseID != r.LeaseID ||
		attempt.IssuedScriptSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(task.Script))) || attempt.IssuedArtifactSHA256 != approval.ArtifactDigest {
		return false, ErrTaskTransitionConflict
	}
	now := time.Now().UTC()
	stored := r
	stored.LeaseID = ""
	if stored.FinishedAt.IsZero() {
		stored.FinishedAt = now
	}
	staged := s.state
	staged.Results = append(append([]model.TaskResult(nil), s.state.Results...), stored)
	if len(staged.Results) > maxTaskResults {
		staged.Results = append([]model.TaskResult(nil), staged.Results[len(staged.Results)-maxTaskResults:]...)
	}
	staged.Tasks = make(map[string]model.Task, len(s.state.Tasks))
	for id, value := range s.state.Tasks {
		staged.Tasks[id] = value
	}
	task.Status, task.FinishedAt = taskAggregateStatus(task, staged.Results)
	staged.Tasks[task.ID] = task
	staged.Approvals = make(map[string]model.Approval, len(s.state.Approvals))
	for id, value := range s.state.Approvals {
		staged.Approvals[id] = value
	}
	approval.CreatedAt = s.state.Approvals[approval.ID].CreatedAt
	approval.UpdatedAt = now
	staged.LineChainAttempts = cloneLineChainAttempts(s.state.LineChainAttempts)
	staged.LineChainDefinitions = cloneLineChainDefinitions(s.state.LineChainDefinitions)
	success := r.ExitCode == 0 && r.Error == ""
	if success {
		approval.Status, approval.Reason = model.ApprovalApplied, ""
		definition := attempt.CandidateDefinition
		definition.ApprovalID = approval.ID
		definition.Generation = attempt.BaseGeneration + 1
		definition.CreatedAt = s.state.LineChainDefinitions[attempt.SourceLineUUID].CreatedAt
		if definition.CreatedAt.IsZero() {
			definition.CreatedAt = now
		}
		definition.UpdatedAt, definition.Status, definition.DriftCode = now, terminalStatus, errorCode
		staged.LineChainDefinitions[attempt.SourceLineUUID] = definition
		delete(staged.LineChainAttempts, approval.ID)
	} else {
		approval.Status, approval.Reason = model.ApprovalApplied, "execution failed"
		attempt.Status, attempt.LastErrorCode, attempt.LastError, attempt.UpdatedAt = LineChainStatusFailed, errorCode, terminalError, now
		staged.LineChainAttempts[approval.ID] = attempt
	}
	staged.Approvals[approval.ID] = approval
	staged.LineChainGraphRevision++
	staged.TaskResultReceipts = cloneTaskResultReceipts(s.state.TaskResultReceipts)
	receiptResult := stored
	receiptResult.LeaseID = r.LeaseID
	staged.TaskResultReceipts[taskResultReceiptKey(r.TaskID, r.NodeID)] = taskResultReceipt(receiptResult)
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return committed, err
}

func lineChainGraphHasCycle(definitions map[string]LineChainDefinition, attempts map[string]LineChainAttempt) bool {
	edges := make(map[string][]string)
	for source, definition := range definitions {
		if definition.TargetLineUUID != "" {
			edges[source] = append(edges[source], definition.TargetLineUUID)
		}
	}
	for _, attempt := range attempts {
		if attempt.Status == LineChainStatusApplying && attempt.CandidateTargetLineUUID != "" {
			edges[attempt.SourceLineUUID] = append(edges[attempt.SourceLineUUID], attempt.CandidateTargetLineUUID)
		}
	}
	state := make(map[string]uint8)
	var visit func(string) bool
	visit = func(node string) bool {
		if state[node] == 1 {
			return true
		}
		if state[node] == 2 {
			return false
		}
		state[node] = 1
		for _, target := range edges[node] {
			if visit(target) {
				return true
			}
		}
		state[node] = 2
		return false
	}
	nodes := make([]string, 0, len(edges))
	for node := range edges {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		if visit(node) {
			return true
		}
	}
	return false
}
