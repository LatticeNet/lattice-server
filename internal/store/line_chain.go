package store

import (
	"crypto/sha256"
	"encoding/json"
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
	SidecarPatchSHA256         string    `json:"sidecar_patch_sha256"`
	ArtifactSHA256             string    `json:"artifact_sha256"`
	ApprovalID                 string    `json:"approval_id"`
	TaskID                     string    `json:"task_id,omitempty"`
	ActorID                    string    `json:"actor_id,omitempty"`
	TokenID                    string    `json:"token_id,omitempty"`
	AuditTargetLineUUID        string    `json:"audit_target_line_uuid,omitempty"`
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

type LineChainObservation struct {
	OutboundTag        string
	DownstreamLineUUID string
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

func stageLineChainAuditEvidence(staged *State, current State, audits []model.AuditEvent) error {
	staged.LineChainAuditEvidence = make(map[string]model.AuditEvent, len(current.LineChainAuditEvidence)+len(audits))
	for id, event := range current.LineChainAuditEvidence {
		staged.LineChainAuditEvidence[id] = event
	}
	for _, event := range audits {
		if event.ID == "" || event.At.IsZero() || event.Decision == "" {
			return errors.New("line chain audit evidence requires id, at, and decision")
		}
		if existing, ok := staged.LineChainAuditEvidence[event.ID]; ok {
			left, _ := json.Marshal(existing)
			right, _ := json.Marshal(event)
			if string(left) != string(right) {
				return fmt.Errorf("line chain audit id %q conflicts with frozen evidence", event.ID)
			}
			continue
		}
		staged.LineChainAuditEvidence[event.ID] = event
	}
	return nil
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

// ReconcileLineChains advances committed set/replace definitions and remove
// tombstones from host-applied state using scheduled inventory evidence.
func (s *Store) ReconcileLineChains(observations map[string]LineChainObservation) (bool, error) {
	return s.ReconcileLineChainsWithAudits(observations, nil)
}

// ReconcileLineChainsWithAudits freezes evidence in the same authoritative
// JSON commit as its observed definition status transition.
func (s *Store) ReconcileLineChainsWithAudits(observations map[string]LineChainObservation, auditFor func(LineChainDefinition) (model.AuditEvent, bool)) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	definitions := cloneLineChainDefinitions(s.state.LineChainDefinitions)
	now, changed := time.Now().UTC(), false
	audits := []model.AuditEvent{}
	for sourceUUID, observation := range observations {
		definition, ok := definitions[sourceUUID]
		if !ok {
			continue
		}
		status, driftCode := LineChainStatusDrifted, "observed_mismatch"
		if definition.TargetLineUUID == "" {
			if observation.OutboundTag == "" && observation.DownstreamLineUUID == "" {
				status, driftCode = LineChainStatusConverged, ""
			} else {
				driftCode = "remove_artifacts_present"
			}
		} else if observation.OutboundTag == definition.OutboundTag && observation.DownstreamLineUUID == definition.TargetLineUUID {
			status, driftCode = LineChainStatusConverged, ""
		}
		if definition.Status == status && definition.DriftCode == driftCode {
			continue
		}
		definition.Status, definition.DriftCode, definition.UpdatedAt = status, driftCode, now
		definitions[sourceUUID], changed = definition, true
		if auditFor != nil {
			if event, ok := auditFor(definition); ok {
				audits = append(audits, event)
			}
		}
	}
	if !changed {
		return false, nil
	}
	staged := s.state
	staged.LineChainDefinitions = definitions
	if err := stageLineChainAuditEvidence(&staged, s.state, audits); err != nil {
		return false, err
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return committed, err
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
func (s *Store) PlanLineChainApproval(attempt LineChainAttempt, approval model.Approval, audits ...model.AuditEvent) (LineChainAttempt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planLineChainLocked(attempt, &approval, audits...)
}

func (s *Store) planLineChainLocked(attempt LineChainAttempt, approval *model.Approval, audits ...model.AuditEvent) (LineChainAttempt, bool, error) {
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
	for approvalID, prior := range staged.LineChainAttempts {
		if prior.SourceLineUUID == attempt.SourceLineUUID && prior.Status == LineChainStatusFailed {
			delete(staged.LineChainAttempts, approvalID)
		}
	}
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
	if err := stageLineChainAuditEvidence(&staged, s.state, audits); err != nil {
		return LineChainAttempt{}, false, err
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

// RejectLineChainApprovalStale atomically retires a planned candidate whose
// bound inputs changed during approval-time recompile. Planned candidates have
// not reserved graph membership, so this transition never increments R.
func (s *Store) RejectLineChainApprovalStale(approvalID, staleCode, reason string, audits ...model.AuditEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejectLineChainApprovalLocked(approvalID, true, staleCode, reason, audits)
}

// RejectLineChainApproval atomically retires a manually rejected candidate.
func (s *Store) RejectLineChainApproval(approvalID, reason string, audits ...model.AuditEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rejectLineChainApprovalLocked(approvalID, false, "approval_rejected", reason, audits)
}

func (s *Store) rejectLineChainApprovalLocked(approvalID string, stale bool, staleCode, reason string, audits []model.AuditEvent) (bool, error) {
	approval, ok := s.state.Approvals[approvalID]
	if !ok || approval.Status != model.ApprovalPending {
		return false, ErrTaskTransitionConflict
	}
	attempt, ok := s.state.LineChainAttempts[approvalID]
	if !ok || attempt.Status != LineChainStatusPlanned || attempt.QueuedGraphRevision != 0 || attempt.IssuedLeaseID != "" {
		return false, ErrTaskTransitionConflict
	}
	now := time.Now().UTC()
	staged := s.state
	staged.Approvals = make(map[string]model.Approval, len(s.state.Approvals))
	for id, current := range s.state.Approvals {
		staged.Approvals[id] = current
	}
	approval.Status, approval.Stale, approval.StaleCode = model.ApprovalRejected, stale, staleCode
	approval.Reason, approval.UpdatedAt = reason, now
	staged.Approvals[approvalID] = approval
	staged.LineChainAttempts = cloneLineChainAttempts(s.state.LineChainAttempts)
	attempt.Status, attempt.LastErrorCode, attempt.LastError, attempt.UpdatedAt = LineChainStatusFailed, staleCode, reason, now
	staged.LineChainAttempts[approvalID] = attempt
	staged.Tasks = make(map[string]model.Task, len(s.state.Tasks))
	for id, task := range s.state.Tasks {
		if task.ApprovalID == approvalID {
			task.Status = model.TaskCancelled
		}
		staged.Tasks[id] = task
	}
	if err := stageLineChainAuditEvidence(&staged, s.state, audits); err != nil {
		return false, err
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return committed, err
}

// ApproveLineChain atomically changes the reviewed approval and attempt to
// applying, reserves the candidate graph edge, queues exactly one bound task,
// and advances R to R+1 in one persistence transaction.
func (s *Store) ApproveLineChain(approval model.Approval, task model.Task, audits ...model.AuditEvent) (LineChainAttempt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	failureAudits := []model.AuditEvent(nil)
	if len(audits) > 1 {
		failureAudits = audits[1:]
		audits = audits[:1]
	}
	currentApproval, ok := s.state.Approvals[approval.ID]
	if !ok || currentApproval.Status != model.ApprovalPending || approval.Status != model.ApprovalApproved ||
		currentApproval.Plugin != approval.Plugin || currentApproval.Service != approval.Service || currentApproval.Method != approval.Method ||
		currentApproval.Action != approval.Action || currentApproval.Plan != approval.Plan || currentApproval.RequestSHA256 != approval.RequestSHA256 {
		return LineChainAttempt{}, false, ErrTaskTransitionConflict
	}
	attempt, ok := s.state.LineChainAttempts[approval.ID]
	if !ok || attempt.Status != LineChainStatusPlanned || attempt.PlanGraphRevision != s.state.LineChainGraphRevision {
		if ok && attempt.Status == LineChainStatusPlanned {
			committed, err := s.rejectLineChainApprovalLocked(approval.ID, true, "line_chain_inputs_changed", "line chain graph revision changed while queueing", failureAudits)
			if err != nil {
				return LineChainAttempt{}, committed, err
			}
			return LineChainAttempt{}, committed, ErrLineChainRevisionConflict
		}
		return LineChainAttempt{}, false, ErrLineChainRevisionConflict
	}
	currentDefinition := s.state.LineChainDefinitions[attempt.SourceLineUUID]
	if currentDefinition.Generation != attempt.BaseGeneration || currentDefinition.ArtifactSHA256 != attempt.BaseArtifactSHA256 {
		committed, err := s.rejectLineChainApprovalLocked(approval.ID, true, "line_chain_inputs_changed", "line chain baseline changed while queueing", failureAudits)
		if err != nil {
			return LineChainAttempt{}, committed, err
		}
		return LineChainAttempt{}, committed, ErrLineChainRevisionConflict
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
		committed, err := s.rejectLineChainApprovalLocked(approval.ID, true, "line_chain_cycle", "line chain candidate would create a cycle", failureAudits)
		if err != nil {
			return LineChainAttempt{}, committed, err
		}
		return LineChainAttempt{}, committed, ErrLineChainCycle
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
	if err := stageLineChainAuditEvidence(&staged, s.state, audits); err != nil {
		return LineChainAttempt{}, false, err
	}
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return attempt, committed, err
}

// CompleteLineChainTaskResult durably records the exact issued lease result and
// promotes (or fails) its candidate in one graph revision transition.
func (s *Store) CompleteLineChainTaskResult(r model.TaskResult, approval model.Approval, terminalStatus, errorCode, terminalError string, audits ...model.AuditEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completeLineChainTaskResultLocked(r, approval, terminalStatus, errorCode, terminalError, nil, nil, audits)
}

// CompleteLineChainTaskResultClassified runs success drift classification from
// one current persistent snapshot while holding the same lock through receipt
// and definition promotion. auditFor freezes evidence from that exact result.
func (s *Store) CompleteLineChainTaskResultClassified(r model.TaskResult, approval model.Approval, terminalError string,
	classifier func(LineChainCompileStateSnapshot, LineChainAttempt) (string, string, func(), error),
	auditFor func(string, string) model.AuditEvent,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completeLineChainTaskResultLocked(r, approval, LineChainStatusAppliedUnobserved, "host_apply_failed", terminalError, classifier, auditFor, nil)
}

func (s *Store) completeLineChainTaskResultLocked(r model.TaskResult, approval model.Approval, terminalStatus, errorCode, terminalError string,
	classifier func(LineChainCompileStateSnapshot, LineChainAttempt) (string, string, func(), error), auditFor func(string, string) model.AuditEvent, audits []model.AuditEvent,
) (bool, error) {
	task, ok := s.state.Tasks[r.TaskID]
	if !ok || task.ApprovalID != approval.ID || !taskLeaseMatches(task, r.NodeID, r.LeaseID) {
		return false, ErrTaskLeaseMismatch
	}
	storedApproval, ok := s.state.Approvals[approval.ID]
	if !ok || storedApproval.Status != model.ApprovalApproved || storedApproval.Plugin != "singbox-linechain" || storedApproval.Service != "network/lines" ||
		(storedApproval.Method != "chain_set_apply" && storedApproval.Method != "chain_remove_apply") || !strings.HasPrefix(storedApproval.Action, "apply-line-chain:") ||
		storedApproval.Action != approval.Action || storedApproval.Plan != approval.Plan || storedApproval.ArtifactDigest != approval.ArtifactDigest ||
		storedApproval.RequestSHA256 != approval.RequestSHA256 || storedApproval.NodeID != approval.NodeID || storedApproval.PluginVersion != approval.PluginVersion ||
		len(storedApproval.Targets) != len(approval.Targets) {
		return false, ErrTaskTransitionConflict
	}
	attempt, ok := s.state.LineChainAttempts[approval.ID]
	if !ok || attempt.Status != LineChainStatusApplying || attempt.IssuedTaskID != task.ID || attempt.IssuedLeaseID != r.LeaseID ||
		attempt.ApprovalID != approval.ID || attempt.SourceNodeID != r.NodeID || attempt.IssuedScriptSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(task.Script))) ||
		attempt.IssuedArtifactSHA256 != storedApproval.ArtifactDigest || attempt.CandidateArtifactSHA256 != storedApproval.ArtifactDigest {
		return false, ErrTaskTransitionConflict
	}
	if len(storedApproval.Targets) != 1 || storedApproval.Targets[0] != attempt.SourceNodeID || approval.Targets[0] != attempt.SourceNodeID {
		return false, ErrTaskTransitionConflict
	}
	success := r.ExitCode == 0 && r.Error == ""
	if success && classifier != nil {
		var err error
		var release func()
		terminalStatus, errorCode, release, err = classifier(s.lineChainCompileStateSnapshotLocked(), attempt)
		if err != nil {
			if release != nil {
				release()
			}
			return false, err
		}
		if release != nil {
			defer release()
		}
	}
	if auditFor != nil {
		audits = append(audits, auditFor(terminalStatus, errorCode))
	}
	validDriftCode := errorCode == "inputs_changed" || errorCode == "target_missing" || errorCode == "source_missing"
	if len(terminalError) > 512 || (success && !((terminalStatus == LineChainStatusAppliedUnobserved && errorCode == "") || (terminalStatus == LineChainStatusDrifted && validDriftCode))) ||
		(!success && (errorCode != "host_apply_failed" || terminalError == "")) {
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
	approval = storedApproval
	approval.UpdatedAt = now
	staged.LineChainAttempts = cloneLineChainAttempts(s.state.LineChainAttempts)
	staged.LineChainDefinitions = cloneLineChainDefinitions(s.state.LineChainDefinitions)
	if success {
		approval.Status, approval.Reason = model.ApprovalApplied, ""
		definition := attempt.CandidateDefinition
		definition.ApprovalID = approval.ID
		definition.TaskID = task.ID
		definition.ActorID = task.ActorID
		definition.TokenID = task.TokenID
		definition.AuditTargetLineUUID = definition.TargetLineUUID
		if definition.AuditTargetLineUUID == "" {
			definition.AuditTargetLineUUID = s.state.LineChainDefinitions[attempt.SourceLineUUID].TargetLineUUID
		}
		definition.Generation = attempt.BaseGeneration + 1
		definition.CreatedAt = s.state.LineChainDefinitions[attempt.SourceLineUUID].CreatedAt
		if definition.CreatedAt.IsZero() {
			definition.CreatedAt = now
		}
		definition.UpdatedAt, definition.Status, definition.DriftCode = now, terminalStatus, errorCode
		staged.LineChainDefinitions[attempt.SourceLineUUID] = definition
		delete(staged.LineChainAttempts, approval.ID)
	} else {
		approval.Status, approval.Reason = model.ApprovalApproved, "execution failed; fresh plan required"
		attempt.Status, attempt.LastErrorCode, attempt.LastError, attempt.UpdatedAt = LineChainStatusFailed, errorCode, terminalError, now
		staged.LineChainAttempts[approval.ID] = attempt
	}
	staged.Approvals[approval.ID] = approval
	staged.LineChainGraphRevision++
	staged.TaskResultReceipts = cloneTaskResultReceipts(s.state.TaskResultReceipts)
	receiptResult := stored
	receiptResult.LeaseID = r.LeaseID
	staged.TaskResultReceipts[taskResultReceiptKey(r.TaskID, r.NodeID)] = taskResultReceipt(receiptResult)
	if err := stageLineChainAuditEvidence(&staged, s.state, audits); err != nil {
		return false, err
	}
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
