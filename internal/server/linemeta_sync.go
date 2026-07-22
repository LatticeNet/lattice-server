package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// design-15 D2/§4: sidecar delivery wiring. The renderer and the reviewed task
// shape landed with linemeta.go; this file connects them to the approval
// pipeline. A sync (manual via lines.sync_metadata, or queued automatically
// when a node's discovered line set changes) creates a pending approval whose
// Plan IS the metadata document — it carries no secrets, so review shows the
// operator the exact bytes that will land on the box. The apply script
// re-verifies the plan hash at execution and fails closed on any drift.
const (
	// singBoxLineMetaPlugin routes metadata approvals through
	// lineMetaApplyScript / handleLineMetaTaskResult.
	singBoxLineMetaPlugin     = "singbox-linemeta"
	lineMetaApplyActionPrefix = "apply-metadata:"
)

func lineMetaSHA(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// vpnCoreLinesSyncMetadata queues one sidecar apply for review. It is
// idempotent: an identical pending approval (same node, same metadata bytes)
// is returned instead of duplicated.
func (s *Server) vpnCoreLinesSyncMetadata(p principal, request []byte) ([]byte, error) {
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, fmt.Errorf("vpn-core/lines sync_metadata: invalid request: %w", err)
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return nil, errors.New("vpn-core/lines sync_metadata: node_id is required")
	}
	return s.queueLineMetaSync(p, nodeID)
}

// queueLineMetaSync renders the node's sidecar and records a pending approval
// for it (or returns the identical pending one). The operator still approves
// every byte — queuing never applies.
func (s *Server) queueLineMetaSync(p principal, nodeID string) ([]byte, error) {
	payload, err := s.renderLineMetadataJSON(nodeID)
	if err != nil {
		return nil, err
	}
	action := lineMetaApplyActionPrefix + lineMetaSHA(payload)
	for _, ap := range s.store.Approvals() {
		if ap.Plugin == singBoxLineMetaPlugin && ap.NodeID == nodeID &&
			ap.Action == action && ap.Status == model.ApprovalPending {
			return json.Marshal(struct {
				Approval model.Approval `json:"approval"`
				Queued   bool           `json:"queued"`
			}{Approval: ap, Queued: false})
		}
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    nodeID,
		Plugin:    singBoxLineMetaPlugin,
		Action:    action,
		Plan:      string(payload),
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		return nil, err
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: nodeID, Action: "linemeta.sync", Scope: "proxy:admin",
		Metadata: map[string]string{"approval_id": approval.ID, "metadata_sha256": strings.TrimPrefix(action, lineMetaApplyActionPrefix)},
	})
	return json.Marshal(struct {
		Approval model.Approval `json:"approval"`
		Queued   bool           `json:"queued"`
	}{Approval: approval, Queued: true})
}

// maybeQueueLineMetaSyncOnDiscovery queues a metadata sync when the node's
// discovered line set changed since the last queued report (tracked by its own
// fingerprint map, independent of the 6h audit throttle). Queueing is
// system-actor, idempotent, and still requires operator approval — discovery
// itself never mutates a node.
func (s *Server) maybeQueueLineMetaSyncOnDiscovery(nodeID string, inv model.SingBoxInventory) {
	if len(inv.Nodes) == 0 || inv.Status == "error" {
		return
	}
	fingerprint := singBoxDiscoveryFingerprint(inv)
	s.linemetaSyncMu.Lock()
	if s.linemetaSyncFP == nil {
		s.linemetaSyncFP = map[string]string{}
	}
	prev, seen := s.linemetaSyncFP[nodeID]
	if seen && prev == fingerprint {
		s.linemetaSyncMu.Unlock()
		return // unchanged inventory: nothing new to describe on-box
	}
	s.linemetaSyncFP[nodeID] = fingerprint
	s.linemetaSyncMu.Unlock()
	if _, err := s.queueLineMetaSync(principal{Principal: rbac.Principal{ActorID: "system"}}, nodeID); err != nil {
		s.logger.Printf("linemeta: queue sync for %s: %v", nodeID, err)
	}
}

// lineMetaApplyScript renders the atomic on-box sidecar write for an approved
// plan, re-verifying that the plan bytes are exactly the approved ones.
func (s *Server) lineMetaApplyScript(approval model.Approval) string {
	fail := func(err error) string {
		return "set -e\n" +
			"echo " + shellQuote("lattice linemeta: "+err.Error()) + " >&2\n" +
			"exit 1\n"
	}
	if !strings.HasPrefix(approval.Action, lineMetaApplyActionPrefix) {
		return fail(fmt.Errorf("invalid approval action %q", approval.Action))
	}
	want := strings.TrimPrefix(approval.Action, lineMetaApplyActionPrefix)
	if lineMetaSHA([]byte(approval.Plan)) != want {
		return fail(errors.New("plan bytes changed since approval; re-queue the sync"))
	}
	return lineMetadataApplyScript([]byte(approval.Plan))
}

// handleLineMetaTaskResult reconciles a metadata approval once the agent
// reports back, mirroring the line-user ladder.
func (s *Server) handleLineMetaTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	metadata := map[string]string{
		"approval_id": approval.ID, "task_id": task.ID, "plugin_id": approval.Plugin,
	}
	if result.Error != "" || result.ExitCode != 0 {
		reason := result.Error
		if reason == "" {
			reason = fmt.Sprintf("linemeta task exited %d", result.ExitCode)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: approval.NodeID, Action: "linemeta.sync.failed",
			Decision: "deny", Reason: reason, Metadata: metadata,
		})
		return nil
	}
	approval.Status = model.ApprovalApplied
	approval.Reason = ""
	approval.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertApproval(approval); err != nil {
		return fmt.Errorf("mark linemeta approval applied: %w", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), NodeID: approval.NodeID, Action: "linemeta.sync.applied",
		Decision: "allow", Metadata: metadata,
	})
	return nil
}
