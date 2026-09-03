package server

import (
	"context"
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

func lineMetaSemanticSHA(payload []byte) string {
	// updated_at is observability, not sidecar intent. Excluding it keeps the
	// approval identity stable when an operator re-renders unchanged metadata.
	semantic := payload
	var doc map[string]json.RawMessage
	if json.Unmarshal(payload, &doc) == nil && string(doc["schema"]) == `"`+lineMetadataSchemaV2+`"` {
		delete(doc, "updated_at")
		if normalized, err := json.Marshal(doc); err == nil {
			semantic = normalized
		}
	}
	sum := sha256.Sum256(semantic)
	return hex.EncodeToString(sum[:])
}

// vpnCoreLinesSyncMetadata queues one sidecar apply for review. It is
// idempotent in both directions: an identical pending approval (same node, same
// metadata bytes) is returned instead of duplicated, and a render that matches
// what the node already has applied queues nothing at all.
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
	s.linemetaSyncMu.Lock()
	defer s.linemetaSyncMu.Unlock()
	return s.queueLineMetaSyncLocked(p, nodeID)
}

// queueLineMetaSyncLocked requires linemetaSyncMu. Serializing the scan and
// write guarantees at most one pending metadata approval per node even when a
// manual sync races discovery.
func (s *Server) queueLineMetaSyncLocked(p principal, nodeID string) ([]byte, error) {
	payload, err := s.renderLineMetadataJSON(nodeID)
	if err != nil {
		return nil, err
	}
	action := lineMetaApplyActionPrefix + lineMetaSHA(payload)
	semanticSHA := lineMetaSemanticSHA(payload)
	var pending *model.Approval
	// The newest plan this node actually has on disk. It is what decides whether
	// a fresh render is worth an operator's attention at all.
	var applied *model.Approval
	for _, ap := range s.store.Approvals() {
		if ap.Plugin != singBoxLineMetaPlugin || ap.NodeID != nodeID {
			continue
		}
		if ap.Status == model.ApprovalApplied {
			if applied == nil || ap.UpdatedAt.After(applied.UpdatedAt) {
				candidate := ap
				applied = &candidate
			}
			continue
		}
		if ap.Status != model.ApprovalPending {
			continue
		}
		if pending == nil {
			candidate := ap
			pending = &candidate
			continue
		}
		ap.Status = model.ApprovalRejected
		ap.Reason = "superseded by a newer line metadata plan"
		ap.UpdatedAt = s.now().UTC()
		if err := s.store.UpsertApproval(ap); err != nil {
			return nil, fmt.Errorf("reject superseded linemeta approval %s: %w", ap.ID, err)
		}
	}
	// A plan that would erase something the box already has is never worth
	// filing, whatever produced it. The render resolves downstream_node from a
	// fleet-wide walk of every node's lines, so a render that runs before the
	// other nodes have posted their inventory names no downstream at all, and
	// the resulting plan is strictly worse than the one already applied.
	// Approving it would write the loss to the box.
	//
	// The guard is deliberately here rather than at the render. "Is the fleet
	// view complete" cannot be decided: no node can be proven to have finished
	// posting. "Is this plan strictly worse than what is on the box" is decided
	// from the applied approval already loaded above, and it holds against every
	// cause of loss rather than the one cause we happen to have diagnosed.
	//
	// Refusing is safe on both call sites. The discovery path logs and leaves
	// its fingerprint uncommitted, so the next inventory post retries with a
	// warmer view; the operator path gets told which field would have gone.
	if applied != nil {
		if lost := lineMetaPlanRegression([]byte(applied.Plan), payload); lost != "" {
			return nil, fmt.Errorf("linemeta sync for %s would drop %s from the applied plan; "+
				"refusing to queue a sidecar that is worse than the one on the box", nodeID, lost)
		}
	}
	if pending != nil {
		queued := lineMetaSemanticSHA([]byte(pending.Plan)) != semanticSHA
		if !queued {
			// Keep the already-reviewed bytes when only updated_at changed.
			payload = []byte(pending.Plan)
			action = pending.Action
		}
		pending.Action = action
		pending.Plan = string(payload)
		pending.ActorID = p.ActorID
		pending.Reason = ""
		pending.UpdatedAt = s.now().UTC()
		// Re-persist even an identical pending record. A previous Save may have
		// failed after mutating the in-memory store, and retry must make it durable.
		if err := s.store.UpsertApproval(*pending); err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Approval model.Approval `json:"approval"`
			Queued   bool           `json:"queued"`
		}{Approval: *pending, Queued: queued})
	}
	// Nothing is pending, so this render would open a fresh review. Only do that
	// when it would actually change the box.
	//
	// The semantic hash already exists to ignore updated_at, but it was only
	// consulted against a PENDING approval. Once that approval was applied the
	// comparison had nothing left to compare against, so the next render queued
	// a brand new approval whose plan differed from the applied one by the
	// updated_at line alone. The discovery fingerprint that would have
	// suppressed the re-render lives in memory, so every server restart cleared
	// it and re-queued one no-op approval per node. Twenty-three nodes meant
	// twenty-three approvals reappearing after every deploy, none of which
	// described a real change.
	// Only the automatic path is suppressed. An operator who explicitly asks for
	// a sync may be repairing a box whose sidecar drifted from what the control
	// plane believes it applied, and answering "nothing to do" would take that
	// repair away.
	if p.ActorID == systemActorID && applied != nil && lineMetaSemanticSHA([]byte(applied.Plan)) == semanticSHA {
		return json.Marshal(struct {
			Approval model.Approval `json:"approval"`
			Queued   bool           `json:"queued"`
		}{Approval: *applied, Queued: false})
	}
	now := s.now().UTC()
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    nodeID,
		Plugin:    singBoxLineMetaPlugin,
		Action:    action,
		Plan:      string(payload),
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	// The plugin-RPC dispatch layer carries no request context; policy
	// evaluation here is synchronous and not request-bound.
	if _, err := s.submitApproval(context.Background(), approval); err != nil {
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

// lineMetaPlanRegression reports what a fresh plan would take away from the
// plan a node has already applied, or "" when it takes nothing away. It is a
// one-way test: a plan that adds or changes a value is fine, and only a value
// going from present to absent is refused.
//
// An entry disappearing entirely is NOT a regression, because removing a line
// is a legitimate thing to do and an operator must be able to. Every entry
// disappearing at once is, since that is a node with no lines in the read model
// rather than a node whose lines were all deleted; requiring a manual sync for
// the rare real case is the right trade.
//
// An applied plan that cannot be parsed yields "": there is nothing to compare
// against, and refusing every sync on a node with one corrupt approval would be
// worse than the loss this prevents.
func lineMetaPlanRegression(applied, fresh []byte) string {
	var was, now lineMetadataDocV2
	if json.Unmarshal(applied, &was) != nil || json.Unmarshal(fresh, &now) != nil {
		return ""
	}
	if len(was.Inbounds) > 0 && len(now.Inbounds) == 0 {
		return fmt.Sprintf("all %d inbound entries", len(was.Inbounds))
	}
	if was.NodeUUID != "" && now.NodeUUID == "" {
		return "node_uuid"
	}
	byTag := make(map[string]lineMetadataInboundV2, len(now.Inbounds))
	for _, ib := range now.Inbounds {
		byTag[ib.Tag] = ib
	}
	for _, before := range was.Inbounds {
		after, ok := byTag[before.Tag]
		if !ok {
			continue // the line is gone, which is a removal and not a loss
		}
		switch {
		case before.LineUUID != "" && after.LineUUID == "":
			return "line_uuid on " + before.Tag
		case before.LineHashID != "" && after.LineHashID == "":
			return "line_hash_id on " + before.Tag
		case before.Chain != nil && after.Chain == nil:
			return "the chain block on " + before.Tag
		}
		if before.Chain == nil || after.Chain == nil {
			continue
		}
		if before.Chain.DownstreamNode != "" && after.Chain.DownstreamNode == "" {
			return "chain.downstream_node on " + before.Tag
		}
		if hadDS := before.Chain.DownstreamLineUUID != nil && *before.Chain.DownstreamLineUUID != ""; hadDS {
			if after.Chain.DownstreamLineUUID == nil || *after.Chain.DownstreamLineUUID == "" {
				return "chain.downstream_line_uuid on " + before.Tag
			}
		}
	}
	return ""
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
	defer s.linemetaSyncMu.Unlock()
	if s.linemetaSyncFP == nil {
		s.linemetaSyncFP = map[string]string{}
	}
	prev, seen := s.linemetaSyncFP[nodeID]
	if seen && prev == fingerprint {
		return // unchanged inventory: nothing new to describe on-box
	}
	if _, err := s.queueLineMetaSyncLocked(principal{Principal: rbac.Principal{ActorID: systemActorID}}, nodeID); err != nil {
		s.logger.Printf("linemeta: queue sync for %s: %v", nodeID, err)
		return
	}
	// Commit only after UpsertApproval succeeded. A persistence failure leaves
	// the fingerprint unchanged so the next discovery can retry.
	s.linemetaSyncFP[nodeID] = fingerprint
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
		// Execution failure is not a decision: return the approval to pending
		// with the reason, so the operator can fix the cause and re-approve.
		// Leaving it approved stranded the plan forever — the approve endpoint
		// is intentionally a no-op on non-pending approvals.
		approval.Status = model.ApprovalPending
		approval.Reason = "execution failed: " + reason
		approval.UpdatedAt = time.Now().UTC()
		if err := s.store.UpsertApproval(approval); err != nil {
			return fmt.Errorf("return failed linemeta approval to pending: %w", err)
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
