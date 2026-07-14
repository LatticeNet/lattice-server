package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// The host-risk operation protocol (spec §9.3).
//
// A plugin may compile intent into a plan; it may never apply one. This file is the
// gap between those two sentences: a `plan`-effect method produces a reviewable plan
// and an approval bound to everything that could change underneath it, and the approval
// executor — and nothing else — invokes the plugin's `execute` action with a one-time
// grant narrow enough that the worst it can do is the thing that was approved.
//
// Why the binding is so wide: an approval that records only "plugin X, action Y" can be
// honoured by a different version of X, by a re-signed artifact, against nodes the
// reviewer never saw, or after the plan was swapped underneath it. So the envelope
// carries plugin ID, version, artifact digest, service, method, a hash of the request
// that produced the plan, and the targets — and because the envelope IS the approval's
// plan text, the existing plan-hash gate covers all of it. The operator approves a
// hash; that hash is the whole tuple.

// pluginOperationMaxTasks bounds how many agent tasks one approved operation may
// enqueue. An approval authorizes a plan, not an open-ended session.
const pluginOperationMaxTasks = 32

// planPluginOperation runs a `plan`-effect method and turns its plan into a pending
// approval. Nothing is applied: the plugin has proposed, and an operator must now read
// what it proposed and decide.
func (s *Server) planPluginOperation(
	ctx context.Context,
	p principal,
	loaded plugin.Loaded,
	service, method string,
	payload json.RawMessage,
	operatorTargets []string,
) ([]byte, error) {
	out, err := s.callRuntimePluginService(ctx, loaded.Manifest.ID, service, method, payload, operatorTargets)
	if err != nil {
		return nil, err
	}
	var proposed plugin.PluginOperationPlan
	if err := json.Unmarshal(out, &proposed); err != nil {
		return nil, fmt.Errorf("plugin %q returned a plan that is not a PluginOperationPlan: %w",
			loaded.Manifest.ID, err)
	}
	if err := plugin.ValidateOperationPlan(proposed); err != nil {
		return nil, err
	}
	// A plugin does not get to widen its own blast radius by naming nodes: every target
	// is authorized against the principal who asked for the plan, exactly as if they had
	// queued the work themselves.
	if err := requireAllNodeScopesErr(s, p, "network:plan", proposed.Targets); err != nil {
		return nil, err
	}

	envelope := plugin.OperationEnvelope{
		PluginID:       loaded.Manifest.ID,
		PluginVersion:  loaded.Manifest.Version,
		ArtifactDigest: loaded.ArtifactDigest,
		Service:        service,
		Method:         method,
		RequestSHA256:  plugin.SHA256Hex(payload),
		Plan:           proposed,
	}
	canonical, err := plugin.CanonicalOperationEnvelope(envelope)
	if err != nil {
		return nil, err
	}

	approval := model.Approval{
		ID:     id.New("approval"),
		NodeID: proposed.Targets[0],
		Plugin: loaded.Manifest.ID,
		Action: service + "/" + method,
		// The canonical envelope IS the plan text, so approvalPlanSHA hashes the entire
		// binding tuple and the operator's plan_sha256 check covers all of it.
		Plan:      canonical,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.store.UpsertApproval(approval); err != nil {
		return nil, err
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "plugin.operation.plan", Scope: "network:plan", Decision: "allow",
		NodeID: approval.NodeID,
		Metadata: map[string]string{
			"plugin_id": loaded.Manifest.ID, "service": service, "method": method,
			"approval_id": approval.ID, "plan_sha256": approvalPlanSHA(approval),
		},
	})

	// The browser gets the approval reference and the redacted preview — never the
	// opaque plan data, which is the plugin's to carry and nobody's to edit.
	return json.Marshal(struct {
		ApprovalID string   `json:"approval_id"`
		PlanSHA256 string   `json:"plan_sha256"`
		Summary    string   `json:"summary"`
		Targets    []string `json:"targets"`
		Preview    string   `json:"preview,omitempty"`
		Steps      []string `json:"steps,omitempty"`
		Rollback   string   `json:"rollback,omitempty"`
	}{
		ApprovalID: approval.ID,
		PlanSHA256: approvalPlanSHA(approval),
		Summary:    proposed.Summary,
		Targets:    proposed.Targets,
		Preview:    proposed.Preview,
		Steps:      proposed.Steps,
		Rollback:   proposed.Rollback,
	})
}

// executePluginOperation is the ONLY path that invokes a plugin's `execute` action.
//
// It is reached from the approval executor and from nowhere else: /api/plugins/invoke
// refuses any non-diagnostic action, and /api/plugins/call dispatches declared interface
// methods, whose effects are read, write, or plan. There is no request a plugin author
// or an operator can craft that reaches `execute` without an approval.
//
// Everything the approval bound is re-checked here, because all of it can change between
// approval and execution: a plugin can be disabled, upgraded, re-signed, or have its
// plan rewritten in the store.
func (s *Server) executePluginOperation(ctx context.Context, p principal, approval model.Approval) error {
	envelope, err := plugin.ParseOperationEnvelope(approval.Plan)
	if err != nil {
		return err
	}
	loaded, ok := s.loadedPlugin(envelope.PluginID)
	if !ok {
		return fmt.Errorf("plugin %q is no longer loaded", envelope.PluginID)
	}
	if !s.pluginIsActive(envelope.PluginID) {
		return fmt.Errorf("plugin %q is not active", envelope.PluginID)
	}
	// The approval named a version and an artifact. If either moved, the operator
	// approved a plan produced by code that is no longer the code that would run it.
	if loaded.Manifest.Version != envelope.PluginVersion {
		return fmt.Errorf("plugin %q is now version %q; this approval was for %q — re-plan it",
			envelope.PluginID, loaded.Manifest.Version, envelope.PluginVersion)
	}
	if !equalFoldHex(loaded.ArtifactDigest, envelope.ArtifactDigest) {
		return fmt.Errorf("plugin %q artifact digest has changed since this approval — re-plan it",
			envelope.PluginID)
	}
	contract, ok := loaded.Manifest.InterfaceFor(envelope.Service)
	if !ok || contract.EffectiveBacking() != plugin.BackingRuntime {
		// A core-backed service has no artifact to execute; core applies its own plans.
		return fmt.Errorf("plugin %q service %q is not runtime-backed", envelope.PluginID, envelope.Service)
	}
	// Re-authorize every target against the APPROVING principal. The planner's scopes
	// are not inherited: the person who approves is the person who is accountable.
	if err := requireAllNodeScopesErr(s, p, "network:apply", envelope.Plan.Targets); err != nil {
		return err
	}

	grant := &plugin.OperationGrant{
		ApprovalID: approval.ID,
		PluginID:   envelope.PluginID,
		PlanSHA256: approvalPlanSHA(approval),
		Targets:    append([]string(nil), envelope.Plan.Targets...),
		Remaining:  pluginOperationMaxTasks,
	}
	// The grant is bound to this one invocation on the host side. The plugin never
	// receives it and cannot widen it; it can only make a host call the broker then
	// checks against it.
	approved, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	resp, err := s.pluginRuntime.InvokeConstrained(ctx, envelope.PluginID, "execute", approved,
		plugin.InvokeConstraints{Operation: grant})
	if err != nil {
		return fmt.Errorf("plugin %q execute failed: %w", envelope.PluginID, err)
	}
	if !resp.OK {
		return fmt.Errorf("plugin %q refused to execute the approved plan: %s", envelope.PluginID, resp.Message)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "plugin.operation.execute", Scope: "network:apply", Decision: "allow",
		NodeID: approval.NodeID,
		Metadata: map[string]string{
			"plugin_id": envelope.PluginID, "approval_id": approval.ID,
			"plan_sha256": grant.PlanSHA256, "artifact_digest": envelope.ArtifactDigest,
			"tasks_enqueued": fmt.Sprint(pluginOperationMaxTasks - grant.Remaining),
		},
	})
	return nil
}

// isPluginOperationApproval reports whether an approval carries a plugin operation
// envelope, so the generic approval flow can route it without a per-plugin ladder.
func isPluginOperationApproval(approval model.Approval) bool {
	_, err := plugin.ParseOperationEnvelope(approval.Plan)
	return err == nil
}

// requireAllNodeScopesErr is the error-returning form of requireAllNodeScopes, for use
// away from an HTTP handler.
func requireAllNodeScopesErr(s *Server, p principal, scope string, nodeIDs []string) error {
	for _, nodeID := range nodeIDs {
		if !rbac.Allows(p.Principal, scope, nodeID) {
			return fmt.Errorf("forbidden: %s on node %s", scope, nodeID)
		}
	}
	return nil
}

func equalFoldHex(a, b string) bool {
	if len(a) != len(b) || a == "" {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
