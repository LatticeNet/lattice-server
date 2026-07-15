package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// The host-risk operation protocol (spec §9.3).
//
// A plugin may compile intent into a plan; it may never apply one. This file is the gap
// between those two sentences: a `plan`-effect method produces a reviewable plan and an
// approval whose typed columns record the exact code and inputs that produced it, a
// human approves what they read, and the approval executor — and nothing else — invokes
// the plugin's `execute` action with a one-time grant bound to that approval.
//
// The binding is typed. An approval that recorded only "plugin X, action Y" could be
// honoured by a different version of X, a re-signed artifact, or against nodes the
// reviewer never saw. So the approval carries PluginVersion, ArtifactDigest, Service,
// Method, RequestSHA256, and Targets as real columns, and execution compares each to
// live state — a mismatch means the operator approved a plan produced by code that is
// no longer the code that would run it.

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
	proposed, err := plugin.ParseOperationPlan(string(out))
	if err != nil {
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

	// Store only the reviewable plan; the operator's plan-hash approval covers these
	// exact bytes.
	canonical, err := plugin.CanonicalOperationPlan(proposed)
	if err != nil {
		return nil, err
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    proposed.Targets[0],
		Plugin:    loaded.Manifest.ID,
		Action:    service + "/" + method,
		Plan:      canonical,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),

		// The binding, as typed columns. Each is re-checked at execute.
		PluginVersion:  loaded.Manifest.Version,
		ArtifactDigest: loaded.ArtifactDigest,
		Service:        service,
		Method:         method,
		RequestSHA256:  plugin.SHA256Hex(payload),
		Targets:        append([]string(nil), proposed.Targets...),
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
// Every column the approval bound is re-checked here against live state, because all of
// it can change between approval and execution.
func (s *Server) executePluginOperation(ctx context.Context, p principal, approval model.Approval) error {
	loaded, ok := s.loadedPlugin(approval.Plugin)
	if !ok {
		return fmt.Errorf("plugin %q is no longer loaded", approval.Plugin)
	}
	if !s.pluginIsActive(approval.Plugin) {
		return fmt.Errorf("plugin %q is not active", approval.Plugin)
	}
	// The approval named a version and an artifact. If either moved, the operator
	// approved a plan produced by code that is no longer the code that would run it.
	if loaded.Manifest.Version != approval.PluginVersion {
		return fmt.Errorf("plugin %q is now version %q; this approval was for %q — re-plan it",
			approval.Plugin, loaded.Manifest.Version, approval.PluginVersion)
	}
	if !equalFoldHex(loaded.ArtifactDigest, approval.ArtifactDigest) {
		return fmt.Errorf("plugin %q artifact digest has changed since this approval — re-plan it",
			approval.Plugin)
	}
	contract, ok := loaded.Manifest.InterfaceFor(approval.Service)
	if !ok || contract.EffectiveBacking() != plugin.BackingRuntime {
		// A core-backed service has no artifact to execute; core applies its own plans.
		return fmt.Errorf("plugin %q service %q is not runtime-backed", approval.Plugin, approval.Service)
	}
	if len(approval.Targets) == 0 {
		return fmt.Errorf("approval %q has no bound targets", approval.ID)
	}
	// Re-authorize every target against the APPROVING principal. The planner's scopes
	// are not inherited: the person who approves is the person who is accountable.
	if err := requireAllNodeScopesErr(s, p, "network:apply", approval.Targets); err != nil {
		return err
	}

	plan, err := plugin.ParseOperationPlan(approval.Plan)
	if err != nil {
		return err
	}
	grant := &plugin.OperationGrant{
		ApprovalID: approval.ID,
		PluginID:   approval.Plugin,
		PlanSHA256: approvalPlanSHA(approval),
		Targets:    append([]string(nil), approval.Targets...),
		Remaining:  pluginOperationMaxTasks,
	}
	request, err := json.Marshal(plugin.OperationExecuteRequest{
		ApprovalID: approval.ID,
		Targets:    approval.Targets,
		Data:       plan.Data,
	})
	if err != nil {
		return err
	}
	// The grant is bound to this one invocation on the host side. The plugin never
	// receives it and cannot widen it; it can only make a host call the broker checks
	// against it.
	resp, err := s.pluginRuntime.InvokeConstrained(ctx, approval.Plugin, "execute", request,
		plugin.InvokeConstraints{Operation: grant})
	if err != nil {
		return fmt.Errorf("plugin %q execute failed: %w", approval.Plugin, err)
	}
	if !resp.OK {
		return fmt.Errorf("plugin %q refused to execute the approved plan: %s", approval.Plugin, resp.Message)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "plugin.operation.execute", Scope: "network:apply", Decision: "allow",
		NodeID: approval.NodeID,
		Metadata: map[string]string{
			"plugin_id": approval.Plugin, "approval_id": approval.ID,
			"plan_sha256": grant.PlanSHA256, "artifact_digest": approval.ArtifactDigest,
			"tasks_enqueued": fmt.Sprint(pluginOperationMaxTasks - grant.Remaining),
		},
	})
	return nil
}

// handlePluginOperationTaskResult reconciles a plugin operation's approval once the
// agent reports back (spec §9.3 step 6). This is the generic branch the result ladder
// needs: without it a plugin operation would run and then leave its approval stuck in
// `approved` forever, because the ladder returns nil for any plugin it does not know.
//
// The plan-SHA staleness check mirrors nftpolicy's: a task result carrying a plan hash
// that no longer matches the approval belongs to a plan that has since been re-planned,
// and is rejected rather than recorded as applied.
func (s *Server) handlePluginOperationTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	node := approval.NodeID
	if len(task.Targets) > 0 {
		node = task.Targets[0]
	}
	metadata := map[string]string{
		"approval_id": approval.ID, "task_id": task.ID,
		"plugin_id": approval.Plugin, "plan_sha": approvalPlanSHA(approval),
	}
	if result.Error != "" || result.ExitCode != 0 {
		reason := result.Error
		if reason == "" {
			reason = fmt.Sprintf("apply task exited %d", result.ExitCode)
		}
		s.recordRequestAudit(r, model.AuditEvent{
			ID: id.New("audit"), NodeID: node, Action: "plugin.operation.failed",
			Decision: "deny", Reason: reason, Metadata: metadata,
		})
		// The approval stays approved: the operator can re-approve to retry, or re-plan.
		// It is not marked applied on a failed apply.
		return nil
	}
	approval.Status = model.ApprovalApplied
	approval.Reason = ""
	approval.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertApproval(approval); err != nil {
		return fmt.Errorf("mark plugin operation approval applied: %w", err)
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), NodeID: node, Action: "plugin.operation.applied",
		Decision: "allow", Metadata: metadata,
	})
	return nil
}

// isPluginOperationApproval reports whether an approval carries a plugin operation, so
// the generic approval flow can route it without a per-plugin ladder. A plugin operation
// is the only kind that sets Service and Method; nft, dns, and agent-update approvals
// never do, so this cannot mistake one of those for an operation.
func isPluginOperationApproval(approval model.Approval) bool {
	return approval.Service != "" && approval.Method != ""
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
