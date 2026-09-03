package server

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Why an approved approval has not applied.
//
// An approval whose status is "approved" has left the operator's hands and has
// not reached the node. That is a legitimate state and the console used to
// render it as a bare word, so the one item that could never clear looked
// identical to the ones that were about to. The page said Pending 0 next to a
// non-empty inbox and an operator reasonably read that as "everything ran".
//
// The explanation cannot be derived by the console. Whether an apply task was
// ever queued is not on the approvals wire at all, the node's contact state
// lives behind a second endpoint, and the capability gate and the fleet kill
// switch are server state with no client-visible projection. Correlating three
// endpoints to produce a sentence that may still be wrong is worse than saying
// nothing, so the control plane answers instead.
//
// The vocabulary is deliberately borrowed. Node reasons carry the exact status
// word node_status.go derives (disabled, never_reported, offline) with its
// "since" instant, so the sentence on this page and the word on the Nodes page
// cannot disagree about the same machine.
//
// Precedence, first match wins. Evidence of what already happened outranks a
// prediction of what will not:
//
//	task_failed         An apply task ran and ended failed or cancelled.
//	task_running        An apply task is leased right now. Nothing is wrong.
//	task_finished       An apply task finished and the approval was never
//	                    marked applied. The control plane does not know why;
//	                    it says so rather than picking a story.
//	plan_superseded     A newer approval exists for the same node, plugin and
//	                    action. This plan is dead whatever the node does.
//	node_unknown        The target node record is gone.
//	node_disabled       An operator switched the node off.
//	node_never_reported The node was enrolled and has never reported.
//	node_offline        The node has stopped reporting.
//	capability_excluded The plugin's capability is excluded for this node, so
//	                    queueing an apply is refused.
//	task_execution_disabled  The fleet kill switch is on; nothing leases.
//	not_queued          Approved without queueing an apply, and nothing since
//	                    has queued one. Nothing will run on its own.
//	task_queued         Queued, node reporting, waiting for the next poll.
//	                    The ordinary case, and the only one that clears itself.
const (
	ApprovalWaitTaskFailed            = "task_failed"
	ApprovalWaitTaskRunning           = "task_running"
	ApprovalWaitTaskFinished          = "task_finished"
	ApprovalWaitPlanSuperseded        = "plan_superseded"
	ApprovalWaitNodeUnknown           = "node_unknown"
	ApprovalWaitNodeDisabled          = "node_disabled"
	ApprovalWaitNodeNeverReported     = "node_never_reported"
	ApprovalWaitNodeOffline           = "node_offline"
	ApprovalWaitCapabilityExcluded    = "capability_excluded"
	ApprovalWaitTaskExecutionDisabled = "task_execution_disabled"
	ApprovalWaitNotQueued             = "not_queued"
	ApprovalWaitTaskQueued            = "task_queued"
)

// approvalWaitView is the additive explanation carried by GET
// /api/network/approvals. It is present only on approvals whose status is
// "approved"; every other status already says what it is. A client that
// predates the field ignores it and renders exactly what it rendered before.
type approvalWaitView struct {
	// Code is the machine word from the list above. Clients switch on it for
	// their own headline and their own translation.
	Code string `json:"code"`
	// Reason is one sentence in terms of the world: which machine, since when,
	// which task. English, like every other server-authored reason on the wire
	// (node status_reason, approval reason).
	Reason string `json:"reason"`
	// Blocked separates "will not proceed on its own" from "is proceeding".
	// task_running and task_queued are not blocked; everything else is.
	Blocked bool `json:"blocked"`

	// The node facts, in node_status.go's vocabulary, so the console can show
	// the same word and instant the Nodes page shows.
	NodeID           string    `json:"node_id,omitempty"`
	NodeName         string    `json:"node_name,omitempty"`
	NodeStatus       string    `json:"node_status,omitempty"`
	NodeStatusSince  time.Time `json:"node_status_since,omitzero"`
	NodeStatusReason string    `json:"node_status_reason,omitempty"`

	// The apply task, when one was ever queued for this approval.
	TaskID     string `json:"task_id,omitempty"`
	TaskStatus string `json:"task_status,omitempty"`

	// SupersededBy is the id of the newer approval for the same target.
	SupersededBy string `json:"superseded_by,omitempty"`

	// Dismissible reports whether POST /api/network/approvals/dismiss will
	// accept this approval as it stands. The console must not offer an exit
	// the server would refuse, so this is computed by the same rule the
	// endpoint enforces rather than guessed from the code.
	Dismissible bool `json:"dismissible"`
}

// approvalWaitContext is the state one listing pass reads. Built once per
// request over the whole store rather than per approval: a fleet with a
// thousand decided approvals would otherwise walk the task list a thousand
// times.
type approvalWaitContext struct {
	now          time.Time
	nodes        map[string]model.Node
	newestTask   map[string]model.Task
	supersededBy map[string]string
}

// newApprovalWaitContext indexes nodes, apply tasks and supersession for the
// approvals in one listing. Returns nil when nothing in the listing is
// approved, so the ordinary read of a history of applied rows costs nothing.
func (s *Server) newApprovalWaitContext(approvals []model.Approval) *approvalWaitContext {
	anyApproved := false
	for _, a := range approvals {
		if a.Status == model.ApprovalApproved {
			anyApproved = true
			break
		}
	}
	if !anyApproved {
		return nil
	}
	ctx := &approvalWaitContext{
		now:          s.now(),
		nodes:        map[string]model.Node{},
		newestTask:   map[string]model.Task{},
		supersededBy: map[string]string{},
	}
	for _, n := range s.store.Nodes() {
		ctx.nodes[n.ID] = n
	}
	for _, task := range s.store.Tasks() {
		if task.ApprovalID == "" {
			continue
		}
		// Newest wins: a rerun is the attempt that describes the approval now.
		if prev, ok := ctx.newestTask[task.ApprovalID]; ok && !task.CreatedAt.After(prev.CreatedAt) {
			continue
		}
		ctx.newestTask[task.ApprovalID] = task
	}
	ctx.indexSupersession(approvals)
	return ctx
}

// indexSupersession maps each approved approval to the newest live approval
// that replaces it: same node, same plugin, same action prefix, created later,
// and not itself retired. A rejected or dismissed successor supersedes
// nothing, which is what makes this safe to say out loud.
func (ctx *approvalWaitContext) indexSupersession(approvals []model.Approval) {
	byTarget := map[string][]model.Approval{}
	for _, a := range approvals {
		switch a.Status {
		case model.ApprovalPending, model.ApprovalApproved, model.ApprovalApplied:
		default:
			continue
		}
		key := approvalTargetKey(a)
		byTarget[key] = append(byTarget[key], a)
	}
	for key, group := range byTarget {
		sort.SliceStable(group, func(i, j int) bool { return group[i].CreatedAt.Before(group[j].CreatedAt) })
		byTarget[key] = group
	}
	for _, a := range approvals {
		if a.Status != model.ApprovalApproved {
			continue
		}
		group := byTarget[approvalTargetKey(a)]
		for i := len(group) - 1; i >= 0; i-- {
			candidate := group[i]
			if candidate.ID == a.ID || !candidate.CreatedAt.After(a.CreatedAt) {
				continue
			}
			ctx.supersededBy[a.ID] = candidate.ID
			break
		}
	}
}

// approvalTargetKey identifies what an approval changes, independent of which
// attempt it is. The action prefix is used because a parameterized action
// ("apply-metadata:<sha256>") names the same change with a different payload.
func approvalTargetKey(a model.Approval) string {
	action := a.Action
	if i := strings.Index(action, ":"); i >= 0 {
		action = action[:i]
	}
	return a.NodeID + "\x00" + a.Plugin + "\x00" + action
}

// approvalWait answers why an approved approval has not applied, or nil when
// the question does not arise.
func (s *Server) approvalWait(a model.Approval, ctx *approvalWaitContext) *approvalWaitView {
	if ctx == nil || a.Status != model.ApprovalApproved {
		return nil
	}
	out := &approvalWaitView{Blocked: true, NodeID: a.NodeID}
	node, nodeKnown := ctx.nodes[a.NodeID]
	var status nodeStatus
	if nodeKnown {
		status = s.nodeStatusFor(node, ctx.now)
		out.NodeName = node.Name
		out.NodeStatus = status.Status
		out.NodeStatusSince = status.Since
		out.NodeStatusReason = status.Reason
	}
	nodeLabel := approvalNodeLabel(a.NodeID, node, nodeKnown)

	task, hasTask := ctx.newestTask[a.ID]
	if hasTask {
		out.TaskID = task.ID
		out.TaskStatus = task.Status
	}

	switch {
	case hasTask && (task.Status == model.TaskFailed || task.Status == model.TaskCancelled):
		out.Code = ApprovalWaitTaskFailed
		out.Reason = fmt.Sprintf("The apply task %s on %s ended %s; the change was never made.", task.ID, nodeLabel, task.Status)
	case hasTask && task.Status == model.TaskLeased:
		out.Code = ApprovalWaitTaskRunning
		out.Blocked = false
		out.Reason = fmt.Sprintf("The apply task %s is running on %s right now.", task.ID, nodeLabel)
	case hasTask && task.Status == model.TaskFinished:
		out.Code = ApprovalWaitTaskFinished
		out.Reason = fmt.Sprintf("The apply task %s on %s finished, but this approval was never recorded as applied. The control plane cannot say whether the change took.", task.ID, nodeLabel)
	case ctx.supersededBy[a.ID] != "":
		out.Code = ApprovalWaitPlanSuperseded
		out.SupersededBy = ctx.supersededBy[a.ID]
		out.Reason = fmt.Sprintf("A newer plan for the same change on %s replaced this one (%s); this approval will not be dispatched.", nodeLabel, out.SupersededBy)
	case a.NodeID != "" && !nodeKnown:
		out.Code = ApprovalWaitNodeUnknown
		out.Reason = fmt.Sprintf("The target node %s no longer exists, so this approval has nowhere to go.", a.NodeID)
	case nodeKnown && status.Status == NodeStatusDisabled:
		out.Code = ApprovalWaitNodeDisabled
		out.Reason = fmt.Sprintf("Waiting for %s, disabled%s. A disabled node is refused work until it is enabled again.", nodeLabel, sinceClause(status.Since))
	case nodeKnown && status.Status == NodeStatusNeverReported:
		out.Code = ApprovalWaitNodeNeverReported
		out.Reason = fmt.Sprintf("Waiting for %s, which has never reported%s. No agent has ever contacted the control plane from that node.", nodeLabel, enrolledClause(status.Since))
	case nodeKnown && status.Status == NodeStatusOffline:
		out.Code = ApprovalWaitNodeOffline
		out.Reason = fmt.Sprintf("Waiting for %s, offline%s. The change is dispatched when the agent reports again.", nodeLabel, sinceClause(status.Since))
	case s.approvalCapabilityRefused(a):
		out.Code = ApprovalWaitCapabilityExcluded
		out.Reason = fmt.Sprintf("%s is excluded from the %s capability, so an apply cannot be queued for it: %s", nodeLabel, a.Plugin, s.approvalCapabilityReason(a))
	case s.taskExecutionDisabled:
		out.Code = ApprovalWaitTaskExecutionDisabled
		out.Reason = "Task execution is switched off on this control plane, so no approved change is handed to any node until it is switched back on."
	case !hasTask:
		out.Code = ApprovalWaitNotQueued
		out.Reason = fmt.Sprintf("Approved without queueing an apply, and nothing has queued one since. %s will not receive this change on its own.", nodeLabel)
	default:
		out.Code = ApprovalWaitTaskQueued
		out.Blocked = false
		out.Reason = fmt.Sprintf("Queued as task %s; %s picks it up on its next poll.", task.ID, nodeLabel)
	}
	out.Dismissible = s.approvalDismissibleWhileWaiting(a, out, hasTask)
	return out
}

// approvalNodeLabel names the machine the way an operator does: its name when
// it has one, its id otherwise. "global" for an approval bound to no node.
func approvalNodeLabel(nodeID string, node model.Node, known bool) string {
	if nodeID == "" {
		return "the fleet"
	}
	if known && strings.TrimSpace(node.Name) != "" {
		return node.Name
	}
	return nodeID
}

func sinceClause(since time.Time) string {
	if since.IsZero() {
		return ""
	}
	return " since " + stamp(since)
}

func enrolledClause(since time.Time) string {
	if since.IsZero() {
		return ""
	}
	return " since it was enrolled at " + stamp(since)
}

func (s *Server) approvalCapabilityRefused(a model.Approval) bool {
	if a.NodeID == "" || a.Plugin == "" {
		return false
	}
	return !s.resolveNodeCapability(a.NodeID, a.Plugin).Allowed
}

func (s *Server) approvalCapabilityReason(a model.Approval) string {
	reason := strings.TrimSpace(s.resolveNodeCapability(a.NodeID, a.Plugin).Reason)
	if reason == "" {
		return "the capability record excludes it"
	}
	return reason
}

// approvalDismissibleWhileWaiting mirrors what handleDismissApproval accepts.
// The console offers dismissal only where this says yes, so the way out it
// shows is one the server will honour.
//
// Two conditions, both load-bearing. The plugin has to be one the dismiss
// endpoint recognises, and nothing may have been queued for the approval: an
// item that produced a task has an execution history, and retiring it would
// hide a failure rather than close a dead end.
func (s *Server) approvalDismissibleWhileWaiting(a model.Approval, wait *approvalWaitView, hasTask bool) bool {
	if !wait.Blocked || hasTask {
		return false
	}
	if a.Plugin != agentUpdatePlugin && !isSSHGuardApproval(a) {
		return false
	}
	switch wait.Code {
	case ApprovalWaitPlanSuperseded, ApprovalWaitNodeUnknown, ApprovalWaitNodeDisabled,
		ApprovalWaitNodeNeverReported, ApprovalWaitNodeOffline, ApprovalWaitCapabilityExcluded,
		ApprovalWaitNotQueued:
		return true
	default:
		return false
	}
}

// approvalWaitReasonFor recomputes one approval's explanation on its own, for
// the dismiss endpoint. Building the whole listing context for a single id
// would walk every node and task to answer one question.
func (s *Server) approvalWaitReasonFor(a model.Approval) (*approvalWaitView, bool) {
	ctx := s.newApprovalWaitContext(s.store.Approvals())
	wait := s.approvalWait(a, ctx)
	if wait == nil {
		return nil, false
	}
	return wait, true
}

// annotateApprovalWaiting attaches the explanation to a listing. Views and
// approvals are order-aligned, which toApprovalViews guarantees.
func (s *Server) annotateApprovalWaiting(views []approvalView, approvals []model.Approval) []approvalView {
	ctx := s.newApprovalWaitContext(approvals)
	if ctx == nil {
		return views
	}
	for i := range views {
		if i >= len(approvals) {
			break
		}
		views[i].Waiting = s.approvalWait(approvals[i], ctx)
	}
	return views
}

// approvalWaitDismissalReason is what the dismissed row records: the sentence
// the operator was shown when they chose to retire it, plus their note. A
// dismissal that says something was retired without saying why is the record
// this endpoint exists to stop producing.
func approvalWaitDismissalReason(wait *approvalWaitView, note string) string {
	reason := "Approved but never applied, dismissed by an operator. " + wait.Reason + " Re-plan if this change is still wanted."
	if note != "" {
		reason = reason + " " + note
	}
	return reason
}
