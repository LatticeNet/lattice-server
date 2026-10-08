package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// latticenet.sub-store/plans: the privileged-change path of design 28
// ("Security model"). Publishing a staged revision of a fleet-bound record to
// its live shares changes what existing token holders receive, so it rides
// plan, approve, apply like every other privileged change:
//
//  1. propose computes, for every live share on the record that names an
//     identity, which lines that identity gains, loses and has excluded when
//     the record moves from its live revision to the staged one, writes that
//     diff as the approval's plan, and files it through submitApproval;
//  2. the operator reads the plan and approves it with its plan_sha256, which
//     the generic approval path checks against the stored bytes, so the
//     approval covers exactly the diff that was shown;
//  3. only then does core call the plugin's apply_revision, under the same
//     subscription mutation gate a record save takes.
//
// The line diff needs the validate-and-bind step, which lives with the line
// catalogue. propose reaches it through subStoreBindPreviewer, a narrow
// interface the bind code implements; until it is wired, propose refuses.

const (
	// subStorePlanApprovalPlugin is the approval's plugin column. It is a
	// core name, not the plugin's id: the plan is core's, and core applies
	// it, so nothing that routes plugin operations may mistake it for one.
	subStorePlanApprovalPlugin = "substore-plan"
	// subStorePlanActionPrefix starts the approval's action; the record id
	// follows, so a newer plan for one record supersedes only that record's.
	subStorePlanActionPrefix = "apply_revision:"
	// subStorePlanKind names the plan document.
	subStorePlanKind = "substore.revision"
	// subStorePlanMaxBytes bounds one plan. A revision that changes every
	// line of a 4096-line record for many identities is split by the
	// operator rather than filed as a plan nobody can read.
	subStorePlanMaxBytes = 1 << 20
	// subStorePlanLineNameBytes and subStorePlanReasonBytes bound the two
	// free-text fields of a plan line.
	subStorePlanLineNameBytes = 120
	subStorePlanReasonBytes   = 64

	auditActionSubStorePlanPropose = "substore.plan.propose"
	auditActionSubStorePlanApply   = "substore.plan.apply"
	auditActionSubStorePlanStale   = "substore.plan.stale"
)

// subStoreBindQuery asks for the validate-and-bind result of one record
// revision for one identity.
type subStoreBindQuery struct {
	PluginID       string
	SubscriptionID string
	// Revision is the record revision to render. Never empty: propose
	// names the live revision and the staged one explicitly.
	Revision   string
	IdentityID string
}

// subStoreBindLine is one line in a bind result or a plan. It carries no
// credential, no host and no template: a line is named by its line_uuid and
// its label.
type subStoreBindLine struct {
	// LineUUID is the line. Empty only for an exclusion of a plan node that
	// had no line (reason no_line).
	LineUUID string `json:"line_uuid,omitempty"`
	// Name is the entry's label, "<node name> <line name>" as identity
	// links write it.
	Name string `json:"name,omitempty"`
	// Reason is why the line is excluded (plan_rejected:<field>, no_line,
	// placeholder_count, service_down, lossy_template, graph_drifted, ...).
	// Empty for an included line.
	Reason string `json:"reason,omitempty"`
}

// subStoreBindResult is what one identity would receive from one revision.
type subStoreBindResult struct {
	// Included is every line the identity would receive, clones included.
	Included []subStoreBindLine
	// Excluded is every node the revision selects that would not be bound,
	// each with its Reason.
	Excluded []subStoreBindLine
}

// subStoreBindPreviewer runs validate-and-bind without serving anything:
// fetch or reuse the record's snapshot, render the named revision to a plan,
// validate every node against the catalogue, bind the identity, and report
// the lines included and excluded, credential-free. bind.preview answers the
// UI from the same step.
type subStoreBindPreviewer interface {
	PreviewBind(ctx context.Context, q subStoreBindQuery) (subStoreBindResult, error)
}

// subStoreApplyRevisionRequest is the payload of the plugin's
// latticenet.sub-store/subscription apply_revision method. The plugin makes
// Revision the record's live revision only when the live revision is still
// ExpectedRevision, and answers with the record and revision it applied.
type subStoreApplyRevisionRequest struct {
	SubscriptionID   string `json:"subscription_id"`
	Revision         string `json:"revision"`
	ExpectedRevision string `json:"expected_revision"`
	ApprovalID       string `json:"approval_id"`
	PlanSHA256       string `json:"plan_sha256"`
}

// subStoreApplyRevisionReply is apply_revision's reply.
type subStoreApplyRevisionReply struct {
	SubscriptionID string `json:"subscription_id"`
	Revision       string `json:"revision"`
}

// subStorePlan is the approval's plan: what the operator reads and what the
// approval's hash covers. Shares are listed one by one with their identity
// and their counts; the lines are listed once per identity, because every
// share of one identity on one record receives the same lines.
type subStorePlan struct {
	Kind           string                 `json:"kind"`
	PluginID       string                 `json:"plugin_id"`
	SubscriptionID string                 `json:"subscription_id"`
	FromRevision   string                 `json:"from_revision"`
	ToRevision     string                 `json:"to_revision"`
	Totals         subStorePlanTotals     `json:"totals"`
	Shares         []subStorePlanShare    `json:"shares"`
	Identities     []subStorePlanIdentity `json:"identities"`
}

type subStorePlanTotals struct {
	Shares     int `json:"shares"`
	Identities int `json:"identities"`
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Excluded   int `json:"excluded"`
}

type subStorePlanShare struct {
	ShareID     string     `json:"share_id"`
	Slug        string     `json:"slug"`
	DisplayName string     `json:"display_name,omitempty"`
	IdentityID  string     `json:"identity_id"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Added       int        `json:"added"`
	Removed     int        `json:"removed"`
	Excluded    int        `json:"excluded"`
}

type subStorePlanIdentity struct {
	IdentityID string `json:"identity_id"`
	// Added are lines the identity receives from the staged revision and
	// not from the live one.
	Added []subStoreBindLine `json:"added"`
	// Removed are lines the identity receives now and would no longer
	// receive; Reason is set when the staged revision still selects the line
	// and excludes it.
	Removed []subStoreBindLine `json:"removed"`
	// Excluded is every exclusion of the staged revision for the identity.
	Excluded []subStoreBindLine `json:"excluded"`
	// Unchanged counts the lines received from both revisions.
	Unchanged int `json:"unchanged"`
}

type subStorePlansProposeRequest struct {
	SubscriptionID string `json:"subscription_id"`
	// FromRevision is the record's live revision, ToRevision the staged one
	// to publish.
	FromRevision string `json:"from_revision"`
	ToRevision   string `json:"to_revision"`
}

// subStorePlansProposeReply answers propose. Required is false when no live
// share on the record names an identity: nothing an existing holder
// receives is bound in core, so the record publishes without a plan.
type subStorePlansProposeReply struct {
	Required   bool   `json:"required"`
	Reason     string `json:"reason,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
	PlanSHA256 string `json:"plan_sha256,omitempty"`
	// Plan is the approval's plan text, byte for byte: plan_sha256 is its
	// SHA-256, and approving with that hash approves exactly this text.
	Plan   string `json:"plan,omitempty"`
	Status string `json:"status,omitempty"`
}

type subStorePlansStatusRequest struct {
	ApprovalID     string `json:"approval_id"`
	SubscriptionID string `json:"subscription_id"`
}

type subStorePlanStatusRow struct {
	ApprovalID     string    `json:"approval_id"`
	Status         string    `json:"status"`
	Reason         string    `json:"reason,omitempty"`
	PlanSHA256     string    `json:"plan_sha256"`
	SubscriptionID string    `json:"subscription_id"`
	FromRevision   string    `json:"from_revision"`
	ToRevision     string    `json:"to_revision"`
	ActorID        string    `json:"actor_id,omitempty"`
	ApprovedBy     string    `json:"approved_by,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (s *Server) subStorePlansRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "propose":
		p, err := s.subStoreSvcOperator(ctx, subStorePlansService, true, "proxy:admin")
		if err != nil {
			return nil, err
		}
		return s.subStorePlansPropose(ctx, p, request)
	case "status":
		// Reading a plan's state needs the domain's read scope; an
		// administrator who may propose may read what was proposed, which
		// the read scope alone does not imply.
		p, err := s.subStoreSvcOperator(ctx, subStorePlansService, false)
		if err != nil {
			return nil, err
		}
		readOK, reason := pluginGatewayScopeAllowed(p, "substore:read")
		if adminOK, _ := pluginGatewayScopeAllowed(p, "proxy:admin"); !readOK && !adminOK {
			return nil, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, subStorePlansService+": "+reason)
		}
		return s.subStorePlansStatus(request)
	default:
		return nil, fmt.Errorf("sub-store/plans: unknown method %q", method)
	}
}

// subStorePlanShares is every live share on a record that names an
// identity, sorted by id: the shares whose holders a revision change
// reaches through core's binding. Disabled and expired shares are included,
// because re-enabling or extending one would serve the new revision to its
// holders without a second review; archived shares are not.
func (s *Server) subStorePlanShares(subscriptionID string) []model.SubscriptionShare {
	var out []model.SubscriptionShare
	for _, share := range s.store.SubscriptionSharesUnordered() {
		if isSubStoreShare(share) && share.Source.SubscriptionID == subscriptionID &&
			share.ArchivedAt == nil && share.Source.IdentityID != "" {
			out = append(out, share)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) subStorePlansPropose(ctx context.Context, p principal, request []byte) ([]byte, error) {
	var req subStorePlansProposeRequest
	if err := subStoreSvcDecode(subStorePlansService, "propose", request, &req); err != nil {
		return nil, err
	}
	if !subStoreSvcValidID(req.SubscriptionID) || !subStoreSvcValidID(req.FromRevision) || !subStoreSvcValidID(req.ToRevision) {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "subscription_id, from_revision and to_revision are required")
	}
	if req.FromRevision == req.ToRevision {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "from_revision and to_revision are the same revision")
	}
	shares := s.subStorePlanShares(req.SubscriptionID)
	if len(shares) == 0 {
		return json.Marshal(subStorePlansProposeReply{Required: false, Reason: "no live share on this record names an identity"})
	}
	previewer := s.subStoreSvc.previewer
	if previewer == nil {
		return nil, rpcAPIError(http.StatusServiceUnavailable, model.APIErrorBadGateway, "bind preview is not available on this server")
	}
	plan, err := s.subStoreBuildPlan(ctx, previewer, req, shares)
	if err != nil {
		return nil, err
	}
	text, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(text) > subStorePlanMaxBytes {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest,
			fmt.Sprintf("the plan is %d bytes, over %d; publish the change in smaller revisions", len(text), subStorePlanMaxBytes))
	}
	canonicalRequest, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	requestSum := sha256.Sum256(canonicalRequest)
	now := s.now()
	approval := model.Approval{
		ID:            id.New("approval"),
		Plugin:        subStorePlanApprovalPlugin,
		Action:        subStorePlanActionPrefix + req.SubscriptionID,
		Plan:          string(text),
		Status:        model.ApprovalPending,
		ActorID:       p.ActorID,
		CreatedAt:     now,
		UpdatedAt:     now,
		RequestSHA256: hex.EncodeToString(requestSum[:]),
	}
	// The approval binds the plugin that will apply it: a plan proposed
	// against one build of the plugin is not applied by another.
	if loaded, ok := s.loadedPlugin(subStorePluginID); ok {
		approval.PluginVersion, approval.ArtifactDigest = loaded.Manifest.Version, loaded.ArtifactDigest
	}
	stored, err := s.submitApproval(ctx, approval)
	if err != nil {
		return nil, err
	}
	planSHA := approvalPlanSHA(approval)
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubStorePlanPropose, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{
			"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": req.SubscriptionID,
			"from_revision": req.FromRevision, "to_revision": req.ToRevision,
			"shares": fmt.Sprint(plan.Totals.Shares), "added": fmt.Sprint(plan.Totals.Added),
			"removed": fmt.Sprint(plan.Totals.Removed), "excluded": fmt.Sprint(plan.Totals.Excluded),
			"via_rpc": subStorePlansService,
		},
	})
	return json.Marshal(subStorePlansProposeReply{
		Required: true, ApprovalID: approval.ID, PlanSHA256: planSHA, Plan: approval.Plan, Status: stored.Status,
	})
}

// subStoreBuildPlan previews both revisions once per identity and diffs them.
func (s *Server) subStoreBuildPlan(ctx context.Context, previewer subStoreBindPreviewer, req subStorePlansProposeRequest, shares []model.SubscriptionShare) (subStorePlan, error) {
	plan := subStorePlan{
		Kind: subStorePlanKind, PluginID: subStorePluginID, SubscriptionID: req.SubscriptionID,
		FromRevision: req.FromRevision, ToRevision: req.ToRevision,
		Shares: []subStorePlanShare{}, Identities: []subStorePlanIdentity{},
	}
	byIdentity := map[string]subStorePlanIdentity{}
	for _, share := range shares {
		identityID := share.Source.IdentityID
		diff, ok := byIdentity[identityID]
		if !ok {
			preview := func(revision string) (subStoreBindResult, error) {
				result, err := previewer.PreviewBind(ctx, subStoreBindQuery{
					PluginID: subStorePluginID, SubscriptionID: req.SubscriptionID, Revision: revision, IdentityID: identityID,
				})
				if err != nil {
					// The previewer's error may carry plugin diagnostics, which
					// are untrusted; the reply and the log name only what failed.
					s.logger.Printf("sub-store plans: bind preview failed for record %s revision %s identity %s (%s)",
						req.SubscriptionID, revision, identityID, subscriptionDiagnosticSummary(err))
					return subStoreBindResult{}, rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway,
						fmt.Sprintf("bind preview failed for revision %s and identity %s", revision, identityID))
				}
				return result, nil
			}
			before, err := preview(req.FromRevision)
			if err != nil {
				return subStorePlan{}, err
			}
			after, err := preview(req.ToRevision)
			if err != nil {
				return subStorePlan{}, err
			}
			diff = subStorePlanDiff(identityID, before, after)
			byIdentity[identityID] = diff
			plan.Identities = append(plan.Identities, diff)
			plan.Totals.Added += len(diff.Added)
			plan.Totals.Removed += len(diff.Removed)
			plan.Totals.Excluded += len(diff.Excluded)
		}
		plan.Shares = append(plan.Shares, subStorePlanShare{
			ShareID: share.ID, Slug: share.Slug, DisplayName: share.DisplayName, IdentityID: identityID,
			Enabled: share.Enabled, ExpiresAt: share.ExpiresAt,
			Added: len(diff.Added), Removed: len(diff.Removed), Excluded: len(diff.Excluded),
		})
	}
	sort.Slice(plan.Identities, func(i, j int) bool { return plan.Identities[i].IdentityID < plan.Identities[j].IdentityID })
	plan.Totals.Shares, plan.Totals.Identities = len(plan.Shares), len(plan.Identities)
	return plan, nil
}

// subStorePlanDiff compares what one identity receives from two revisions.
// Lines are compared by line_uuid, so a renamed line is unchanged, and clones
// of one line count once.
func subStorePlanDiff(identityID string, before, after subStoreBindResult) subStorePlanIdentity {
	included := func(result subStoreBindResult) map[string]subStoreBindLine {
		out := make(map[string]subStoreBindLine, len(result.Included))
		for _, line := range result.Included {
			line = subStorePlanCleanLine(line)
			if line.LineUUID == "" {
				continue
			}
			line.Reason = ""
			if _, seen := out[line.LineUUID]; !seen {
				out[line.LineUUID] = line
			}
		}
		return out
	}
	was, now := included(before), included(after)
	excludedNow := map[string]string{}
	diff := subStorePlanIdentity{IdentityID: identityID, Added: []subStoreBindLine{}, Removed: []subStoreBindLine{}, Excluded: []subStoreBindLine{}}
	for _, line := range after.Excluded {
		line = subStorePlanCleanLine(line)
		if line.Reason == "" {
			line.Reason = "excluded"
		}
		diff.Excluded = append(diff.Excluded, line)
		if line.LineUUID != "" {
			if _, seen := excludedNow[line.LineUUID]; !seen {
				excludedNow[line.LineUUID] = line.Reason
			}
		}
	}
	for lineUUID, line := range now {
		if _, ok := was[lineUUID]; ok {
			diff.Unchanged++
			continue
		}
		diff.Added = append(diff.Added, line)
	}
	for lineUUID, line := range was {
		if _, ok := now[lineUUID]; ok {
			continue
		}
		line.Reason = excludedNow[lineUUID]
		diff.Removed = append(diff.Removed, line)
	}
	for _, lines := range [][]subStoreBindLine{diff.Added, diff.Removed, diff.Excluded} {
		sort.Slice(lines, func(i, j int) bool {
			if lines[i].LineUUID != lines[j].LineUUID {
				return lines[i].LineUUID < lines[j].LineUUID
			}
			if lines[i].Name != lines[j].Name {
				return lines[i].Name < lines[j].Name
			}
			return lines[i].Reason < lines[j].Reason
		})
	}
	return diff
}

// subStorePlanCleanLine bounds a line's text fields and drops control
// characters, so a plan reads as one line per entry whatever a record named
// its nodes.
func subStorePlanCleanLine(line subStoreBindLine) subStoreBindLine {
	clean := func(value string, limit int) string {
		value = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, strings.TrimSpace(value))
		for len(value) > limit {
			_, size := utf8.DecodeLastRuneInString(value)
			value = value[:len(value)-size]
		}
		return value
	}
	return subStoreBindLine{
		LineUUID: clean(line.LineUUID, 36),
		Name:     clean(line.Name, subStorePlanLineNameBytes),
		Reason:   clean(line.Reason, subStorePlanReasonBytes),
	}
}

func (s *Server) subStorePlansStatus(request []byte) ([]byte, error) {
	var req subStorePlansStatusRequest
	if err := subStoreSvcDecode(subStorePlansService, "status", request, &req); err != nil {
		return nil, err
	}
	if (req.ApprovalID == "") == (req.SubscriptionID == "") {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "status takes approval_id or subscription_id, not both")
	}
	rows := []subStorePlanStatusRow{}
	add := func(approval model.Approval) {
		var plan subStorePlan
		if approval.Plugin != subStorePlanApprovalPlugin || json.Unmarshal([]byte(approval.Plan), &plan) != nil {
			return
		}
		if req.SubscriptionID != "" && plan.SubscriptionID != req.SubscriptionID {
			return
		}
		rows = append(rows, subStorePlanStatusRow{
			ApprovalID: approval.ID, Status: approval.Status, Reason: approval.Reason, PlanSHA256: approvalPlanSHA(approval),
			SubscriptionID: plan.SubscriptionID, FromRevision: plan.FromRevision, ToRevision: plan.ToRevision,
			ActorID: approval.ActorID, ApprovedBy: approval.ApprovedBy, CreatedAt: approval.CreatedAt, UpdatedAt: approval.UpdatedAt,
		})
	}
	if req.ApprovalID != "" {
		approval, ok := s.store.Approval(req.ApprovalID)
		if ok {
			add(approval)
		}
		if len(rows) == 0 {
			return nil, rpcAPIError(http.StatusNotFound, model.APIErrorNotFound, "plan not found")
		}
	} else {
		for _, approval := range s.store.Approvals() {
			add(approval)
		}
		sort.Slice(rows, func(i, j int) bool {
			if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
				return rows[i].CreatedAt.After(rows[j].CreatedAt)
			}
			return rows[i].ApprovalID < rows[j].ApprovalID
		})
	}
	return json.Marshal(map[string]any{"plans": rows})
}

// isSubStorePlanApproval reports an approval this file files and applies.
func isSubStorePlanApproval(approval model.Approval) bool {
	return approval.Plugin == subStorePlanApprovalPlugin
}

// subStorePlanApprove is approveApprovalCore's branch for a Sub-Store plan,
// reached after the generic path has checked the plan hash against the
// stored bytes. It checks that the plan still describes the record's live
// shares, moves the approval from pending to approved exactly once, and
// only then calls apply_revision.
//
// The bindings checked here are the inputs the plan was computed from: the
// plugin build, and the set of live shares on the record with the identity
// each serves. A share created, archived or restored since the proposal
// means an existing holder would receive what nobody reviewed, so the plan
// is rejected as stale. Which lines a service outage or a probe verdict
// excludes is not re-checked: that changes at serve time whatever is
// approved, and re-checking it would make every plan stale on a flapping
// line.
func (s *Server) subStorePlanApprove(ctx context.Context, p principal, approval model.Approval, queueApply bool) (model.Approval, error) {
	if !queueApply {
		return approval, &approvalDecisionError{status: http.StatusBadRequest, err: apiError(model.APIErrorBadRequest,
			"a sub-store plan is applied when it is approved: approve with queue_apply")}
	}
	var plan subStorePlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil || plan.Kind != subStorePlanKind ||
		plan.PluginID != subStorePluginID || !subStoreSvcValidID(plan.SubscriptionID) {
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale, "the plan is not a sub-store revision plan")}
	}
	s.subStoreSvc.mu.Lock()
	defer s.subStoreSvc.mu.Unlock()
	// A decision that waited on the lock behind another answers what the
	// first one left, rather than judging a plan that is no longer pending.
	current, ok := s.store.Approval(approval.ID)
	if !ok {
		return approval, &approvalDecisionError{status: http.StatusNotFound, err: apiError(model.APIErrorNotFound, "approval not found")}
	}
	if current.Status != model.ApprovalPending {
		return current, nil
	}

	if reason := s.subStorePlanStaleReason(approval, plan); reason != "" {
		rejected, ok, err := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
			if a.Status != model.ApprovalPending {
				return false
			}
			a.Status, a.Reason, a.UpdatedAt = model.ApprovalRejected, reason, s.now()
			return true
		})
		if err != nil {
			return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
		}
		if !ok {
			return rejected, nil
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionSubStorePlanStale, Scope: "proxy:admin", Decision: "deny", Reason: reason,
			Metadata: map[string]string{"approval_id": approval.ID, "subscription_id": plan.SubscriptionID},
		})
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale, reason)}
	}

	// Pending to approved exactly once: of two decisions racing on one
	// approval, one applies and the other answers what it finds.
	approved, ok, err := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
		if a.Status != model.ApprovalPending {
			return false
		}
		a.Status, a.ApprovedBy, a.UpdatedAt = model.ApprovalApproved, p.ActorID, s.now()
		return true
	})
	if err != nil {
		return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	if !ok {
		current, _ := s.store.Approval(approval.ID)
		return current, nil
	}

	planSHA := approvalPlanSHA(approval)
	applyReq := subStoreApplyRevisionRequest{
		SubscriptionID: plan.SubscriptionID, Revision: plan.ToRevision, ExpectedRevision: plan.FromRevision,
		ApprovalID: approval.ID, PlanSHA256: planSHA,
	}
	if err := s.subStorePlanApply(ctx, applyReq); err != nil {
		// The approval stays approved and unapplied, as a plugin operation's
		// does: the record did not move, and the operator proposes again.
		// The reason is fixed text, because the plugin's message is not
		// trusted to be free of record content.
		const reason = "apply_revision failed; the record is unchanged, propose the revision again"
		if current, ok, _ := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
			if a.Status != model.ApprovalApproved {
				return false
			}
			a.Reason, a.UpdatedAt = reason, s.now()
			return true
		}); ok {
			approved = current
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionSubStorePlanApply, Scope: "proxy:admin", Decision: "deny",
			Reason:   "apply_revision failed",
			Metadata: map[string]string{"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": plan.SubscriptionID, "to_revision": plan.ToRevision},
		})
		return approved, &approvalDecisionError{status: http.StatusBadGateway, err: apiError(model.APIErrorBadGateway, reason)}
	}
	applied, _, err := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
		if a.Status != model.ApprovalApproved {
			return false
		}
		a.Status, a.Reason, a.UpdatedAt = model.ApprovalApplied, "", s.now()
		return true
	})
	if err != nil {
		return approved, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubStorePlanApply, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{
			"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": plan.SubscriptionID,
			"from_revision": plan.FromRevision, "to_revision": plan.ToRevision, "shares": fmt.Sprint(len(plan.Shares)),
		},
	})
	return applied, nil
}

// subStorePlanStaleReason names what moved since the plan was proposed, or
// returns "".
func (s *Server) subStorePlanStaleReason(approval model.Approval, plan subStorePlan) string {
	if approval.PluginVersion != "" {
		loaded, ok := s.loadedPlugin(subStorePluginID)
		if !ok || loaded.Manifest.Version != approval.PluginVersion || !equalFoldHex(loaded.ArtifactDigest, approval.ArtifactDigest) {
			return "the sub-store plugin changed since this plan was proposed; propose it again"
		}
	}
	want := make(map[string]string, len(plan.Shares))
	for _, share := range plan.Shares {
		want[share.ShareID] = share.IdentityID
	}
	live := s.subStorePlanShares(plan.SubscriptionID)
	if len(live) != len(want) {
		return "the record's live shares changed since this plan was proposed; propose it again"
	}
	for _, share := range live {
		if identityID, ok := want[share.ID]; !ok || identityID != share.Source.IdentityID {
			return "the record's live shares changed since this plan was proposed; propose it again"
		}
	}
	return ""
}

// subStorePlanApply calls the plugin's apply_revision under the subscription
// mutation gate, exactly as the gateway runs a record save
// (server_plugin_invoke.go): the plugin's snapshots are marked stale and the
// cached bodies of its shares dropped before the call, so no body rendered
// from the old revision is served after it.
func (s *Server) subStorePlanApply(ctx context.Context, req subStoreApplyRevisionRequest) error {
	state, release, err := s.acquireSubscriptionPluginGate(ctx, subStorePluginID)
	if err != nil {
		return err
	}
	defer func() {
		state.mu.Lock()
		state.generation++
		state.mu.Unlock()
		release()
	}()
	persist := s.store.MarkPluginSubscriptionSnapshotsStale
	if s.subscriptionMutationPersist != nil {
		persist = s.subscriptionMutationPersist
	}
	committed, err := persist(subStorePluginID, s.now())
	if committed {
		state.mu.Lock()
		state.generation++
		state.mu.Unlock()
		s.invalidateSharesForPlugin(subStorePluginID)
	}
	if err != nil {
		return err
	}
	var reply subStoreApplyRevisionReply
	if s.subStoreSvc.applyRevision != nil {
		reply, err = s.subStoreSvc.applyRevision(ctx, req)
	} else {
		reply, err = s.subStoreCallApplyRevision(ctx, req)
	}
	if err != nil {
		s.logger.Printf("sub-store plans: apply_revision failed for record %s (%s)", req.SubscriptionID, subscriptionDiagnosticSummary(err))
		return err
	}
	if reply.SubscriptionID != req.SubscriptionID || reply.Revision != req.Revision {
		return errors.New("apply_revision answered for another record or revision")
	}
	return nil
}

// subStoreCallApplyRevision is the plugin call, under the method's signed
// budget.
func (s *Server) subStoreCallApplyRevision(ctx context.Context, req subStoreApplyRevisionRequest) (subStoreApplyRevisionReply, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return subStoreApplyRevisionReply{}, err
	}
	out, err := s.callRuntimePluginService(ctx, subStorePluginID, subStorePluginID+"/subscription", "apply_revision", payload, nil, nil)
	if err != nil {
		return subStoreApplyRevisionReply{}, err
	}
	var reply subStoreApplyRevisionReply
	if err := json.Unmarshal(out, &reply); err != nil {
		return subStoreApplyRevisionReply{}, errors.New("apply_revision reply does not decode")
	}
	return reply, nil
}
