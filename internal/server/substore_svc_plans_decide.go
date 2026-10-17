package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// Deciding and applying a Sub-Store plan (S2 plan section 2.6).

// subStorePlanApprove is approveApprovalCore's branch for a Sub-Store plan,
// reached after the generic path has checked the plan hash against the
// stored bytes. It previews every record of the plan again outside the
// share-write lock, then takes the lock, computes the closure once more,
// checks that the plan still describes every record, moves the approval from
// pending to approved exactly once, and applies it, still holding the lock,
// so no share appears on a record between the check and the apply.
//
// What is checked is everything the plan was computed from: the plugin
// build, the records of the closure, the live shares of each with the
// identity each serves, each record's live and staged revision, and what each
// identity would receive from each side. A share created, archived or
// restored, a collection that started reading a changed record, a revision
// re-staged, or a catalogue change that binds a line differently all mean an
// existing holder would receive what nobody reviewed, so the plan is rejected
// as stale. That includes an exclusion a service outage or a probe verdict
// causes: a plan approved while a line flaps is proposed again rather than
// applied over a diff nobody read.
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
	// A decision that arrives after another answers what the first one
	// left, rather than previewing a plan that is no longer pending.
	current, ok := s.store.Approval(approval.ID)
	if !ok {
		return approval, &approvalDecisionError{status: http.StatusNotFound, err: apiError(model.APIErrorNotFound, "approval not found")}
	}
	if current.Status != model.ApprovalPending {
		return current, nil
	}

	mode := plan.mode()
	staleReason := ""
	var previews map[string]map[string]subStorePlanIdentity
	if mode != subStorePlanModeClear {
		// The previews run outside the share-write lock: one may fetch and
		// render, and no share write waits on it.
		var err error
		previews, err = s.subStorePlanDecisionPreviews(ctx, plan)
		var previewErr *subStorePlanPreviewError
		var scriptNetwork *substoreScriptNetworkRefusal
		switch {
		case err == nil:
		case errors.As(err, &scriptNetwork):
			// A record of the plan that moved makes the plan stale, as for
			// any failed preview; otherwise the chain as it stands asks for
			// the network and cannot render, and the operator sees why.
			if moved := s.subStorePlanMovedReason(ctx, plan); moved != "" {
				staleReason = moved
				break
			}
			return approval, &approvalDecisionError{status: http.StatusConflict,
				err: apiError(apiErrorFleetScriptNetworkUnavailable, scriptNetwork.Error()+"; the plan stays pending")}
		case errors.Is(err, errSubStorePlanNotLive):
			staleReason = subStorePlanStaleLive
		case errors.Is(err, errSubStorePlanNoPreviewer):
			// A preview that could not run says nothing about the plan: it
			// stays pending, and the operator decides again.
			return approval, &approvalDecisionError{status: http.StatusServiceUnavailable,
				err: apiError(model.APIErrorBadGateway, "bind preview is not available on this server; the plan stays pending")}
		case errors.As(err, &previewErr):
			// A staged revision a later save replaced, or a live revision that
			// moved, answers revision_unknown from render and can never apply:
			// the plan is stale, not pending.
			if moved := s.subStorePlanMovedReason(ctx, plan); moved != "" {
				staleReason = moved
				break
			}
			return approval, &approvalDecisionError{status: http.StatusBadGateway,
				err: apiError(model.APIErrorBadGateway, previewErr.Error()+"; the plan stays pending")}
		default:
			return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
		}
	}

	release := s.subStoreSvcLockShareWrites()
	var g subStorePlanGraph
	if mode != subStorePlanModeClear && staleReason == "" {
		var err error
		g, err = s.subStorePlanGraphFor(ctx, subStorePlanRoots(plan), false)
		if err != nil {
			release()
			s.logger.Printf("sub-store plans: depends_on failed at the decision (%s)", subscriptionDiagnosticSummary(err))
			return approval, &approvalDecisionError{status: http.StatusBadGateway,
				err: apiError(model.APIErrorBadGateway, "the sub-store plugin's depends_on did not answer; the plan stays pending")}
		}
	}
	decided, approvedNow, err := s.subStorePlanDecide(p, approval, plan, previews, g, staleReason)
	if err != nil || !approvedNow {
		release()
		return decided, err
	}
	result := s.subStorePlanApplyApproved(ctx, p, decided, plan, g)
	release()
	if result.failed != "" {
		// The refresh runs only now, with the share-write lock released and
		// subStorePlanApply returned, so the plugin gate it takes is free. A
		// half-done promotion completes before the operator's next action
		// rather than at the next poll; the stale mark stays, so a refresh
		// that fails here runs again then.
		if _, err := s.snapshotFor(ctx, subStorePluginID, result.failed, true); err != nil {
			s.logger.Printf("sub-store plans: refetch of record %s after a failed apply failed (%s)", result.failed, subscriptionDiagnosticSummary(err))
		}
	}
	return result.approval, result.err
}

// subStorePlanRoots are the records a plan's closure is computed from.
func subStorePlanRoots(plan subStorePlan) []string {
	if order := plan.applyOrder(); len(order) > 0 {
		return order
	}
	return []string{plan.SubscriptionID}
}

// subStorePlanDecisionPreviews previews every section of a plan as propose
// did, by section.
func (s *Server) subStorePlanDecisionPreviews(ctx context.Context, plan subStorePlan) (map[string]map[string]subStorePlanIdentity, error) {
	out := map[string]map[string]subStorePlanIdentity{}
	for _, section := range plan.sections() {
		diffs, err := s.subStorePlanPreviewSection(ctx, section)
		if err != nil {
			return nil, err
		}
		out[section.SubscriptionID] = diffs
	}
	return out, nil
}

// subStorePlanMovedReason reads the closure again after a preview failed
// and names the stale reason when a record of the plan moved under it: a
// promoted record's staged revision replaced or discarded, a record's live
// revision moved, a record gone. It answers "" when nothing moved, and the
// failure says nothing about the plan.
func (s *Server) subStorePlanMovedReason(ctx context.Context, plan subStorePlan) string {
	g, err := s.subStorePlanGraphFor(ctx, subStorePlanRoots(plan), false)
	if err != nil {
		return ""
	}
	for _, section := range plan.sections() {
		if section.Role == subStorePlanRoleStagedOnly {
			continue
		}
		facts, ok := g.facts(section.SubscriptionID)
		switch {
		case !ok:
			return subStorePlanStaleClosure
		case section.Role == subStorePlanRolePromote && facts.StagedRevision != section.ToRevision:
			return subStorePlanStaleStaged
		case facts.Revision != section.FromRevision:
			return subStorePlanStaleLive
		}
	}
	return ""
}

// subStorePlanDecide runs under the share-write lock. It answers the
// approval as another decision left it, rejects the plan as stale, or moves
// it from pending to approved; approved is true only in the last case.
func (s *Server) subStorePlanDecide(p principal, approval model.Approval, plan subStorePlan, previews map[string]map[string]subStorePlanIdentity, g subStorePlanGraph, staleReason string) (model.Approval, bool, error) {
	current, ok := s.store.Approval(approval.ID)
	if !ok {
		return approval, false, &approvalDecisionError{status: http.StatusNotFound, err: apiError(model.APIErrorNotFound, "approval not found")}
	}
	if current.Status != model.ApprovalPending {
		return current, false, nil
	}
	if staleReason == "" {
		staleReason = s.subStorePlanStaleReason(approval, plan, previews, g)
	}
	if staleReason != "" {
		rejected, ok, err := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
			if a.Status != model.ApprovalPending {
				return false
			}
			a.Status, a.Reason, a.UpdatedAt = model.ApprovalRejected, staleReason, s.now()
			return true
		})
		if err != nil {
			return approval, false, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
		}
		if !ok {
			return rejected, false, nil
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), Action: auditActionSubStorePlanStale, Scope: "proxy:admin", Decision: "deny", Reason: staleReason,
			Metadata: map[string]string{"approval_id": approval.ID, "subscription_id": plan.SubscriptionID},
		})
		return approval, false, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale, staleReason)}
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
		return approval, false, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	if !ok {
		current, _ := s.store.Approval(approval.ID)
		return current, false, nil
	}
	return approved, true, nil
}

// subStorePlanStaleReason names what moved since the plan was proposed, or
// returns "". previews is what each section's identities would receive,
// previewed at this decision; g is the closure computed again under the
// share-write lock. A clear-only plan is checked against its shares alone.
func (s *Server) subStorePlanStaleReason(approval model.Approval, plan subStorePlan, previews map[string]map[string]subStorePlanIdentity, g subStorePlanGraph) string {
	mode := plan.mode()
	if mode != subStorePlanModeClear && approval.PluginVersion != "" {
		loaded, ok := s.loadedPlugin(subStorePluginID)
		if !ok || loaded.Manifest.Version != approval.PluginVersion || !equalFoldHex(loaded.ArtifactDigest, approval.ArtifactDigest) {
			return subStorePlanStalePlugin
		}
	}
	if mode == subStorePlanModePromote || mode == subStorePlanModeDelete {
		if recomputed := g.sortedIDs(); !slices.Equal(recomputed, plan.Closure) {
			return subStorePlanStaleClosure
		}
	}
	sections := plan.sections()
	for _, section := range sections {
		facts, known := g.facts(section.SubscriptionID)
		if mode == subStorePlanModeClear {
			break
		}
		if !known {
			return subStorePlanStaleClosure
		}
		switch section.Role {
		case subStorePlanRoleStagedOnly:
			if facts.Revision != "" {
				// A staged-only record went live: its shares were never
				// reviewed.
				return subStorePlanStaleClosure
			}
			continue
		case subStorePlanRolePromote:
			if facts.StagedRevision != section.ToRevision {
				return subStorePlanStaleStaged
			}
		}
		if facts.Revision != section.FromRevision {
			return subStorePlanStaleLive
		}
		// The revisions are what depends_on reports; the steps are read
		// from the documents themselves, so a chain that moved under an
		// unchanged revision id is caught too.
		if !s.subStorePlanChainHolds(section) {
			return subStorePlanStaleChain
		}
	}
	live := s.subStorePlanSharesOf(slices.Collect(func(yield func(string) bool) {
		for id := range plan.shareMaps() {
			if !yield(id) {
				return
			}
		}
	}))
	for recordID, want := range plan.shareMaps() {
		got := live[recordID]
		if len(got) != len(want) {
			return subStorePlanStaleShares
		}
		for _, share := range got {
			if identityID, ok := want[share.ID]; !ok || identityID != share.Source.IdentityID {
				return subStorePlanStaleShares
			}
		}
	}
	if mode == subStorePlanModeClear {
		return ""
	}
	for _, section := range sections {
		if section.Role == subStorePlanRoleStagedOnly {
			continue
		}
		if !subStorePlanIdentitiesEqual(section.Identities, previews[section.SubscriptionID], section) {
			return subStorePlanStaleReceive
		}
	}
	return ""
}

// subStorePlanApplyResult is how an apply ended. failed names the record
// whose apply_revision failed, for the refetch after the lock.
type subStorePlanApplyResult struct {
	approval model.Approval
	err      error
	failed   string
}

// subStorePlanChangesOf is every share change a plan makes, by record.
func subStorePlanChangesOf(plan subStorePlan) map[string][]subStorePlanShareChange {
	out := map[string][]subStorePlanShareChange{}
	for _, a := range plan.Assignments {
		out[a.SubscriptionID] = append(out[a.SubscriptionID], subStorePlanShareChange{ShareID: a.ShareID, IdentityID: a.IdentityID})
	}
	for _, c := range plan.Clearings {
		out[c.SubscriptionID] = append(out[c.SubscriptionID], subStorePlanShareChange{ShareID: c.ShareID})
	}
	for _, a := range plan.Archivals {
		out[a.SubscriptionID] = append(out[a.SubscriptionID], subStorePlanShareChange{ShareID: a.ShareID, Archive: true})
	}
	return out
}

// subStorePlanWriteChanges writes one record's share changes and audits
// each. A failed write is logged and the apply continues: the revision is
// already live, and the operator retries the assignment with an
// assignment-only plan.
func (s *Server) subStorePlanWriteChanges(p principal, approvalID string, changes []subStorePlanShareChange) {
	for _, change := range changes {
		if err := s.subStoreSvcShareApplyPlanChange(p, approvalID, change); err != nil {
			s.logger.Printf("sub-store plans: approval %s could not change share %s: %v", approvalID, change.ShareID, err)
		}
	}
}

// subStorePlanDropSnapshots drops the snapshots of the records and every
// cached body of the plugin's shares, advancing each source's epoch. Right
// after a migration the last-good snapshot is the legacy envelope with
// owner-credential links in its raw text, so a refetch that fails must
// answer an error, never that content.
func (s *Server) subStorePlanDropSnapshots(ids []string) {
	for _, id := range ids {
		if err := s.store.DeleteSubscriptionSnapshot(subStorePluginID, id); err != nil {
			s.logger.Printf("sub-store plans: drop the snapshot of record %s: %v", id, err)
		}
	}
	s.invalidateSharesForPlugin(subStorePluginID)
}

// subStorePlanMarkStale stale-marks the snapshots of the records, so the
// next access refetches them, and drops the plugin's cached bodies. A failed
// apply is not always a no-op: a kill after the plugin's index write leaves
// a half-done promotion that the refetch completes, while a clean failure
// refetches the unchanged record and serves the last-good snapshot if that
// refetch fails.
func (s *Server) subStorePlanMarkStale(ids []string) {
	if _, err := s.store.MarkSubscriptionSnapshotsStale(subStorePluginID, ids, s.now()); err != nil {
		s.logger.Printf("sub-store plans: stale-mark the closure's snapshots: %v", err)
	}
	s.invalidateSharesForPlugin(subStorePluginID)
}

// subStorePlanApplyApproved applies an approved plan under the share-write
// lock its caller holds. For each promoted record in order it calls
// apply_revision with its grant and, only on its success, drops that record's
// snapshot and writes and audits its own shares' changes; after the last it
// drops the snapshots of the recomputed closure and writes the changes of
// the closure's unpromoted records. A failure at any record stops the apply:
// the closure is stale-marked and nothing further dropped or written, and the
// approval's reason names the records that applied. An assignment-only or
// clear-only plan calls no apply_revision and writes its share changes.
func (s *Server) subStorePlanApplyApproved(ctx context.Context, p principal, approval model.Approval, plan subStorePlan, g subStorePlanGraph) subStorePlanApplyResult {
	planSHA := approvalPlanSHA(approval)
	changes := subStorePlanChangesOf(plan)
	sections := map[string]subStorePlanRecord{}
	for _, section := range plan.sections() {
		sections[section.SubscriptionID] = section
	}
	closure := g.sortedIDs()
	order := plan.applyOrder()
	var applied []string
	claimedAll := true
	for i, recordID := range order {
		section := sections[recordID]
		req := subStoreApplyRevisionRequest{SubscriptionID: recordID, Revision: section.ToRevision, ExpectedRevision: section.FromRevision,
			ApprovalID: approval.ID, PlanSHA256: planSHA}
		if section.Role == subStorePlanRoleDelete {
			req.Action, req.Revision = subStorePlanActionDelete, section.FromRevision
		}
		last := i == len(order)-1
		claimed, err := s.subStorePlanApply(ctx, req, func(err error) {
			if err != nil {
				s.subStorePlanMarkStale(closure)
				return
			}
			s.subStorePlanDropSnapshots([]string{recordID})
			s.subStorePlanWriteChanges(p, approval.ID, changes[recordID])
			if last {
				s.subStorePlanDropSnapshots(closure)
				for _, id := range closure {
					if !slices.Contains(order, id) {
						s.subStorePlanWriteChanges(p, approval.ID, changes[id])
					}
				}
			}
		})
		if err != nil {
			reason := "apply_revision failed; the record may have been promoted: list shows its live revision. Propose again if it was not"
			if len(order) > 1 {
				reason = fmt.Sprintf("apply_revision failed at record %s; records applied before it: %s, with their shares' changes written. "+
					"The record may have been promoted: list shows its live revision. Propose the rest", recordID, orNoneText(applied))
			}
			decided := approval
			if current, ok, _ := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
				if a.Status != model.ApprovalApproved {
					return false
				}
				a.Reason, a.UpdatedAt = reason, s.now()
				return true
			}); ok {
				decided = current
			}
			s.recordPrincipalAudit(p, model.AuditEvent{
				ID: id.New("audit"), Action: auditActionSubStorePlanApply, Scope: "proxy:admin", Decision: "deny",
				Reason: "apply_revision failed",
				Metadata: map[string]string{"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": recordID,
					"to_revision": section.ToRevision, "grant_claimed": strconv.FormatBool(claimed), "applied": strings.Join(applied, ",")},
			})
			return subStorePlanApplyResult{approval: decided, err: &approvalDecisionError{status: http.StatusBadGateway,
				err: apiError(model.APIErrorBadGateway, reason)}, failed: recordID}
		}
		applied = append(applied, recordID)
		claimedAll = claimedAll && claimed
		if !claimed {
			// The plugin published without asking whether core called it, so
			// it would publish for any caller. The apply is real and is
			// recorded as applied; the audit and the log say the contract was
			// not kept.
			s.logger.Printf("sub-store plans: apply_revision for approval %s answered without claiming its grant; the plugin does not check that core called it", approval.ID)
		}
	}
	if len(order) == 0 {
		for _, section := range plan.sections() {
			s.subStorePlanWriteChanges(p, approval.ID, changes[section.SubscriptionID])
		}
	}
	appliedApproval, _, err := s.store.MutateApproval(approval.ID, func(a *model.Approval) bool {
		if a.Status != model.ApprovalApproved {
			return false
		}
		a.Status, a.Reason, a.UpdatedAt = model.ApprovalApplied, "", s.now()
		return true
	})
	if err != nil {
		return subStorePlanApplyResult{approval: approval, err: &approvalDecisionError{status: http.StatusInternalServerError, err: err}}
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionSubStorePlanApply, Scope: "proxy:admin", Decision: "allow",
		Metadata: map[string]string{
			"approval_id": approval.ID, "plan_sha256": planSHA, "subscription_id": plan.SubscriptionID,
			"from_revision": plan.FromRevision, "to_revision": plan.ToRevision, "mode": plan.mode(),
			"applied": strings.Join(applied, ","), "shares": fmt.Sprint(plan.Totals.Shares), "unbound_shares": fmt.Sprint(plan.Totals.UnboundShares),
			"assignments": fmt.Sprint(len(plan.Assignments)), "clearings": fmt.Sprint(len(plan.Clearings)), "archivals": fmt.Sprint(len(plan.Archivals)),
			"grant_claimed": strconv.FormatBool(claimedAll && len(order) > 0),
		},
	})
	return subStorePlanApplyResult{approval: appliedApproval}
}

// orNoneText lists ids, or says there are none.
func orNoneText(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}
