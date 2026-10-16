package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// plans.publish (S2 plan section 2.6): a change Required says is not
// privileged is by design 28 an ordinary record edit, so a staged revision of
// a record with no live fleet-bound share in its closure goes live through
// this method, with no approval, and still only inside core's apply with its
// one-time grant. Under the share-write lock, held into the apply, it
// computes the closure, refuses what only a plan may do, and runs the apply.
//
// Its refusals read the staged facts from depends_on, because the live index
// says nothing about a staged revision:
//
//   - plan_required: a live share of the closure is fleet-bound;
//   - migration_incomplete: as propose refuses it;
//   - migration_requires_plan: a migrated revision whose closure has any live
//     share (a migrated record whose closure has none publishes like any
//     other, design-28.md:190);
//   - shares_without_identity: a record of the closure that is not
//     fleet-bound live and would be after the promotion has a live share
//     naming no identity, which would start answering the decoy the moment
//     the revision went live. The edges carry no live or staged marker, so
//     the check runs over the union graph and may refuse where the promotion
//     would in fact remove the edge;
//   - fleet_file_unavailable and fleet_delete_has_explicit_dependents, as
//     propose refuses them.

type subStorePlansPublishRequest struct {
	SubscriptionID string `json:"subscription_id"`
	// Revision is the staged revision to publish; for a delete, the live
	// revision deleted, or empty.
	Revision string `json:"revision"`
	// ExpectedRevision is the record's live revision ("" for a record with
	// none, such as a restored or brand-new one).
	ExpectedRevision string `json:"expected_revision"`
	// Action is promote (the default) or delete.
	Action string `json:"action,omitempty"`
}

type subStorePlansPublishReply struct {
	Published      bool   `json:"published"`
	SubscriptionID string `json:"subscription_id"`
	Revision       string `json:"revision"`
	Action         string `json:"action"`
}

func (s *Server) subStorePlansPublish(ctx context.Context, p principal, request []byte) ([]byte, error) {
	var req subStorePlansPublishRequest
	if err := subStoreSvcDecode(subStorePlansService, "publish", request, &req); err != nil {
		return nil, err
	}
	validRevision := func(revision string) bool { return revision == "" || subStoreSvcValidID(revision) }
	if !subStoreSvcValidID(req.SubscriptionID) || !validRevision(req.Revision) || !validRevision(req.ExpectedRevision) {
		return nil, subStorePlanBadRequest("subscription_id is required, and revision and expected_revision must be revisions")
	}
	spec := subStorePlanSpec{primary: req.SubscriptionID, from: req.ExpectedRevision, to: req.Revision, changes: map[string]subStorePlanShareChange{}}
	switch req.Action {
	case "", subStorePlanActionPromote:
		if req.Revision == "" || req.Revision == req.ExpectedRevision {
			return nil, subStorePlanBadRequest("revision names the staged revision to publish, which differs from expected_revision")
		}
		spec.mode = subStorePlanModePromote
		spec.promoted = []subStorePlanRecordRequest{{SubscriptionID: req.SubscriptionID, FromRevision: req.ExpectedRevision, ToRevision: req.Revision}}
	case subStorePlanActionDelete:
		if req.ExpectedRevision == "" || (req.Revision != "" && req.Revision != req.ExpectedRevision) {
			return nil, subStorePlanBadRequest("a delete names the record's live revision as expected_revision")
		}
		spec.mode, spec.to = subStorePlanModeDelete, ""
		spec.promoted = []subStorePlanRecordRequest{{SubscriptionID: req.SubscriptionID, FromRevision: req.ExpectedRevision}}
	default:
		return nil, subStorePlanBadRequest("action is promote or delete")
	}

	release := s.subStoreSvcLockShareWrites()
	g, err := s.subStorePlanGraphFor(ctx, []string{req.SubscriptionID}, spec.mode == subStorePlanModePromote)
	if err != nil {
		release()
		return nil, s.subStorePlanDependsError(err)
	}
	if err := subStorePlanProposeRefusal(spec, g); err != nil {
		release()
		return nil, err
	}
	var previewed []string
	for _, section := range s.subStorePlanSections(spec, g) {
		if section.Role != subStorePlanRoleStagedOnly {
			previewed = append(previewed, section.SubscriptionID)
		}
	}
	shares := s.subStorePlanSharesOf(previewed)
	var all []model.SubscriptionShare
	for _, id := range previewed {
		all = append(all, shares[id]...)
	}
	if err := subStorePlanPublishRefusal(spec, g, previewed, shares, all); err != nil {
		release()
		return nil, err
	}

	closure := g.sortedIDs()
	publishID := id.New("publish")
	sum := sha256.Sum256(append(append([]byte(nil), request...), publishID...))
	applyReq := subStoreApplyRevisionRequest{SubscriptionID: req.SubscriptionID, Revision: req.Revision, ExpectedRevision: req.ExpectedRevision,
		ApprovalID: publishID, PlanSHA256: hex.EncodeToString(sum[:])}
	action := subStorePlanActionPromote
	if spec.mode == subStorePlanModeDelete {
		action, applyReq.Action, applyReq.Revision = subStorePlanActionDelete, subStorePlanActionDelete, req.ExpectedRevision
	}
	claimed, applyErr := s.subStorePlanApply(ctx, applyReq, func(err error) {
		if err != nil {
			s.subStorePlanMarkStale(closure)
			return
		}
		s.subStorePlanDropSnapshots(closure)
		if spec.mode == subStorePlanModeDelete {
			// The record is archived, so its own shares are too, as a delete
			// plan's apply archives them; they are restorable with it.
			for _, share := range shares[req.SubscriptionID] {
				s.subStorePlanWriteChanges(p, publishID, []subStorePlanShareChange{{ShareID: share.ID, Archive: true}})
			}
		}
	})
	release()
	meta := map[string]string{"publish_id": publishID, "subscription_id": req.SubscriptionID, "revision": applyReq.Revision,
		"expected_revision": req.ExpectedRevision, "action": action, "records": fmt.Sprint(len(closure)),
		"grant_claimed": fmt.Sprint(claimed), "via_rpc": subStorePlansService}
	if applyErr != nil {
		if _, err := s.snapshotFor(ctx, subStorePluginID, req.SubscriptionID, true); err != nil {
			s.logger.Printf("sub-store plans: refetch of record %s after a failed publish failed (%s)", req.SubscriptionID, subscriptionDiagnosticSummary(err))
		}
		s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: auditActionSubStorePlanPublish, Scope: "substore:admin",
			Decision: "deny", Reason: "apply_revision failed", Metadata: meta})
		return nil, rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway,
			"apply_revision failed; the record may have been promoted: list shows its live revision. Publish again if it was not")
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: auditActionSubStorePlanPublish, Scope: "substore:admin",
		Decision: "allow", Metadata: meta})
	return json.Marshal(subStorePlansPublishReply{Published: true, SubscriptionID: req.SubscriptionID, Revision: applyReq.Revision, Action: action})
}

// subStorePlanPublishRefusal is what publish refuses beyond propose's own
// refusals, in the order a plan would be needed for.
func subStorePlanPublishRefusal(spec subStorePlanSpec, g subStorePlanGraph, previewed []string, shares map[string][]model.SubscriptionShare, all []model.SubscriptionShare) error {
	if spec.mode == subStorePlanModePromote {
		if facts, _ := g.facts(spec.primary); facts.StagedMigrated && len(all) > 0 {
			return rpcAPIError(http.StatusConflict, apiErrorMigrationRequiresPlan, fmt.Sprintf(
				"migration_requires_plan: record %s's staged revision is a migration and its fleet closure has live shares; "+
					"propose it with an identity or an archival for each share", spec.primary))
		}
		var offending []string
		for _, id := range previewed {
			facts, _ := g.facts(id)
			if facts.FleetBound || facts.Source == subStoreSourceFleet || !g.closure.fleetBound[id] {
				continue
			}
			for _, share := range shares[id] {
				if share.Source.IdentityID == "" {
					offending = append(offending, share.ID)
				}
			}
		}
		if len(offending) > 0 {
			sort.Strings(offending)
			return rpcAPIError(http.StatusConflict, apiErrorSharesWithoutIdentity, fmt.Sprintf(
				"shares_without_identity: shares %s name no identity on a record this revision makes fleet-bound, so they would answer the decoy "+
					"once it is live; propose it with an identity or an archival for each", strings.Join(offending, ", ")))
		}
	}
	if subStorePlanRequired(all) {
		return rpcAPIError(http.StatusConflict, apiErrorPlanRequired,
			"plan_required: a live share in this record's fleet closure is fleet-bound; propose a plan (plans.propose)")
	}
	return nil
}
