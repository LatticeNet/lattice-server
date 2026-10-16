package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestPlansStaleWhenAssignedShareMoves: a share the plan assigns that is
// archived, or given its identity some other way, before the decision makes
// the plan stale, and nothing is applied.
func TestPlansStaleWhenAssignedShareMoves(t *testing.T) {
	e := s2SubWithCollection(t)
	e.share(t, "sh-free", "F", "")
	reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-free":"`+s2Carol+`"}}`)
	e.mustCall(t, subStoreSharesService, "archive", `{"share_id":"sh-free"}`)
	res := e.approve(reply)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "live shares changed") {
		t.Fatalf("approve after the assigned share was archived: %d %s", res.Code, res.Body.String())
	}
	if len(e.appliedRequests()) != 0 {
		t.Fatal("a stale plan was applied")
	}
	if a := e.approval(reply.ApprovalID); a.Status != model.ApprovalRejected || a.Reason != subStorePlanStaleShares {
		t.Fatalf("approval = %s %q", a.Status, a.Reason)
	}
}

// TestPlansStaleWhenShareIdentityChanges: a share that keeps its place on
// the record but serves a different identity at the decision than at the
// propose makes the plan stale, and nothing is applied. The share count is
// unchanged in every case, and the decision previews render the identities
// the plan names, so the identity comparison is the only check that sees
// the move. Without it the operator would approve a diff computed for a
// binding that no longer exists.
func TestPlansStaleWhenShareIdentityChanges(t *testing.T) {
	assertStale := func(t *testing.T, e *s2PlanEnv, reply subStorePlansProposeReply, applied int) {
		t.Helper()
		res := e.approve(reply)
		if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "live shares changed") {
			t.Fatalf("approve after a share's identity changed: %d %s", res.Code, res.Body.String())
		}
		if got := e.appliedRequests(); len(got) != applied {
			t.Fatalf("a stale plan was applied: %+v", got)
		}
		if a := e.approval(reply.ApprovalID); a.Status != model.ApprovalRejected || a.Reason != subStorePlanStaleShares {
			t.Fatalf("approval = %s %q", a.Status, a.Reason)
		}
	}
	t.Run("bound share cleared by a clear-only plan", func(t *testing.T) {
		e := s2SubWithCollection(t)
		reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
		if !reply.Required {
			t.Fatalf("propose = %+v", reply)
		}
		clearing, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r1","share_identities":{"sh-f":""}}`)
		if plan.Mode != subStorePlanModeClear {
			t.Fatalf("clearing plan mode = %q", plan.Mode)
		}
		if res := e.approve(clearing); res.Code != http.StatusOK {
			t.Fatalf("approve the clearing: %d %s", res.Code, res.Body.String())
		}
		assertStale(t, e, reply, 0)
		for _, id := range []string{"F", "C"} {
			if snap, ok := e.snapshot(id); !ok || snap.Stale {
				t.Fatalf("a stale plan touched the snapshot of %s: %+v present=%v", id, snap, ok)
			}
		}
		if got, _ := e.shareIdentity(t, "sh-c"); got != s2Alice {
			t.Fatalf("a stale plan changed the collection's share: %q", got)
		}
	})
	t.Run("bound share moved to another identity", func(t *testing.T) {
		e := s2SubWithCollection(t)
		reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
		e.share(t, "sh-f", "F", s2Carol)
		assertStale(t, e, reply, 0)
	})
	t.Run("assigned share given an identity by another plan", func(t *testing.T) {
		e := s2SubWithCollection(t)
		e.share(t, "sh-free", "F", "")
		reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-free":"`+s2Carol+`"}}`)
		other, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r1","share_identities":{"sh-free":"`+s2Alice+`"}}`)
		if res := e.approve(other); res.Code != http.StatusOK {
			t.Fatalf("approve the other assignment: %d %s", res.Code, res.Body.String())
		}
		assertStale(t, e, reply, 0)
		if got, _ := e.shareIdentity(t, "sh-free"); got != s2Alice {
			t.Fatalf("a stale plan moved the share from one identity to another: %q", got)
		}
	})
	t.Run("cleared share rebound before a clear-only decision", func(t *testing.T) {
		e := newS2PlanEnv(t)
		e.share(t, "sh-dark", "provider-rec", s2Alice)
		reply, _ := e.propose(t, `{"subscription_id":"provider-rec","from_revision":"p1","to_revision":"p1","share_identities":{"sh-dark":""}}`)
		e.share(t, "sh-dark", "provider-rec", s2Bob)
		assertStale(t, e, reply, 0)
		if got, _ := e.shareIdentity(t, "sh-dark"); got != s2Bob {
			t.Fatalf("a stale clearing cleared an identity it never showed: %q", got)
		}
	})
}

// s2MigrateBoth proposes the migration of both legacy members of C with an
// identity for every share.
func s2MigrateBoth(t *testing.T, e *s2PlanEnv) subStorePlansProposeReply {
	t.Helper()
	reply, _ := e.propose(t, `{"subscription_id":"L1","from_revision":"v1","to_revision":"f1",
		"records":[{"subscription_id":"L2","from_revision":"v2","to_revision":"f2"}],
		"share_identities":{"sh-l1":"`+s2Bob+`","sh-l2":"`+s2Carol+`","sh-c":"`+s2Alice+`"}}`)
	if !reply.Required {
		t.Fatalf("migration = %+v", reply)
	}
	return reply
}

// TestPlansMultiRecordMigrationAppliesInOrder: both members are promoted in
// one apply, in order, each with its own grant, and each record's shares
// and the collection's take their identities, with every closure snapshot
// dropped.
func TestPlansMultiRecordMigrationAppliesInOrder(t *testing.T) {
	e := s2TwoLegacyMembers(t)
	e.record(t, fleetDependsFacts{ID: "unrelated", Revision: "u1", Source: "remote"})
	reply := s2MigrateBoth(t, e)
	if res := e.approve(reply); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	applied := e.appliedRequests()
	if len(applied) != 2 || applied[0].SubscriptionID != "L1" || applied[0].Revision != "f1" || applied[0].ExpectedRevision != "v1" ||
		applied[1].SubscriptionID != "L2" || applied[1].Revision != "f2" || applied[0].ApprovalID != reply.ApprovalID {
		t.Fatalf("apply_revision ran %+v", applied)
	}
	for share, want := range map[string]string{"sh-l1": s2Bob, "sh-l2": s2Carol, "sh-c": s2Alice} {
		if got, _ := e.shareIdentity(t, share); got != want {
			t.Fatalf("%s serves %q, want %q", share, got, want)
		}
	}
	for _, id := range []string{"L1", "L2", "C"} {
		if _, ok := e.snapshot(id); ok {
			t.Fatalf("the snapshot of %s survived the apply", id)
		}
	}
	if snap, ok := e.snapshot("unrelated"); !ok || snap.Stale {
		t.Fatalf("a record outside the closure lost its snapshot: %+v %v", snap, ok)
	}
	if a := e.approval(reply.ApprovalID); a.Status != model.ApprovalApplied {
		t.Fatalf("approval = %s %q", a.Status, a.Reason)
	}
}

// TestPlansMultiRecordPartialFailureLeavesCollectionRefusing: when the second
// member fails, the first is finished (promoted, its snapshot dropped, its
// shares assigned), while the failed record's shares and the collection's
// keep their state; the reason names the record applied.
func TestPlansMultiRecordPartialFailureLeavesCollectionRefusing(t *testing.T) {
	e := s2TwoLegacyMembers(t)
	reply := s2MigrateBoth(t, e)
	e.failApply("L2", errors.New("plugin said: record L2 secret-marker"))
	res := e.approve(reply)
	if res.Code != http.StatusBadGateway || strings.Contains(res.Body.String(), "secret-marker") {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if got, _ := e.shareIdentity(t, "sh-l1"); got != s2Bob {
		t.Fatalf("the promoted member's share = %q, want its identity", got)
	}
	for _, share := range []string{"sh-l2", "sh-c"} {
		if got, archived := e.shareIdentity(t, share); got != "" || archived {
			t.Fatalf("%s changed although its record did not apply: %q archived=%v", share, got, archived)
		}
	}
	if _, ok := e.snapshot("L1"); ok {
		t.Fatal("the promoted member's snapshot was kept")
	}
	a := e.approval(reply.ApprovalID)
	if a.Status != model.ApprovalApproved || !strings.Contains(a.Reason, "failed at record L2") || !strings.Contains(a.Reason, "L1") ||
		strings.Contains(a.Reason, "the record is unchanged") || strings.Contains(a.Reason, "secret-marker") {
		t.Fatalf("approval after a partial failure = %s %q", a.Status, a.Reason)
	}
}

// TestPartialMultiRecordFailureStaleMarksClosure: a failure at any record
// stale-marks the recomputed closure and drops nothing further, so the
// failed member and the collection keep their last-good snapshots for the
// refetch, and a record outside the closure is untouched.
func TestPartialMultiRecordFailureStaleMarksClosure(t *testing.T) {
	e := s2TwoLegacyMembers(t)
	e.record(t, fleetDependsFacts{ID: "unrelated", Revision: "u1", Source: "remote"})
	reply := s2MigrateBoth(t, e)
	e.failApply("L2", errors.New("index conflict"))
	// The refetch after the failure fails too, so what the stale mark left
	// is what the next poll sees.
	e.srv.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{}, errors.New("provider down")
	}
	e.approve(reply)
	for _, id := range []string{"L2", "C"} {
		snap, ok := e.snapshot(id)
		if !ok || !snap.Stale || snap.Raw != "snap-"+id {
			t.Fatalf("%s after a partial failure: %+v present=%v, want its last-good snapshot stale-marked", id, snap, ok)
		}
	}
	if snap, _ := e.snapshot("unrelated"); snap.Stale {
		t.Fatal("a record outside the closure was stale-marked")
	}
}

// TestPlanApplyFailureLeavesSharesUnchanged: a failed apply writes no share
// change: assignments, clearings and archivals wait for a successful one.
func TestPlanApplyFailureLeavesSharesUnchanged(t *testing.T) {
	e := s2SubWithCollection(t)
	e.share(t, "sh-free", "F", "")
	e.share(t, "sh-gone", "F", "")
	reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-free":"`+s2Carol+`","sh-c":""},"archive_shares":["sh-gone"]}`)
	e.failApply("F", errors.New("expected_revision_mismatch"))
	if res := e.approve(reply); res.Code != http.StatusBadGateway {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	for share, want := range map[string]string{"sh-free": "", "sh-c": s2Alice, "sh-gone": ""} {
		if got, archived := e.shareIdentity(t, share); got != want || archived {
			t.Fatalf("%s after a failed apply: %q archived=%v", share, got, archived)
		}
	}
	if a := e.approval(reply.ApprovalID); !strings.Contains(a.Reason, "may have been promoted") {
		t.Fatalf("reason = %q", a.Reason)
	}
}

// TestPlanApplyDropsClosureSnapshotsOnlyOnSuccess: the closure's snapshots
// are dropped after apply_revision succeeded and never before: during the
// call they are untouched, and a failed apply keeps them, stale-marked.
func TestPlanApplyDropsClosureSnapshotsOnlyOnSuccess(t *testing.T) {
	e := s2SubWithCollection(t)
	presentDuring := false
	e.onApply = func(context.Context, subStoreApplyRevisionRequest) {
		f, okF := e.snapshot("F")
		c, okC := e.snapshot("C")
		presentDuring = okF && okC && !f.Stale && !c.Stale
	}
	reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if res := e.approve(reply); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if !presentDuring {
		t.Fatal("the closure's snapshots were dropped or marked before apply_revision returned")
	}
	for _, id := range []string{"F", "C"} {
		if _, ok := e.snapshot(id); ok {
			t.Fatalf("%s's snapshot survived a successful apply", id)
		}
	}

	failed := s2SubWithCollection(t)
	failed.failApply("F", errors.New("refused"))
	failed.srv.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{}, errors.New("provider down")
	}
	reply, _ = failed.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	failed.approve(reply)
	for _, id := range []string{"F", "C"} {
		if snap, ok := failed.snapshot(id); !ok || snap.Raw != "snap-"+id {
			t.Fatalf("%s's snapshot was dropped by a failed apply: %+v %v", id, snap, ok)
		}
	}
}

// TestPlanApplyMarksStaleOnFailure: a failed apply stale-marks the closure's
// snapshots so the next access refetches, which completes a half-done
// promotion.
func TestPlanApplyMarksStaleOnFailure(t *testing.T) {
	e := s2SubWithCollection(t)
	e.record(t, fleetDependsFacts{ID: "outside", Revision: "o1", Source: "remote"})
	e.failApply("F", errors.New("killed after the index put"))
	// The refetch after the failure must fail too, so the stale mark is what
	// the next poll sees.
	e.srv.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{}, errors.New("provider down")
	}
	reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	e.approve(reply)
	for _, id := range []string{"F", "C"} {
		if snap, ok := e.snapshot(id); !ok || !snap.Stale {
			t.Fatalf("%s after a failed apply: %+v %v, want stale-marked", id, snap, ok)
		}
	}
	if snap, _ := e.snapshot("outside"); snap.Stale {
		t.Fatal("a record outside the closure was stale-marked")
	}
}

// TestFailedApplyRefetchesAtOnce: after a failed apply core refreshes the
// failed record at once, from the decision path, once the share-write lock
// and the plugin gate are free. The test runs under a deadline, so a gate
// deadlock fails it instead of hanging it.
func TestFailedApplyRefetchesAtOnce(t *testing.T) {
	defer s2Deadline(t, 30*time.Second)()
	e := s2SubWithCollection(t)
	e.failApply("F", errors.New("killed after the index put"))
	var fetched atomic.Int64
	var gateFree, lockFree atomic.Bool
	e.srv.subscriptionFetch = func(_ context.Context, _, id string) (model.SubscriptionSnapshot, error) {
		if id == "F" {
			fetched.Add(1)
			if e.srv.subStoreSvc.mu.TryLock() {
				e.srv.subStoreSvc.mu.Unlock()
				lockFree.Store(true)
			}
			gateFree.Store(true)
		}
		return model.SubscriptionSnapshot{Raw: "after-" + id, FetchedAt: e.srv.now()}, nil
	}
	reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if res := e.approve(reply); res.Code != http.StatusBadGateway {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if fetched.Load() != 1 || !lockFree.Load() || !gateFree.Load() {
		t.Fatalf("refetches %d, lock free %v, gate free %v", fetched.Load(), lockFree.Load(), gateFree.Load())
	}
	if snap, ok := e.snapshot("F"); !ok || snap.Raw != "after-F" {
		t.Fatalf("F after the refetch: %+v %v", snap, ok)
	}
}

// s2DeleteFixture is a fleet record F with two shares of its own, read by a
// collection T through a member tag, with a share of its own.
func s2DeleteFixture(t *testing.T) *s2PlanEnv {
	t.Helper()
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "T", Revision: "t1", Kind: subStoreRecordKindCollection, FleetBound: true})
	e.graph.edge("T", "F", fleetDependsViaMemberTag)
	e.share(t, "sh-f", "F", s2Alice)
	e.share(t, "sh-f2", "F", "")
	e.share(t, "sh-t", "T", s2Bob)
	e.previewer.set("F", "r1", nil, s2Result(0, 1))
	e.previewer.set("T", "t1", nil, s2Result(0, 1, 2))
	e.previewer.set("T", "t1", map[string]string{"F": ""}, s2Result(2))
	return e
}

// TestPlanDeleteActionArchivesOwnSharesOnly: a delete plan archives the
// record's own shares and calls apply_revision with action delete; the
// tag-dependent collection's diff shows the member's lines removed, its
// share keeps serving, and its snapshot is dropped so it refetches without
// the member.
func TestPlanDeleteActionArchivesOwnSharesOnly(t *testing.T) {
	e := s2DeleteFixture(t)
	reply, plan := e.propose(t, `{"subscription_id":"F","action":"delete","from_revision":"r1"}`)
	if !reply.Required || plan.Action != subStorePlanActionDelete || plan.ToRevision != "" || len(plan.Archivals) != 2 {
		t.Fatalf("delete plan = %+v", plan)
	}
	tSection := s2Section(t, plan, "T")
	bob, _ := s2Identity(tSection, s2Bob)
	if tSection.MemberRevisions["F"] != "" || len(tSection.MemberRevisions) != 1 || len(bob.Removed) != 2 {
		t.Fatalf("the tag-dependent collection's section = %+v", tSection)
	}
	alice, _ := s2Identity(s2Section(t, plan, "F"), s2Alice)
	if len(alice.Removed) != 2 || len(alice.Added) != 0 {
		t.Fatalf("the deleted record's diff is not all-removed: %+v", alice)
	}
	if res := e.approve(reply); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	applied := e.appliedRequests()
	if len(applied) != 1 || applied[0].Action != subStorePlanActionDelete || applied[0].Revision != "r1" || applied[0].ExpectedRevision != "r1" {
		t.Fatalf("apply_revision ran %+v", applied)
	}
	for share, archivedWant := range map[string]bool{"sh-f": true, "sh-f2": true, "sh-t": false} {
		if _, archived := e.shareIdentity(t, share); archived != archivedWant {
			t.Fatalf("%s archived=%v, want %v", share, archived, archivedWant)
		}
	}
	if _, ok := e.snapshot("T"); ok {
		t.Fatal("the dependent collection's snapshot was kept")
	}
	if code, _ := e.proposeErr(`{"subscription_id":"F","action":"delete","from_revision":"r1","to_revision":"r2"}`); code != http.StatusBadRequest {
		t.Fatalf("a delete with a to_revision: %d", code)
	}
}

// TestPlanDeleteRefusesExplicitDependents: a delete is refused while a
// collection names the record explicitly, live or staged.
func TestPlanDeleteRefusesExplicitDependents(t *testing.T) {
	e := s2DeleteFixture(t)
	e.record(t, fleetDependsFacts{ID: "E", Revision: "e1", Kind: subStoreRecordKindCollection, FleetBound: true})
	e.graph.edge("E", "F", fleetDependsViaMember)
	code, body := e.proposeErr(`{"subscription_id":"F","action":"delete","from_revision":"r1"}`)
	if code != http.StatusConflict || !strings.Contains(body, apiErrorFleetDeleteHasExplicitDependents) || !strings.Contains(body, "E") {
		t.Fatalf("a delete under an explicit member: %d %s", code, body)
	}
	if _, status, body := e.publish(`{"subscription_id":"F","action":"delete","expected_revision":"r1"}`); status != http.StatusConflict ||
		!strings.Contains(body, apiErrorFleetDeleteHasExplicitDependents) {
		t.Fatalf("publish of a delete under an explicit member: %d %s", status, body)
	}
}

// TestSharesUpdateStillRefusesIdentityChange: shares.update refuses any
// change of a share's identity for every caller, empty to an id included;
// only a plan's apply gives or clears one.
func TestSharesUpdateStillRefusesIdentityChange(t *testing.T) {
	e := s2SubWithCollection(t)
	e.share(t, "sh-free", "F", "")
	for _, body := range []string{
		`{"share_id":"sh-free","identity_id":"` + s2Alice + `"}`,
		`{"share_id":"sh-f","identity_id":"` + s2Carol + `"}`,
		`{"share_id":"sh-f","identity_id":""}`,
	} {
		_, err := e.call(subStoreSvcAdmin, subStoreSharesService, "update", body)
		if subStoreSvcErrStatus(err) != http.StatusConflict || !strings.Contains(subStoreSvcErrBody(err), apiErrorIdentityChangeRefused) {
			t.Fatalf("update %s: %v %s", body, err, subStoreSvcErrBody(err))
		}
	}
	// Sending the share's own identity back with another field is fine.
	if _, err := e.call(subStoreSvcAdmin, subStoreSharesService, "update", `{"share_id":"sh-f","identity_id":"`+s2Bob+`","display_name":"Bob"}`); err != nil {
		t.Fatalf("an update that keeps the identity: %v", err)
	}
}

// TestPlansStatusReportsStale: the status row says stale for a plan
// rejected as stale, and names the action and mode, so the UI never parses a
// reason.
func TestPlansStatusReportsStale(t *testing.T) {
	e := s2SubWithCollection(t)
	stale, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	e.share(t, "sh-late", "F", s2Carol)
	e.approve(stale)
	pending, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	var rows struct {
		Plans []subStorePlanStatusRow `json:"plans"`
	}
	if err := json.Unmarshal(e.mustCall(t, subStorePlansService, "status", `{"subscription_id":"F"}`), &rows); err != nil {
		t.Fatal(err)
	}
	byID := map[string]subStorePlanStatusRow{}
	for _, row := range rows.Plans {
		byID[row.ApprovalID] = row
	}
	if row := byID[stale.ApprovalID]; !row.Stale || row.Status != model.ApprovalRejected || row.Action != subStorePlanActionPromote || row.Mode != subStorePlanModePromote {
		t.Fatalf("stale row = %+v", row)
	}
	if row := byID[pending.ApprovalID]; row.Stale || row.Status != model.ApprovalPending {
		t.Fatalf("pending row = %+v", row)
	}
	// A plan an operator rejected is rejected, not stale.
	body, _ := json.Marshal(map[string]string{"approval_id": pending.ApprovalID})
	rec := httptestRecorder(t, e, "/api/network/approvals/reject", body)
	if rec != http.StatusOK {
		t.Fatalf("reject: %d", rec)
	}
	var rejected struct {
		Plans []subStorePlanStatusRow `json:"plans"`
	}
	if err := json.Unmarshal(e.mustCall(t, subStorePlansService, "status", `{"approval_id":"`+pending.ApprovalID+`"}`), &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Plans[0].Stale || rejected.Plans[0].Status != model.ApprovalRejected {
		t.Fatalf("an operator's rejection reads stale: %+v", rejected.Plans[0])
	}
	// The collection's plans list them too: it is in their closure.
	var byClosure struct {
		Plans []subStorePlanStatusRow `json:"plans"`
	}
	if err := json.Unmarshal(e.mustCall(t, subStorePlansService, "status", `{"subscription_id":"C"}`), &byClosure); err != nil {
		t.Fatal(err)
	}
	if len(byClosure.Plans) != 2 {
		t.Fatalf("status by a closure record lists %d plans", len(byClosure.Plans))
	}
}

// TestAssignmentOnlyPlanAppliesWithoutStagedRevision: an assignment-only
// plan calls no apply_revision, drops no snapshot, and gives the share its
// identity under the lock.
func TestAssignmentOnlyPlanAppliesWithoutStagedRevision(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, FleetBound: true})
	e.share(t, "sh-new", "F", "")
	e.previewer.set("F", "r1", nil, s2Result(0, 1))
	reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r1","share_identities":{"sh-new":"`+s2Alice+`"}}`)
	if res := e.approve(reply); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if len(e.appliedRequests()) != 0 {
		t.Fatal("an assignment-only plan called apply_revision")
	}
	if got, _ := e.shareIdentity(t, "sh-new"); got != s2Alice {
		t.Fatalf("the share serves %q", got)
	}
	if snap, ok := e.snapshot("F"); !ok || snap.Stale {
		t.Fatal("an assignment-only plan touched the record's snapshot")
	}
	if a := e.approval(reply.ApprovalID); a.Status != model.ApprovalApplied {
		t.Fatalf("approval = %s", a.Status)
	}
	// The record moved before the decision: the plan is stale.
	e.share(t, "sh-new2", "F", "")
	reply2, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r1","share_identities":{"sh-new2":"`+s2Bob+`"}}`)
	e.graph.update("F", func(f *fleetDependsFacts) { f.Revision = "r9" })
	if res := e.approve(reply2); res.Code != http.StatusConflict || e.approval(reply2.ApprovalID).Reason != subStorePlanStaleLive {
		t.Fatalf("approve after the record moved: %d %s", res.Code, res.Body.String())
	}
}

// TestPlansAssignmentOnlyPlanClearsIdentity: from_revision equal to
// to_revision with an identity cleared clears it at the apply, the exit for
// an identity-bound share on a record the decoy darkened.
func TestPlansAssignmentOnlyPlanClearsIdentity(t *testing.T) {
	e := newS2PlanEnv(t)
	e.share(t, "sh-dark", "provider-rec", s2Alice)
	reply, plan := e.propose(t, `{"subscription_id":"provider-rec","from_revision":"p1","to_revision":"p1","share_identities":{"sh-dark":""}}`)
	if !reply.Required || plan.Mode != subStorePlanModeClear || len(plan.Clearings) != 1 || plan.Clearings[0].IdentityID != s2Alice {
		t.Fatalf("clearing plan = %+v", plan)
	}
	if res := e.approve(reply); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if got, archived := e.shareIdentity(t, "sh-dark"); got != "" || archived {
		t.Fatalf("the share after the clearing: %q archived=%v", got, archived)
	}
}

// TestClearOnlyPlanMakesNoPluginCall: a clear-only plan's propose, decision
// and apply call no previewer, no depends_on and no render: a plugin outage
// never blocks a clearing.
func TestClearOnlyPlanMakesNoPluginCall(t *testing.T) {
	e := newS2PlanEnv(t)
	e.share(t, "sh-dark", "purged-rec", s2Alice)
	e.share(t, "sh-old", "purged-rec", "")
	e.previewer.err = errors.New("previewer must not be called")
	e.graph.setErr(errors.New("depends_on must not be called"))
	var renders atomic.Int64
	e.srv.subscriptionRender = func(context.Context, model.SubscriptionShare, string, string, shareRenderVariant, model.SubscriptionSnapshot) (renderedSubscription, error) {
		renders.Add(1)
		return renderedSubscription{}, errors.New("render must not be called")
	}
	reply, _ := e.propose(t, `{"subscription_id":"purged-rec","from_revision":"","to_revision":"","share_identities":{"sh-dark":""},"archive_shares":["sh-old"]}`)
	if res := e.approve(reply); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if got, _ := e.shareIdentity(t, "sh-dark"); got != "" {
		t.Fatalf("the share serves %q", got)
	}
	if _, archived := e.shareIdentity(t, "sh-old"); !archived {
		t.Fatal("the archival did not apply")
	}
	if len(e.previewer.queries()) != 0 || e.graph.callCount() != 0 || renders.Load() != 0 || len(e.appliedRequests()) != 0 {
		t.Fatalf("plugin calls: previews %d, depends_on %d, renders %d, applies %d",
			len(e.previewer.queries()), e.graph.callCount(), renders.Load(), len(e.appliedRequests()))
	}
	// A clear-only plan's stale check is its shares: a new share on the
	// record makes it stale.
	reply, _ = e.propose(t, `{"subscription_id":"purged-rec","from_revision":"","to_revision":"","archive_shares":["sh-dark"]}`)
	e.share(t, "sh-late", "purged-rec", "")
	if res := e.approve(reply); res.Code != http.StatusConflict {
		t.Fatalf("approve a clearing after a share appeared: %d %s", res.Code, res.Body.String())
	}
	// An identity cannot be given in one.
	if code, _ := e.proposeErr(`{"subscription_id":"purged-rec","from_revision":"","to_revision":"","share_identities":{"sh-late":"` + s2Alice + `"}}`); code != http.StatusBadRequest {
		t.Fatalf("an assignment without a revision: %d", code)
	}
}

// TestPlansStaleWhenStagedRevisionReplaced: a later save that stages a new
// revision replaces the one the plan publishes; render answers
// revision_unknown for it, and the decision records the plan as stale
// instead of leaving it pending forever.
func TestPlansStaleWhenStagedRevisionReplaced(t *testing.T) {
	e := s2SubWithCollection(t)
	reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	e.graph.update("F", func(f *fleetDependsFacts) { f.StagedRevision = "r3" })
	res := e.approve(reply)
	if res.Code != http.StatusConflict {
		t.Fatalf("approve over a replaced staged revision: %d %s", res.Code, res.Body.String())
	}
	if a := e.approval(reply.ApprovalID); a.Status != model.ApprovalRejected || a.Reason != subStorePlanStaleStaged {
		t.Fatalf("approval = %s %q", a.Status, a.Reason)
	}
	if len(e.appliedRequests()) != 0 {
		t.Fatal("a replaced revision was applied")
	}
}

// TestPlansStaleWhenClosureGrows: a collection created over the record after
// the propose, with a share of its own, is outside the reviewed closure, so
// the decision, which computes the closure again under the share-write lock,
// finds the plan stale; also when the collection appears while the decision's
// previews run.
func TestPlansStaleWhenClosureGrows(t *testing.T) {
	grow := func(e *s2PlanEnv) {
		e.record(t, fleetDependsFacts{ID: "C2", Revision: "n1", Kind: subStoreRecordKindCollection, FleetBound: true})
		e.graph.edge("C2", "F", fleetDependsViaMember)
		e.share(t, "sh-c2", "C2", s2Carol)
	}
	t.Run("between propose and approve", func(t *testing.T) {
		e := s2SubWithCollection(t)
		reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
		grow(e)
		if res := e.approve(reply); res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "records this plan covers changed") {
			t.Fatalf("approve after the closure grew: %d %s", res.Code, res.Body.String())
		}
		if len(e.appliedRequests()) != 0 {
			t.Fatal("applied")
		}
	})
	t.Run("during the decision's previews", func(t *testing.T) {
		e := s2SubWithCollection(t)
		reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
		grown := false
		e.previewer.onCall = func(q subStoreBindQuery) {
			if !grown && q.SubscriptionID == "C" {
				grown = true
				grow(e)
			}
		}
		if res := e.approve(reply); res.Code != http.StatusConflict || e.approval(reply.ApprovalID).Reason != subStorePlanStaleClosure {
			t.Fatalf("approve while the closure grew: %d %s", res.Code, res.Body.String())
		}
	})
}

// TestPlanApplyDropsRecomputedClosure: the plan proposed again over the grown
// closure covers the new collection, and its apply drops that collection's
// snapshot with the rest.
func TestPlanApplyDropsRecomputedClosure(t *testing.T) {
	e := s2SubWithCollection(t)
	e.record(t, fleetDependsFacts{ID: "C2", Revision: "n1", Kind: subStoreRecordKindCollection, FleetBound: true})
	e.graph.edge("C2", "F", fleetDependsViaMember)
	e.share(t, "sh-c2", "C2", s2Carol)
	reply, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if !slices.Equal(plan.Closure, []string{"C", "C2", "F"}) {
		t.Fatalf("closure = %v", plan.Closure)
	}
	if res := e.approve(reply); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if _, ok := e.snapshot("C2"); ok {
		t.Fatal("the new collection's snapshot was kept")
	}
}

// httptestRecorder posts body to an approval endpoint as the approver.
func httptestRecorder(t *testing.T, e *s2PlanEnv, path string, body []byte) int {
	t.Helper()
	if path != "/api/network/approvals/reject" {
		t.Fatalf("no endpoint %s", path)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	e.srv.handleRejectApproval(rec, req, subStorePlanApprover)
	return rec.Code
}
