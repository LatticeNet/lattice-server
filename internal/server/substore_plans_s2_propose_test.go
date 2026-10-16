package server

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// s2SubWithCollection is a fleet sub F (live r1, staged r2) gathered by a
// collection C (live c1) that serves alice through share sh-c, while F
// itself serves bob through sh-f.
func s2SubWithCollection(t testing.TB) *s2PlanEnv {
	t.Helper()
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "C", Revision: "c1", Kind: subStoreRecordKindCollection, FleetBound: true})
	e.graph.edge("C", "F", fleetDependsViaMember)
	e.share(t, "sh-f", "F", s2Bob)
	e.share(t, "sh-c", "C", s2Alice)
	e.previewer.set("F", "r1", nil, s2Result(0, 1))
	e.previewer.set("F", "r2", nil, s2Result(0, 1, 2))
	e.previewer.set("C", "c1", nil, s2Result(0, 1))
	e.previewer.set("C", "c1", map[string]string{"F": "r2"}, s2Result(0, 1, 2))
	return e
}

// TestPlansProposeRendersOncePerRevision: a plan over a record and a
// collection that reads it renders each side of each record once, whatever
// the number of identities, and binds every identity into that render.
func TestPlansProposeRendersOncePerRevision(t *testing.T) {
	e := s2SubWithCollection(t)
	e.share(t, "sh-f2", "F", s2Carol)
	e.share(t, "sh-f3", "F", s2Alice)
	reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if !reply.Required {
		t.Fatalf("propose = %+v", reply)
	}
	queries := e.previewer.queries()
	if len(queries) != 4 {
		t.Fatalf("propose rendered %d times, want 4 (two sides of two records): %+v", len(queries), queries)
	}
	for _, q := range queries {
		if q.SubscriptionID == "F" && len(q.IdentityIDs) != 3 {
			t.Fatalf("F's render bound %v, want all three identities in one render", q.IdentityIDs)
		}
	}
}

// TestPlansRequiredCoversFleetClosure: a sub whose own shares are all
// identity-less still needs a plan when a collection reading it has a share
// that names an identity.
func TestPlansRequiredCoversFleetClosure(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "C", Revision: "c1", Kind: subStoreRecordKindCollection, FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "lonely", Revision: "l1", Source: subStoreSourceFleet, StagedRevision: "l2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.graph.edge("C", "F", fleetDependsViaMemberTag)
	e.share(t, "sh-f", "F", "")
	e.share(t, "sh-c", "C", s2Alice)
	e.share(t, "sh-l", "lonely", "")
	reply, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if !reply.Required || !slices.Equal(plan.Closure, []string{"C", "F"}) {
		t.Fatalf("a sub read by a collection with an identity share: %+v, closure %v", reply, plan.Closure)
	}
	if c := s2Section(t, plan, "C"); c.Role != subStorePlanRoleDependent || len(c.Shares) != 1 || c.Shares[0].IdentityID != s2Alice {
		t.Fatalf("the collection's section = %+v", c)
	}
	if reply, _ := e.propose(t, `{"subscription_id":"lonely","from_revision":"l1","to_revision":"l2"}`); reply.Required {
		t.Fatalf("a record whose closure has no fleet-bound share needed a plan: %+v", reply)
	}
}

// TestPlansProposeWithAssignmentsIsAlwaysRequired: a propose that gives a
// share an identity is privileged even when no live share names one.
func TestPlansProposeWithAssignmentsIsAlwaysRequired(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "L", Revision: "v1", Source: subStoreSourceVPNCore, StagedRevision: "f1", StagedSource: subStoreSourceFleet, StagedMigrated: true, OwnerCredentials: true})
	e.share(t, "sh-l", "L", "")
	e.previewer.set("L", "f1", nil, s2Result(0, 1))
	reply, plan := e.propose(t, `{"subscription_id":"L","from_revision":"v1","to_revision":"f1","share_identities":{"sh-l":"`+s2Alice+`"}}`)
	if !reply.Required || reply.ApprovalID == "" {
		t.Fatalf("a migration with an assignment = %+v", reply)
	}
	if len(plan.Assignments) != 1 || plan.Assignments[0].ShareID != "sh-l" || plan.Assignments[0].IdentityID != s2Alice || plan.Assignments[0].Lines != 2 {
		t.Fatalf("assignments = %+v", plan.Assignments)
	}
	// An archival alone is privileged too.
	e.share(t, "sh-l2", "L", "")
	if reply, _ := e.propose(t, `{"subscription_id":"L","from_revision":"v1","to_revision":"f1","archive_shares":["sh-l2"],"share_identities":{"sh-l":"`+s2Alice+`"}}`); !reply.Required {
		t.Fatalf("an archival = %+v", reply)
	}
}

// TestPlansProposeAdmitsAssignmentOnlyPlan: from_revision equal to
// to_revision with an assignment files an assignment-only plan over the
// record's live revision alone.
func TestPlansProposeAdmitsAssignmentOnlyPlan(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, FleetBound: true})
	e.share(t, "sh-new", "F", "")
	e.share(t, "sh-old", "F", s2Bob)
	e.previewer.set("F", "r1", nil, s2Result(0, 1, 2))
	reply, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r1","share_identities":{"sh-new":"`+s2Alice+`"}}`)
	if !reply.Required || plan.Mode != subStorePlanModeAssign || plan.Role != subStorePlanRoleSelf || len(plan.ApplyOrder) != 0 {
		t.Fatalf("assignment-only plan = %+v / %+v", reply, plan)
	}
	queries := e.previewer.queries()
	if len(queries) != 1 || queries[0].Revision != "r1" || !slices.Equal(queries[0].IdentityIDs, []string{s2Alice}) {
		t.Fatalf("an assignment previews the live revision once, for the identity given: %+v", queries)
	}
	alice, ok := s2Identity(s2Section(t, plan, "F"), s2Alice)
	if !ok || len(alice.Added) != 3 || alice.Unchanged != 0 {
		t.Fatalf("the assigned identity's lines are added for the share: %+v", alice)
	}
	// Both revisions empty is a clear-only plan, which an assignment is not.
	if code, _ := e.proposeErr(`{"subscription_id":"F","from_revision":"","to_revision":"","share_identities":{"sh-new":"` + s2Alice + `"}}`); code != http.StatusBadRequest {
		t.Fatalf("an assignment with no revision: %d", code)
	}
}

// TestPlansProposeCarriesShareIdentityAssignments: the plan lists each
// assignment and clearing under its heading and marks the share rows, so
// the approval's hash covers them.
func TestPlansProposeCarriesShareIdentityAssignments(t *testing.T) {
	e := s2SubWithCollection(t)
	e.share(t, "sh-f-free", "F", "")
	e.share(t, "sh-c-free", "C", "")
	reply, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2",
		"share_identities":{"sh-f-free":"`+s2Carol+`","sh-c":""},"archive_shares":["sh-c-free"]}`)
	if !reply.Required {
		t.Fatal("not required")
	}
	if len(plan.Assignments) != 1 || plan.Assignments[0] != (subStorePlanAssignment{ShareID: "sh-f-free", SubscriptionID: "F", Slug: "sh-f-free", IdentityID: s2Carol, Lines: 3}) {
		t.Fatalf("assignments = %+v", plan.Assignments)
	}
	if len(plan.Clearings) != 1 || plan.Clearings[0].ShareID != "sh-c" || plan.Clearings[0].IdentityID != s2Alice || plan.Clearings[0].Lines != 2 {
		t.Fatalf("clearings = %+v", plan.Clearings)
	}
	if len(plan.Archivals) != 1 || plan.Archivals[0].ShareID != "sh-c-free" || plan.Archivals[0].SubscriptionID != "C" {
		t.Fatalf("archivals = %+v", plan.Archivals)
	}
	f := s2Section(t, plan, "F")
	assigned := false
	for _, share := range f.Shares {
		if share.ShareID == "sh-f-free" && share.Assigned && share.IdentityID == s2Carol && share.Added == 3 {
			assigned = true
		}
	}
	if !assigned {
		t.Fatalf("F's share rows = %+v", f.Shares)
	}
	c := s2Section(t, plan, "C")
	if len(c.UnboundShares) != 2 || !strings.Contains(reply.Plan, `"cleared_identity_id": "`+s2Alice+`"`) {
		t.Fatalf("C's unbound rows = %+v", c.UnboundShares)
	}
}

// TestPlansCollectionDiffFollowsStagedMember: the collection's after side
// is previewed at its live revision with member_revisions naming the changed
// member's staged revision, so its diff shows the line the staged member
// adds.
func TestPlansCollectionDiffFollowsStagedMember(t *testing.T) {
	e := s2SubWithCollection(t)
	_, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	c := s2Section(t, plan, "C")
	if c.Role != subStorePlanRoleDependent || c.FromRevision != "c1" || c.MemberRevisions["F"] != "r2" {
		t.Fatalf("collection section = %+v", c)
	}
	alice, ok := s2Identity(c, s2Alice)
	if !ok || len(alice.Added) != 1 || alice.Added[0].LineUUID != s2Lines[2] {
		t.Fatalf("the collection's diff does not follow the staged member: %+v", alice)
	}
	sawMembers := false
	for _, q := range e.previewer.queries() {
		if q.SubscriptionID == "C" && q.Revision == "c1" && q.MemberRevisions["F"] == "r2" {
			sawMembers = true
		}
	}
	if !sawMembers {
		t.Fatal("the collection was not previewed with member_revisions")
	}
}

// TestPlansClosureSeesStagedEdges: a collection that would gather the record
// only at the record's staged revision (a staged tag) is in the closure,
// because depends_on is read with include_staged.
func TestPlansClosureSeesStagedEdges(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "hk", Revision: "h1", Kind: subStoreRecordKindCollection})
	// The edge exists only in the staged state: F's staged tags carry hk's
	// member tag.
	e.graph.edge("hk", "F", fleetDependsViaMemberTag)
	e.share(t, "sh-hk", "hk", s2Alice)
	_, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if !slices.Equal(plan.Closure, []string{"F", "hk"}) {
		t.Fatalf("closure = %v", plan.Closure)
	}
	for _, call := range e.graph.calls {
		if call.SubscriptionID == "F" && !call.IncludeStaged {
			t.Fatal("the closure was read without include_staged")
		}
	}
}

// TestPlansCheckEachClosurePreviewAgainstItsOwnRevision: each record's
// preview is checked against that record's own live revision, not the plan's
// from_revision, which a dependent collection's never equals; a collection
// that moved makes propose refuse.
func TestPlansCheckEachClosurePreviewAgainstItsOwnRevision(t *testing.T) {
	e := s2SubWithCollection(t)
	if reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`); !reply.Required {
		t.Fatal("a closure whose collection is live at another revision than the record was refused")
	}
	// The previewer reads C live at c1 from the graph; the graph now says c2,
	// so the preview's live revision no longer matches what depends_on said.
	e.previewer.mu.Lock()
	e.previewer.live["C"] = "c-moved"
	e.previewer.mu.Unlock()
	if code, body := e.proposeErr(`{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`); code != http.StatusConflict || !strings.Contains(body, "live revision") {
		t.Fatalf("a collection that moved under the preview: %d %s", code, body)
	}
}

// TestPlansSkipStagedOnlyClosureRecords: a staged-only collection gathering
// the record is listed, not previewed, and neither its shares nor it count
// toward Required.
func TestPlansSkipStagedOnlyClosureRecords(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "new-c", Kind: subStoreRecordKindCollection, StagedRevision: "n1"})
	e.graph.edge("new-c", "F", fleetDependsViaMemberTag)
	e.share(t, "sh-f", "F", s2Bob)
	e.share(t, "sh-survivor", "new-c", s2Alice)
	e.previewer.set("F", "r1", nil, s2Result(0))
	e.previewer.set("F", "r2", nil, s2Result(0, 1))
	_, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	section := s2Section(t, plan, "new-c")
	if section.Role != subStorePlanRoleStagedOnly || len(section.Shares)+len(section.UnboundShares) != 0 {
		t.Fatalf("staged-only section = %+v", section)
	}
	for _, q := range e.previewer.queries() {
		if q.SubscriptionID == "new-c" {
			t.Fatal("a staged-only record was previewed")
		}
	}
	// Its surviving share alone does not make a plan required.
	e2 := newS2PlanEnv(t)
	e2.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e2.record(t, fleetDependsFacts{ID: "new-c", Kind: subStoreRecordKindCollection, StagedRevision: "n1"})
	e2.graph.edge("new-c", "F", fleetDependsViaMemberTag)
	e2.share(t, "sh-survivor", "new-c", s2Alice)
	if reply, _ := e2.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`); reply.Required {
		t.Fatalf("a staged-only record's share made the plan required: %+v", reply)
	}
}

// TestPlansProposeRefusesMigrationIncomplete: a collection over two legacy
// members cannot have one migrated alone; propose names the other, and
// accepts the plan once it promotes both.
func TestPlansProposeRefusesMigrationIncomplete(t *testing.T) {
	e := s2TwoLegacyMembers(t)
	code, body := e.proposeErr(`{"subscription_id":"L1","from_revision":"v1","to_revision":"f1"}`)
	if code != http.StatusConflict || !strings.Contains(body, apiErrorMigrationIncomplete) || !strings.Contains(body, "L2") {
		t.Fatalf("migrating one of two legacy members: %d %s", code, body)
	}
	reply, plan := e.propose(t, `{"subscription_id":"L1","from_revision":"v1","to_revision":"f1","records":[{"subscription_id":"L2","from_revision":"v2","to_revision":"f2"}],
		"share_identities":{"sh-c":"`+s2Alice+`"}}`)
	if !reply.Required || !slices.Equal(plan.ApplyOrder, []string{"L1", "L2"}) {
		t.Fatalf("both members: %+v order %v", reply, plan.ApplyOrder)
	}
	if !strings.HasPrefix(e.approval(reply.ApprovalID).Action, subStorePlanActionPrefix+"L1,L2") {
		t.Fatalf("the approval's action does not name both records: %s", e.approval(reply.ApprovalID).Action)
	}
}

// s2TwoLegacyMembers is a collection C over two legacy members L1 and L2,
// each with a staged migration; C serves alice, L1 serves bob, L2 carol.
func s2TwoLegacyMembers(t *testing.T) *s2PlanEnv {
	t.Helper()
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "L1", Revision: "v1", Source: subStoreSourceVPNCoreGraph, StagedRevision: "f1", StagedSource: subStoreSourceFleet, StagedMigrated: true, OwnerCredentials: true})
	e.record(t, fleetDependsFacts{ID: "L2", Revision: "v2", Source: subStoreSourceVPNCore, StagedRevision: "f2", StagedSource: subStoreSourceFleet, StagedMigrated: true, OwnerCredentials: true})
	e.record(t, fleetDependsFacts{ID: "C", Revision: "c1", Kind: subStoreRecordKindCollection, OwnerCredentials: true})
	e.graph.edge("C", "L1", fleetDependsViaMember)
	e.graph.edge("C", "L2", fleetDependsViaMember)
	e.graph.markUnionFleet("C")
	e.share(t, "sh-l1", "L1", "")
	e.share(t, "sh-l2", "L2", "")
	e.share(t, "sh-c", "C", "")
	for record, rev := range map[string]string{"L1": "f1", "L2": "f2"} {
		e.previewer.set(record, rev, nil, s2Result(0, 1))
	}
	return e
}

// TestPlansMultiRecordApplyOrdersMembersFirst: a plan promoting a collection
// and its members applies the members first, whatever order the request
// names them in.
func TestPlansMultiRecordApplyOrdersMembersFirst(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "a-coll", Revision: "c1", Kind: subStoreRecordKindCollection, StagedRevision: "c2", FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "z-member", Revision: "", StagedRevision: "z1", StagedSource: subStoreSourceFleet})
	e.graph.edge("a-coll", "z-member", fleetDependsViaMember)
	e.share(t, "sh-c", "a-coll", s2Alice)
	_, plan := e.propose(t, `{"subscription_id":"a-coll","from_revision":"c1","to_revision":"c2","records":[{"subscription_id":"z-member","from_revision":"","to_revision":"z1"}]}`)
	if !slices.Equal(plan.ApplyOrder, []string{"z-member", "a-coll"}) {
		t.Fatalf("apply order = %v, want the member first", plan.ApplyOrder)
	}
	if res := e.approve(subStorePlansProposeReply{ApprovalID: e.lastApproval(t), PlanSHA256: e.lastPlanSHA(t)}); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	applied := e.appliedRequests()
	if len(applied) != 2 || applied[0].SubscriptionID != "z-member" || applied[1].SubscriptionID != "a-coll" {
		t.Fatalf("apply_revision ran %+v", applied)
	}
	if got := subStorePlanApplyOrder([]string{"c", "b", "a"}, subStorePlanGraph{closure: fleetDependsGraph{edges: []fleetDependsEdge{
		{From: "a", To: "c", Via: fleetDependsViaMember}, {From: "a", To: "b", Via: fleetDependsViaMemberTag}}}}); !slices.Equal(got, []string{"b", "c", "a"}) {
		t.Fatalf("order = %v", got)
	}
}

func (e *s2PlanEnv) lastApproval(t *testing.T) string {
	t.Helper()
	newest := ""
	var at int64
	for _, a := range e.st.Approvals() {
		if a.Plugin == subStorePlanApprovalPlugin && (newest == "" || a.CreatedAt.UnixNano() >= at) {
			newest, at = a.ID, a.CreatedAt.UnixNano()
		}
	}
	if newest == "" {
		t.Fatal("no plan filed")
	}
	return newest
}

func (e *s2PlanEnv) lastPlanSHA(t *testing.T) string {
	return approvalPlanSHA(e.approval(e.lastApproval(t)))
}

// TestPlansProposeRefusesClosureWithFile: a file reading a record the plan
// makes fleet-bound cannot exist in S2, so propose refuses before anything is
// previewed, naming the file.
func TestPlansProposeRefusesClosureWithFile(t *testing.T) {
	e := s2SubWithCollection(t)
	e.record(t, fleetDependsFacts{ID: "clash", Revision: "x1", Kind: subStoreRecordKindFile})
	e.graph.edge("clash", "C", fleetDependsViaNodeSource)
	code, body := e.proposeErr(`{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if code != http.StatusConflict || !strings.Contains(body, apiErrorFleetFileUnavailable) || !strings.Contains(body, "clash") {
		t.Fatalf("a closure with a file: %d %s", code, body)
	}
	if len(e.previewer.queries()) != 0 {
		t.Fatal("a closure with a file was previewed")
	}
}

// TestPlansEmptyFromRevisionForRestoredRecord: a restored record has no live
// revision; propose accepts from_revision "" for it alone, skips its before
// render and shows every line as added.
func TestPlansEmptyFromRevisionForRestoredRecord(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "R", StagedRevision: "s1", StagedSource: subStoreSourceFleet})
	e.share(t, "sh-r", "R", s2Alice)
	e.previewer.set("R", "s1", nil, s2Result(0, 1))
	reply, plan := e.propose(t, `{"subscription_id":"R","from_revision":"","to_revision":"s1"}`)
	alice, ok := s2Identity(s2Section(t, plan, "R"), s2Alice)
	if !reply.Required || !plan.BeforeEmpty || !ok || len(alice.Added) != 2 || alice.Unchanged != 0 {
		t.Fatalf("restored record plan = %+v, alice %+v", plan, alice)
	}
	for _, q := range e.previewer.queries() {
		if q.Revision == "" {
			t.Fatal("the empty from side was rendered")
		}
	}
	e.record(t, fleetDependsFacts{ID: "live", Revision: "l1", Source: subStoreSourceFleet, StagedRevision: "l2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.share(t, "sh-live", "live", s2Alice)
	if code, body := e.proposeErr(`{"subscription_id":"live","from_revision":"","to_revision":"l2"}`); code != http.StatusConflict || !strings.Contains(body, "live revision") {
		t.Fatalf("an empty from_revision for a record that has a live one: %d %s", code, body)
	}
}

// TestPlanCoverageTextNamesTheDecoy: the plan says that an identity-less
// share on a fleet-bound record answers the decoy.
func TestPlanCoverageTextNamesTheDecoy(t *testing.T) {
	e := s2SubWithCollection(t)
	e.share(t, "sh-free", "F", "")
	_, plan := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if plan.Coverage != subStorePlanUnboundCoverage || !strings.Contains(plan.Coverage, "decoy") || !strings.Contains(plan.Coverage, "fleet-bound") {
		t.Fatalf("coverage = %q", plan.Coverage)
	}
}

// TestPlansProposeRefusesIdentityToIdentity: a share that serves one
// identity is never moved to another; it may be cleared.
func TestPlansProposeRefusesIdentityToIdentity(t *testing.T) {
	e := s2SubWithCollection(t)
	code, body := e.proposeErr(`{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-f":"` + s2Carol + `"}}`)
	if code != http.StatusConflict || !strings.Contains(body, apiErrorIdentityChangeRefused) {
		t.Fatalf("a move from bob to carol: %d %s", code, body)
	}
	for _, bad := range []string{
		`{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-f":"` + s2Bob + `"}}`,
		`{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-nowhere":"` + s2Bob + `"}}`,
		`{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-f":""},"archive_shares":["sh-f"]}`,
	} {
		if code, body := e.proposeErr(bad); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", bad, code, body)
		}
	}
	e.share(t, "sh-free", "F", "")
	if code, body := e.proposeErr(`{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-free":"vpnuser_nobody"}}`); code != http.StatusBadRequest {
		t.Fatalf("an unknown identity: %d %s", code, body)
	}
	if reply, _ := e.propose(t, `{"subscription_id":"F","from_revision":"r1","to_revision":"r2","share_identities":{"sh-f":""}}`); !reply.Required {
		t.Fatal("a clearing was refused")
	}
}

// An identity lands only on a record fleet-bound after the plan: a share of
// a provider record named by an assignment-only plan is refused.
func TestPlansAssignmentNeedsFleetRecord(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "P", Revision: "p1", Source: "remote"})
	e.share(t, "sh-p", "P", "")
	code, body := e.proposeErr(`{"subscription_id":"P","from_revision":"p1","to_revision":"p1","share_identities":{"sh-p":"` + s2Alice + `"}}`)
	if code != http.StatusBadRequest || !strings.Contains(body, apiErrorIdentityRequiresFleetRecord) {
		t.Fatalf("an identity on a provider record: %d %s", code, body)
	}
}

// TestDependsV2DecoderAcceptsV1Reply: the v2 decoder reads a v1 answer as
// ids without a closure, which the plans service refuses as an old plugin,
// while the fleet-write expiry keeps reading the ids of either version.
func TestDependsV2DecoderAcceptsV1Reply(t *testing.T) {
	v1 := []byte(`{"records":[{"id":"a","revision":"r"},{"id":"b"}],"version":"x"}`)
	g, err := decodeFleetDependsGraph(v1)
	if err != nil || g.v2 || len(g.records) != 2 || g.records["a"].Revision != "r" {
		t.Fatalf("v1 through the v2 decoder: %+v %v", g, err)
	}
	ids, err := decodeFleetDependsReply(v1)
	if err != nil || len(ids) != 2 {
		t.Fatalf("v1 through the expiry decoder: %v %v", ids, err)
	}
	v2 := []byte(`{"records":[{"id":"F","revision":"r1","kind":"sub","source":"fleet","fleet_bound":true},{"id":"C","revision":"c1","kind":"collection"}],
		"fleet_bound":["C","F"],"owner_credentials":[],"edges":[{"from":"C","to":"F","via":"member_tag"}],"version":"v"}`)
	g, err = decodeFleetDependsGraph(v2)
	if err != nil || !g.v2 || !g.fleetBound["C"] || len(g.edges) != 1 || !g.readers("F")["C"] {
		t.Fatalf("v2: %+v %v", g, err)
	}
	ids, err = decodeFleetDependsReply(v2)
	if err != nil || !ids["F"] || !ids["C"] {
		t.Fatalf("v2 through the expiry decoder: %v %v", ids, err)
	}
	for _, bad := range []string{
		`{"records":[{"id":"a"},{"id":"a"}],"fleet_bound":[],"owner_credentials":[],"edges":[]}`,
		`{"records":[{"id":"a"}],"fleet_bound":[],"owner_credentials":[],"edges":[{"from":"a","to":"b","via":"sibling"}]}`,
		`{"records":[{"id":"a"}],"fleet_bound":[],"owner_credentials":[],"edges":[{"from":"a","to":"a","via":"member"}]}`,
		`{"records":[{"id":"a\u0001"}]}`,
		`{"fleet_bound":[]}`,
	} {
		if _, err := decodeFleetDependsGraph([]byte(bad)); err == nil {
			t.Fatalf("decoded %s", bad)
		}
	}
}

// The plans service refuses a v1 depends_on answer instead of computing a
// closure from ids alone.
func TestPlansRefuseAV1DependsAnswer(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.share(t, "sh-f", "F", s2Alice)
	e.srv.substoreCatalogue.deps.query = func(context.Context, string, []byte) ([]byte, error) {
		return []byte(`{"records":[{"id":"F","revision":"r1"}]}`), nil
	}
	code, body := e.proposeErr(`{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	if code != http.StatusConflict || !strings.Contains(body, "0.18") {
		t.Fatalf("propose over a v1 depends_on: %d %s", code, body)
	}
}
