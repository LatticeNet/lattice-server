package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestPlansPublishAppliesWithoutApprovalWhenNoFleetBoundShare: a staged
// revision of a fleet record whose closure has no fleet-bound share goes
// live through publish, with no approval, inside core's apply and its grant,
// and the closure's snapshots are dropped.
func TestPlansPublishAppliesWithoutApprovalWhenNoFleetBoundShare(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "C", Revision: "c1", Kind: subStoreRecordKindCollection, FleetBound: true})
	e.graph.edge("C", "F", fleetDependsViaMember)
	var claimed error
	e.onApply = func(ctx context.Context, req subStoreApplyRevisionRequest) {
		body, _ := json.Marshal(req)
		_, claimed = e.srv.pluginRPC.CallGranted(ctx, subStorePluginID, map[string]map[string]struct{}{subStorePlansService: {"claim_apply": {}}},
			subStorePlansService, "claim_apply", body)
	}
	out, status, body := e.publish(`{"subscription_id":"F","revision":"r2","expected_revision":"r1"}`)
	if status != 0 {
		t.Fatalf("publish: %d %s", status, body)
	}
	var reply subStorePlansPublishReply
	if err := json.Unmarshal(out, &reply); err != nil || !reply.Published || reply.Revision != "r2" || reply.Action != subStorePlanActionPromote {
		t.Fatalf("publish reply = %s", out)
	}
	applied := e.appliedRequests()
	if len(applied) != 1 || applied[0].Revision != "r2" || applied[0].ExpectedRevision != "r1" || !strings.HasPrefix(applied[0].ApprovalID, "publish") {
		t.Fatalf("apply_revision ran %+v", applied)
	}
	if claimed != nil {
		t.Fatalf("the publish's apply carried no grant: %v", claimed)
	}
	for _, id := range []string{"F", "C"} {
		if _, ok := e.snapshot(id); ok {
			t.Fatalf("%s's snapshot survived the publish", id)
		}
	}
	for _, a := range e.st.Approvals() {
		if a.Plugin == subStorePlanApprovalPlugin {
			t.Fatal("publish filed an approval")
		}
	}
	audited := false
	for _, ev := range e.st.AuditEvents() {
		if ev.Action == auditActionSubStorePlanPublish && ev.Decision == "allow" && ev.Metadata["grant_claimed"] == "true" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("the publish was not audited")
	}
}

// TestPlansPublishRefusesPlanRequired: a closure with a fleet-bound share
// (an identity on the collection) needs a plan.
func TestPlansPublishRefusesPlanRequired(t *testing.T) {
	e := s2SubWithCollection(t)
	_, status, body := e.publish(`{"subscription_id":"F","revision":"r2","expected_revision":"r1"}`)
	if status != http.StatusConflict || !strings.Contains(body, apiErrorPlanRequired) {
		t.Fatalf("publish with an identity share in the closure: %d %s", status, body)
	}
	if len(e.appliedRequests()) != 0 {
		t.Fatal("applied")
	}
	// The scope is substore:admin, and only the operator's own call.
	limited := principal{Principal: subStoreSvcAdmin.Principal}
	limited.Scopes = []string{"substore:read", "network:plan"}
	if _, err := e.call(limited, subStorePlansService, "publish", `{"subscription_id":"F","revision":"r2","expected_revision":"r1"}`); subStoreSvcErrStatus(err) != http.StatusForbidden {
		t.Fatalf("publish without substore:admin: %v", err)
	}
}

// TestPlansPublishRefusesMigratedRevision: a migrated revision whose closure
// has a live share needs a plan, even with a live index that calls the
// record a plain remote record: the staged facts come from depends_on.
func TestPlansPublishRefusesMigratedRevision(t *testing.T) {
	e := newS2PlanEnv(t)
	putSubStoreRecords(t, e.st, `{"records":[{"id":"M","name":"M","source":"remote","url":"https://provider.example/sub"}]}`)
	e.record(t, fleetDependsFacts{ID: "M", Revision: "v1", Source: "remote", StagedRevision: "f1", StagedSource: subStoreSourceFleet, StagedMigrated: true})
	e.share(t, "sh-m", "M", s2Alice)
	_, status, body := e.publish(`{"subscription_id":"M","revision":"f1","expected_revision":"v1"}`)
	if status != http.StatusConflict || !strings.Contains(body, apiErrorMigrationRequiresPlan) {
		t.Fatalf("publish of a migrated revision with a share: %d %s", status, body)
	}
}

// TestPlansPublishPromotesMigratedRevisionWithoutShares: a migrated record
// whose closure has no live share publishes like any other record.
func TestPlansPublishPromotesMigratedRevisionWithoutShares(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "M", Revision: "v1", Source: subStoreSourceVPNCore, StagedRevision: "f1", StagedSource: subStoreSourceFleet, StagedMigrated: true, OwnerCredentials: true})
	if _, status, body := e.publish(`{"subscription_id":"M","revision":"f1","expected_revision":"v1"}`); status != 0 {
		t.Fatalf("publish of a share-less migration: %d %s", status, body)
	}
	if applied := e.appliedRequests(); len(applied) != 1 || applied[0].SubscriptionID != "M" {
		t.Fatalf("apply_revision ran %+v", applied)
	}
}

// TestPlansPublishRefusesSharesWithoutIdentity: a record that becomes
// fleet-bound with the revision and has an identity-less share would start
// answering the decoy; publish refuses it, naming the share.
func TestPlansPublishRefusesSharesWithoutIdentity(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "N", StagedRevision: "n1", StagedSource: subStoreSourceFleet})
	e.share(t, "sh-survivor", "N", "")
	_, status, body := e.publish(`{"subscription_id":"N","revision":"n1","expected_revision":""}`)
	if status != http.StatusConflict || !strings.Contains(body, apiErrorSharesWithoutIdentity) || !strings.Contains(body, "sh-survivor") {
		t.Fatalf("publish over a surviving identity-less share: %d %s", status, body)
	}
}

// TestPlansPublishRefusesRemoteToFleetWithUnboundShares: a remote record
// switched to fleet is the case the live index cannot see; its identity-less
// shares are refused.
func TestPlansPublishRefusesRemoteToFleetWithUnboundShares(t *testing.T) {
	e := newS2PlanEnv(t)
	putSubStoreRecords(t, e.st, `{"records":[{"id":"R","name":"R","source":"remote","url":"https://provider.example/sub"}]}`)
	e.record(t, fleetDependsFacts{ID: "R", Revision: "p1", Source: "remote", StagedRevision: "f1", StagedSource: subStoreSourceFleet})
	e.share(t, "sh-r", "R", "")
	_, status, body := e.publish(`{"subscription_id":"R","revision":"f1","expected_revision":"p1"}`)
	if status != http.StatusConflict || !strings.Contains(body, apiErrorSharesWithoutIdentity) {
		t.Fatalf("publish of a remote record switched to fleet: %d %s", status, body)
	}
}

// TestPlansPublishAdmitsDecoyShareOnLiveFleetRecord: a record already
// fleet-bound live publishes past an identity-less share that already
// answers the decoy: the promotion changes nothing for it.
func TestPlansPublishAdmitsDecoyShareOnLiveFleetRecord(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.share(t, "sh-decoy", "F", "")
	if _, status, body := e.publish(`{"subscription_id":"F","revision":"r2","expected_revision":"r1"}`); status != 0 {
		t.Fatalf("publish past a decoy share on a live fleet record: %d %s", status, body)
	}
}

// TestPlansPublishRefusesWhenStagedTagsDecoyDependentShares: a provider-only
// collection that gathers the record only through the record's staged tag
// becomes fleet-bound with it; its identity-less shares would answer the
// decoy, so publish refuses, although the collection has no staged facts.
func TestPlansPublishRefusesWhenStagedTagsDecoyDependentShares(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	e.record(t, fleetDependsFacts{ID: "C2", Revision: "c1", Kind: subStoreRecordKindCollection})
	e.graph.edge("C2", "F", fleetDependsViaMemberTag)
	e.graph.markUnionFleet("C2")
	e.share(t, "sh-c2", "C2", "")
	_, status, body := e.publish(`{"subscription_id":"F","revision":"r2","expected_revision":"r1"}`)
	if status != http.StatusConflict || !strings.Contains(body, apiErrorSharesWithoutIdentity) || !strings.Contains(body, "sh-c2") {
		t.Fatalf("publish that darkens a dependent collection's share: %d %s", status, body)
	}
}

// TestPlansPublishRefusesMigrationIncomplete: publish refuses a promotion
// that would leave a collection mixed: a member feeding a collection whose
// other member stays legacy, a changed collection gathering a legacy-live
// member, and one naming a member that is not live.
func TestPlansPublishRefusesMigrationIncomplete(t *testing.T) {
	t.Run("member feeding a collection", func(t *testing.T) {
		e := newS2PlanEnv(t)
		e.record(t, fleetDependsFacts{ID: "R", Revision: "p1", Source: "remote", StagedRevision: "f1", StagedSource: subStoreSourceFleet})
		e.record(t, fleetDependsFacts{ID: "L2", Revision: "v2", Source: subStoreSourceVPNCore, OwnerCredentials: true})
		e.record(t, fleetDependsFacts{ID: "C", Revision: "c1", Kind: subStoreRecordKindCollection, OwnerCredentials: true})
		e.graph.edge("C", "R", fleetDependsViaMember)
		e.graph.edge("C", "L2", fleetDependsViaMember)
		_, status, body := e.publish(`{"subscription_id":"R","revision":"f1","expected_revision":"p1"}`)
		if status != http.StatusConflict || !strings.Contains(body, apiErrorMigrationIncomplete) || !strings.Contains(body, "L2") {
			t.Fatalf("%d %s", status, body)
		}
	})
	t.Run("changed collection gathering a legacy member", func(t *testing.T) {
		e := newS2PlanEnv(t)
		e.record(t, fleetDependsFacts{ID: "C", Revision: "c1", Kind: subStoreRecordKindCollection, StagedRevision: "c2", FleetBound: true})
		e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, FleetBound: true})
		e.record(t, fleetDependsFacts{ID: "L", Revision: "v1", Source: subStoreSourceVPNCoreGraph, StagedRevision: "f1", StagedSource: subStoreSourceFleet, OwnerCredentials: true})
		e.graph.edge("C", "F", fleetDependsViaMember)
		e.graph.edge("C", "L", fleetDependsViaMember)
		_, status, body := e.publish(`{"subscription_id":"C","revision":"c2","expected_revision":"c1"}`)
		if status != http.StatusConflict || !strings.Contains(body, apiErrorMigrationIncomplete) || !strings.Contains(body, "L") {
			t.Fatalf("%d %s", status, body)
		}
	})
	t.Run("collection naming a member that is not live", func(t *testing.T) {
		e := newS2PlanEnv(t)
		e.record(t, fleetDependsFacts{ID: "C", Revision: "c1", Kind: subStoreRecordKindCollection, StagedRevision: "c2", FleetBound: true})
		e.record(t, fleetDependsFacts{ID: "N", StagedRevision: "n1", StagedSource: subStoreSourceFleet})
		e.graph.edge("C", "N", fleetDependsViaMember)
		_, status, body := e.publish(`{"subscription_id":"C","revision":"c2","expected_revision":"c1"}`)
		if status != http.StatusConflict || !strings.Contains(body, apiErrorMigrationIncomplete) || !strings.Contains(body, "N") {
			t.Fatalf("%d %s", status, body)
		}
	})
}

// TestPlansPublishHoldsLockIntoApply: publish holds the share-write lock
// from its Required check into the apply, so a share created in between
// cannot receive the revision unreviewed.
func TestPlansPublishHoldsLockIntoApply(t *testing.T) {
	e := newS2PlanEnv(t)
	e.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, StagedRevision: "r2", StagedSource: subStoreSourceFleet, FleetBound: true})
	held := false
	e.onApply = func(context.Context, subStoreApplyRevisionRequest) {
		if e.srv.subStoreSvc.mu.TryLock() {
			e.srv.subStoreSvc.mu.Unlock()
			return
		}
		held = true
	}
	checked := false
	e.graph.onQuery = func(fleetDependsRequest) {
		if e.srv.subStoreSvc.mu.TryLock() {
			e.srv.subStoreSvc.mu.Unlock()
			return
		}
		checked = true
	}
	if _, status, body := e.publish(`{"subscription_id":"F","revision":"r2","expected_revision":"r1"}`); status != 0 {
		t.Fatalf("publish: %d %s", status, body)
	}
	if !checked || !held {
		t.Fatalf("closure read under the lock %v, apply under the lock %v", checked, held)
	}
}

// Publish deletes a fleet-bound record whose closure has no fleet-bound
// share, archiving its own shares as a delete plan does.
func TestPlansPublishDeletesWithoutApproval(t *testing.T) {
	e := s2DeleteFixture(t)
	if _, status, _ := e.publish(`{"subscription_id":"F","action":"delete","expected_revision":"r1"}`); status != http.StatusConflict {
		t.Fatalf("publish of a delete with identity shares in the closure: %d", status)
	}
	plain := newS2PlanEnv(t)
	plain.record(t, fleetDependsFacts{ID: "F", Revision: "r1", Source: subStoreSourceFleet, FleetBound: true})
	plain.share(t, "sh-f", "F", "")
	if _, status, body := plain.publish(`{"subscription_id":"F","action":"delete","expected_revision":"r1"}`); status != 0 {
		t.Fatalf("publish of a delete: %d %s", status, body)
	}
	if applied := plain.appliedRequests(); len(applied) != 1 || applied[0].Action != subStorePlanActionDelete {
		t.Fatalf("apply_revision ran %+v", applied)
	}
	if _, archived := plain.shareIdentity(t, "sh-f"); !archived {
		t.Fatal("the deleted record's share was not archived")
	}
}

// TestSharesCreateRefusesIdentityOnNonFleetRecord: shares.create and the
// REST create refuse an identity on a record that is not fleet-bound, and
// admit one on a fleet record; a share without an identity is created on
// either.
func TestSharesCreateRefusesIdentityOnNonFleetRecord(t *testing.T) {
	t.Run("service", func(t *testing.T) {
		h := newSubStoreSvcHarness(t)
		if err := h.srv.putVpnUser(VpnUser{ID: s2Alice, Email: "alice@example.com", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		putSubStoreRecords(t, h.st, `{"records":[{"id":"fleet-rec","name":"f","source":"fleet"},{"id":"provider","name":"p","url":"https://p.example/sub"},
			{"id":"coll","kind":"collection","name":"c","members":["fleet-rec"]}]}`)
		_, err := h.call(subStoreSvcAdmin, subStoreSharesService, "create", `{"subscription_id":"provider","slug":"p-alice","identity_id":"`+s2Alice+`"}`)
		if subStoreSvcErrStatus(err) != http.StatusBadRequest || !strings.Contains(subStoreSvcErrBody(err), apiErrorIdentityRequiresFleetRecord) {
			t.Fatalf("an identity on a provider record: %v %s", err, subStoreSvcErrBody(err))
		}
		if _, err := h.call(subStoreSvcAdmin, subStoreSharesService, "create", `{"subscription_id":"missing","slug":"m-alice","identity_id":"`+s2Alice+`"}`); subStoreSvcErrStatus(err) != http.StatusBadRequest {
			t.Fatalf("an identity on a record the index does not hold: %v", err)
		}
		h.createShare(t, `{"subscription_id":"provider","slug":"p-plain"}`)
		h.createShare(t, `{"subscription_id":"fleet-rec","slug":"f-alice","identity_id":"`+s2Alice+`"}`)
		// A collection over a fleet member is fleet-bound once the index says
		// so; this one's flag is not set, so it is refused.
		if _, err := h.call(subStoreSvcAdmin, subStoreSharesService, "create", `{"subscription_id":"coll","slug":"c-alice","identity_id":"`+s2Alice+`"}`); subStoreSvcErrStatus(err) != http.StatusBadRequest {
			t.Fatalf("an identity on a collection without the fleet_bound flag: %v", err)
		}
		// An index that does not parse vouches for nothing.
		putSubStoreRecords(t, h.st, `{"records":[`)
		if _, err := h.call(subStoreSvcAdmin, subStoreSharesService, "create", `{"subscription_id":"fleet-rec","slug":"f-bob","identity_id":"`+s2Alice+`"}`); subStoreSvcErrStatus(err) != http.StatusBadRequest {
			t.Fatalf("an identity over an unreadable index: %v", err)
		}
	})
	t.Run("REST", func(t *testing.T) {
		h := newRevealHarness(t)
		if err := h.srv.putVpnUser(VpnUser{ID: s2Alice, Email: "alice@example.com", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		putSubStoreRecords(t, h.srv.store, `{"records":[{"id":"fleet-rec","name":"f","source":"fleet"},{"id":"provider","name":"p","url":"https://p.example/sub"}]}`)
		create := func(slug, record, identity string) (int, string) {
			body := fmt.Sprintf(`{"slug":%q,"source":{"kind":"plugin","plugin_id":"latticenet.sub-store","subscription_id":%q,"identity_id":%q}}`, slug, record, identity)
			res := doJSON(t, h.handler, http.MethodPost, "/api/subscription-shares", body, h.cookies, h.csrf)
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			return res.StatusCode, string(raw)
		}
		if status, body := create("p-alice", "provider", s2Alice); status != http.StatusBadRequest || !strings.Contains(body, apiErrorIdentityRequiresFleetRecord) {
			t.Fatalf("REST identity on a provider record: %d %s", status, body)
		}
		if status, body := create("f-nobody", "fleet-rec", "vpnuser_nobody"); status != http.StatusBadRequest {
			t.Fatalf("REST unknown identity: %d %s", status, body)
		}
		if status, body := create("f-alice", "fleet-rec", s2Alice); status != http.StatusCreated {
			t.Fatalf("REST identity on a fleet record: %d %s", status, body)
		}
		if status, body := create("p-plain", "provider", ""); status != http.StatusCreated {
			t.Fatalf("REST share without an identity: %d %s", status, body)
		}
	})
}

// BenchmarkPlansPropose20Identities times a propose over a record and the
// collection that reads it, with twenty identities on each, against the
// stub previewer: two renders per record and the binds, diffs and plan text.
// The wall-clock figure belongs to the perf job.
func BenchmarkPlansPropose20Identities(b *testing.B) {
	e := s2SubWithCollection(b)
	var lines []int
	for i := range s2Lines {
		lines = append(lines, i)
	}
	e.previewer.set("F", "r2", nil, s2Result(lines...))
	for i := range 20 {
		id := fmt.Sprintf("vpnuser_bench_%02d", i)
		if err := e.srv.putVpnUser(VpnUser{ID: id, Email: id + "@example.com", Enabled: true}); err != nil {
			b.Fatal(err)
		}
		e.share(b, "sh-bf-"+id, "F", id)
		e.share(b, "sh-bc-"+id, "C", id)
	}
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, subStoreSvcAdmin)
	body := []byte(`{"subscription_id":"F","from_revision":"r1","to_revision":"r2"}`)
	b.ResetTimer()
	for range b.N {
		if _, err := e.srv.callCoreServiceForOperator(ctx, subStorePlansService, "propose", body); err != nil {
			b.Fatal(err)
		}
	}
}
