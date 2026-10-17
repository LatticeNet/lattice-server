package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The server half of the S2 security review's S2-SR-2 (design 28, "S2
// security review"): a revision that only changes a record's process chain
// looked like no change in the plan and in its hash.

// chainStep is a stored process step.
func chainStep(fields map[string]any) json.RawMessage {
	raw, _ := json.Marshal(fields)
	return raw
}

// newChainOnlyHarness is the plan harness with rev-2 binding exactly what
// rev-1 binds for every identity, so a plan from rev-1 to rev-2 has an empty
// line diff and any difference in the plan comes from the chain.
func newChainOnlyHarness(t *testing.T) *subStorePlanHarness {
	t.Helper()
	h := newSubStorePlanHarness(t)
	h.previewer.mu.Lock()
	h.previewer.results["rev-2|vpnuser_alice"] = h.previewer.results["rev-1|vpnuser_alice"]
	h.previewer.mu.Unlock()
	return h
}

func decodePlan(t *testing.T, text string) subStorePlan {
	t.Helper()
	var plan subStorePlan
	if err := json.Unmarshal([]byte(text), &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

// TestSubStorePlanChainOnlyRevisionShowsInThePlan: a revision whose only
// change is a step (a Script Operator that passes every node through binds
// the same lines) gives a plan whose line diff is empty. The plan still says
// which step was added, by position and type and without its script, and
// hashes differently from the plan of the same revisions with the chain
// unchanged; putting the chain back gives the first hash again.
func TestSubStorePlanChainOnlyRevisionShowsInThePlan(t *testing.T) {
	h := newChainOnlyHarness(t)
	sorter := chainStep(map[string]any{"type": "Sort Operator", "args": map[string]any{"order": "asc"}})
	h.graph.setSteps(t, "rec", false, sorter)
	h.graph.setSteps(t, "rec", true, sorter)
	unchanged := h.propose(t)
	script := chainStep(map[string]any{"type": "Script Operator", "customName": "tidy names",
		"args": map[string]any{"mode": "script", "content": "function operator(p) { return p } // SCRIPT-BODY-MARKER"}})
	h.graph.setSteps(t, "rec", true, sorter, script)
	added := h.propose(t)
	if added.PlanSHA256 == unchanged.PlanSHA256 {
		t.Fatal("a revision that only adds a step hashes like the revision with the chain unchanged")
	}

	plan := decodePlan(t, unchanged.Plan)
	if plan.Totals.Added+plan.Totals.Removed+plan.Totals.Changed+plan.Totals.Excluded != 0 {
		t.Fatalf("the harness's revisions differ in lines: %+v", plan.Totals)
	}
	if plan.Chain == nil || plan.Chain.Before == "" || plan.Chain.Before != plan.Chain.After || len(plan.Chain.Changes) != 0 {
		t.Fatalf("an unchanged chain: %+v", plan.Chain)
	}
	plan = decodePlan(t, added.Plan)
	if plan.Totals.Added+plan.Totals.Removed+plan.Totals.Changed+plan.Totals.Excluded != 0 {
		t.Fatalf("the chain-only revision moved lines: %+v", plan.Totals)
	}
	if plan.Chain == nil || plan.Chain.Before == plan.Chain.After ||
		!slices.Equal(plan.Chain.Changes, []string{"step 2 added: Script Operator"}) {
		t.Fatalf("the chain-only revision's chain: %+v", plan.Chain)
	}
	for _, leak := range []string{"SCRIPT-BODY-MARKER", "tidy names", "function operator"} {
		if strings.Contains(added.Plan, leak) {
			t.Fatalf("the plan shows a step's %q", leak)
		}
	}

	h.graph.setSteps(t, "rec", true, sorter)
	if again := h.propose(t); again.PlanSHA256 != unchanged.PlanSHA256 || again.Plan != unchanged.Plan {
		t.Fatal("the same revisions with the same chain do not give the same plan and hash")
	}
}

// TestSubStorePlanChainOnEverySection: a dependent collection previewed over
// a promoted member carries its own chain too, the same on both sides
// because the collection does not move, and a change to it after the
// proposal is caught at the decision like a change to the member's.
func TestSubStorePlanChainOnEverySection(t *testing.T) {
	h := newChainOnlyHarness(t)
	h.graph.put(fleetDependsFacts{ID: "combo", Revision: "rev-c", Kind: "collection", Source: subStoreSourceFleet, FleetBound: true})
	h.graph.edge("combo", "rec", fleetDependsViaMember)
	h.graph.setSteps(t, "combo", false, chainStep(map[string]any{"type": "Flag Operator"}))
	reply := h.propose(t)
	plan := decodePlan(t, reply.Plan)
	var combo *subStorePlanRecord
	for i := range plan.Records {
		if plan.Records[i].SubscriptionID == "combo" {
			combo = &plan.Records[i]
		}
	}
	if combo == nil || combo.Role != subStorePlanRoleDependent || combo.Chain == nil || combo.Chain.Before == "" ||
		combo.Chain.Before != combo.Chain.After || len(combo.Chain.Changes) != 0 {
		t.Fatalf("the dependent collection's section carries no unchanged chain: %v", combo != nil && combo.Chain != nil)
	}
	h.graph.setSteps(t, "combo", false, chainStep(map[string]any{"type": "Flag Operator"}), chainStep(map[string]any{"type": "Script Operator"}))
	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), subStorePlanStaleChain) || h.appliedCount() != 0 {
		t.Fatalf("a dependent collection's chain changed after the proposal: %d %.200s, %d applies", res.Code, res.Body.String(), h.appliedCount())
	}
}

// TestSubStorePlanStaleWhenChainChangesAfterProposal: the decision reads the
// record documents again, so a chain that changed after the plan was
// proposed rejects it as stale even when depends_on still reports the same
// revisions, on either side, and nothing is applied.
func TestSubStorePlanStaleWhenChainChangesAfterProposal(t *testing.T) {
	for _, staged := range []bool{true, false} {
		name := "live side"
		if staged {
			name = "staged side"
		}
		t.Run(name, func(t *testing.T) {
			h := newChainOnlyHarness(t)
			reply := h.propose(t)
			h.graph.setSteps(t, "rec", staged, chainStep(map[string]any{"type": "Script Operator",
				"args": map[string]any{"mode": "script", "content": "function operator(p) { return p }"}}))
			res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
			if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), subStorePlanStaleChain) {
				t.Fatalf("approve after the chain changed: %d %.200s", res.Code, res.Body.String())
			}
			if h.appliedCount() != 0 {
				t.Fatal("a plan whose chain changed was applied")
			}
			current := h.status(reply.ApprovalID)
			if current.Status != model.ApprovalRejected || current.Reason != subStorePlanStaleChain {
				t.Fatalf("approval after a stale chain = %+v", current)
			}
			var status struct {
				Plans []subStorePlanStatusRow `json:"plans"`
			}
			if err := json.Unmarshal(h.mustCall(t, subStorePlansService, "status", `{"approval_id":"`+reply.ApprovalID+`"}`), &status); err != nil {
				t.Fatal(err)
			}
			if len(status.Plans) != 1 || !status.Plans[0].Stale {
				t.Fatalf("the status row does not mark a stale chain as stale: %+v", status.Plans)
			}
		})
	}
}

// TestSubStorePlanUnchangedChainApplies: with the chain as proposed, the
// decision's chain check passes and the plan applies.
func TestSubStorePlanUnchangedChainApplies(t *testing.T) {
	h := newChainOnlyHarness(t)
	h.graph.setSteps(t, "rec", true, chainStep(map[string]any{"type": "Regex Filter", "args": map[string]any{"regex": []string{"HK"}}}))
	reply := h.propose(t)
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK || h.appliedCount() != 1 {
		t.Fatalf("approve with the chain as proposed: %d %.200s, %d applies", res.Code, res.Body.String(), h.appliedCount())
	}
}

// TestSubStorePlanProposeRefusesAnUnreadableChain: a plan that cannot show
// a record's steps is not filed.
func TestSubStorePlanProposeRefusesAnUnreadableChain(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(h *subStorePlanHarness) error
	}{
		{name: "staged document missing", edit: func(h *subStorePlanHarness) error {
			return h.st.DeleteKV(usageSubStoreKVBucket, subStoreStagedKey("rec"))
		}},
		{name: "live document names another record", edit: func(h *subStorePlanHarness) error {
			return h.st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: subStoreRecordKey("rec"), Value: `{"id":"other","process":[]}`})
		}},
		{name: "staged steps do not decode", edit: func(h *subStorePlanHarness) error {
			return h.st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: subStoreStagedKey("rec"), Value: `{"record":{"id":"rec","process":{}}}`})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newSubStorePlanHarness(t)
			if err := c.edit(h); err != nil {
				t.Fatal(err)
			}
			before := len(h.st.Approvals())
			_, err := h.call(subStoreSvcAdmin, subStorePlansService, "propose", `{"subscription_id":"rec","from_revision":"rev-1","to_revision":"rev-2"}`)
			if subStoreSvcErrStatus(err) != http.StatusConflict {
				t.Fatalf("propose over an unreadable chain: %v %s", err, subStoreSvcErrBody(err))
			}
			if len(h.st.Approvals()) != before {
				t.Fatal("propose filed a plan whose chain it could not read")
			}
		})
	}
}

// TestSubStorePlanChainChanges pins the change lines: steps matched by
// content are unchanged, the rest matched by type are changed in place, and
// what is left was removed or added, numbered by its own side.
func TestSubStorePlanChainChanges(t *testing.T) {
	step := func(kind string, extra ...any) json.RawMessage {
		fields := map[string]any{"type": kind}
		for i := 0; i+1 < len(extra); i += 2 {
			fields[extra[i].(string)] = extra[i+1]
		}
		return chainStep(fields)
	}
	regexA, regexB := step("Regex Filter", "args", "a"), step("Regex Filter", "args", "b")
	sortOn, sortOff := step("Sort Operator"), step("Sort Operator", "disabled", true)
	script := step("Script Operator", "args", map[string]any{"content": "x"})
	for _, c := range []struct {
		name          string
		before, after []json.RawMessage
		want          []string
	}{
		{name: "identical", before: []json.RawMessage{regexA, sortOn}, after: []json.RawMessage{regexA, sortOn}},
		{name: "added at the end", before: []json.RawMessage{regexA}, after: []json.RawMessage{regexA, script},
			want: []string{"step 2 added: Script Operator"}},
		{name: "removed", before: []json.RawMessage{script, regexA}, after: []json.RawMessage{regexA},
			want: []string{"step 1 removed: Script Operator"}},
		{name: "changed, added and disabled", before: []json.RawMessage{regexA, sortOn}, after: []json.RawMessage{regexB, script, sortOff},
			want: []string{"step 1 changed: Regex Filter", "step 2 added: Script Operator", "step 3 changed: Sort Operator (was step 2, now disabled)"}},
		{name: "re-enabled", before: []json.RawMessage{sortOff}, after: []json.RawMessage{sortOn},
			want: []string{"step 1 changed: Sort Operator (now enabled)"}},
		{name: "replaced by another type", before: []json.RawMessage{regexA}, after: []json.RawMessage{script},
			want: []string{"step 1 removed: Regex Filter", "step 1 added: Script Operator"}},
		{name: "a moved step is a removal and an addition", before: []json.RawMessage{script, regexA}, after: []json.RawMessage{regexA, script},
			want: []string{"step 1 removed: Script Operator", "step 2 added: Script Operator"}},
		{name: "added disabled", before: nil, after: []json.RawMessage{sortOff},
			want: []string{"step 1 added: Sort Operator (disabled)"}},
		{name: "types are cleaned", before: nil, after: []json.RawMessage{step("Script‮ Operator\n" + strings.Repeat("x", 80)), step(""), json.RawMessage(`{"type":7}`)},
			want: []string{"step 1 added: Script Operator " + strings.Repeat("x", subStorePlanStepTypeBytes-len("Script Operator ")),
				"step 2 added: step with no type", "step 3 added: unreadable step"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := subStorePlanChainChanges(subStorePlanStepsOf(c.before), subStorePlanStepsOf(c.after))
			if !slices.Equal(got, c.want) {
				t.Fatalf("changes = %q, want %q", got, c.want)
			}
		})
	}

	long := make([]json.RawMessage, subStorePlanChainDiffSteps+1)
	for i := range long {
		long[i] = sortOn
	}
	if got := subStorePlanChainChanges(subStorePlanStepsOf(long), subStorePlanStepsOf(long)); got != nil {
		t.Fatalf("an unchanged long chain: %q", got)
	}
	if got := subStorePlanChainChanges(nil, subStorePlanStepsOf(long)); len(got) != 1 || !strings.Contains(got[0], "too many to list") {
		t.Fatalf("a long chain: %q", got)
	}
	many := make([]json.RawMessage, subStorePlanChainLines+10)
	for i := range many {
		many[i] = step("Flag Operator", "n", i)
	}
	got := subStorePlanChainChanges(nil, subStorePlanStepsOf(many))
	if len(got) != subStorePlanChainLines || got[len(got)-1] != "and 11 more step changes" {
		t.Fatalf("the change lines are not bounded: %d, last %q", len(got), got[len(got)-1])
	}
}

// TestSubStoreStagedKeyEscapesLikeTheRecordKey: the staged key escapes an id
// exactly as the plugin's stagedKey does.
func TestSubStoreStagedKeyEscapesLikeTheRecordKey(t *testing.T) {
	for id, want := range map[string]string{
		"rec":     "staged-v2-rec",
		"a/b%c":   "staged-v2-a%2Fb%25c",
		"tab\tid": "staged-v2-tab%09id",
	} {
		if got := subStoreStagedKey(id); got != want {
			t.Fatalf("subStoreStagedKey(%q) = %q, want %q", id, got, want)
		}
	}
}
