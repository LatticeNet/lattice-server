package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The listing used to hand every plan body to every reader. On a fleet with a
// thousand applied approvals that was megabytes per console load, so the
// listing now omits the plan unless asked, carries plan_sha256 so a client can
// tell a changed plan without downloading it, filters on more than status, and
// answers a bare count for the overview counters.

func seedListingApprovals(t *testing.T, st *store.Store) {
	t.Helper()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	rows := []model.Approval{
		{ID: "ap-pending-a", NodeID: "node-a", Plugin: "nftpolicy", Action: "apply", Status: model.ApprovalPending, Plan: "plan pending a"},
		{ID: "ap-applied-a", NodeID: "node-a", Plugin: "nftpolicy", Action: "apply", Status: model.ApprovalApplied, Plan: "plan applied a"},
		{ID: "ap-rejected-b", NodeID: "node-b", Plugin: "wireguard", Action: "apply-config", Status: model.ApprovalRejected, Plan: "plan rejected b"},
		{ID: "ap-approved-b", NodeID: "node-b", Plugin: "wireguard", Action: "apply-config", Status: model.ApprovalApproved, Plan: "plan approved b"},
		{ID: "ap-dismissed-a", NodeID: "node-a", Plugin: sshGuardPlugin, Action: sshGuardArmAction, Status: approvalStatusDismissed, Plan: "plan dismissed a"},
		{ID: "ap-stale-a", NodeID: "node-a", Plugin: agentUpdatePlugin, Action: "update", Status: model.ApprovalRejected,
			Reason: errAgentUpdateApprovalStale.Error() + ": target moved", Plan: "plan stale a"},
	}
	// The store stamps updated_at itself; only created_at is under the
	// fixture's control.
	for i, row := range rows {
		row.CreatedAt = base.Add(time.Duration(i) * time.Minute)
		if err := st.UpsertApproval(row); err != nil {
			t.Fatal(err)
		}
	}
}

func getApprovalsEnvelope(t *testing.T, handler http.Handler, cookies []*http.Cookie, query string) approvalsQueryResponse {
	t.Helper()
	res := doJSON(t, handler, http.MethodGet, "/api/network/approvals?"+query, "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("GET approvals?%s = %d: %s", query, res.StatusCode, body)
	}
	var env approvalsQueryResponse
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		t.Fatalf("approvals query must be enveloped: %v", err)
	}
	return env
}

func approvalIDs(views []approvalView) []string {
	out := make([]string, 0, len(views))
	for _, v := range views {
		out = append(out, v.ID)
	}
	return out
}

func sameIDs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range got {
		seen[id] = true
	}
	for _, id := range want {
		if !seen[id] {
			return false
		}
	}
	return true
}

func TestApprovalsListStatusAcceptsCommaList(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	seedListingApprovals(t, st)

	env := getApprovalsEnvelope(t, handler, cookies, "status=pending,rejected")
	if env.Total != 3 || !sameIDs(approvalIDs(env.Approvals), []string{"ap-pending-a", "ap-rejected-b", "ap-stale-a"}) {
		t.Fatalf("status=pending,rejected should match the three rows, got total=%d ids=%v", env.Total, approvalIDs(env.Approvals))
	}
	// Whitespace and empty members are tolerated; the list is a UI convenience.
	env = getApprovalsEnvelope(t, handler, cookies, "status=+applied+,,approved")
	if !sameIDs(approvalIDs(env.Approvals), []string{"ap-applied-a", "ap-approved-b"}) {
		t.Fatalf("status list with padding should match, got %v", approvalIDs(env.Approvals))
	}
	// Dismissed rows stay hidden unless include_dismissed asks for them, even
	// when the status filter names them.
	env = getApprovalsEnvelope(t, handler, cookies, "status=dismissed")
	if env.Total != 0 {
		t.Fatalf("status=dismissed without include_dismissed must hide tombstones, got %v", approvalIDs(env.Approvals))
	}
	env = getApprovalsEnvelope(t, handler, cookies, "status=dismissed&include_dismissed=1")
	if !sameIDs(approvalIDs(env.Approvals), []string{"ap-dismissed-a"}) {
		t.Fatalf("status=dismissed with include_dismissed should match, got %v", approvalIDs(env.Approvals))
	}
}

func TestApprovalsListFiltersCombine(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	seedListingApprovals(t, st)

	env := getApprovalsEnvelope(t, handler, cookies, "plugin=wireguard")
	if !sameIDs(approvalIDs(env.Approvals), []string{"ap-rejected-b", "ap-approved-b"}) {
		t.Fatalf("plugin filter wrong: %v", approvalIDs(env.Approvals))
	}
	env = getApprovalsEnvelope(t, handler, cookies, "node_id=node-a")
	if !sameIDs(approvalIDs(env.Approvals), []string{"ap-pending-a", "ap-applied-a", "ap-stale-a"}) {
		t.Fatalf("node_id filter wrong: %v", approvalIDs(env.Approvals))
	}
	// since is inclusive on updated_at. The store stamps updated_at itself on
	// every upsert, and the seed rows can share one clock tick, so two rows are
	// touched again until the clock has visibly moved past the rest.
	stored := map[string]model.Approval{}
	ids := []string{"ap-pending-a", "ap-applied-a", "ap-rejected-b", "ap-approved-b", "ap-stale-a"}
	for _, id := range ids {
		row, _ := st.Approval(id)
		stored[id] = row
	}
	for _, id := range []string{"ap-rejected-b", "ap-stale-a"} {
		row := stored[id]
		for !row.UpdatedAt.After(stored["ap-approved-b"].UpdatedAt) {
			if err := st.UpsertApproval(row); err != nil {
				t.Fatal(err)
			}
			row, _ = st.Approval(id)
		}
		stored[id] = row
	}
	pivot := stored["ap-rejected-b"].UpdatedAt
	expectSince := func(ids ...string) []string {
		var out []string
		for _, id := range ids {
			if !stored[id].UpdatedAt.Before(pivot) {
				out = append(out, id)
			}
		}
		return out
	}
	want := expectSince(ids...)
	if len(want) == 5 {
		t.Fatalf("fixture: the pivot must exclude at least one row: %v", stored)
	}
	env = getApprovalsEnvelope(t, handler, cookies, "since="+pivot.Format(time.RFC3339Nano))
	if !sameIDs(approvalIDs(env.Approvals), want) {
		t.Fatalf("since filter wrong: got %v want %v", approvalIDs(env.Approvals), want)
	}
	// The same instant in another zone selects the same rows.
	shifted := pivot.In(time.FixedZone("plus8", 8*3600)).Format(time.RFC3339Nano)
	env = getApprovalsEnvelope(t, handler, cookies, "since="+strings.ReplaceAll(shifted, "+", "%2B"))
	if !sameIDs(approvalIDs(env.Approvals), want) {
		t.Fatalf("since must compare instants, not strings: %v", approvalIDs(env.Approvals))
	}
	env = getApprovalsEnvelope(t, handler, cookies, "status=pending,applied,rejected&node_id=node-a&plugin=nftpolicy&since="+pivot.Format(time.RFC3339Nano))
	if !sameIDs(approvalIDs(env.Approvals), expectSince("ap-pending-a", "ap-applied-a")) {
		t.Fatalf("combined filters wrong: %v", approvalIDs(env.Approvals))
	}
	// Empty values are ignored rather than matching nothing.
	env = getApprovalsEnvelope(t, handler, cookies, "status=&plugin=&node_id=&since=")
	if env.Total != 5 {
		t.Fatalf("empty filters must be ignored, got total=%d", env.Total)
	}
	// limit keeps its meaning under the new filters.
	env = getApprovalsEnvelope(t, handler, cookies, "node_id=node-a&limit=2")
	if env.Total != 3 || len(env.Approvals) != 2 || env.Limit != 2 {
		t.Fatalf("limit semantics changed: total=%d len=%d limit=%d", env.Total, len(env.Approvals), env.Limit)
	}
}

func TestApprovalsListSinceRejectsMalformedTimestamp(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	seedListingApprovals(t, st)
	res := doJSON(t, handler, http.MethodGet, "/api/network/approvals?since=yesterday", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed since should be 400, got %d", res.StatusCode)
	}
}

// rawApprovalRows decodes a listing into maps so the test can tell an omitted
// key from an empty one.
func rawApprovalRows(t *testing.T, res *http.Response) []map[string]any {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(body, &arr); err == nil {
		return arr
	}
	var env struct {
		Approvals []map[string]any `json:"approvals"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("listing is neither array nor envelope: %v: %s", err, body)
	}
	return env.Approvals
}

func TestApprovalsListOmitsPlanUnlessIncluded(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	seedListingApprovals(t, st)

	for _, query := range []string{"", "?include_dismissed=1", "?status=pending", "?plugin=nftpolicy&limit=10"} {
		res := doJSON(t, handler, http.MethodGet, "/api/network/approvals"+query, "", cookies, "")
		rows := rawApprovalRows(t, res)
		res.Body.Close()
		if len(rows) == 0 {
			t.Fatalf("%q returned no rows", query)
		}
		for _, row := range rows {
			if _, ok := row["plan"]; ok {
				t.Fatalf("%q must omit plan by default, row %v", query, row["id"])
			}
			stored, _ := st.Approval(row["id"].(string))
			if got := row["plan_sha256"]; got != planSHA256(stored.Plan) {
				t.Fatalf("%q plan_sha256 = %v, want sha256 of the stored plan", query, got)
			}
		}
	}
	for _, query := range []string{"?include=plan", "?include=plan&status=pending", "?include=plan&include_dismissed=1"} {
		res := doJSON(t, handler, http.MethodGet, "/api/network/approvals"+query, "", cookies, "")
		rows := rawApprovalRows(t, res)
		res.Body.Close()
		if len(rows) == 0 {
			t.Fatalf("%q returned no rows", query)
		}
		for _, row := range rows {
			stored, _ := st.Approval(row["id"].(string))
			if row["plan"] != stored.Plan {
				t.Fatalf("%q must carry the plan, row %v has %v", query, row["id"], row["plan"])
			}
			if row["plan_sha256"] != planSHA256(stored.Plan) {
				t.Fatalf("%q plan_sha256 wrong with include=plan", query)
			}
		}
	}
	// Anything other than plan is not a recognised include.
	res := doJSON(t, handler, http.MethodGet, "/api/network/approvals?include=secrets", "", cookies, "")
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown include should be 400, got %d", res.StatusCode)
	}
}

func TestApprovalsListPlanSHA256TracksPlanChanges(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	seedListingApprovals(t, st)

	first := getApprovalsEnvelope(t, handler, cookies, "status=pending")
	second := getApprovalsEnvelope(t, handler, cookies, "status=pending")
	if first.Approvals[0].PlanSHA256 == "" || first.Approvals[0].PlanSHA256 != second.Approvals[0].PlanSHA256 {
		t.Fatalf("plan_sha256 must be stable across reads: %q vs %q", first.Approvals[0].PlanSHA256, second.Approvals[0].PlanSHA256)
	}
	stored, _ := st.Approval("ap-pending-a")
	stored.Plan = "plan pending a, revised"
	if err := st.UpsertApproval(stored); err != nil {
		t.Fatal(err)
	}
	third := getApprovalsEnvelope(t, handler, cookies, "status=pending")
	if third.Approvals[0].PlanSHA256 == first.Approvals[0].PlanSHA256 || third.Approvals[0].PlanSHA256 != planSHA256(stored.Plan) {
		t.Fatalf("plan_sha256 must follow the plan text: %q", third.Approvals[0].PlanSHA256)
	}
}

func TestApprovalsReadByIDReturnsFullRecord(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	seedListingApprovals(t, st)

	res := doJSON(t, handler, http.MethodGet, "/api/network/approvals?id=ap-applied-a", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("read by id = %d", res.StatusCode)
	}
	var out struct {
		Approval approvalView `json:"approval"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Approval.ID != "ap-applied-a" || out.Approval.Plan != "plan applied a" || out.Approval.PlanSHA256 != planSHA256("plan applied a") {
		t.Fatalf("read by id must carry the plan and its hash: %+v", out.Approval)
	}

	// A dismissed tombstone is readable by id without include_dismissed: the
	// caller already holds the id, so nothing is being discovered.
	dismissed := doJSON(t, handler, http.MethodGet, "/api/network/approvals?id=ap-dismissed-a", "", cookies, "")
	dismissed.Body.Close()
	if dismissed.StatusCode != http.StatusOK {
		t.Fatalf("read dismissed by id = %d", dismissed.StatusCode)
	}

	missing := doJSON(t, handler, http.MethodGet, "/api/network/approvals?id=ap-nope", "", cookies, "")
	missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id should be 404, got %d", missing.StatusCode)
	}

	// A principal scoped to node-b cannot read node-a's plan through the id
	// path any more than through the listing, and learns nothing about
	// whether the id exists.
	scoped := createPAT(t, handler, cookies, csrf, []string{"network:plan"}, []string{"node-b"})
	denied := doBearerJSON(t, handler, http.MethodGet, "/api/network/approvals?id=ap-applied-a", "", scoped)
	denied.Body.Close()
	if denied.StatusCode != http.StatusNotFound {
		t.Fatalf("out-of-scope id should read as 404, got %d", denied.StatusCode)
	}
}

func TestApprovalsCountsWithoutRecords(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, _ := loginSession(t, handler)
	seedListingApprovals(t, st)

	res := doJSON(t, handler, http.MethodGet, "/api/network/approvals?count=1", "", cookies, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("count = %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	var out map[string]json.RawMessage
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["approvals"]; ok || len(out) != 1 {
		t.Fatalf("count=1 must answer counts only: %s", body)
	}
	var counts map[string]int
	if err := json.Unmarshal(out["counts"], &counts); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"pending": 1, "approved": 1, "stale": 1, "applied": 1, "rejected": 2, "dismissed": 1, "total": 6}
	for key, n := range want {
		if counts[key] != n {
			t.Fatalf("counts[%s] = %d, want %d (%s)", key, counts[key], n, body)
		}
	}
	if len(counts) != len(want) {
		t.Fatalf("counts carries unexpected keys: %s", body)
	}

	// The record filters narrow the counts too; the status breakdown is the
	// answer, so status itself is not a filter here.
	filtered := doJSON(t, handler, http.MethodGet, "/api/network/approvals?count=1&node_id=node-a&status=pending", "", cookies, "")
	defer filtered.Body.Close()
	var narrowed struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.NewDecoder(filtered.Body).Decode(&narrowed); err != nil {
		t.Fatal(err)
	}
	if narrowed.Counts["total"] != 4 || narrowed.Counts["pending"] != 1 || narrowed.Counts["applied"] != 1 || narrowed.Counts["rejected"] != 1 || narrowed.Counts["dismissed"] != 1 || narrowed.Counts["stale"] != 1 {
		t.Fatalf("node_id-narrowed counts wrong: %+v", narrowed.Counts)
	}
}

// TestApprovalDecisionsWorkFromPlanlessListing is the contract the console
// relies on: it lists without plans, decides by id (and by the listing's
// plan_sha256 for approve), and the server reads the stored plan itself.
func TestApprovalDecisionsWorkFromPlanlessListing(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	for _, nodeID := range []string{"pn1", "pn2"} {
		plan := doJSON(t, handler, http.MethodPost, "/api/network/nft/plan",
			`{"node_id":"`+nodeID+`","public_tcp":[443],"accept_lockout_risk":true}`, cookies, csrf)
		if plan.StatusCode != http.StatusOK {
			plan.Body.Close()
			t.Fatalf("nft plan %s: %d", nodeID, plan.StatusCode)
		}
		plan.Body.Close()
	}

	listing := getApprovalsEnvelope(t, handler, cookies, "status=pending&plugin=nft")
	if len(listing.Approvals) != 2 {
		t.Fatalf("expected two pending nft approvals, got %v", approvalIDs(listing.Approvals))
	}
	byNode := map[string]approvalView{}
	for _, row := range listing.Approvals {
		if row.Plan != "" {
			t.Fatalf("listing leaked the plan: %+v", row)
		}
		byNode[row.NodeID] = row
	}

	approve := doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": byNode["pn1"].ID, "plan_sha256": byNode["pn1"].PlanSHA256})), cookies, csrf)
	approve.Body.Close()
	if approve.StatusCode != http.StatusOK {
		t.Fatalf("approve from plan-less listing = %d", approve.StatusCode)
	}
	if got, _ := st.Approval(byNode["pn1"].ID); got.Status != model.ApprovalApproved {
		t.Fatalf("approve did not persist: %+v", got)
	}

	reject := doJSON(t, handler, http.MethodPost, "/api/network/approvals/reject",
		string(mustJSON(t, map[string]any{"approval_id": byNode["pn2"].ID})), cookies, csrf)
	reject.Body.Close()
	if reject.StatusCode != http.StatusOK {
		t.Fatalf("reject from plan-less listing = %d", reject.StatusCode)
	}
	if got, _ := st.Approval(byNode["pn2"].ID); got.Status != model.ApprovalRejected {
		t.Fatalf("reject did not persist: %+v", got)
	}
}

func TestDismissWorksFromPlanlessListing(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	cookies, csrf := loginSession(t, handler)
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.2.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    agentUpdateTestSHA, InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "auto", time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, AutoPlan: true, TargetVersion: "0.3.0",
		BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64",
		SHA256:    strings.Repeat("a", 64), InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}

	listing := getApprovalsEnvelope(t, handler, cookies, "plugin="+agentUpdatePlugin)
	if len(listing.Approvals) != 1 || listing.Approvals[0].ID != approval.ID || listing.Approvals[0].Plan != "" {
		t.Fatalf("expected one plan-less agent update row, got %+v", listing.Approvals)
	}
	dismiss := doJSON(t, handler, http.MethodPost, "/api/network/approvals/dismiss",
		string(mustJSON(t, map[string]any{"approval_id": listing.Approvals[0].ID})), cookies, csrf)
	dismiss.Body.Close()
	if dismiss.StatusCode != http.StatusOK {
		t.Fatalf("dismiss from plan-less listing = %d", dismiss.StatusCode)
	}
	if got, _ := st.Approval(approval.ID); got.Status != approvalStatusDismissed {
		t.Fatalf("dismiss did not persist: %+v", got)
	}
}
