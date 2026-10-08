package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	subStorePlanLine1 = "11111111-1111-4111-8111-111111111111"
	subStorePlanLine2 = "22222222-2222-4222-8222-222222222222"
	subStorePlanLine3 = "33333333-3333-4333-8333-333333333333"
	subStorePlanLine4 = "44444444-4444-4444-8444-444444444444"
)

// subStoreFakePreviewer is the test double of the bind code: a fixed result
// per revision and identity, and a record of every query.
type subStoreFakePreviewer struct {
	mu      sync.Mutex
	results map[string]subStoreBindResult
	calls   []subStoreBindQuery
	err     error
}

func (f *subStoreFakePreviewer) PreviewBind(_ context.Context, q subStoreBindQuery) (subStoreBindResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, q)
	if f.err != nil {
		return subStoreBindResult{}, f.err
	}
	return f.results[q.Revision+"|"+q.IdentityID], nil
}

type subStorePlanHarness struct {
	*subStoreSvcHarness
	previewer *subStoreFakePreviewer
	mu        sync.Mutex
	applied   []subStoreApplyRevisionRequest
	applyErr  error
	renders   atomic.Int64
}

// newSubStorePlanHarness has a record "rec" with three live identity shares
// (two for alice, one for bob), a share that names no identity, an archived
// alice share, and an alice share on another record. Moving rec from rev-1
// to rev-2 gives alice line 4 (twice, as clones), takes line 3 away, and
// excludes line 2 and a node without a line; bob is unchanged.
func newSubStorePlanHarness(t *testing.T) *subStorePlanHarness {
	t.Helper()
	h := &subStorePlanHarness{subStoreSvcHarness: newSubStoreSvcHarness(t)}
	for _, u := range []VpnUser{{ID: "vpnuser_alice", Email: "alice@example.com", Enabled: true}, {ID: "vpnuser_bob", Email: "bob@example.com", Enabled: true}} {
		if err := h.srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}
	h.previewer = &subStoreFakePreviewer{results: map[string]subStoreBindResult{
		"rev-1|vpnuser_alice": {Included: []subStoreBindLine{
			{LineUUID: subStorePlanLine1, Name: "tokyo vless"}, {LineUUID: subStorePlanLine2, Name: "osaka vless"}, {LineUUID: subStorePlanLine3, Name: "seoul trojan"},
		}},
		"rev-2|vpnuser_alice": {
			Included: []subStoreBindLine{
				{LineUUID: subStorePlanLine1, Name: "tokyo vless renamed"}, {LineUUID: subStorePlanLine4, Name: "paris hy2"}, {LineUUID: subStorePlanLine4, Name: "paris hy2 copy"},
			},
			Excluded: []subStoreBindLine{
				{LineUUID: subStorePlanLine2, Name: "osaka vless", Reason: "plan_rejected:server"},
				{Name: "injected\nnode", Reason: "no_line"},
			},
		},
		"rev-1|vpnuser_bob": {Included: []subStoreBindLine{{LineUUID: subStorePlanLine1, Name: "tokyo vless"}}},
		"rev-2|vpnuser_bob": {Included: []subStoreBindLine{{LineUUID: subStorePlanLine1, Name: "tokyo vless"}}},
	}}
	h.srv.subStoreSvc.previewer = h.previewer
	h.srv.subStoreSvc.applyRevision = func(_ context.Context, req subStoreApplyRevisionRequest) (subStoreApplyRevisionReply, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.applied = append(h.applied, req)
		if h.applyErr != nil {
			return subStoreApplyRevisionReply{}, h.applyErr
		}
		return subStoreApplyRevisionReply{SubscriptionID: req.SubscriptionID, Revision: req.Revision}, nil
	}
	render := h.srv.subscriptionRender
	h.srv.subscriptionRender = func(ctx context.Context, share model.SubscriptionShare, format, ua string, v shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		h.renders.Add(1)
		return render(ctx, share, format, ua, v, snap)
	}
	h.createShare(t, `{"subscription_id":"rec","slug":"alice-phone","identity_id":"vpnuser_alice"}`)
	h.createShare(t, `{"subscription_id":"rec","slug":"alice-laptop","identity_id":"vpnuser_alice"}`)
	h.createShare(t, `{"subscription_id":"rec","slug":"bob","identity_id":"vpnuser_bob"}`)
	h.createShare(t, `{"subscription_id":"rec","slug":"provider-only"}`)
	gone := h.createShare(t, `{"subscription_id":"rec","slug":"alice-old","identity_id":"vpnuser_alice"}`)
	h.mustCall(t, subStoreSharesService, "archive", `{"share_id":"`+gone.ShareID+`"}`)
	h.createShare(t, `{"subscription_id":"other","slug":"alice-other","identity_id":"vpnuser_alice"}`)
	return h
}

func (h *subStorePlanHarness) appliedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.applied)
}

func (h *subStorePlanHarness) propose(t *testing.T) subStorePlansProposeReply {
	t.Helper()
	var reply subStorePlansProposeReply
	if err := json.Unmarshal(h.mustCall(t, subStorePlansService, "propose", `{"subscription_id":"rec","from_revision":"rev-1","to_revision":"rev-2"}`), &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

// subStorePlanApprover may decide a Sub-Store plan.
var subStorePlanApprover = principal{Principal: rbac.Principal{ActorID: "approver", Scopes: []string{"network:apply", "network:plan", "proxy:admin"}}}

// approve drives the real approve endpoint.
func (h *subStorePlanHarness) approve(p principal, approvalID, planSHA string, queue bool) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"approval_id": approvalID, "plan_sha256": planSHA, "queue_apply": queue})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/network/approvals/approve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	h.srv.handleApprove(rec, req, p)
	return rec
}

// propose files an approval whose hash is the hash of the plan text it
// returns, and that text is the per-share, per-identity diff. Nothing is
// applied until the operator approves that hash; then apply_revision is
// called once, with the reviewed revisions, under the subscription mutation
// gate.
func TestSubStorePlansProposeHashCoversDiffAndApplyWaitsForApproval(t *testing.T) {
	h := newSubStorePlanHarness(t)
	alice, _ := h.st.SubscriptionShare(h.findShare(t, "alice-phone"))
	if res := h.fetch("/sub/alice-phone/" + alice.Token); res.Code != http.StatusOK {
		t.Fatalf("serve before apply: %d", res.Code)
	}
	rendersBefore := h.renders.Load()

	reply := h.propose(t)
	if !reply.Required || reply.ApprovalID == "" || reply.Status != model.ApprovalPending {
		t.Fatalf("propose reply = %+v", reply)
	}
	sum := sha256.Sum256([]byte(reply.Plan))
	if reply.PlanSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("plan_sha256 is not the hash of the plan text returned")
	}
	stored, ok := h.st.Approval(reply.ApprovalID)
	if !ok || stored.Plan != reply.Plan || approvalPlanSHA(stored) != reply.PlanSHA256 || stored.Status != model.ApprovalPending ||
		stored.Plugin != subStorePlanApprovalPlugin || stored.Action != subStorePlanActionPrefix+"rec" || stored.Service != "" {
		t.Fatalf("stored approval = %+v", stored)
	}

	var plan subStorePlan
	if err := json.Unmarshal([]byte(reply.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Kind != subStorePlanKind || plan.SubscriptionID != "rec" || plan.FromRevision != "rev-1" || plan.ToRevision != "rev-2" {
		t.Fatalf("plan header = %+v", plan)
	}
	slugs := map[string]subStorePlanShare{}
	for _, share := range plan.Shares {
		slugs[share.Slug] = share
	}
	if len(plan.Shares) != 3 || slugs["alice-phone"].IdentityID != "vpnuser_alice" || slugs["alice-laptop"].Added != 1 ||
		slugs["alice-laptop"].Removed != 2 || slugs["alice-laptop"].Excluded != 2 || slugs["bob"].Added+slugs["bob"].Removed+slugs["bob"].Excluded != 0 {
		t.Fatalf("plan shares = %+v", plan.Shares)
	}
	if len(plan.Identities) != 2 || plan.Identities[0].IdentityID != "vpnuser_alice" || plan.Identities[1].IdentityID != "vpnuser_bob" {
		t.Fatalf("plan identities = %+v", plan.Identities)
	}
	a := plan.Identities[0]
	if len(a.Added) != 1 || a.Added[0].LineUUID != subStorePlanLine4 || a.Unchanged != 1 ||
		len(a.Removed) != 2 || a.Removed[0].LineUUID != subStorePlanLine2 || a.Removed[0].Reason != "plan_rejected:server" ||
		a.Removed[1].LineUUID != subStorePlanLine3 || a.Removed[1].Reason != "" ||
		len(a.Excluded) != 2 || a.Excluded[0].Reason != "no_line" || a.Excluded[0].Name != "injectednode" {
		t.Fatalf("alice's diff = %+v", a)
	}
	if plan.Totals != (subStorePlanTotals{Shares: 3, Identities: 2, Added: 1, Removed: 2, Excluded: 2}) {
		t.Fatalf("totals = %+v", plan.Totals)
	}
	// One preview per revision per identity, not per share.
	if len(h.previewer.calls) != 4 {
		t.Fatalf("previewer called %d times, want 4", len(h.previewer.calls))
	}
	if h.appliedCount() != 0 {
		t.Fatal("propose applied the revision")
	}

	// A hash other than the plan's is refused and applies nothing.
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, strings.Repeat("0", 64), true); res.Code != http.StatusConflict {
		t.Fatalf("approve with a wrong hash: %d %s", res.Code, res.Body.String())
	}
	// So is an approval that would not apply.
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, false); res.Code != http.StatusBadRequest {
		t.Fatalf("approve without queue_apply: %d %s", res.Code, res.Body.String())
	}
	if h.appliedCount() != 0 {
		t.Fatal("a refused approval applied the revision")
	}
	if current, _ := h.st.Approval(reply.ApprovalID); current.Status != model.ApprovalPending {
		t.Fatalf("a refused approval moved the plan to %s", current.Status)
	}

	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if h.appliedCount() != 1 {
		t.Fatalf("apply_revision called %d times", h.appliedCount())
	}
	got := h.applied[0]
	if got != (subStoreApplyRevisionRequest{SubscriptionID: "rec", Revision: "rev-2", ExpectedRevision: "rev-1",
		ApprovalID: reply.ApprovalID, PlanSHA256: reply.PlanSHA256}) {
		t.Fatalf("apply_revision payload = %+v", got)
	}
	if current, _ := h.st.Approval(reply.ApprovalID); current.Status != model.ApprovalApplied || current.ApprovedBy != "approver" {
		t.Fatalf("approval after apply = %+v", current)
	}
	// The body rendered from rev-1 is not served after the apply.
	if res := h.fetch("/sub/alice-phone/" + alice.Token); res.Code != http.StatusOK || h.renders.Load() == rendersBefore {
		t.Fatalf("the share was served from the pre-apply cache (%d renders before, %d after)", rendersBefore, h.renders.Load())
	}
	// Approving again applies nothing more.
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK || h.appliedCount() != 1 {
		t.Fatalf("a second approval: %d, %d applies", res.Code, h.appliedCount())
	}

	actions := map[string]int{}
	for _, ev := range h.st.AuditEvents() {
		if ev.Metadata["approval_id"] == reply.ApprovalID {
			actions[ev.Action+"/"+ev.Decision]++
		}
	}
	if actions[auditActionSubStorePlanPropose+"/allow"] != 1 || actions[auditActionSubStorePlanApply+"/allow"] != 1 {
		t.Fatalf("plan audit = %v", actions)
	}
}

func (h *subStorePlanHarness) findShare(t *testing.T, slug string) string {
	t.Helper()
	for _, share := range h.st.SubscriptionShares() {
		if share.Slug == slug {
			return share.ID
		}
	}
	t.Fatalf("no share %s", slug)
	return ""
}

// Deciding a plan takes network:apply and proxy:admin on an unrestricted
// principal, and reading one takes the same reach.
func TestSubStorePlanApprovalScopes(t *testing.T) {
	h := newSubStorePlanHarness(t)
	reply := h.propose(t)
	approval, _ := h.st.Approval(reply.ApprovalID)

	applyOnly := principal{Principal: rbac.Principal{ActorID: "a", Scopes: []string{"network:apply", "network:plan"}}}
	confined := principal{Principal: rbac.Principal{ActorID: "c", Scopes: []string{"network:apply", "network:plan", "proxy:admin"}, ServerAllowlist: []string{"node-1"}}}
	for name, p := range map[string]principal{"network:apply only": applyOnly, "node-restricted": confined} {
		if res := h.approve(p, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusForbidden {
			t.Fatalf("%s approving: %d %s", name, res.Code, res.Body.String())
		}
		if h.srv.approvalVisibleToPrincipal(p, approval) {
			t.Fatalf("%s can read the plan", name)
		}
	}
	// Reading a plan is not deciding it: proxy:read with network:apply may
	// read the plan and may not approve it.
	readApply := principal{Principal: rbac.Principal{ActorID: "ra", Scopes: []string{"network:apply", "network:plan", "proxy:read"}}}
	if !h.srv.approvalVisibleToPrincipal(readApply, approval) {
		t.Fatal("proxy:read with network:plan cannot read the plan")
	}
	if res := h.approve(readApply, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusForbidden {
		t.Fatalf("proxy:read approving: %d %s", res.Code, res.Body.String())
	}
	if h.appliedCount() != 0 {
		t.Fatal("a refused decider applied the plan")
	}
	reader := principal{Principal: rbac.Principal{ActorID: "r", Scopes: []string{"proxy:read", "network:plan"}}}
	if !h.srv.approvalVisibleToPrincipal(reader, approval) || !h.srv.approvalVisibleToPrincipal(subStorePlanApprover, approval) {
		t.Fatal("a principal with the read scopes cannot read the plan")
	}

	// The listing a console reads shows it to the approver.
	rec := httptest.NewRecorder()
	h.srv.handleApprovals(rec, httptest.NewRequest(http.MethodGet, "/api/network/approvals?id="+reply.ApprovalID, nil), subStorePlanApprover)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), reply.ApprovalID) {
		t.Fatalf("approval by id: %d %s", rec.Code, rec.Body.String())
	}
}

// A share created after the proposal would receive what nobody reviewed, so
// the plan is rejected as stale and nothing is applied.
func TestSubStorePlanStaleWhenLiveSharesChange(t *testing.T) {
	h := newSubStorePlanHarness(t)
	reply := h.propose(t)
	h.createShare(t, `{"subscription_id":"rec","slug":"bob-tablet","identity_id":"vpnuser_bob"}`)

	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), model.APIErrorApprovalStale) {
		t.Fatalf("approve after a share was added: %d %s", res.Code, res.Body.String())
	}
	if h.appliedCount() != 0 {
		t.Fatal("a stale plan was applied")
	}
	if current, _ := h.st.Approval(reply.ApprovalID); current.Status != model.ApprovalRejected || !strings.Contains(current.Reason, "live shares changed") {
		t.Fatalf("stale approval = %+v", current)
	}
}

// A failed apply leaves the approval approved and unapplied, audited.
func TestSubStorePlanApplyFailure(t *testing.T) {
	h := newSubStorePlanHarness(t)
	h.applyErr = errors.New("plugin said: record rec is at rev-9 (PLAINTEXT-MARKER)")
	reply := h.propose(t)
	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusBadGateway || strings.Contains(res.Body.String(), "PLAINTEXT-MARKER") {
		t.Fatalf("approve with a failing apply: %d %s", res.Code, res.Body.String())
	}
	if current, _ := h.st.Approval(reply.ApprovalID); current.Status != model.ApprovalApproved || !strings.Contains(current.Reason, "apply_revision failed") ||
		strings.Contains(current.Reason, "PLAINTEXT-MARKER") {
		t.Fatalf("approval after a failed apply = %+v", current)
	}
	denied := false
	for _, ev := range h.st.AuditEvents() {
		if ev.Action == auditActionSubStorePlanApply && ev.Decision == "deny" && ev.Metadata["approval_id"] == reply.ApprovalID {
			denied = true
		}
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "PLAINTEXT-MARKER") {
			t.Fatal("the plugin's error text reached the audit trail")
		}
	}
	if !denied || strings.Contains(h.log.String(), "PLAINTEXT-MARKER") {
		t.Fatalf("failed apply audited %v; log %q", denied, h.log.String())
	}
}

// A rejected plan is never applied.
func TestSubStorePlanRejectedIsNeverApplied(t *testing.T) {
	h := newSubStorePlanHarness(t)
	reply := h.propose(t)
	body, _ := json.Marshal(map[string]string{"approval_id": reply.ApprovalID})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/network/approvals/reject", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	h.srv.handleRejectApproval(rec, req, subStorePlanApprover)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK || h.appliedCount() != 0 {
		t.Fatalf("approving a rejected plan: %d, %d applies", res.Code, h.appliedCount())
	}
}

func TestSubStorePlansProposeRefusals(t *testing.T) {
	h := newSubStorePlanHarness(t)
	body := `{"subscription_id":"rec","from_revision":"rev-1","to_revision":"rev-2"}`
	countApprovals := func() int {
		n := 0
		for _, a := range h.st.Approvals() {
			if a.Plugin == subStorePlanApprovalPlugin {
				n++
			}
		}
		return n
	}

	limited := principal{Principal: rbac.Principal{ActorID: "l", Scopes: []string{"substore:admin"}}}
	if _, err := h.call(limited, subStorePlansService, "propose", body); subStoreSvcErrStatus(err) != http.StatusForbidden {
		t.Fatalf("propose without proxy:admin: %v", err)
	}
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, subStoreSvcAdmin)
	if _, err := h.srv.subStorePlansRPC(ctx, "propose", []byte(body)); subStoreSvcErrStatus(err) != http.StatusForbidden {
		t.Fatalf("propose through rpc.call: %v", err)
	}
	for _, bad := range []string{
		`{"subscription_id":"rec","from_revision":"rev-1","to_revision":"rev-1"}`,
		`{"subscription_id":"rec","from_revision":"rev-1"}`,
		`{"subscription_id":"rec","from_revision":"rev-1","to_revision":"rev-2","extra":1}`,
	} {
		if _, err := h.call(subStoreSvcAdmin, subStorePlansService, "propose", bad); subStoreSvcErrStatus(err) != http.StatusBadRequest {
			t.Fatalf("propose %s: %v", bad, err)
		}
	}

	h.previewer.err = errors.New("render failed: vless://secret@host (PLAINTEXT-MARKER)")
	_, err := h.call(subStoreSvcAdmin, subStorePlansService, "propose", body)
	if subStoreSvcErrStatus(err) != http.StatusBadGateway || strings.Contains(subStoreSvcErrBody(err), "PLAINTEXT-MARKER") ||
		strings.Contains(h.log.String(), "PLAINTEXT-MARKER") {
		t.Fatalf("a failed preview: %v %s", err, subStoreSvcErrBody(err))
	}
	h.previewer.err = nil

	h.srv.subStoreSvc.previewer = nil
	if _, err := h.call(subStoreSvcAdmin, subStorePlansService, "propose", body); subStoreSvcErrStatus(err) != http.StatusServiceUnavailable {
		t.Fatalf("propose without a previewer: %v", err)
	}
	if countApprovals() != 0 {
		t.Fatal("a refused propose filed an approval")
	}

	// A record with no live identity share needs no plan.
	var reply subStorePlansProposeReply
	if err := json.Unmarshal(h.mustCall(t, subStorePlansService, "propose", `{"subscription_id":"no-shares","from_revision":"a","to_revision":"b"}`), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Required || reply.ApprovalID != "" || countApprovals() != 0 {
		t.Fatalf("propose for a record without identity shares = %+v", reply)
	}
}

func TestSubStorePlansStatus(t *testing.T) {
	h := newSubStorePlanHarness(t)
	first := h.propose(t)
	second := h.propose(t)
	h.approve(subStorePlanApprover, second.ApprovalID, second.PlanSHA256, true)

	var byID struct {
		Plans []subStorePlanStatusRow `json:"plans"`
	}
	if err := json.Unmarshal(h.mustCall(t, subStorePlansService, "status", `{"approval_id":"`+first.ApprovalID+`"}`), &byID); err != nil {
		t.Fatal(err)
	}
	if len(byID.Plans) != 1 || byID.Plans[0].Status != model.ApprovalPending || byID.Plans[0].PlanSHA256 != first.PlanSHA256 ||
		byID.Plans[0].ToRevision != "rev-2" {
		t.Fatalf("status by id = %+v", byID.Plans)
	}
	var byRecord struct {
		Plans []subStorePlanStatusRow `json:"plans"`
	}
	if err := json.Unmarshal(h.mustCall(t, subStorePlansService, "status", `{"subscription_id":"rec"}`), &byRecord); err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, row := range byRecord.Plans {
		statuses[row.ApprovalID] = row.Status
	}
	if len(statuses) != 2 || statuses[first.ApprovalID] != model.ApprovalPending || statuses[second.ApprovalID] != model.ApprovalApplied {
		t.Fatalf("status by record = %+v", byRecord.Plans)
	}
	if _, err := h.call(subStoreSvcAdmin, subStorePlansService, "status", `{}`); subStoreSvcErrStatus(err) != http.StatusBadRequest {
		t.Fatalf("status with neither id: %v", err)
	}
	if _, err := h.call(subStoreSvcAdmin, subStorePlansService, "status", `{"approval_id":"approval_missing"}`); subStoreSvcErrStatus(err) != http.StatusNotFound {
		t.Fatalf("status of a missing plan: %v", err)
	}
	noRead := principal{Principal: rbac.Principal{ActorID: "x", Scopes: []string{"network:plan"}}}
	if _, err := h.call(noRead, subStorePlansService, "status", `{"subscription_id":"rec"}`); subStoreSvcErrStatus(err) != http.StatusForbidden {
		t.Fatalf("status without substore:read: %v", err)
	}
}

// Lines are compared by line_uuid: a renamed line is unchanged, clones count
// once, and every text field is one bounded line.
func TestSubStorePlanDiff(t *testing.T) {
	long := strings.Repeat("é", 100)
	diff := subStorePlanDiff("id", subStoreBindResult{
		Included: []subStoreBindLine{{LineUUID: subStorePlanLine1, Name: "old name"}, {LineUUID: subStorePlanLine1, Name: "clone"}},
	}, subStoreBindResult{
		Included: []subStoreBindLine{{LineUUID: subStorePlanLine1, Name: "new name"}, {LineUUID: subStorePlanLine2, Name: long}},
		Excluded: []subStoreBindLine{{LineUUID: subStorePlanLine3, Name: "a\tb", Reason: ""}},
	})
	if diff.Unchanged != 1 || len(diff.Removed) != 0 || len(diff.Added) != 1 || len(diff.Excluded) != 1 {
		t.Fatalf("diff = %+v", diff)
	}
	if name := diff.Added[0].Name; len(name) > subStorePlanLineNameBytes || !strings.HasPrefix(long, name) {
		t.Fatalf("a long name was not cut on a rune boundary: %d bytes", len(name))
	}
	if diff.Excluded[0].Name != "ab" || diff.Excluded[0].Reason != "excluded" {
		t.Fatalf("excluded line = %+v", diff.Excluded[0])
	}
}

// Decisions racing on one plan apply it once, and a decision that arrives
// after the apply answers the applied plan even when the record's shares have
// changed since: it never rewrites the outcome.
func TestSubStorePlanConcurrentApprovalsApplyOnce(t *testing.T) {
	h := newSubStorePlanHarness(t)
	reply := h.propose(t)
	var wg sync.WaitGroup
	codes := make(chan int, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true).Code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("a racing approval answered %d", code)
		}
	}
	if h.appliedCount() != 1 {
		t.Fatalf("apply_revision called %d times", h.appliedCount())
	}

	h.createShare(t, `{"subscription_id":"rec","slug":"late","identity_id":"vpnuser_bob"}`)
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK {
		t.Fatalf("a late approval: %d %s", res.Code, res.Body.String())
	}
	if current, _ := h.st.Approval(reply.ApprovalID); current.Status != model.ApprovalApplied {
		t.Fatalf("a late approval rewrote the applied plan to %s", current.Status)
	}
}
