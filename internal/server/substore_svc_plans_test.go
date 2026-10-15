package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	subStorePlanLine1 = "11111111-1111-4111-8111-111111111111"
	subStorePlanLine2 = "22222222-2222-4222-8222-222222222222"
	subStorePlanLine3 = "33333333-3333-4333-8333-333333333333"
	subStorePlanLine4 = "44444444-4444-4444-8444-444444444444"
)

// subStoreFakePreviewer is the test double of the bind code: a fixed result
// per revision and identity, the record's live revision, and a record of
// every query. One query is one render of one revision, whatever the
// identities it binds.
type subStoreFakePreviewer struct {
	mu      sync.Mutex
	results map[string]subStoreBindResult
	live    string
	calls   []subStoreBindQuery
	err     error
}

func (f *subStoreFakePreviewer) PreviewBind(_ context.Context, q subStoreBindQuery) (map[string]subStoreBindResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, q)
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]subStoreBindResult, len(q.IdentityIDs))
	for _, identityID := range q.IdentityIDs {
		result := f.results[q.Revision+"|"+identityID]
		result.LiveRevision = f.live
		out[identityID] = result
	}
	return out, nil
}

func (f *subStoreFakePreviewer) set(key string, result subStoreBindResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[key] = result
}

func (f *subStoreFakePreviewer) setLive(revision string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live = revision
}

func (f *subStoreFakePreviewer) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *subStoreFakePreviewer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type subStorePlanHarness struct {
	*subStoreSvcHarness
	previewer *subStoreFakePreviewer
	mu        sync.Mutex
	applied   []subStoreApplyRevisionRequest
	applyErr  error
	// onApply runs inside the fake apply_revision with the context core
	// called it with, as the plugin's host calls would see it.
	onApply func(ctx context.Context, req subStoreApplyRevisionRequest)
	renders atomic.Int64
}

// newSubStorePlanHarness has a record "rec" with three live identity shares
// (two for alice, one for bob), a share that names no identity, an archived
// alice share, and an alice share on another record. rev-1 is live. Moving
// rec from rev-1 to rev-2 gives alice line 4 (twice, as clones), takes line
// 3 away, excludes line 2 and a node without a line, and renames line 1;
// bob is unchanged.
func newSubStorePlanHarness(t *testing.T) *subStorePlanHarness {
	t.Helper()
	h := &subStorePlanHarness{subStoreSvcHarness: newSubStoreSvcHarness(t)}
	for _, u := range []VpnUser{{ID: "vpnuser_alice", Email: "alice@example.com", Enabled: true}, {ID: "vpnuser_bob", Email: "bob@example.com", Enabled: true}} {
		if err := h.srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}
	h.previewer = &subStoreFakePreviewer{live: "rev-1", results: map[string]subStoreBindResult{
		"rev-1|vpnuser_alice": {Included: []subStoreBindLine{
			{LineUUID: subStorePlanLine1, Name: "tokyo vless", Digest: "d1"}, {LineUUID: subStorePlanLine2, Name: "osaka vless", Digest: "d2"},
			{LineUUID: subStorePlanLine3, Name: "seoul trojan", Digest: "d3"},
		}},
		"rev-2|vpnuser_alice": {
			Included: []subStoreBindLine{
				{LineUUID: subStorePlanLine1, Name: "tokyo vless renamed", Digest: "d1"},
				{LineUUID: subStorePlanLine4, Name: "paris hy2", Digest: "d4"}, {LineUUID: subStorePlanLine4, Name: "paris hy2 copy", Digest: "d4b"},
			},
			Excluded: []subStoreBindLine{
				{LineUUID: subStorePlanLine2, Name: "osaka vless", Reason: "plan_rejected:server"},
				{Name: "injected\nnode", Reason: "no_line"},
			},
		},
		"rev-1|vpnuser_bob": {Included: []subStoreBindLine{{LineUUID: subStorePlanLine1, Name: "tokyo vless", Digest: "d1"}}},
		"rev-2|vpnuser_bob": {Included: []subStoreBindLine{{LineUUID: subStorePlanLine1, Name: "tokyo vless", Digest: "d1"}}},
	}}
	h.srv.subStoreSvc.previewer = h.previewer
	h.srv.subStoreSvc.applyRevision = func(ctx context.Context, req subStoreApplyRevisionRequest) (subStoreApplyRevisionReply, error) {
		h.mu.Lock()
		h.applied = append(h.applied, req)
		applyErr, onApply := h.applyErr, h.onApply
		h.mu.Unlock()
		if onApply != nil {
			onApply(ctx, req)
		}
		if applyErr != nil {
			return subStoreApplyRevisionReply{}, applyErr
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

func (h *subStorePlanHarness) setOnApply(fn func(context.Context, subStoreApplyRevisionRequest)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onApply = fn
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

func (h *subStorePlanHarness) status(approvalID string) model.Approval {
	current, _ := h.st.Approval(approvalID)
	return current
}

// claimApply is the plugin's claim_apply from inside apply_revision: a host
// rpc.call on the invocation's context, under the manifest's grant.
func (h *subStorePlanHarness) claimApply(ctx context.Context, req subStoreApplyRevisionRequest) error {
	body, _ := json.Marshal(req)
	_, err := h.srv.pluginRPC.CallGranted(ctx, subStorePluginID, plugin.RPCGrant{subStorePlansService: {"claim_apply": {}}},
		subStorePlansService, "claim_apply", body)
	return err
}

// propose files an approval whose hash is the hash of the plan text it
// returns, and that text is the per-share, per-identity diff. Nothing is
// applied until the operator approves that hash; then apply_revision is
// called once, with the reviewed revisions, under the subscription mutation
// gate.
func TestSubStorePlansProposeHashCoversDiffAndApplyWaitsForApproval(t *testing.T) {
	h := newSubStorePlanHarness(t)
	// The harness's record renders a document, which an identity-bound share
	// answers with the decoy (fleet_share_legacy_document), so the cache is
	// watched through the share that names no identity.
	unbound, _ := h.st.SubscriptionShare(h.findShare(t, "provider-only"))
	if res := h.fetch("/sub/provider-only/" + unbound.Token); res.Code != http.StatusOK {
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
	if strings.Contains(reply.Plan, `"d1"`) || strings.Contains(reply.Plan, `"d4"`) {
		t.Fatal("the plan shows a previewer's entry digest")
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
		slugs["alice-laptop"].Removed != 2 || slugs["alice-laptop"].Changed != 1 || slugs["alice-laptop"].Excluded != 2 ||
		slugs["bob"].Added+slugs["bob"].Removed+slugs["bob"].Changed+slugs["bob"].Excluded != 0 {
		t.Fatalf("plan shares = %+v", plan.Shares)
	}
	if len(plan.UnboundShares) != 1 || plan.UnboundShares[0].Slug != "provider-only" || plan.UnboundShares[0].FleetCredentials ||
		plan.Coverage != subStorePlanUnboundCoverage {
		t.Fatalf("plan unbound shares = %+v, coverage %q", plan.UnboundShares, plan.Coverage)
	}
	if len(plan.Identities) != 2 || plan.Identities[0].IdentityID != "vpnuser_alice" || plan.Identities[1].IdentityID != "vpnuser_bob" {
		t.Fatalf("plan identities = %+v", plan.Identities)
	}
	a := plan.Identities[0]
	if len(a.Added) != 1 || a.Added[0].LineUUID != subStorePlanLine4 || strings.Join(a.Added[0].Names, ",") != "paris hy2,paris hy2 copy" ||
		a.Unchanged != 0 ||
		len(a.Changed) != 1 || a.Changed[0].LineUUID != subStorePlanLine1 ||
		strings.Join(a.Changed[0].Before.Names, ",") != "tokyo vless" || strings.Join(a.Changed[0].After.Names, ",") != "tokyo vless renamed" ||
		len(a.Removed) != 2 || a.Removed[0].LineUUID != subStorePlanLine2 || a.Removed[0].Reason != "plan_rejected:server" ||
		a.Removed[1].LineUUID != subStorePlanLine3 || a.Removed[1].Reason != "" ||
		len(a.Excluded) != 2 || a.Excluded[0].Reason != "no_line" || a.Excluded[0].Name != "injectednode" {
		t.Fatalf("alice's diff = %+v", a)
	}
	if b := plan.Identities[1]; b.Unchanged != 1 || len(b.Added)+len(b.Removed)+len(b.Changed)+len(b.Excluded) != 0 {
		t.Fatalf("bob's diff = %+v", b)
	}
	if plan.Totals != (subStorePlanTotals{Shares: 3, UnboundShares: 1, Identities: 2, Added: 1, Removed: 2, Changed: 1, Excluded: 2}) {
		t.Fatalf("totals = %+v", plan.Totals)
	}
	// One render per revision, binding both identities, not one per share
	// or per identity.
	if h.previewer.callCount() != 2 {
		t.Fatalf("previewer called %d times, want 2", h.previewer.callCount())
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
	if current := h.status(reply.ApprovalID); current.Status != model.ApprovalPending {
		t.Fatalf("a refused approval moved the plan to %s", current.Status)
	}

	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	// The decision previewed both revisions again before applying.
	if h.previewer.callCount() != 4 {
		t.Fatalf("previewer called %d times by the decision, want 2 more", h.previewer.callCount()-2)
	}
	if h.appliedCount() != 1 {
		t.Fatalf("apply_revision called %d times", h.appliedCount())
	}
	got := h.applied[0]
	if got != (subStoreApplyRevisionRequest{SubscriptionID: "rec", Revision: "rev-2", ExpectedRevision: "rev-1",
		ApprovalID: reply.ApprovalID, PlanSHA256: reply.PlanSHA256}) {
		t.Fatalf("apply_revision payload = %+v", got)
	}
	if current := h.status(reply.ApprovalID); current.Status != model.ApprovalApplied || current.ApprovedBy != "approver" {
		t.Fatalf("approval after apply = %+v", current)
	}
	// The body rendered from rev-1 is not served after the apply.
	if res := h.fetch("/sub/provider-only/" + unbound.Token); res.Code != http.StatusOK || h.renders.Load() == rendersBefore {
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

// Deciding a plan takes network:apply, network:plan and proxy:admin on an
// unrestricted principal, and reading one takes the same reach.
func TestSubStorePlanApprovalScopes(t *testing.T) {
	h := newSubStorePlanHarness(t)
	reply := h.propose(t)
	approval, _ := h.st.Approval(reply.ApprovalID)

	applyOnly := principal{Principal: rbac.Principal{ActorID: "a", Scopes: []string{"network:apply", "network:plan"}}}
	confined := principal{Principal: rbac.Principal{ActorID: "c", Scopes: []string{"network:apply", "network:plan", "proxy:admin"}, ServerAllowlist: []string{"node-1"}}}
	// Every share scope without network:plan: deciding hands the plan back,
	// and reading a plan takes network:plan.
	noPlan := principal{Principal: rbac.Principal{ActorID: "np", Scopes: []string{"network:apply", "proxy:admin", "proxy:read"}}}
	for name, p := range map[string]principal{"network:apply only": applyOnly, "node-restricted": confined, "no network:plan": noPlan} {
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
	if h.appliedCount() != 0 || h.status(reply.ApprovalID).Status != model.ApprovalPending {
		t.Fatal("a refused decider applied or decided the plan")
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

// A share created after the proposal, with an identity or without one,
// would receive what nobody reviewed, so the plan is rejected as stale and
// nothing is applied.
func TestSubStorePlanStaleWhenLiveSharesChange(t *testing.T) {
	for name, body := range map[string]string{
		"identity share": `{"subscription_id":"rec","slug":"bob-tablet","identity_id":"vpnuser_bob"}`,
		"unbound share":  `{"subscription_id":"rec","slug":"provider-two"}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newSubStorePlanHarness(t)
			reply := h.propose(t)
			h.createShare(t, body)

			res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
			if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), model.APIErrorApprovalStale) {
				t.Fatalf("approve after a share was added: %d %s", res.Code, res.Body.String())
			}
			if h.appliedCount() != 0 {
				t.Fatal("a stale plan was applied")
			}
			if current := h.status(reply.ApprovalID); current.Status != model.ApprovalRejected || !strings.Contains(current.Reason, "live shares changed") {
				t.Fatalf("stale approval = %+v", current)
			}
		})
	}
}

// The plan pins what holders receive, not only the revision ids: a staged
// revision re-staged under its id, or a catalogue change that binds a line
// to another server, after the proposal makes the plan stale.
func TestSubStorePlanStaleWhenWhatHoldersReceiveChanges(t *testing.T) {
	for name, change := range map[string]subStoreBindResult{
		"server moved inside the allowed set": {Included: []subStoreBindLine{
			{LineUUID: subStorePlanLine1, Name: "tokyo vless renamed", Digest: "d1-other-port"},
			{LineUUID: subStorePlanLine4, Name: "paris hy2", Digest: "d4"}, {LineUUID: subStorePlanLine4, Name: "paris hy2 copy", Digest: "d4b"},
		}},
		"a clone dropped": {Included: []subStoreBindLine{
			{LineUUID: subStorePlanLine1, Name: "tokyo vless renamed", Digest: "d1"},
			{LineUUID: subStorePlanLine4, Name: "paris hy2", Digest: "d4"},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newSubStorePlanHarness(t)
			reply := h.propose(t)
			h.previewer.set("rev-2|vpnuser_alice", change)
			res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
			if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "would receive changed") {
				t.Fatalf("approve after the staged revision changed: %d %s", res.Code, res.Body.String())
			}
			if h.appliedCount() != 0 || h.status(reply.ApprovalID).Status != model.ApprovalRejected {
				t.Fatalf("a plan nobody read was applied (%d) or left %s", h.appliedCount(), h.status(reply.ApprovalID).Status)
			}
		})
	}
}

// propose refuses a from_revision that is not the record's live revision,
// and a plan whose record moved before the decision is stale.
func TestSubStorePlanLiveRevision(t *testing.T) {
	h := newSubStorePlanHarness(t)
	_, err := h.call(subStoreSvcAdmin, subStorePlansService, "propose", `{"subscription_id":"rec","from_revision":"rev-0","to_revision":"rev-2"}`)
	if subStoreSvcErrStatus(err) != http.StatusConflict || !strings.Contains(subStoreSvcErrBody(err), "live revision") {
		t.Fatalf("propose from a revision that is not live: %v %s", err, subStoreSvcErrBody(err))
	}
	for _, a := range h.st.Approvals() {
		if a.Plugin == subStorePlanApprovalPlugin {
			t.Fatal("a refused propose filed an approval")
		}
	}

	reply := h.propose(t)
	h.previewer.setLive("rev-3")
	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "live revision moved") {
		t.Fatalf("approve after the record moved: %d %s", res.Code, res.Body.String())
	}
	if h.appliedCount() != 0 || h.status(reply.ApprovalID).Status != model.ApprovalRejected {
		t.Fatal("a plan for a record that moved was applied or left pending")
	}
}

// A preview that fails at the decision says nothing about the plan: it stays
// pending, nothing is applied, and the next decision applies it.
func TestSubStorePlanPreviewFailureAtDecisionKeepsPlanPending(t *testing.T) {
	h := newSubStorePlanHarness(t)
	reply := h.propose(t)
	h.previewer.setErr(errors.New("render failed: vless://secret@host (PLAINTEXT-MARKER)"))
	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusBadGateway || strings.Contains(res.Body.String(), "PLAINTEXT-MARKER") {
		t.Fatalf("approve with a failing preview: %d %s", res.Code, res.Body.String())
	}
	if h.appliedCount() != 0 || h.status(reply.ApprovalID).Status != model.ApprovalPending {
		t.Fatalf("a failed preview applied (%d) or decided the plan (%s)", h.appliedCount(), h.status(reply.ApprovalID).Status)
	}
	h.previewer.setErr(nil)
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK || h.appliedCount() != 1 {
		t.Fatalf("approve after the preview recovered: %d %s, %d applies", res.Code, res.Body.String(), h.appliedCount())
	}
}

// A share that names no identity is listed, not diffed; one that publishes
// the fleet export makes a plan required on its own, and a record whose
// every live share is provider-only publishes without one.
func TestSubStorePlanUnboundShares(t *testing.T) {
	h := newSubStorePlanHarness(t)
	mustUpsertShare(t, h.st, withShareFleetCredentials(model.SubscriptionShare{ID: "share_fleet", Slug: "fleet-feed", Token: strings.Repeat("f", 43),
		Enabled: true, Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "legacy"}}))
	mustUpsertShare(t, h.st, model.SubscriptionShare{ID: "share_provider", Slug: "provider-feed", Token: strings.Repeat("p", 43),
		Enabled: true, Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "provider"}})

	var reply subStorePlansProposeReply
	if err := json.Unmarshal(h.mustCall(t, subStorePlansService, "propose", `{"subscription_id":"legacy","from_revision":"rev-1","to_revision":"rev-2"}`), &reply); err != nil {
		t.Fatal(err)
	}
	var plan subStorePlan
	if !reply.Required || json.Unmarshal([]byte(reply.Plan), &plan) != nil {
		t.Fatalf("a record with a fleet-feed share published without a plan: %+v", reply)
	}
	if len(plan.Shares) != 0 || len(plan.Identities) != 0 || len(plan.UnboundShares) != 1 || !plan.UnboundShares[0].FleetCredentials ||
		plan.Totals.UnboundShares != 1 || plan.Coverage == "" {
		t.Fatalf("fleet-feed plan = %+v", plan)
	}
	callsBefore := h.previewer.callCount()
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK ||
		h.status(reply.ApprovalID).Status != model.ApprovalApplied {
		t.Fatalf("approve the fleet-feed plan: %d %s", res.Code, res.Body.String())
	}
	if h.previewer.callCount() != callsBefore {
		t.Fatal("a plan with no identity was previewed")
	}

	reply = subStorePlansProposeReply{}
	if err := json.Unmarshal(h.mustCall(t, subStorePlansService, "propose", `{"subscription_id":"provider","from_revision":"rev-1","to_revision":"rev-2"}`), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Required || reply.ApprovalID != "" {
		t.Fatalf("a provider-only record needed a plan: %+v", reply)
	}
}

// A failed apply leaves the approval approved and unapplied, audited, and
// nothing can apply it afterwards: the grant died with core's call.
func TestSubStorePlanApplyFailure(t *testing.T) {
	h := newSubStorePlanHarness(t)
	h.applyErr = errors.New("plugin said: record rec is at rev-9 (PLAINTEXT-MARKER)")
	var captured context.Context
	h.setOnApply(func(ctx context.Context, _ subStoreApplyRevisionRequest) { captured = ctx })
	reply := h.propose(t)
	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusBadGateway || strings.Contains(res.Body.String(), "PLAINTEXT-MARKER") {
		t.Fatalf("approve with a failing apply: %d %s", res.Code, res.Body.String())
	}
	if current := h.status(reply.ApprovalID); current.Status != model.ApprovalApproved || !strings.Contains(current.Reason, "apply_revision failed") ||
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
	// A replay of the approved, unapplied plan finds no grant to claim.
	if err := h.claimApply(captured, h.applied[0]); subStoreSvcErrStatus(err) != http.StatusForbidden {
		t.Fatalf("a replay claimed the dead grant: %v", err)
	}
}

// apply_revision's grant lives on core's call: claimable once, for the
// request core made, while the call runs, and by nothing else.
func TestSubStorePlanApplyGrantIsClaimedOnceInsideCoreCall(t *testing.T) {
	h := newSubStorePlanHarness(t)
	var captured context.Context
	var mismatched, first, second error
	h.setOnApply(func(ctx context.Context, req subStoreApplyRevisionRequest) {
		captured = ctx
		other := req
		other.Revision = "rev-9"
		mismatched = h.claimApply(ctx, other)
		first = h.claimApply(ctx, req)
		second = h.claimApply(ctx, req)
	})
	reply := h.propose(t)
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if subStoreSvcErrStatus(mismatched) != http.StatusForbidden || first != nil || subStoreSvcErrStatus(second) != http.StatusForbidden {
		t.Fatalf("claims inside core's call: mismatched %v, first %v, second %v", mismatched, first, second)
	}
	req := h.applied[0]
	if err := h.claimApply(captured, req); subStoreSvcErrStatus(err) != http.StatusForbidden {
		t.Fatalf("a claim after core's call returned: %v", err)
	}
	// The operator's own call, and a plugin method reached through the
	// gateway (the operator principal but no grant), are both refused.
	body, _ := json.Marshal(req)
	if _, err := h.call(subStoreSvcAdmin, subStorePlansService, "claim_apply", string(body)); subStoreSvcErrStatus(err) != http.StatusForbidden {
		t.Fatalf("the operator's claim_apply: %v", err)
	}
	served := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, subStoreSvcAdmin)
	if err := h.claimApply(served, req); subStoreSvcErrStatus(err) != http.StatusForbidden {
		t.Fatalf("a claim from an operator-served call: %v", err)
	}
	claimed, denied := "", 0
	for _, ev := range h.st.AuditEvents() {
		if ev.Action == auditActionSubStorePlanApply && ev.Decision == "allow" && ev.Metadata["approval_id"] == reply.ApprovalID {
			claimed = ev.Metadata["grant_claimed"]
		}
		if ev.Action == auditActionSubStorePlanClaim && ev.Decision == "deny" {
			denied++
		}
	}
	if claimed != "true" || denied != 5 {
		t.Fatalf("apply audit grant_claimed=%q, %d refused claims audited", claimed, denied)
	}
}

// A plugin that publishes without claiming its grant would publish for any
// caller; the apply is recorded as applied and the audit and the log say so.
func TestSubStorePlanUnclaimedApplyIsAudited(t *testing.T) {
	h := newSubStorePlanHarness(t)
	reply := h.propose(t)
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	found := false
	for _, ev := range h.st.AuditEvents() {
		if ev.Action == auditActionSubStorePlanApply && ev.Metadata["approval_id"] == reply.ApprovalID && ev.Metadata["grant_claimed"] == "false" {
			found = true
		}
	}
	if !found || !strings.Contains(h.log.String(), "without claiming its grant") || h.status(reply.ApprovalID).Status != model.ApprovalApplied {
		t.Fatalf("unclaimed apply: audited %v, log %q, status %s", found, h.log.String(), h.status(reply.ApprovalID).Status)
	}
}

// The share-write lock is released before apply_revision runs: a slow apply
// does not hold up every share change.
func TestSubStorePlanApplyRunsOutsideShareWriteLock(t *testing.T) {
	h := newSubStorePlanHarness(t)
	lockFree := false
	h.setOnApply(func(context.Context, subStoreApplyRevisionRequest) {
		if h.srv.subStoreSvc.mu.TryLock() {
			lockFree = true
			h.srv.subStoreSvc.mu.Unlock()
		}
	})
	reply := h.propose(t)
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", res.Code, res.Body.String())
	}
	if !lockFree {
		t.Fatal("apply_revision ran under the share-write lock")
	}
}

// The task kill switch stops node tasks; a plan applies by a plugin call
// and queues none, so the switch does not hold it.
func TestSubStorePlanApprovalIsNotHeldByTaskKillSwitch(t *testing.T) {
	h := newSubStorePlanHarness(t)
	h.srv.taskExecutionDisabled = true
	reply := h.propose(t)
	if res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true); res.Code != http.StatusOK || h.appliedCount() != 1 {
		t.Fatalf("approve with the kill switch on: %d %s, %d applies", res.Code, res.Body.String(), h.appliedCount())
	}
	for _, ev := range h.st.AuditEvents() {
		if ev.Action == "network."+subStorePlanApprovalPlugin+".approve" {
			t.Fatalf("the plan was refused as a node task: %+v", ev)
		}
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

	h.previewer.setErr(errors.New("render failed: vless://secret@host (PLAINTEXT-MARKER)"))
	_, err := h.call(subStoreSvcAdmin, subStorePlansService, "propose", body)
	if subStoreSvcErrStatus(err) != http.StatusBadGateway || strings.Contains(subStoreSvcErrBody(err), "PLAINTEXT-MARKER") ||
		strings.Contains(h.log.String(), "PLAINTEXT-MARKER") {
		t.Fatalf("a failed preview: %v %s", err, subStoreSvcErrBody(err))
	}
	h.previewer.setErr(nil)

	h.srv.subStoreSvc.previewer = nil
	if _, err := h.call(subStoreSvcAdmin, subStorePlansService, "propose", body); subStoreSvcErrStatus(err) != http.StatusServiceUnavailable {
		t.Fatalf("propose without a previewer: %v", err)
	}
	if countApprovals() != 0 {
		t.Fatal("a refused propose filed an approval")
	}

	// A record with no live share needs no plan.
	var reply subStorePlansProposeReply
	if err := json.Unmarshal(h.mustCall(t, subStorePlansService, "propose", `{"subscription_id":"no-shares","from_revision":"a","to_revision":"b"}`), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Required || reply.ApprovalID != "" || countApprovals() != 0 {
		t.Fatalf("propose for a record without fleet-bound shares = %+v", reply)
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

// A line received from both revisions is unchanged only when its entries
// are: a rename, a clone added or dropped, and an entry digested
// differently (a server or port moved) each make it changed. Every text
// field is one bounded line.
func TestSubStorePlanDiff(t *testing.T) {
	long := strings.Repeat("é", 100)
	same := []subStoreBindLine{{LineUUID: subStorePlanLine4, Name: "same", Digest: "x"}}
	diff := subStorePlanDiff("id", subStoreBindResult{
		Included: append([]subStoreBindLine{
			{LineUUID: subStorePlanLine1, Name: "old name", Digest: "a"},
			{LineUUID: subStorePlanLine3, Name: "port", Digest: "p443"},
			{LineUUID: subStorePlanLine2, Name: "clone", Digest: "c"}, {LineUUID: subStorePlanLine2, Name: "clone", Digest: "c"},
		}, same...),
	}, subStoreBindResult{
		Included: append([]subStoreBindLine{
			{LineUUID: subStorePlanLine1, Name: "new name", Digest: "a"},
			{LineUUID: subStorePlanLine3, Name: "port", Digest: "p8443"},
			{LineUUID: subStorePlanLine2, Name: "clone", Digest: "c"},
			{LineUUID: "55555555-5555-4555-8555-555555555555", Name: long},
		}, same...),
		Excluded: []subStoreBindLine{{LineUUID: subStorePlanLine3, Name: "a\tb", Reason: ""}},
	})
	if diff.Unchanged != 1 || len(diff.Removed) != 0 || len(diff.Added) != 1 || len(diff.Changed) != 3 || len(diff.Excluded) != 1 {
		t.Fatalf("diff = %+v", diff)
	}
	for _, change := range diff.Changed {
		if change.Before.Digest == change.After.Digest {
			t.Fatalf("a changed line kept its digest: %+v", change)
		}
	}
	if diff.Changed[1].LineUUID != subStorePlanLine2 || len(diff.Changed[1].Before.Names) != 2 || len(diff.Changed[1].After.Names) != 1 {
		t.Fatalf("a dropped clone = %+v", diff.Changed[1])
	}
	if name := diff.Added[0].Names[0]; len(name) > subStorePlanLineNameBytes || !strings.HasPrefix(long, name) {
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
	if current := h.status(reply.ApprovalID); current.Status != model.ApprovalApplied {
		t.Fatalf("a late approval rewrote the applied plan to %s", current.Status)
	}
}

// The gateway refuses apply_revision for every operator, whatever the
// manifest declares: it runs only as an approved plan's apply step.
func TestPluginGatewayRefusesSubStoreApplyRevision(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	manifest := plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: subStorePluginID, Name: "Sub-Store", Type: plugin.TypeSystem, Publisher: "latticenet",
		Interfaces: []plugin.InterfaceContract{{
			Service: subStorePluginID + "/subscription", Backing: plugin.BackingRuntime,
			MethodSpecs: []plugin.InterfaceMethod{{Name: subStoreApplyRevisionMethod, Effect: plugin.InterfaceEffectRead, Scopes: []string{"substore:admin"}}},
		}},
	}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{
		ID: manifest.ID, Name: manifest.Name, Type: manifest.Type, Status: model.PluginStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{store: st, plugins: []plugin.Loaded{{Manifest: manifest}}, pluginRPC: plugin.NewRPCRegistry()}
	body, _ := json.Marshal(map[string]any{"id": subStorePluginID, "service": subStorePluginID + "/subscription", "method": subStoreApplyRevisionMethod,
		"payload": subStoreApplyRevisionRequest{SubscriptionID: "rec", Revision: "rev-2", ExpectedRevision: "rev-1", ApprovalID: "approval_x", PlanSHA256: strings.Repeat("a", 64)}})
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handlePluginCall(rec, req, principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"*"}}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "approved Sub-Store plan") {
		t.Fatalf("an operator's apply_revision: %d %s", rec.Code, rec.Body.String())
	}
	denied := false
	for _, ev := range st.AuditEvents() {
		if ev.Decision == "deny" && ev.Reason == subStoreCoreOnlyReason {
			denied = true
		}
	}
	if !denied {
		t.Fatal("the refused apply_revision was not audited")
	}
}

// apply_revision is named by exactly one non-test file, the plan applier, so
// no other handler reaches it by reflex. The gateway refusal and the grant
// stand behind this; this keeps a new caller from appearing unnoticed.
func TestSubStoreApplyRevisionIsNamedOnlyByThePlanApplier(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var callers []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `"apply_revision"`) {
			callers = append(callers, name)
		}
	}
	if len(callers) != 1 || callers[0] != "substore_svc_plans.go" {
		t.Fatalf("apply_revision must be named only by substore_svc_plans.go, but these files name it: %v", callers)
	}
}
