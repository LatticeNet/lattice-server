package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// cutoverFixture adds to the identity-link fixture two identities whose
// credential the fleet export carries: carol holds the vless line owner's
// uuid and is bound to that line, dave holds the trojan owner's password
// and is disabled. alice and bob hold credentials of their own.
func newCutoverFixture(t *testing.T) *identityLinkFixture {
	t.Helper()
	f := newIdentityLinkFixture(t)
	carol := VpnUser{ID: "vpnuser_carol", Email: "carol@example.com", Enabled: true, Credentials: []VpnCredential{
		{Protocol: "vless", UUID: idlOwnerUUID, Flow: "xtls-rprx-vision"}}}
	carol.Bindings = []LineBinding{f.applied(t, carol, f.vless)}
	dave := VpnUser{ID: "vpnuser_dave", Email: "dave@example.com", Enabled: true, Credentials: []VpnCredential{
		{Protocol: "trojan", Password: idlOwnerPass}}}
	dave.Bindings = []LineBinding{f.applied(t, dave, f.trojan)}
	dave.Enabled = false
	for _, u := range []VpnUser{carol, dave} {
		if err := f.srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func cutoverPrincipal(scopes ...string) principal {
	return principal{Principal: rbac.Principal{ActorID: "op", Scopes: scopes}}
}

func cutoverCall(t *testing.T, srv *Server, p principal, method, path string, body any) (int, []byte) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handleVpnCutover(rec, req, p)
	return rec.Code, rec.Body.Bytes()
}

func cutoverPreview(t *testing.T, srv *Server) (cutoverView, string) {
	t.Helper()
	code, raw := cutoverCall(t, srv, cutoverPrincipal("vpncore:admin"), http.MethodGet, "/api/vpn/cutover", nil)
	if code != http.StatusOK {
		t.Fatalf("preview: %d %s", code, raw)
	}
	var view cutoverView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	return view, string(raw)
}

func TestCutoverPreviewListsExposedIdentityCredentialsWithoutSecrets(t *testing.T) {
	f := newCutoverFixture(t)
	view, raw := cutoverPreview(t, f.srv)

	for _, secret := range []string{idlOwnerUUID, idlOwnerPass, idlAliceUUID, idlAlicePass, idlBobUUID} {
		if strings.Contains(raw, secret) {
			t.Fatalf("preview carries a credential %q: %s", secret, raw)
		}
	}
	if len(view.Rotations) != 2 {
		t.Fatalf("want carol and dave exposed, got %+v", view.Rotations)
	}
	carol, dave := view.Rotations[0], view.Rotations[1]
	if carol.IdentityID != "vpnuser_carol" || carol.Protocol != "vless" || strings.Join(carol.Exposure, ",") != "owner_share_url" {
		t.Fatalf("carol rotation: %+v", carol)
	}
	if len(carol.Pairs) != 1 || carol.Pairs[0].LineHashID != f.vless.LineHashID || !carol.Pairs[0].Plannable || carol.Pairs[0].NodeName != "Tokyo 1" {
		t.Fatalf("carol pairs: %+v", carol.Pairs)
	}
	if dave.IdentityID != "vpnuser_dave" || len(dave.Pairs) != 1 || dave.Pairs[0].Plannable || dave.Pairs[0].Reason != "identity_disabled" {
		t.Fatalf("dave rotation: %+v", dave)
	}
	if len(view.OwnerEntries) != 2 {
		t.Fatalf("owner entries: %+v", view.OwnerEntries)
	}
	for _, e := range view.OwnerEntries {
		if e.LineHashID == "" || !e.SharedWithIdentity {
			t.Fatalf("owner entry %+v: want a resolved line shared with an identity", e)
		}
	}
	if view.Links.Identities != 4 || view.Links.Issued != 0 || len(view.Links.NotIssued) != 4 {
		t.Fatalf("links: %+v", view.Links)
	}
	if view.AutoSync.Retired || len(view.Remaining) != 3 || len(view.Batches) != 0 || view.Digest == "" {
		t.Fatalf("autosync %+v remaining %q batches %+v digest %q", view.AutoSync, view.Remaining, view.Batches, view.Digest)
	}
}

func TestCutoverRotateActsOnlyOnTheDigestItShowed(t *testing.T) {
	f := newCutoverFixture(t)
	view, _ := cutoverPreview(t, f.srv)
	planner := cutoverPrincipal("vpncore:admin", "network:plan", "proxy:admin")

	if code, _ := cutoverCall(t, f.srv, cutoverPrincipal("vpncore:admin"), http.MethodPost, "/api/vpn/cutover/rotate", map[string]string{"digest": view.Digest}); code != http.StatusForbidden {
		t.Fatalf("rotate without network:plan: %d", code)
	}
	code, raw := cutoverCall(t, f.srv, planner, http.MethodPost, "/api/vpn/cutover/rotate", map[string]string{"digest": strings.Repeat("0", 64)})
	if code != http.StatusConflict || apiErrorCodeOf(t, raw) != apiErrorCutoverPlanChanged || !strings.Contains(string(raw), view.Digest) {
		t.Fatalf("stale digest: %d %s", code, raw)
	}
	if u, _ := f.srv.getVpnUser("vpnuser_carol"); u.Credentials[0].UUID != idlOwnerUUID {
		t.Fatal("a refused rotate changed a credential")
	}

	code, raw = cutoverCall(t, f.srv, planner, http.MethodPost, "/api/vpn/cutover/rotate", map[string]string{"digest": view.Digest})
	if code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, raw)
	}
	for _, secret := range []string{idlOwnerUUID, idlOwnerPass} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("rotate result carries a credential: %s", raw)
		}
	}
	var result cutoverRotateResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Batch, cutoverBatchPrefix+"_") || len(result.Rotated) != 1 || len(result.Approvals) != 1 || len(result.Skipped) != 1 {
		t.Fatalf("result: %+v", result)
	}
	if result.Skipped[0].IdentityID != "vpnuser_dave" {
		t.Fatalf("skipped: %+v", result.Skipped)
	}
	carol, _ := f.srv.getVpnUser("vpnuser_carol")
	if carol.Credentials[0].UUID == idlOwnerUUID || carol.Credentials[0].UUID == "" {
		t.Fatal("carol's exposed credential was not rotated")
	}
	if dave, _ := f.srv.getVpnUser("vpnuser_dave"); dave.Credentials[0].Password != idlOwnerPass {
		t.Fatal("dave has no plannable line, so his credential must stay until one exists")
	}
	approvals := f.srv.store.ApprovalsByID(result.Approvals)
	if len(approvals) != 1 {
		t.Fatalf("approvals: %+v", approvals)
	}
	var plan lineUserPlan
	if err := json.Unmarshal([]byte(approvals[0].Plan), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Batch != result.Batch || plan.Op != lineUserOpUpdate || plan.UserID != "vpnuser_carol" || plan.LineHashID != f.vless.LineHashID ||
		!strings.HasPrefix(plan.Summary, result.Batch+": ") || approvals[0].Status != model.ApprovalPending {
		t.Fatalf("filed plan: %+v status %s", plan, approvals[0].Status)
	}

	after, _ := cutoverPreview(t, f.srv)
	if len(after.Rotations) != 1 || after.Rotations[0].IdentityID != "vpnuser_dave" {
		t.Fatalf("after rotate only dave stays exposed: %+v", after.Rotations)
	}
	if len(after.Batches) != 1 || after.Batches[0].Batch != result.Batch || after.Batches[0].Counts[model.ApprovalPending] != 1 ||
		strings.Join(after.Batches[0].Pending, ",") != result.Approvals[0] {
		t.Fatalf("batches: %+v", after.Batches)
	}
	if after.Digest == view.Digest {
		t.Fatal("the digest must move once the plan changed")
	}
	if code, _ := cutoverCall(t, f.srv, planner, http.MethodPost, "/api/vpn/cutover/rotate", map[string]string{"digest": view.Digest}); code != http.StatusConflict {
		t.Fatalf("replaying the first digest: %d", code)
	}
}

// Rotate calls carrying one digest at once (a double click, an agent retry)
// rotate once and file one batch; every other call is refused because the
// plan moved under it.
func TestCutoverRotateRunsOnceForOneDigest(t *testing.T) {
	f := newCutoverFixture(t)
	view, _ := cutoverPreview(t, f.srv)
	planner := cutoverPrincipal("vpncore:admin", "network:plan", "proxy:admin")
	const calls = 8
	start := make(chan struct{})
	errs := make([]error, calls)
	results := make([]cutoverRotateResult, calls)
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], _, errs[i] = f.srv.runVpnCutoverRotate(planner, view.Digest)
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for i, err := range errs {
		switch {
		case err == nil:
			ok++
			if len(results[i].Approvals) != 1 {
				t.Fatalf("the one rotate files carol's pair: %+v", results[i])
			}
		case err != errCutoverPlanChanged:
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if ok != 1 {
		t.Fatalf("one digest must rotate once, %d calls rotated", ok)
	}
	after, _ := cutoverPreview(t, f.srv)
	if len(after.Batches) != 1 || after.Batches[0].Approvals != 1 {
		t.Fatalf("one batch with one approval, got %+v", after.Batches)
	}
}

// A batch pair whose approval is rejected stays listed with the fix it
// needs, because its rotated credential no longer matches the export and
// would otherwise vanish from the preview while the old one still works on
// the node. It leaves the list once the node holds the current credential.
func TestCutoverBatchKeepsUnappliedPairsVisible(t *testing.T) {
	f := newCutoverFixture(t)
	view, _ := cutoverPreview(t, f.srv)
	planner := cutoverPrincipal("vpncore:admin", "network:plan", "proxy:admin")
	result, _, err := f.srv.runVpnCutoverRotate(planner, view.Digest)
	if err != nil || len(result.Approvals) != 1 {
		t.Fatalf("rotate: %+v %v", result, err)
	}
	approvalID := result.Approvals[0]
	unapplied := func() ([]cutoverUnappliedPair, []string) {
		t.Helper()
		v, raw := cutoverPreview(t, f.srv)
		if strings.Contains(raw, idlOwnerUUID) {
			t.Fatal("the preview carries a credential")
		}
		if len(v.Batches) != 1 {
			t.Fatalf("batches: %+v", v.Batches)
		}
		return v.Batches[0].Unapplied, v.Remaining
	}

	pairs, remaining := unapplied()
	if len(pairs) != 1 || pairs[0].ApprovalID != approvalID || pairs[0].IdentityID != "vpnuser_carol" || pairs[0].LineHashID != f.vless.LineHashID ||
		pairs[0].Fix != cutoverFixApprove || pairs[0].Stale {
		t.Fatalf("a filed pair waits for its approval: %+v", pairs)
	}
	if !strings.Contains(strings.Join(remaining, "\n"), "waiting for their approval") {
		t.Fatalf("remaining must say a pair waits: %q", remaining)
	}

	if _, _, err := f.srv.store.MutateApproval(approvalID, func(a *model.Approval) bool {
		a.Status = model.ApprovalRejected
		return true
	}); err != nil {
		t.Fatal(err)
	}
	pairs, remaining = unapplied()
	if len(pairs) != 1 || pairs[0].Status != model.ApprovalRejected || pairs[0].Fix != cutoverFixPlanUpdate {
		t.Fatalf("a rejected pair needs a new plan_update: %+v", pairs)
	}
	if !strings.Contains(strings.Join(remaining, "\n"), "file a new plan_update") {
		t.Fatalf("remaining must name the rejected pair: %q", remaining)
	}

	// A pending plan overtaken by another rotation cannot apply either.
	if _, _, err := f.srv.store.MutateApproval(approvalID, func(a *model.Approval) bool {
		a.Status = model.ApprovalPending
		return true
	}); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]string{"user_id": "vpnuser_carol", "protocol": "vless"})
	if _, err := f.srv.vpnUserRotateCredential(planner, request); err != nil {
		t.Fatal(err)
	}
	if pairs, _ = unapplied(); len(pairs) != 1 || !pairs[0].Stale || pairs[0].Fix != cutoverFixPlanUpdate {
		t.Fatalf("an overtaken plan needs a new plan_update: %+v", pairs)
	}

	// Once the node holds the current credential, nothing is left to do.
	carol, _ := f.srv.getVpnUser("vpnuser_carol")
	carol.Bindings = []LineBinding{f.applied(t, carol, f.vless)}
	if err := f.srv.putVpnUser(carol); err != nil {
		t.Fatal(err)
	}
	if pairs, remaining = unapplied(); len(pairs) != 0 || strings.Contains(strings.Join(remaining, "\n"), "cutover batch") {
		t.Fatalf("an applied pair leaves the list: %+v %q", pairs, remaining)
	}
}

func TestRetiringTheSubStoreAutoSyncStopsIt(t *testing.T) {
	srv := newSubStoreSyncTestServer(t)
	srv.pluginRuntime = plugin.NewRuntimeManagerWithOptions(plugin.RuntimeManagerOptions{})
	seedSubStoreSecrets(t, srv, "https://sub.example.com", "1")
	if err := srv.store.UpsertPluginInstallation(model.PluginInstallation{ID: subStorePluginID, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv.subStoreSync.invoke = func(context.Context, string, string, string, json.RawMessage, []string) ([]byte, error) {
		calls.Add(1)
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := srv.runSubStoreAutoSync(); err != nil || calls.Load() != 1 {
		t.Fatalf("before retirement the sync runs: calls=%d err=%v", calls.Load(), err)
	}

	admin := cutoverPrincipal("vpncore:admin", "substore:admin")
	if code, _ := cutoverCall(t, srv, cutoverPrincipal("vpncore:admin"), http.MethodPost, "/api/vpn/cutover/retire-autosync", map[string]bool{"confirm": true}); code != http.StatusForbidden {
		t.Fatalf("retire without substore:admin: %d", code)
	}
	if code, _ := cutoverCall(t, srv, admin, http.MethodPost, "/api/vpn/cutover/retire-autosync", map[string]bool{"confirm": false}); code != http.StatusBadRequest {
		t.Fatalf("retire without confirm: %d", code)
	}
	code, raw := cutoverCall(t, srv, admin, http.MethodPost, "/api/vpn/cutover/retire-autosync", map[string]bool{"confirm": true})
	var state cutoverAutoSyncView
	if code != http.StatusOK || json.Unmarshal(raw, &state) != nil || !state.Retired || state.RetiredAt == nil || !state.Configured || !state.Enabled {
		t.Fatalf("retire: %d %s", code, raw)
	}
	first := *state.RetiredAt

	if err := srv.runSubStoreAutoSync(); err != nil || calls.Load() != 1 {
		t.Fatalf("a retired sync must not invoke the plugin: calls=%d err=%v", calls.Load(), err)
	}
	statusRaw, _ := srv.pluginSecretValue(subStorePluginID, "autosync_status")
	var status subStoreAutoSyncStatus
	if json.Unmarshal([]byte(statusRaw), &status) != nil || status.State != "retired" || status.Error != subStoreAutoSyncRetiredReason || status.LastSuccessAt == "" {
		t.Fatalf("retired status: %s", statusRaw)
	}
	_, raw = cutoverCall(t, srv, admin, http.MethodPost, "/api/vpn/cutover/retire-autosync", map[string]bool{"confirm": true})
	if json.Unmarshal(raw, &state) != nil || state.RetiredAt == nil || !state.RetiredAt.Equal(first) {
		t.Fatalf("a second retire must keep the first time: %s", raw)
	}
	retires := 0
	for _, ev := range srv.store.AuditEvents() {
		if ev.Action == auditActionAutoSyncRetired {
			retires++
		}
	}
	if retires != 1 {
		t.Fatalf("retire audits = %d, want 1", retires)
	}
}
