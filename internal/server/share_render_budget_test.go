package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// budgetVariants lists distinct explicit variants in a stable order.
func budgetVariants() []string {
	targets := make([]string, 0, len(subscriptionShareTargets))
	for target := range subscriptionShareTargets {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	var variants []string
	for _, target := range targets {
		for _, flags := range []string{"", "&includeUnsupportedProxy=1", "&prettyYaml=1", "&includeUnsupportedProxy=1&prettyYaml=1"} {
			variants = append(variants, "?target="+target+flags)
		}
	}
	return variants
}

func budgetFetch(s *Server, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
	return rec
}

// A failed render used to spend budget like a successful one. Failures are
// now refunded, but only from a small allowance: a variant that fails for
// this record fails every time, so refunding all of them would let one token
// holder run plugin renders without bound.
func TestAFailedRenderIsRefundedOnlyWithinTheAllowance(t *testing.T) {
	s, st, path := flightShareServer(t)
	var renders atomic.Int64
	s.subscriptionRender = func(context.Context, model.SubscriptionShare, string, string, shareRenderVariant, model.SubscriptionSnapshot) (renderedSubscription, error) {
		renders.Add(1)
		return renderedSubscription{}, errors.New("plugin threw")
	}
	attempts := shareRenderRefundBurst + shareRenderBudgetBurst
	for i := 0; i < attempts; i++ {
		if rec := budgetFetch(s, path+"?target=QX"); rec.Code != http.StatusNotFound {
			t.Fatalf("failing render %d answered %d, want the decoy", i, rec.Code)
		}
	}
	if renders.Load() != int64(attempts) {
		t.Fatalf("renders = %d, want %d (the allowance refunded, then the budget charged)", renders.Load(), attempts)
	}
	for i := 0; i < 3; i++ {
		budgetFetch(s, path+"?target=QX")
	}
	if renders.Load() != int64(attempts) {
		t.Fatalf("renders = %d once the budget and the allowance were spent", renders.Load())
	}

	// The operator can see the link locked itself out, in the share view and
	// in one audit event for the hour however many refusals followed.
	share, _ := st.SubscriptionShare("s1")
	view := s.shareViewFor(share).RenderBudget
	if view == nil || !view.Exhausted || view.Remaining != 0 || view.Refused != 3 || view.LastRefusedAt == nil ||
		view.Burst != shareRenderBudgetBurst || view.PerHour != shareRenderBudgetPerHour {
		t.Fatalf("share view budget = %+v", view)
	}
	s.shareRefusalAudits.Wait()
	announced := 0
	for _, ev := range st.AuditEvents() {
		if ev.Reason == shareRenderBudgetExhaustedReason && ev.Metadata["share_id"] == "s1" && ev.Decision == "deny" {
			announced++
		}
	}
	if announced != 1 {
		t.Fatalf("exhaustion events = %d, want one for the hour", announced)
	}

	// Rotating the token is the answer to a burned budget: the link renders
	// again at once.
	rec := httptest.NewRecorder()
	s.rotateSubscriptionShare(rec, share, principal{})
	var rotated shareView
	if err := json.Unmarshal(rec.Body.Bytes(), &rotated); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("rotate = %d %v", rec.Code, err)
	}
	if rotated.RenderBudget != nil {
		t.Fatalf("rotation kept the burned budget: %+v", rotated.RenderBudget)
	}
	before := renders.Load()
	budgetFetch(s, "/sub/team/"+rotated.Token+"?target=QX")
	if renders.Load() != before+1 {
		t.Fatal("the rotated link could not render")
	}
}

// Anyone holding a link can spend its budget on variant churn. When the
// content moves, the clients already on the link still get it: a variant the
// link rendered before re-renders for free once per content version, while
// new variants and repeat renders of one version stay charged.
func TestKnownVariantsGetMovedContentWhateverTheBudgetHolds(t *testing.T) {
	s, _, path := flightShareServer(t)
	content, failQX := "nodes", false
	var renders atomic.Int64
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: content}, nil
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, variant shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		renders.Add(1)
		if failQX && variant.Target == "QX" {
			return renderedSubscription{}, errors.New("plugin threw")
		}
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte(variant.Target + " " + snap.Raw), RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	clients := []string{"?target=Surge", "?target=ClashMeta", "?target=QX"}
	for _, c := range clients {
		if rec := budgetFetch(s, path+c); rec.Code != http.StatusOK {
			t.Fatalf("client %s answered %d", c, rec.Code)
		}
	}
	variants := budgetVariants()
	fresh := path + variants[len(variants)-1] // never rendered below
	churn := 0
	for _, v := range variants {
		if churn == shareRenderBudgetBurst-len(clients) {
			break
		}
		if v == clients[0] || v == clients[1] || v == clients[2] {
			continue
		}
		if rec := budgetFetch(s, path+v); rec.Code != http.StatusOK {
			t.Fatalf("churn variant %s answered %d inside the budget", v, rec.Code)
		}
		churn++
	}
	if rec := budgetFetch(s, fresh); rec.Code != http.StatusNotFound {
		t.Fatalf("a new variant past the budget answered %d", rec.Code)
	}

	content = "nodes without the suspended identity"
	failQX = true
	s.triggerVPNCoreMutation()
	for _, c := range clients[:2] {
		rec := budgetFetch(s, path+c)
		if rec.Code != http.StatusOK || rec.Body.String() != c[len("?target="):]+" "+content {
			t.Fatalf("known client %s after the move answered %d %q", c, rec.Code, rec.Body.String())
		}
	}
	if rec := budgetFetch(s, fresh); rec.Code != http.StatusNotFound {
		t.Fatalf("a new variant rode the free re-render: %d", rec.Code)
	}

	// A free render that fails settles the version, so retrying it is charged
	// and the empty budget refuses it without a render.
	before := renders.Load()
	if rec := budgetFetch(s, path+"?target=QX"); rec.Code != http.StatusNotFound || renders.Load() != before+1 {
		t.Fatalf("the failing free render answered %d after %d renders", rec.Code, renders.Load()-before)
	}
	if rec := budgetFetch(s, path+"?target=QX"); rec.Code != http.StatusNotFound || renders.Load() != before+1 {
		t.Fatalf("a failed free render was retried for free: %d after %d renders", rec.Code, renders.Load()-before)
	}

	// The same variant at the same version, after its body was dropped, is a
	// repeat render and is charged.
	s.subscriptionCache.InvalidateShare("s1")
	before = renders.Load()
	if rec := budgetFetch(s, path+clients[0]); rec.Code != http.StatusNotFound || renders.Load() != before {
		t.Fatalf("a repeat render of one version was free: %d after %d renders", rec.Code, renders.Load()-before)
	}
}
