package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A provider being unreachable must not take a client's configuration with it.
// The test server has no plugin runtime, so every fetch fails - which is exactly
// the condition this behaviour exists for.
func TestSnapshotForServesTheLastGoodSnapshotWhenRefreshFails(t *testing.T) {
	s, st := newShareTestServer(t)
	stale := s.now().Add(-2 * subscriptionRefreshInterval)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{
		PluginID: "p", SubscriptionID: "s1", Raw: "vless://kept", Userinfo: "upload=1", FetchedAt: stale,
	}); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	got, err := s.snapshotFor(context.Background(), "p", "s1", false)
	if err != nil {
		t.Fatalf("a failed refresh with a usable snapshot must not error: %v", err)
	}
	if got.Raw != "vless://kept" {
		t.Fatalf("raw = %q, want the stored snapshot", got.Raw)
	}
	if got.Userinfo != "upload=1" {
		t.Fatalf("the stored traffic figures were dropped: %q", got.Userinfo)
	}

	stored, ok := st.SubscriptionSnapshot("p", "s1")
	if !ok {
		t.Fatal("snapshot disappeared")
	}
	if stored.FetchError == "" {
		t.Fatal("the failure was not recorded on the snapshot; the operator would never learn it is stale")
	}
	if stored.Raw != "vless://kept" {
		t.Fatalf("a failed refresh overwrote the content: %q", stored.Raw)
	}
}

// With nothing to fall back to there is no honest answer, and returning an error
// is what stops the caller from serving an empty body.
func TestSnapshotForFailsWhenThereIsNothingToFallBackTo(t *testing.T) {
	s, _ := newShareTestServer(t)
	if _, err := s.snapshotFor(context.Background(), "p", "missing", false); err == nil {
		t.Fatal("a failed fetch with no snapshot returned success")
	}
}

// A fresh snapshot is used without attempting a fetch at all, which is what
// makes a client poll cheap.
func TestSnapshotForUsesAFreshSnapshotWithoutFetching(t *testing.T) {
	s, st := newShareTestServer(t)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{
		PluginID: "p", SubscriptionID: "s1", Raw: "vless://fresh", FetchedAt: s.now(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.snapshotFor(context.Background(), "p", "s1", false)
	if err != nil {
		t.Fatalf("fresh snapshot errored: %v", err)
	}
	if got.Raw != "vless://fresh" {
		t.Fatalf("raw = %q", got.Raw)
	}
	stored, _ := st.SubscriptionSnapshot("p", "s1")
	if stored.FetchError != "" {
		t.Fatal("a fresh snapshot triggered a fetch; no attempt should have been made")
	}
}

// force skips the freshness check, which is what a manual refresh needs.
func TestSnapshotForForceAttemptsAFetchEvenWhenFresh(t *testing.T) {
	s, st := newShareTestServer(t)
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{
		PluginID: "p", SubscriptionID: "s1", Raw: "vless://fresh", FetchedAt: s.now(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := s.snapshotFor(context.Background(), "p", "s1", true); err != nil {
		t.Fatalf("forced refresh with a usable snapshot must still serve it: %v", err)
	}
	stored, _ := st.SubscriptionSnapshot("p", "s1")
	if stored.FetchError == "" {
		t.Fatal("force did not attempt a fetch")
	}
}

func TestSnapshotRefreshIntervalIsSane(t *testing.T) {
	// A shorter interval than a client's own poll cadence would mean every poll
	// pays for a provider round trip; much longer and a rotated provider URL takes
	// too long to be noticed.
	if subscriptionRefreshInterval < time.Minute || subscriptionRefreshInterval > 6*time.Hour {
		t.Fatalf("refresh interval %v is outside a defensible range", subscriptionRefreshInterval)
	}
}

func TestFetchErrorTextNamesTheSubscription(t *testing.T) {
	s, _ := newShareTestServer(t)
	_, err := s.snapshotFor(context.Background(), "p", "s1", false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "s1") {
		t.Fatalf("error does not identify the subscription: %v", err)
	}
}
