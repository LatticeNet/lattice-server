package server

import (
	"context"
	"encoding/json"
	"errors"
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
	manifest, sourceVersion, err := model.CanonicalSubscriptionSourceManifest(model.SubscriptionSourceManifestV1{
		Schema: model.SubscriptionSourceManifestSchemaV1, Renderer: model.SubscriptionSourceRendererV1,
		Identity: model.SubscriptionSourceManifestIdentity{ID: "identity", Generation: 1}, EntryRoots: []string{"11111111-1111-4111-8111-111111111111"},
		Entries: []model.SubscriptionSourceManifestEntry{{Root: "11111111-1111-4111-8111-111111111111",
			Endpoint: model.SubscriptionSourceManifestEndpoint{LineUUID: "11111111-1111-4111-8111-111111111111", NodeID: "node", Label: "entry", Host: "entry.example.com", Port: 443, SNI: "entry.example.com", Fingerprint: "chrome", ALPN: []string{}, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "0123456789abcdef", Flow: "xtls-rprx-vision"},
			Path:     []model.SubscriptionSourceManifestEdge{}, Terminal: model.SubscriptionSourceManifestTerminal{LineUUID: "11111111-1111-4111-8111-111111111111", Generation: 1, ObservationRevision: 1, Status: "converged"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{
		PluginID: "p", SubscriptionID: "s1", Raw: "vless://kept", Userinfo: "upload=1", FetchedAt: stale,
		SourceVersion: sourceVersion, SourceManifest: json.RawMessage(manifest),
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
	if got.SourceVersion != sourceVersion || string(got.SourceManifest) != string(manifest) || !got.FetchedAt.Equal(stale) {
		t.Fatalf("last-good authority changed: %+v", got)
	}
	if !got.Stale {
		t.Fatal("preserved last-good snapshot was not marked stale")
	}

	stored, ok := st.SubscriptionSnapshot("p", "s1")
	if !ok {
		t.Fatal("snapshot disappeared")
	}
	if stored.FetchError == "" || !stored.Stale {
		t.Fatal("the failure was not recorded on the snapshot; the operator would never learn it is stale")
	}
	if stored.Raw != "vless://kept" {
		t.Fatalf("a failed refresh overwrote the content: %q", stored.Raw)
	}
	for _, event := range st.AuditEvents() {
		if event.Action != auditActionSubscriptionFetch {
			continue
		}
		if event.Metadata["stale"] != "true" || event.Metadata["source_version"] != sourceVersion || event.Metadata["snapshot_age_seconds"] == "" {
			t.Fatalf("stale audit metadata = %+v", event.Metadata)
		}
		if _, leaked := event.Metadata["fetch_error"]; leaked || strings.Contains(event.Reason, stored.FetchError) {
			t.Fatalf("diagnostic leaked into audit: %+v", event)
		}
	}
}

func TestSnapshotForFailsLoudlyWhenStaleTransitionCannotPersist(t *testing.T) {
	s, st := newShareTestServer(t)
	base := model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s1", Raw: "last-good", FetchedAt: s.now().Add(-time.Hour)}
	if err := st.UpsertSubscriptionSnapshot(base); err != nil {
		t.Fatal(err)
	}
	s.subscriptionSnapshotPersist = func(model.SubscriptionSnapshot) error { return errors.New("persist denied") }
	if got, err := s.snapshotFor(context.Background(), "p", "s1", true); err == nil || got.Raw != "" {
		t.Fatalf("failed persistence looked successful: got=%+v err=%v", got, err)
	}
	stored, _ := st.SubscriptionSnapshot("p", "s1")
	if stored.Stale || stored.FetchError != "" || stored.Raw != "last-good" {
		t.Fatalf("failed transition published state: %+v", stored)
	}
}

func TestSubscriptionSnapshotVersionUsesGraphAuthorityAndLegacyContent(t *testing.T) {
	graphA := model.SubscriptionSnapshot{Raw: "first", SourceVersion: "sv1:same"}
	graphB := model.SubscriptionSnapshot{Raw: "changed", SourceVersion: "sv1:same"}
	if subscriptionSnapshotVersion(graphA) != subscriptionSnapshotVersion(graphB) {
		t.Fatal("same graph source version did not remain the revalidation authority")
	}
	if subscriptionSnapshotVersion(model.SubscriptionSnapshot{Raw: "first"}) == subscriptionSnapshotVersion(model.SubscriptionSnapshot{Raw: "changed"}) {
		t.Fatal("legacy content changes did not change the revalidation key")
	}
}

func TestSnapshotForRetriesRecentStaleAndClearsOnRecovery(t *testing.T) {
	s, st := newShareTestServer(t)
	now := s.now()
	if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: "s1", Raw: "last-good", FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{}, errors.New("temporary outage")
	}
	failed, err := s.snapshotFor(context.Background(), "p", "s1", true)
	if err != nil || !failed.Stale {
		t.Fatalf("forced failure = %+v err=%v", failed, err)
	}
	calls := 0
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		calls++
		return model.SubscriptionSnapshot{Raw: "recovered"}, nil
	}
	recovered, err := s.snapshotFor(context.Background(), "p", "s1", false)
	if err != nil || recovered.Stale || recovered.Raw != "recovered" || calls != 1 {
		t.Fatalf("recovery = %+v calls=%d err=%v", recovered, calls, err)
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
