package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// dependsFixture is plugin "p" with two shared records, "fleet-rec" and
// "provider-rec", whose provider content the test sets, and whose bodies are
// cached by one fetch each. It returns the per-record provider fetch counts
// and the paths of the two shares.
func dependsFixture(t *testing.T, contents map[string]string) (*Server, map[string]*atomic.Int64, map[string]string) {
	t.Helper()
	s, st := newShareTestServer(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { return now }
	fetches := map[string]*atomic.Int64{}
	paths := map[string]string{}
	var mu sync.Mutex
	for i, record := range []string{"fleet-rec", "provider-rec"} {
		token := strings.Repeat(string(rune('a'+i)), 32)
		slug := strings.TrimSuffix(record, "-rec")
		mustUpsertShare(t, st, model.SubscriptionShare{ID: "s-" + record, Slug: slug, Token: token, Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: record}})
		if err := st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: record, Raw: contents[record], FetchedAt: now}); err != nil {
			t.Fatal(err)
		}
		fetches[record] = &atomic.Int64{}
		paths[record] = "/sub/" + slug + "/" + token
	}
	s.subscriptionFetch = func(_ context.Context, _ string, record string) (model.SubscriptionSnapshot, error) {
		fetches[record].Add(1)
		mu.Lock()
		defer mu.Unlock()
		return model.SubscriptionSnapshot{Raw: contents[record]}, nil
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("render of " + snap.Raw), RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	for record, path := range paths {
		if got := fleetFetch(t, s, path).Body.String(); got != "render of "+contents[record] {
			t.Fatalf("warm %s: %q", record, got)
		}
	}
	return s, fetches, paths
}

// A fleet write used to expire every plugin share body, because the core
// could not tell which records read the fleet. A plugin that answers
// depends_on names them, and only those records' bodies expire: the
// dependent record refreshes and serves the change, the independent one
// keeps its body, is not fetched, and is not left due.
func TestAFleetWriteExpiresOnlyTheDependentRecordsBodies(t *testing.T) {
	contents := map[string]string{"fleet-rec": "fleet nodes", "provider-rec": "provider nodes"}
	s, fetches, paths := dependsFixture(t, contents)
	var asked atomic.Int64
	s.substoreCatalogue.deps.call = func(_ context.Context, pluginID string) ([]byte, error) {
		asked.Add(1)
		if pluginID != "p" {
			t.Errorf("depends_on asked of %q", pluginID)
		}
		return []byte(`{"records":[{"id":"fleet-rec","revision":"r3"}],"version":"idx-1"}`), nil
	}

	contents["fleet-rec"] = "fleet nodes after the write"
	contents["provider-rec"] = "provider nodes the fleet write did not move"
	s.triggerVPNCoreMutation()
	s.substoreCatalogue.deps.wg.Wait()

	if got := fleetFetch(t, s, paths["fleet-rec"]).Body.String(); got != "render of fleet nodes after the write" || fetches["fleet-rec"].Load() != 1 {
		t.Fatalf("the dependent record served %q after %d fetches", got, fetches["fleet-rec"].Load())
	}
	if got := fleetFetch(t, s, paths["provider-rec"]).Body.String(); got != "render of provider nodes" || fetches["provider-rec"].Load() != 0 {
		t.Fatalf("the independent record served %q after %d fetches; its body must not expire", got, fetches["provider-rec"].Load())
	}
	publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: "p", subscriptionID: "provider-rec"})
	publication.mu.Lock()
	gen := publication.vpnGen
	publication.mu.Unlock()
	if gen != s.vpnCoreGen.Load() || asked.Load() != 1 {
		t.Fatalf("independent source at generation %d of %d, depends_on asked %d times", gen, s.vpnCoreGen.Load(), asked.Load())
	}
}

// Unknown is dependent: a plugin whose depends_on fails or answers something
// malformed has every share expired, exactly as before the method existed.
func TestAFailedDependsOnExpiresEveryShareOfThePlugin(t *testing.T) {
	for name, answer := range map[string]func() ([]byte, error){
		"error":      func() ([]byte, error) { return nil, errors.New("worker crashed") },
		"no records": func() ([]byte, error) { return []byte(`{"version":"x"}`), nil },
		"bad id":     func() ([]byte, error) { return []byte(`{"records":[{"id":""}]}`), nil },
		"not json":   func() ([]byte, error) { return []byte(`records`), nil },
	} {
		t.Run(name, func(t *testing.T) {
			contents := map[string]string{"fleet-rec": "fleet nodes", "provider-rec": "provider nodes"}
			s, fetches, paths := dependsFixture(t, contents)
			s.substoreCatalogue.deps.call = func(context.Context, string) ([]byte, error) { return answer() }
			s.triggerVPNCoreMutation()
			s.substoreCatalogue.deps.wg.Wait()
			for record, path := range paths {
				fleetFetch(t, s, path)
				if fetches[record].Load() != 1 {
					t.Fatalf("%s fetched %d times after a fleet write with an unusable answer", record, fetches[record].Load())
				}
			}
		})
	}
}

func TestDecodeFleetDependsReply(t *testing.T) {
	got, err := decodeFleetDependsReply([]byte(`{"records":[{"id":"a","revision":"1"},{"id":"b"},{"id":"a"}],"version":"v","extra":true}`))
	if err != nil || len(got) != 2 || !got["a"] || !got["b"] {
		t.Fatalf("decode = %v, %v", got, err)
	}
	if got, err := decodeFleetDependsReply([]byte(`{"records":[]}`)); err != nil || len(got) != 0 {
		t.Fatalf("an empty list is an answer that nothing depends on: %v %v", got, err)
	}
	for _, bad := range []string{`{}`, `{"records":null}`, `{"records":[{"id":"x\u0000"}]}`, `{"records":[{"id":"` + strings.Repeat("x", 257) + `"}]}`} {
		if _, err := decodeFleetDependsReply([]byte(bad)); err == nil {
			t.Fatalf("decode accepted %s", bad)
		}
	}
}
