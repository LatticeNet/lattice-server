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

// dependsEnv is plugin "p" with shared records whose provider content the
// test sets, each body cached by one fetch, on a clock the test moves.
type dependsEnv struct {
	s        *Server
	mu       sync.Mutex
	contents map[string]string
	fetches  map[string]*atomic.Int64
	paths    map[string]string
	clock    atomic.Int64
}

// dependsFixture shares "fleet-rec" and "provider-rec" with the given
// contents and warms both bodies.
func dependsFixture(t *testing.T, contents map[string]string) *dependsEnv {
	t.Helper()
	s, _ := newShareTestServer(t)
	e := &dependsEnv{s: s, contents: map[string]string{}, fetches: map[string]*atomic.Int64{}, paths: map[string]string{}}
	e.clock.Store(time.Unix(1_700_000_000, 0).UTC().UnixNano())
	s.now = func() time.Time { return time.Unix(0, e.clock.Load()).UTC() }
	s.subscriptionFetch = func(_ context.Context, _ string, record string) (model.SubscriptionSnapshot, error) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.fetches[record].Add(1)
		return model.SubscriptionSnapshot{Raw: e.contents[record]}, nil
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		return renderedSubscription{Body: []byte("render of " + snap.Raw), RevalidationVersion: subscriptionRevalidationVersion(snap),
			SourceEpoch: epoch, FetchedAt: snap.FetchedAt}, nil
	}
	e.add(t, "fleet-rec", contents["fleet-rec"])
	e.add(t, "provider-rec", contents["provider-rec"])
	return e
}

// add shares one more record of plugin "p" and warms its body.
func (e *dependsEnv) add(t *testing.T, record, content string) {
	t.Helper()
	e.mu.Lock()
	token := strings.Repeat(string(rune('a'+len(e.paths))), 32)
	slug := strings.TrimSuffix(record, "-rec")
	e.contents[record] = content
	e.fetches[record] = &atomic.Int64{}
	e.paths[record] = "/sub/" + slug + "/" + token
	e.mu.Unlock()
	mustUpsertShare(t, e.s.store, model.SubscriptionShare{ID: "s-" + record, Slug: slug, Token: token, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "p", SubscriptionID: record}})
	if err := e.s.store.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: "p", SubscriptionID: record, Raw: content, FetchedAt: e.s.now()}); err != nil {
		t.Fatal(err)
	}
	if got := e.fetch(t, record); got != "render of "+content {
		t.Fatalf("warm %s: %q", record, got)
	}
}

func (e *dependsEnv) set(record, content string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.contents[record] = content
}

func (e *dependsEnv) fetch(t *testing.T, record string) string {
	t.Helper()
	e.mu.Lock()
	path := e.paths[record]
	e.mu.Unlock()
	return fleetFetch(t, e.s, path).Body.String()
}

func (e *dependsEnv) count(record string) int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fetches[record].Load()
}

// advance commits a vpn-core write after the pacing interval, so the
// generation advances at once.
func (e *dependsEnv) advance() {
	e.clock.Add(int64(vpnCoreLinkChangeInterval + time.Second))
	e.s.triggerVPNCoreMutation()
}

func (e *dependsEnv) wait() { e.s.substoreCatalogue.deps.wg.Wait() }

func dependsAnswer(records ...string) []byte {
	var b strings.Builder
	b.WriteString(`{"records":[`)
	for i, record := range records {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":"` + record + `","revision":"r1"}`)
	}
	b.WriteString(`],"version":"idx-1"}`)
	return []byte(b.String())
}

// A fleet write used to expire every plugin share body, because the core
// could not tell which records read the fleet. A plugin that answers
// depends_on names them. The first advance after a start has no answer to go
// by and expires everything; from then on only the named records' bodies
// expire: the dependent record refreshes and serves the change, the
// independent one keeps its body, is not fetched, and is not left due.
func TestAFleetWriteExpiresOnlyTheDependentRecordsBodies(t *testing.T) {
	e := dependsFixture(t, map[string]string{"fleet-rec": "fleet nodes", "provider-rec": "provider nodes"})
	var asked atomic.Int64
	e.s.substoreCatalogue.deps.call = func(_ context.Context, pluginID string) ([]byte, error) {
		asked.Add(1)
		if pluginID != "p" {
			t.Errorf("depends_on asked of %q", pluginID)
		}
		return dependsAnswer("fleet-rec"), nil
	}

	e.advance()
	e.wait()
	for _, record := range []string{"fleet-rec", "provider-rec"} {
		e.fetch(t, record)
		if e.count(record) != 1 {
			t.Fatalf("the first advance must expire %s too; fetched %d times", record, e.count(record))
		}
	}

	e.set("fleet-rec", "fleet nodes after the write")
	e.set("provider-rec", "provider nodes the fleet write did not move")
	e.advance()
	e.wait()
	if got := e.fetch(t, "fleet-rec"); got != "render of fleet nodes after the write" || e.count("fleet-rec") != 2 {
		t.Fatalf("the dependent record served %q after %d fetches", got, e.count("fleet-rec"))
	}
	if got := e.fetch(t, "provider-rec"); got != "render of provider nodes" || e.count("provider-rec") != 1 {
		t.Fatalf("the independent record served %q after %d fetches; its body must not expire", got, e.count("provider-rec"))
	}
	publication := e.s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: "p", subscriptionID: "provider-rec"})
	publication.mu.Lock()
	gen := publication.vpnGen
	publication.mu.Unlock()
	if gen != e.s.vpnCoreGen.Load() || asked.Load() != 2 {
		t.Fatalf("independent source at generation %d of %d, depends_on asked %d times", gen, e.s.vpnCoreGen.Load(), asked.Load())
	}
}

// A write that revokes access must reach the bodies that carry it without
// waiting for the plugin: while the ask is still out, the record the last
// answer named and a record no answer has judged yet already serve fresh
// content, and only the record judged independent keeps its body.
func TestAFleetWriteExpiresANamedRecordBeforeThePluginAnswers(t *testing.T) {
	e := dependsFixture(t, map[string]string{"fleet-rec": "fleet nodes", "provider-rec": "provider nodes"})
	e.s.substoreCatalogue.deps.call = func(context.Context, string) ([]byte, error) { return dependsAnswer("fleet-rec"), nil }
	e.advance()
	e.wait()
	e.fetch(t, "fleet-rec")
	e.fetch(t, "provider-rec")
	e.add(t, "late-rec", "a record shared after the answer")

	release := make(chan struct{})
	e.s.substoreCatalogue.deps.call = func(ctx context.Context, _ string) ([]byte, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return dependsAnswer("fleet-rec"), nil
	}
	e.set("fleet-rec", "fleet nodes without the revoked identity")
	e.set("late-rec", "late content after the write")
	e.advance()
	if got := e.fetch(t, "fleet-rec"); got != "render of fleet nodes without the revoked identity" {
		t.Fatalf("while depends_on is pending the named record served %q", got)
	}
	if got := e.fetch(t, "late-rec"); got != "render of late content after the write" {
		t.Fatalf("while depends_on is pending a record no answer judged served %q", got)
	}
	if got := e.fetch(t, "provider-rec"); got != "render of provider nodes" || e.count("provider-rec") != 1 {
		t.Fatalf("the independent record served %q after %d fetches", got, e.count("provider-rec"))
	}
	close(release)
	e.wait()
}

// A plugin bug that answers an empty list must not release a record an
// earlier answer named: the record stays dependent while it has a share.
func TestAnEmptyDependsOnAnswerDoesNotReleaseANamedRecord(t *testing.T) {
	e := dependsFixture(t, map[string]string{"fleet-rec": "fleet nodes", "provider-rec": "provider nodes"})
	var empty atomic.Bool
	e.s.substoreCatalogue.deps.call = func(context.Context, string) ([]byte, error) {
		if empty.Load() {
			return []byte(`{"records":[]}`), nil
		}
		return dependsAnswer("fleet-rec"), nil
	}
	e.advance()
	e.wait()
	e.fetch(t, "fleet-rec")
	e.fetch(t, "provider-rec")

	empty.Store(true)
	e.advance()
	e.wait()
	// Unchanged content: the refresh publishes nothing, so the record's
	// epoch is the one the empty answer was given at.
	e.fetch(t, "fleet-rec")
	e.advance()
	e.wait()
	e.set("fleet-rec", "fleet nodes after the third write")
	if got := e.fetch(t, "fleet-rec"); got != "render of fleet nodes after the third write" {
		t.Fatalf("after two empty answers the named record served %q", got)
	}
	if got := e.fetch(t, "provider-rec"); got != "render of provider nodes" {
		t.Fatalf("the independent record served %q", got)
	}
}

// A record whose content moved since it was judged may have gained a fleet
// source: an operator edit moves every record's epoch, and the next write
// expires the record before the plugin answers.
func TestARecordWhoseContentMovedIsJudgedAgain(t *testing.T) {
	e := dependsFixture(t, map[string]string{"fleet-rec": "fleet nodes", "provider-rec": "provider nodes"})
	e.s.substoreCatalogue.deps.call = func(context.Context, string) ([]byte, error) { return dependsAnswer("fleet-rec"), nil }
	e.advance()
	e.wait()
	e.fetch(t, "provider-rec")

	e.s.invalidateSharesForPlugin("p")
	e.fetch(t, "provider-rec")
	before := e.count("provider-rec")
	release := make(chan struct{})
	e.s.substoreCatalogue.deps.call = func(ctx context.Context, _ string) ([]byte, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return dependsAnswer("fleet-rec"), nil
	}
	e.set("provider-rec", "provider nodes after the edit")
	e.advance()
	if got := e.fetch(t, "provider-rec"); got != "render of provider nodes after the edit" || e.count("provider-rec") != before+1 {
		t.Fatalf("an edited record kept its body through a fleet write: %q after %d fetches", got, e.count("provider-rec"))
	}
	close(release)
	e.wait()
}

// Unknown is dependent: a plugin whose depends_on fails or answers something
// malformed has every share expired, exactly as before the method existed,
// including the shares its last answer let it keep, and its independent
// judgments are dropped.
func TestAFailedDependsOnExpiresEveryShareOfThePlugin(t *testing.T) {
	for name, answer := range map[string]func() ([]byte, error){
		"error":      func() ([]byte, error) { return nil, errors.New("worker crashed") },
		"no records": func() ([]byte, error) { return []byte(`{"version":"x"}`), nil },
		"bad id":     func() ([]byte, error) { return []byte(`{"records":[{"id":""}]}`), nil },
		"not json":   func() ([]byte, error) { return []byte(`records`), nil },
	} {
		t.Run(name, func(t *testing.T) {
			e := dependsFixture(t, map[string]string{"fleet-rec": "fleet nodes", "provider-rec": "provider nodes"})
			var failing atomic.Bool
			e.s.substoreCatalogue.deps.call = func(context.Context, string) ([]byte, error) {
				if failing.Load() {
					return answer()
				}
				return dependsAnswer("fleet-rec"), nil
			}
			e.advance()
			e.wait()
			e.fetch(t, "fleet-rec")
			e.fetch(t, "provider-rec")
			if len(e.s.substoreCatalogue.deps.independentOf("p")) != 1 {
				t.Fatal("the good answer left no independent record; the fixture tests nothing")
			}

			failing.Store(true)
			e.advance()
			e.wait()
			for _, record := range []string{"fleet-rec", "provider-rec"} {
				before := e.count(record)
				e.fetch(t, record)
				if e.count(record) != before+1 {
					t.Fatalf("%s was not refreshed after a fleet write with an unusable answer", record)
				}
			}
			if got := e.s.substoreCatalogue.deps.independentOf("p"); len(got) != 0 {
				t.Fatalf("an unusable answer left independent judgments standing: %v", got)
			}
		})
	}
}

// The asks are bound to the server's lifetime: Close cancels one in flight
// and waits for it, and a write after Close asks nothing and expires every
// share.
func TestCloseCancelsAPendingDependsOn(t *testing.T) {
	e := dependsFixture(t, map[string]string{"fleet-rec": "fleet nodes", "provider-rec": "provider nodes"})
	started := make(chan struct{})
	var asked atomic.Int64
	var cancelled atomic.Bool
	e.s.substoreCatalogue.deps.call = func(ctx context.Context, _ string) ([]byte, error) {
		if asked.Add(1) == 1 {
			close(started)
		}
		<-ctx.Done()
		cancelled.Store(true)
		return nil, ctx.Err()
	}
	e.advance()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	begun := time.Now()
	if err := e.s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !cancelled.Load() || time.Since(begun) > fleetDependsTimeout/2 {
		t.Fatalf("Close returned after %s without cancelling the pending ask", time.Since(begun))
	}
	if _, ok := e.s.substoreCatalogue.deps.begin(); ok {
		t.Fatal("an ask began after Close")
	}
	e.advance()
	if asked.Load() != 1 {
		t.Fatalf("depends_on asked %d times; none may start after Close", asked.Load())
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
