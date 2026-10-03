package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// fakeNotifySender stands in for the channel clients, which refuse the
// loopback listener a test could offer them. answer decides each send by
// channel and by how many sends that channel has had (1-based).
type fakeNotifySender struct {
	mu     sync.Mutex
	sends  []fakeNotifySend
	counts map[string]int
	answer func(channelID string, n int) error
}

type fakeNotifySend struct {
	channelID   string
	title, body string
}

func installFakeNotifySender(srv *Server, answer func(channelID string, n int) error) *fakeNotifySender {
	f := &fakeNotifySender{counts: map[string]int{}, answer: answer}
	srv.notifySend = func(_ context.Context, c model.NotifyChannel, msg notify.Message) error {
		f.mu.Lock()
		f.counts[c.ID]++
		n := f.counts[c.ID]
		f.sends = append(f.sends, fakeNotifySend{c.ID, msg.Title, msg.Body})
		answer := f.answer
		f.mu.Unlock()
		if answer == nil {
			return nil
		}
		return answer(c.ID, n)
	}
	srv.notifyRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	return f
}

func (f *fakeNotifySender) setAnswer(answer func(channelID string, n int) error) {
	f.mu.Lock()
	f.answer = answer
	f.mu.Unlock()
}

func (f *fakeNotifySender) sentTo(channelID string) []fakeNotifySend {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeNotifySend
	for _, s := range f.sends {
		if s.channelID == channelID {
			out = append(out, s)
		}
	}
	return out
}

func upstream(status int) error {
	return &notify.StatusError{Status: status}
}

// waitOutboxSettled waits until no delivery is owed a send and none is
// running.
func waitOutboxSettled(t *testing.T, srv *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		srv.notifyDeliveries.mu.Lock()
		running := srv.notifyDeliveries.n
		srv.notifyDeliveries.mu.Unlock()
		if running == 0 && len(srv.store.UnsettledNotifyDeliveries()) == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("outbox did not settle: %+v", srv.store.UnsettledNotifyDeliveries())
}

func addNotifyChannel(t *testing.T, st *store.Store, id, name string) {
	t.Helper()
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: id, Name: name, Kind: "bark", Enabled: true, Config: map[string]string{"base_url": "https://bark.example.com", "key": "k-" + id}}); err != nil {
		t.Fatal(err)
	}
}

func deliveriesOf(st *store.Store, f store.NotifyDeliveryFilter) []store.NotifyDelivery {
	return st.NotifyDeliveries(f)
}

// The one function allowed to read a raw send error returns nothing that can
// carry the credential: the Telegram token sits in the URL of every transport
// error, and a 4xx body is text the remote side chose.
func TestRedactSendErrorNeverReturnsTheCredential(t *testing.T) {
	const token = "123456:SECRET-BOT-TOKEN"
	endpoint := "https://api.telegram.org/bot" + token + "/sendMessage"
	cases := []struct {
		name      string
		err       error
		kind      string
		status    int
		transient bool
	}{
		{"dial", &url.Error{Op: "Post", URL: endpoint, Err: errors.New("dial tcp: connection refused")}, notifyKindNetwork, 0, true},
		{"timeout", &url.Error{Op: "Post", URL: endpoint, Err: context.DeadlineExceeded}, notifyKindTimeout, 0, true},
		{"refused 401", fmt.Errorf("telegram: %w", &notify.StatusError{Status: 401}), notifyKindUpstream4xx, 401, false},
		{"bad gateway", &notify.StatusError{Status: 502}, notifyKindUpstream5xx, 502, true},
		{"rate limited", &notify.StatusError{Status: 429}, notifyKindRateLimited, 429, true},
		{"config", notifyConfigError{errors.New("telegram requires config.token " + token)}, notifyKindConfigInvalid, 0, false},
		{"blocked", &url.Error{Op: "Post", URL: endpoint, Err: errors.New("outbound: blocked address 127.0.0.1")}, notifyKindConfigInvalid, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, status, transient := redactSendError(tc.err)
			if kind != tc.kind || status != tc.status || transient != tc.transient {
				t.Fatalf("redactSendError = (%q, %d, %v), want (%q, %d, %v)", kind, status, transient, tc.kind, tc.status, tc.transient)
			}
			for _, out := range []string{kind, notifyFailureSentence(kind, status, 2)} {
				if strings.Contains(out, "SECRET") {
					t.Fatalf("%q carries the token", out)
				}
			}
		})
	}
	if !strings.Contains((&notify.StatusError{Status: 401}).Error(), "401") {
		t.Fatal("the log line lost the status")
	}
}

// A transient failure is retried on the schedule and a later success settles
// the delivery sent, with one receipt per attempt and the channel healthy.
func TestOutboxRetriesTransientFailuresThenSends(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	fake := installFakeNotifySender(srv, func(_ string, n int) error {
		if n <= 2 {
			return upstream(502)
		}
		return nil
	})
	srv.notifyEventTyped(EventNodeOffline, "Node offline: alpha", "alpha went quiet")
	waitOutboxSettled(t, srv)

	rows := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: EventNodeOffline})
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	row := rows[0]
	if row.Outcome != store.NotifyOutcomeSent || len(row.Attempts) != 3 || row.Reason != "" {
		t.Fatalf("delivery = %+v", row)
	}
	if row.Attempts[0].OK || row.Attempts[0].Kind != notifyKindUpstream5xx || row.Attempts[0].Status != 502 || !row.Attempts[2].OK {
		t.Fatalf("receipts = %+v", row.Attempts)
	}
	if got := len(fake.sentTo("nc-a")); got != 3 {
		t.Fatalf("sends = %d, want 3", got)
	}
	h, _ := st.NotifyChannelHealth("nc-a")
	if h.ConsecutiveFailures != 0 || h.LastOKAt.IsZero() || !h.FailingSince.IsZero() {
		t.Fatalf("health after a recovered retry = %+v", h)
	}
}

// A refusal (a wrong key) is not retried, and counts against the channel.
func TestOutboxSettlesAPermanentFailureAtOnce(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	installFakeNotifySender(srv, func(string, int) error { return upstream(401) })
	srv.notifyEventTyped(EventServiceDown, "sing-box down on alpha", "b")
	waitOutboxSettled(t, srv)

	row := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: EventServiceDown})[0]
	if row.Outcome != store.NotifyOutcomeFailed || len(row.Attempts) != 1 || row.Reason != "upstream status 401" {
		t.Fatalf("delivery = %+v", row)
	}
	h, _ := st.NotifyChannelHealth("nc-a")
	if h.ConsecutiveFailures != 1 || h.LastFailureKind != notifyKindUpstream4xx || h.LastStatusCode != 401 {
		t.Fatalf("health = %+v", h)
	}
}

// A transient failure that never clears gives up after one send and three
// retries.
func TestOutboxGivesUpAfterTheRetrySchedule(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	installFakeNotifySender(srv, func(string, int) error { return upstream(502) })
	srv.notifyEventTyped(EventServiceDown, "sing-box down on alpha", "b")
	waitOutboxSettled(t, srv)

	row := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: EventServiceDown})[0]
	if row.Outcome != store.NotifyOutcomeFailed || len(row.Attempts) != 1+len(notifyRetryDelays) {
		t.Fatalf("delivery = %+v", row)
	}
	if row.Reason != "upstream status 502 after 4 attempts" {
		t.Fatalf("reason = %q", row.Reason)
	}
}

// An event no rule routes leaves a no_route row instead of vanishing.
func TestOutboxRecordsAnUnroutedEvent(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	if err := st.UpsertNotifyRule(model.NotifyRule{ID: "r-urgent", Name: "Urgent", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	fake := installFakeNotifySender(srv, nil)
	srv.notifyEventTyped("ssh.login", "SSH login on alpha", "root from 203.0.113.9")
	rows := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: "ssh.login"})
	if len(rows) != 1 || rows[0].Outcome != store.NotifyOutcomeNoRoute || rows[0].Reason != "no enabled rule routes this event type" {
		t.Fatalf("rows = %+v", rows)
	}
	if len(fake.sentTo("nc-a")) != 0 {
		t.Fatal("an unrouted event was sent")
	}
}

// Three failed deliveries in a row raise notify.channel_failing, which goes to
// another channel even though no rule routes it, never to the failing
// channel, and only once an hour. A later success announces the recovery.
func TestFailingChannelIsAnnouncedOnAnotherChannel(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-urgent", "Bark urgent")
	addNotifyChannel(t, st, "nc-info", "Bark info")
	if err := st.UpsertNotifyRule(model.NotifyRule{ID: "r-urgent", Name: "Urgent", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-urgent"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	fake := installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-urgent" {
			return upstream(400)
		}
		return nil
	})
	for i := 0; i < 4; i++ {
		srv.notifyEventTyped(EventNodeOffline, fmt.Sprintf("Node offline: n%d", i), "b")
		waitOutboxSettled(t, srv)
	}
	failing := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: EventNotifyChannelFailing})
	if len(failing) != 1 {
		t.Fatalf("channel_failing deliveries = %+v", failing)
	}
	if failing[0].ChannelID != "nc-info" || failing[0].Outcome != store.NotifyOutcomeSent {
		t.Fatalf("announcement went to %s (%s)", failing[0].ChannelID, failing[0].Outcome)
	}
	if !strings.Contains(failing[0].Title, "Bark urgent") || !strings.Contains(failing[0].Body, "HTTP 400") {
		t.Fatalf("announcement = %q / %q", failing[0].Title, failing[0].Body)
	}
	for _, s := range fake.sentTo("nc-urgent") {
		if strings.Contains(s.title, "failing") {
			t.Fatal("the failing channel was told about itself")
		}
	}
	h, _ := st.NotifyChannelHealth("nc-urgent")
	if h.ConsecutiveFailures != 4 || !h.Announced || notifyChannelHealthState(h, time.Now()) != notifyHealthFailing {
		t.Fatalf("health = %+v", h)
	}

	fake.setAnswer(nil)
	srv.notifyEventTyped(EventNodeOffline, "Node offline: n9", "b")
	waitOutboxSettled(t, srv)
	ok := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: EventNotifyChannelOK, ChannelID: "nc-info"})
	if len(ok) != 1 || ok[0].Outcome != store.NotifyOutcomeSent {
		t.Fatalf("channel_ok deliveries = %+v", ok)
	}
	if h, _ := st.NotifyChannelHealth("nc-urgent"); h.Announced || h.ConsecutiveFailures != 0 {
		t.Fatalf("health after recovery = %+v", h)
	}
}

// A rule's fallback gets the message only when every primary of the rule
// failed it for good.
func TestFallbackChannelGetsTheMessageWhenEveryPrimaryFails(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-b", "Bark second")
	addNotifyChannel(t, st, "nc-fb", "Telegram fallback")
	rule := model.NotifyRule{ID: "r-urgent", Name: "Urgent", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-a"}, Enabled: true}
	if err := st.UpsertNotifyRuleWithOptions(rule, store.NotifyRuleOptions{FallbackChannelID: "nc-fb"}); err != nil {
		t.Fatal(err)
	}
	failA := func(id string, _ int) error {
		if id == "nc-a" {
			return upstream(401)
		}
		return nil
	}
	fake := installFakeNotifySender(srv, failA)
	srv.notifyEventTyped(EventNodeOffline, "Node offline: alpha", "alpha went quiet")
	waitOutboxSettled(t, srv)
	fb := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-fb"})
	if len(fb) != 1 || fb[0].Role != store.NotifyRoleFallback || fb[0].Outcome != store.NotifyOutcomeSent || fb[0].FallbackFor != "Bark urgent" {
		t.Fatalf("fallback = %+v", fb)
	}
	if got := fake.sentTo("nc-fb"); len(got) != 1 || !strings.Contains(got[0].body, "did not deliver it") || got[0].title != "Node offline: alpha" {
		t.Fatalf("fallback message = %+v", got)
	}

	// One primary of two delivering is enough: no fallback.
	rule.ChannelIDs = []string{"nc-a", "nc-b"}
	if err := st.UpsertNotifyRuleWithOptions(rule, store.NotifyRuleOptions{FallbackChannelID: "nc-fb"}); err != nil {
		t.Fatal(err)
	}
	srv.notifyEventTyped(EventNodeOffline, "Node offline: bravo", "b")
	waitOutboxSettled(t, srv)
	if got := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-fb"}); len(got) != 1 {
		t.Fatalf("a delivered message still went to the fallback: %+v", got)
	}

	// A message that got through needs no fallback at all.
	fake.setAnswer(nil)
	srv.notifyEventTyped(EventNodeOffline, "Node offline: charlie", "b")
	waitOutboxSettled(t, srv)
	if got := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-fb"}); len(got) != 1 {
		t.Fatalf("fallback used without a failure: %+v", got)
	}
}

// openNotifyFixture is a server on a state file with the bolt hot store, the
// production layout.
func openNotifyFixture(t *testing.T, dir string) ingestFixture {
	t.Helper()
	f := openIngestFixture(t, dir)
	t.Cleanup(func() { _ = f.st.Close() })
	return f
}

// Boot answers every row a previous process left owed: inside the 15 minute
// horizon it is sent again and says so, outside it settles failed, and a
// stored-channel test is never repeated.
func TestBootRedrivesTheOutboxInsideTheHorizon(t *testing.T) {
	dir := t.TempDir()
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	now := time.Now().UTC()
	planned := func(id string, age time.Duration, role string) store.NotifyDelivery {
		return store.NotifyDelivery{ID: id, EventID: "evt-" + id, EventType: EventNodeOffline, Source: store.NotifySourceServer,
			ChannelID: "nc-a", ChannelName: "Bark urgent", Role: role, Outcome: store.NotifyOutcomePlanned,
			Title: "t-" + id, CreatedAt: now.Add(-age), NextAttemptAt: now.Add(-age)}
	}
	retrying := planned("nd-retry", 30*time.Second, store.NotifyRolePrimary)
	retrying.Attempts = []store.NotifyAttempt{{At: now.Add(-25 * time.Second), Kind: notifyKindUpstream5xx, Status: 502}}
	retrying.NextAttemptAt = now.Add(time.Hour)
	if err := st.RecordNotifyDeliveries([]store.NotifyDelivery{
		planned("nd-fresh", time.Minute, store.NotifyRolePrimary),
		planned("nd-stale", 40*time.Minute, store.NotifyRolePrimary),
		planned("nd-test", time.Minute, store.NotifyRoleTest),
		retrying,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if err := st2.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	// Hold sends until the reconcile has been read back.
	gate := make(chan struct{})
	srv, err := newServerWithSender(st2, func(context.Context, model.NotifyChannel, notify.Message) error {
		<-gate
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]store.NotifyDelivery{}
	for _, d := range st2.NotifyDeliveries(store.NotifyDeliveryFilter{}) {
		byID[d.ID] = d
	}
	if d := byID["nd-fresh"]; !d.Redriven || d.Reason != "redriven after restart" || d.Outcome != store.NotifyOutcomePlanned {
		t.Fatalf("fresh row = %+v", d)
	}
	for _, id := range []string{"nd-stale", "nd-test"} {
		if d := byID[id]; d.Outcome != store.NotifyOutcomeFailed || d.Reason != "interrupted by restart, not retried" || d.SettledAt.IsZero() {
			t.Fatalf("%s = %+v", id, d)
		}
	}
	if d := byID["nd-retry"]; !d.Redriven || !d.NextAttemptAt.After(now) {
		t.Fatalf("waiting retry = %+v", d)
	}
	close(gate)
	// Pull the waiting retry forward, as its timer would.
	retry := byID["nd-retry"]
	retry.NextAttemptAt = time.Now()
	if err := st2.PutNotifyDelivery(retry, nil); err != nil {
		t.Fatal(err)
	}
	srv.wakeNotifyOutbox()
	waitOutboxSettled(t, srv)
	if left := st2.NotifyDeliveries(store.NotifyDeliveryFilter{Outcome: store.NotifyOutcomePlanned}); len(left) != 0 {
		t.Fatalf("rows still planned after boot: %+v", left)
	}
	if d, _ := st2.NotifyDelivery("nd-fresh"); d.Outcome != store.NotifyOutcomeSent {
		t.Fatalf("redriven row = %+v", d)
	}
}

// newServerWithSender builds a server whose sends go to send. Background
// loops stay off, so nothing is sent before send is in place; the wake stands
// in for their start.
func newServerWithSender(st *store.Store, send func(context.Context, model.NotifyChannel, notify.Message) error) (*Server, error) {
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		return nil, err
	}
	srv.notifySend = send
	srv.notifyRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	srv.wakeNotifyOutbox()
	return srv, nil
}

// A page planned just before the process dies is sent by the next one.
func TestOutboxPageSurvivesACrashBeforeDelivery(t *testing.T) {
	dir := t.TempDir()
	f := openNotifyFixture(t, dir)
	addNotifyChannel(t, f.st, "nc-a", "Bark urgent")
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	f.srv.notifySend = func(ctx context.Context, _ model.NotifyChannel, _ notify.Message) error {
		select {
		case <-hold:
		case <-ctx.Done():
		}
		return ctx.Err()
	}
	f.srv.notifyEventTyped(EventNodeOffline, "Node offline: alpha", "alpha went quiet")

	crashDir := t.TempDir()
	copyStateFiles(t, dir, crashDir)
	st2, err := store.OpenWithCipher(filepath.Join(crashDir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if err := st2.EnableRuntimeBoltHotStore(filepath.Join(crashDir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	srv2, err := newServerWithSender(st2, func(_ context.Context, _ model.NotifyChannel, msg notify.Message) error {
		mu.Lock()
		got = append(got, msg.Title)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	waitOutboxSettled(t, srv2)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "Node offline: alpha" {
		t.Fatalf("after the crash the page was %v", got)
	}
	row := st2.NotifyDeliveries(store.NotifyDeliveryFilter{EventType: EventNodeOffline})[0]
	if !row.Redriven || row.Outcome != store.NotifyOutcomeSent {
		t.Fatalf("row = %+v", row)
	}
}

// A digest line queued before the process dies is sent by the next one: the
// decision behind it (the sing-box episode, the monitor run) is already on
// disk, so losing the line would lose the page.
func TestQueuedDigestLineSurvivesACrash(t *testing.T) {
	dir := t.TempDir()
	f := openNotifyFixture(t, dir)
	f.srv.queueAlertDigest(EventServiceDown, alertDigestLine{sortKey: "alpha", title: "sing-box failed on alpha", body: "b", line: "alpha: failed"})

	crashDir := t.TempDir()
	copyStateFiles(t, dir, crashDir)
	st2, err := store.OpenWithCipher(filepath.Join(crashDir, "state.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if err := st2.EnableRuntimeBoltHotStore(filepath.Join(crashDir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	srv2, err := New(Options{Store: st2, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	sent := captureTypedNotices(srv2)
	srv2.flushAlertDigests()
	if len(*sent) != 1 || (*sent)[0].title != "sing-box failed on alpha" {
		t.Fatalf("restored digest sent %+v", *sent)
	}
	if left := st2.NotifyDigestLines(); len(left) != 0 {
		t.Fatalf("flushed lines still stored: %+v", left)
	}
	// The flushed line is gone, so a later flush sends nothing again.
	srv2.flushAlertDigests()
	if len(*sent) != 1 {
		t.Fatalf("the line was sent twice: %+v", *sent)
	}
}

// The design's benchmark: a burst of 30 events against three channels and
// one matching rule costs record writes and no rewrite of the state file,
// whether every send succeeds (last_ok_at moves on each) or every send fails
// (retries, failure counts and channel_failing announcements).
func TestNotifyOutboxNeverRewritesTheStateFile(t *testing.T) {
	dir := t.TempDir()
	f := openNotifyFixture(t, dir)
	for _, id := range []string{"nc-a", "nc-b", "nc-c"} {
		addNotifyChannel(t, f.st, id, "Channel "+id)
	}
	if err := f.st.UpsertNotifyRule(model.NotifyRule{ID: "r-all", Name: "All", EventTypes: []string{EventServiceDown}, ChannelIDs: []string{"nc-a", "nc-b", "nc-c"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	fake := installFakeNotifySender(f.srv, nil)
	for _, pass := range []struct {
		name   string
		answer func(string, int) error
	}{
		{"all sends succeed", nil},
		{"all sends fail", func(string, int) error { return upstream(502) }},
	} {
		t.Run(pass.name, func(t *testing.T) {
			fake.setAnswer(pass.answer)
			watch := watchStateFile(t, f.statePath())
			for i := 0; i < 30; i++ {
				f.srv.notifyEventTyped(EventServiceDown, fmt.Sprintf("sing-box down on n%02d", i), "b")
			}
			waitOutboxSettled(t, f.srv)
			if watch.check() {
				t.Fatal("notification delivery rewrote the state file")
			}
		})
	}
	if n := f.st.NotifyDeliveryCount(); n < 180 {
		t.Fatalf("outbox holds %d rows, want at least 180", n)
	}
	if !f.st.NotifyOutboxDurable() {
		t.Fatal("the fixture's outbox is not on bolt")
	}
}

// A real channel failing stores no credential anywhere: not in the receipts,
// the health record, the state file or the hot store.
func TestChannelFailureStoresNoCredential(t *testing.T) {
	dir := t.TempDir()
	cipher, err := secret.NewAESGCM(bytes.Repeat([]byte{0x6e}, secret.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenWithCipher(filepath.Join(dir, "state.json"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableRuntimeBoltHotStore(filepath.Join(dir, "state-hot.db")); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	f := ingestFixture{dir: dir, srv: srv, st: st}
	const token = "424242:SECRET-BOT-TOKEN"
	if err := f.st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-tg", Name: "Telegram", Kind: "telegram", Enabled: true,
		Config: map[string]string{"token": token, "chat_id": "1", "base_url": "http://127.0.0.1:9"}}); err != nil {
		t.Fatal(err)
	}
	// The real client: it refuses the loopback base URL with an error that
	// names the URL, token included.
	f.srv.notifySend = defaultNotifySend
	f.srv.notifyEventTyped(EventNodeOffline, "Node offline: alpha", "b")
	waitOutboxSettled(t, f.srv)
	row := f.st.NotifyDeliveries(store.NotifyDeliveryFilter{ChannelID: "nc-tg"})[0]
	if row.Outcome != store.NotifyOutcomeFailed {
		t.Fatalf("row = %+v", row)
	}
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"state.json", "state-hot.db"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("SECRET-BOT-TOKEN")) {
			t.Fatalf("%s carries the channel token", name)
		}
	}
}

// testClock is a server clock a test moves by hand.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

// An operator's failed test neither counts toward failing nor starts its
// window: a test that failed 20 minutes ago followed by one real failure is
// not a failing channel and pages nobody. The rule itself still holds: three
// real failures announce it.
func TestFailedTestDoesNotStartTheFailingWindow(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	clock := &testClock{at: time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)}
	srv.now = clock.now
	addNotifyChannel(t, st, "nc-urgent", "Bark urgent")
	addNotifyChannel(t, st, "nc-info", "Bark info")
	if err := st.UpsertNotifyRule(model.NotifyRule{ID: "r-urgent", Name: "Urgent", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-urgent"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-urgent" {
			return upstream(400)
		}
		return nil
	})
	channel, _ := srv.notifyChannelByID("nc-urgent")
	row, health := srv.sendNotifyChannelTest(channel)
	if row.Outcome != store.NotifyOutcomeFailed || health.ConsecutiveFailures != 0 || !health.FailingSince.IsZero() {
		t.Fatalf("after a failed test: row %+v, health %+v", row, health)
	}
	if state := notifyChannelHealthState(health, clock.now()); state != notifyHealthDegraded {
		t.Fatalf("a failed test shows %s, want degraded", state)
	}

	clock.advance(20 * time.Minute)
	srv.notifyEventTyped(EventNodeOffline, "Node offline: alpha", "b")
	waitOutboxSettled(t, srv)
	if rows := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: EventNotifyChannelFailing}); len(rows) != 0 {
		t.Fatalf("one real failure after an old failed test paged: %+v", rows)
	}
	h, _ := st.NotifyChannelHealth("nc-urgent")
	if h.ConsecutiveFailures != 1 || !h.FailingSince.Equal(clock.now()) || notifyChannelHealthState(h, clock.now()) != notifyHealthDegraded {
		t.Fatalf("health after one real failure = %+v", h)
	}

	for i := 0; i < 2; i++ {
		clock.advance(time.Minute)
		srv.notifyEventTyped(EventNodeOffline, fmt.Sprintf("Node offline: n%d", i), "b")
		waitOutboxSettled(t, srv)
	}
	if rows := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: EventNotifyChannelFailing}); len(rows) != 1 || rows[0].ChannelID != "nc-info" {
		t.Fatalf("three real failures did not announce once: %+v", rows)
	}
}

// A message longer than the bound is cut once, at plan time: the channel
// receives exactly what the Sent log stores, the row says it was cut, and a
// fallback keeps its explanation at the end.
func TestOutboxSendsAndStoresTheSameBoundedText(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-fb", "Telegram fallback")
	rule := model.NotifyRule{ID: "r-urgent", Name: "Urgent", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-a"}, Enabled: true}
	if err := st.UpsertNotifyRuleWithOptions(rule, store.NotifyRuleOptions{FallbackChannelID: "nc-fb"}); err != nil {
		t.Fatal(err)
	}
	fake := installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-a" {
			return upstream(401)
		}
		return nil
	})
	long := strings.Repeat("node alpha went quiet. ", 1000)
	srv.notifyEventTyped(EventNodeOffline, strings.Repeat("Node offline ", 100), long)
	waitOutboxSettled(t, srv)
	primary := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-a"})
	sent := fake.sentTo("nc-a")
	if len(primary) != 1 || len(sent) != 1 || !primary[0].Truncated {
		t.Fatalf("primary rows %+v, sends %d", primary, len(sent))
	}
	if sent[0].body != primary[0].Body || sent[0].title != primary[0].Title || len(sent[0].body) > store.MaxNotifyBodyBytes || len(sent[0].title) > store.MaxNotifyTitleBytes {
		t.Fatalf("sent %d/%d bytes, stored %d/%d", len(sent[0].title), len(sent[0].body), len(primary[0].Title), len(primary[0].Body))
	}
	fb := fake.sentTo("nc-fb")
	if len(fb) != 1 || len(fb[0].body) > store.MaxNotifyBodyBytes || !strings.HasSuffix(fb[0].body, "Bark urgent did not deliver it.") {
		t.Fatalf("fallback body (%d bytes) lost its explanation", len(fb[0].body))
	}
}

// A chatty unrouted event keeps one row with a count, not one row per event.
func TestOutboxFoldsRepeatedUnroutedEvents(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	if err := st.UpsertNotifyRule(model.NotifyRule{ID: "r-urgent", Name: "Urgent", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	installFakeNotifySender(srv, nil)
	for i := 0; i < 5; i++ {
		srv.notifyEventTyped("ssh.login", "SSH login on alpha", fmt.Sprintf("root from 203.0.113.%d", i))
	}
	rows := deliveriesOf(st, store.NotifyDeliveryFilter{EventType: "ssh.login"})
	if len(rows) != 1 || rows[0].Repeats != 4 || rows[0].Body != "root from 203.0.113.4" {
		t.Fatalf("rows = %+v", rows)
	}
}
