package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
)

func outboxRow(id, source, sourceID string, at time.Time, outcome string) NotifyDelivery {
	return NotifyDelivery{ID: id, EventID: "evt-" + id, EventType: "node.offline", Source: source, SourceID: sourceID,
		ChannelID: "nc-a", Outcome: outcome, Title: "title " + id, CreatedAt: at}
}

// The outbox holds at most 1000 deliveries and never takes a source below its
// last 50 while another source has more, so a quiet webhook keeps the window
// its own ring gave it. A delivery still owed a send is never evicted.
func TestNotifyOutboxKeepsAFloorPerSource(t *testing.T) {
	s, _ := openReportClockStore(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return base.Add(time.Duration(i) * time.Second) }
	owed := outboxRow("nd-owed", NotifySourceServer, "", at(0), NotifyOutcomePlanned)
	rows := []NotifyDelivery{owed}
	for i := 0; i < 50; i++ {
		rows = append(rows, outboxRow(fmt.Sprintf("nd-hook-%03d", i), NotifySourceWebhook, "nwh-backup", at(1+i), NotifyOutcomeSent))
	}
	if err := s.RecordNotifyDeliveries(rows); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1100; i++ {
		if err := s.RecordNotifyDeliveries([]NotifyDelivery{outboxRow(fmt.Sprintf("nd-srv-%04d", i), NotifySourceServer, "", at(100+i), NotifyOutcomeSent)}); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.NotifyDeliveryCount(); n != MaxNotifyDeliveries {
		t.Fatalf("outbox holds %d, want %d", n, MaxNotifyDeliveries)
	}
	if hook := s.NotifyDeliveries(NotifyDeliveryFilter{Source: NotifySourceWebhook, SourceID: "nwh-backup"}); len(hook) != 50 {
		t.Fatalf("the webhook kept %d of its 50", len(hook))
	}
	if _, ok := s.NotifyDelivery("nd-owed"); !ok {
		t.Fatal("a delivery still owed a send was evicted")
	}
	newest := s.NotifyDeliveries(NotifyDeliveryFilter{Limit: 1})
	if len(newest) != 1 || newest[0].ID != "nd-srv-1099" {
		t.Fatalf("newest = %+v", newest)
	}
	if _, ok := s.NotifyDelivery("nd-srv-0000"); ok {
		t.Fatal("the oldest server row survived the bound")
	}
}

// On the hot store the outbox, the health and the digest queue survive a
// reopen and stay out of the state file; without it they are memory only.
func TestNotifyOutboxSurvivesAReopenOnlyOnTheHotStore(t *testing.T) {
	for _, hot := range []bool{true, false} {
		t.Run(fmt.Sprintf("bolt_hot_%v", hot), func(t *testing.T) {
			s, path := openReportClockStore(t)
			hotPath := filepath.Join(filepath.Dir(path), "hot.db")
			if hot {
				if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
					t.Fatal(err)
				}
			}
			at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
			row := outboxRow("nd-1", NotifySourceServer, "", at, NotifyOutcomeFailed)
			row.Title = "MARKER-TITLE-OF-A-DELIVERY"
			row.Attempts = []NotifyAttempt{{At: at, Kind: "upstream_4xx", Status: 401}}
			if err := s.PutNotifyDelivery(row, &NotifyChannelHealth{ChannelID: "nc-a", LastFailureAt: at, ConsecutiveFailures: 1}); err != nil {
				t.Fatal(err)
			}
			if err := s.QueueNotifyDigestLine(NotifyDigestLine{Key: NewNotifyDigestKey(at, "ndq-1"), EventType: "service.down", Title: "t", Line: "l", QueuedAt: at}); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertNode(model.Node{ID: "node-a", Name: "a"}); err != nil {
				t.Fatal(err) // forces a state file write
			}
			s = reopenReportClockStore(t, s, path)
			if hot {
				if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = s.Close() })
			got, ok := s.NotifyDelivery("nd-1")
			_, healthOK := s.NotifyChannelHealth("nc-a")
			lines := s.NotifyDigestLines()
			if hot {
				if !ok || len(got.Attempts) != 1 || got.Attempts[0].Status != 401 || !healthOK || len(lines) != 1 {
					t.Fatalf("after reopen: row %v %+v, health %v, lines %+v", ok, got, healthOK, lines)
				}
			} else if ok || healthOK || len(lines) != 0 {
				t.Fatalf("a memory-only outbox survived a reopen: %v %v %v", ok, healthOK, lines)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("MARKER-TITLE")) || bytes.Contains(data, []byte("notify_deliveries")) {
				t.Fatal("the outbox reached the state file")
			}
		})
	}
}

// Nothing the outbox writes rewrites the JSON state, in either mode.
func TestNotifyOutboxNeverPersistsTheJSONState(t *testing.T) {
	for _, hot := range []bool{false, true} {
		t.Run(fmt.Sprintf("bolt_hot_%v", hot), func(t *testing.T) {
			s, _ := openReportClockStore(t)
			if hot {
				if err := s.EnableRuntimeBoltHotStore(filepath.Join(t.TempDir(), "hot.db")); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = s.Close() })
			at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
			before := s.testPersistCalls
			for i := 0; i < 50; i++ {
				row := outboxRow(fmt.Sprintf("nd-%d", i), NotifySourceServer, "", at, NotifyOutcomePlanned)
				if err := s.RecordNotifyDeliveries([]NotifyDelivery{row}); err != nil {
					t.Fatal(err)
				}
				row.Outcome = NotifyOutcomeSent
				if err := s.PutNotifyDelivery(row, &NotifyChannelHealth{ChannelID: "nc-a", LastOKAt: at}); err != nil {
					t.Fatal(err)
				}
				key := NewNotifyDigestKey(at, fmt.Sprintf("ndq-%d", i))
				if err := s.QueueNotifyDigestLine(NotifyDigestLine{Key: key, EventType: "service.down"}); err != nil {
					t.Fatal(err)
				}
				if err := s.RemoveNotifyDigestLines([]string{key}); err != nil {
					t.Fatal(err)
				}
			}
			if calls := s.testPersistCalls - before; calls != 0 {
				t.Fatalf("the outbox rewrote the state %d times", calls)
			}
		})
	}
}

// Rows written before the hot store is enabled are carried into it, not
// dropped.
func TestNotifyOutboxCarriesMemoryRowsIntoTheHotStore(t *testing.T) {
	s, path := openReportClockStore(t)
	hotPath := filepath.Join(filepath.Dir(path), "hot.db")
	at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	if err := s.RecordNotifyDeliveries([]NotifyDelivery{outboxRow("nd-early", NotifySourceServer, "", at, NotifyOutcomeSent)}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.NotifyDelivery("nd-early"); !ok {
		t.Fatal("enabling the hot store dropped the row")
	}
	s = reopenReportClockStore(t, s, path)
	t.Cleanup(func() { _ = s.Close() })
	if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.NotifyDelivery("nd-early"); !ok {
		t.Fatal("the early row did not reach bolt")
	}
}

// A rule's options are saved with it, survive a reopen, go when the rule goes,
// and lose a fallback whose channel is deleted, which also drops the
// channel's health.
func TestNotifyRuleOptionsLiveAndDieWithTheirRule(t *testing.T) {
	s, path := openReportClockStore(t)
	for _, id := range []string{"nc-a", "nc-fb"} {
		if err := s.UpsertNotifyChannel(model.NotifyChannel{ID: id, Name: id, Kind: "bark", Enabled: true, Config: map[string]string{"base_url": "https://b.example", "key": "k"}}); err != nil {
			t.Fatal(err)
		}
	}
	rule := model.NotifyRule{ID: "r-1", Name: "Urgent", ChannelIDs: []string{"nc-a"}, Enabled: true}
	if err := s.UpsertNotifyRuleWithOptions(rule, NotifyRuleOptions{FallbackChannelID: "nc-fb"}); err != nil {
		t.Fatal(err)
	}
	s = reopenReportClockStore(t, s, path)
	t.Cleanup(func() { _ = s.Close() })
	if got := s.NotifyRuleOptionsByRule()["r-1"]; got.FallbackChannelID != "nc-fb" {
		t.Fatalf("after reopen = %+v", got)
	}
	if err := s.PutNotifyDelivery(outboxRow("nd-1", NotifySourceServer, "", time.Now(), NotifyOutcomeSent), &NotifyChannelHealth{ChannelID: "nc-fb", LastOKAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNotifyChannel("nc-fb"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.NotifyRuleOptionsByRule()["r-1"]; ok {
		t.Fatal("a deleted channel is still a fallback")
	}
	if _, ok := s.NotifyChannelHealth("nc-fb"); ok {
		t.Fatal("a deleted channel kept its health")
	}
	if _, ok := s.NotifyDelivery("nd-1"); !ok {
		t.Fatal("deleting a channel removed its history")
	}
	if err := s.UpsertNotifyRuleWithOptions(rule, NotifyRuleOptions{FallbackChannelID: "nc-a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNotifyRule("r-1"); err != nil {
		t.Fatal(err)
	}
	if len(s.NotifyRuleOptionsByRule()) != 0 {
		t.Fatal("a deleted rule left its options")
	}
}

// A channel's critical fallback is saved with the channel, survives a
// reopen, goes when the channel goes, and is cleared from every channel that
// named a deleted one.
func TestNotifyChannelOptionsLiveAndDieWithTheirChannel(t *testing.T) {
	s, path := openReportClockStore(t)
	channel := func(id string) model.NotifyChannel {
		return model.NotifyChannel{ID: id, Name: id, Kind: "bark", Enabled: true, Config: map[string]string{"base_url": "https://b.example", "key": "k"}}
	}
	if err := s.UpsertNotifyChannel(channel("nc-fb")); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNotifyChannelWithOptions(channel("nc-a"), NotifyChannelOptions{FallbackChannelID: "nc-fb"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNotifyChannelWithOptions(channel("nc-b"), NotifyChannelOptions{FallbackChannelID: "nc-a"}); err != nil {
		t.Fatal(err)
	}
	s = reopenReportClockStore(t, s, path)
	t.Cleanup(func() { _ = s.Close() })
	if got := s.NotifyChannelOptionsByChannel()["nc-a"]; got.FallbackChannelID != "nc-fb" {
		t.Fatalf("after reopen = %+v", got)
	}
	if err := s.DeleteNotifyChannel("nc-a"); err != nil {
		t.Fatal(err)
	}
	opts := s.NotifyChannelOptionsByChannel()
	if _, ok := opts["nc-a"]; ok {
		t.Fatal("a deleted channel kept its options")
	}
	if _, ok := opts["nc-b"]; ok {
		t.Fatal("a deleted channel is still another channel's fallback")
	}
	if err := s.UpsertNotifyChannelWithOptions(channel("nc-b"), NotifyChannelOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(s.NotifyChannelOptionsByChannel()) != 0 {
		t.Fatal("clearing the fallback left an empty options row")
	}
}

func noRouteRow(id, eventType string, at time.Time) NotifyDelivery {
	return NotifyDelivery{ID: id, EventID: "evt-" + id, EventType: eventType, Source: NotifySourceServer,
		Outcome: NotifyOutcomeNoRoute, Reason: "no enabled rule routes this event type", Title: "unrouted " + id, CreatedAt: at}
}

// Unrouted events cannot push out the receipts the Sent log exists for: 2000
// of them, each a distinct type so none folds into another, leave a failed
// delivery and a sent one in place, hold no more than their own bound, and
// keep the newest.
func TestNotifyOutboxNoRouteRowsNeverEvictReceipts(t *testing.T) {
	s, _ := openReportClockStore(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	failed := outboxRow("nd-failed", NotifySourceServer, "", base, NotifyOutcomeFailed)
	sent := outboxRow("nd-sent", NotifySourceServer, "", base.Add(time.Second), NotifyOutcomeSent)
	if err := s.RecordNotifyDeliveries([]NotifyDelivery{failed, sent}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		row := noRouteRow(fmt.Sprintf("nd-nr-%04d", i), fmt.Sprintf("custom.type_%04d", i), base.Add(time.Duration(2+i)*time.Second))
		if err := s.RecordNotifyNoRoute(row); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"nd-failed", "nd-sent"} {
		if _, ok := s.NotifyDelivery(id); !ok {
			t.Fatalf("%s was evicted by unrouted events", id)
		}
	}
	noRoute := s.NotifyDeliveries(NotifyDeliveryFilter{Outcome: NotifyOutcomeNoRoute})
	if len(noRoute) != MaxNotifyNoRouteDeliveries {
		t.Fatalf("no_route rows = %d, want %d", len(noRoute), MaxNotifyNoRouteDeliveries)
	}
	if noRoute[0].ID != "nd-nr-1999" || noRoute[len(noRoute)-1].ID != "nd-nr-1900" {
		t.Fatalf("kept %s..%s, want the newest", noRoute[len(noRoute)-1].ID, noRoute[0].ID)
	}
}

// When the outbox is full, a new delivery takes a no_route row before any
// receipt, and a no_route row does not count toward its source's floor.
func TestNotifyOutboxEvictsNoRouteRowsFirst(t *testing.T) {
	s, _ := openReportClockStore(t)
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		if err := s.RecordNotifyNoRoute(noRouteRow(fmt.Sprintf("nd-nr-%02d", i), fmt.Sprintf("custom.type_%02d", i), base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	rows := make([]NotifyDelivery, 0, MaxNotifyDeliveries-10)
	for i := 0; i < MaxNotifyDeliveries-10; i++ {
		rows = append(rows, outboxRow(fmt.Sprintf("nd-srv-%04d", i), NotifySourceServer, "", base.Add(time.Hour+time.Duration(i)*time.Second), NotifyOutcomeSent))
	}
	if err := s.RecordNotifyDeliveries(rows); err != nil {
		t.Fatal(err)
	}
	if n := s.NotifyDeliveryCount(); n != MaxNotifyDeliveries {
		t.Fatalf("outbox holds %d", n)
	}
	for i := 0; i < 3; i++ {
		row := outboxRow(fmt.Sprintf("nd-new-%d", i), NotifySourceServer, "", base.Add(2*time.Hour+time.Duration(i)*time.Second), NotifyOutcomeFailed)
		if err := s.RecordNotifyDeliveries([]NotifyDelivery{row}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.NotifyDelivery("nd-srv-0000"); !ok {
		t.Fatal("a receipt went before the unrouted rows")
	}
	if got := len(s.NotifyDeliveries(NotifyDeliveryFilter{Outcome: NotifyOutcomeNoRoute})); got != 7 {
		t.Fatalf("no_route rows = %d, want 7", got)
	}
	if _, ok := s.NotifyDelivery("nd-nr-02"); ok {
		t.Fatal("the oldest no_route rows were not the ones evicted")
	}
}

// Repeats of one unrouted event fold into the row first written for it for an
// hour, carrying the latest text, and a repeat is written to bolt at most
// once a minute: a reopen inside that minute shows the last written count.
func TestNotifyOutboxCollapsesRepeatedNoRouteRows(t *testing.T) {
	s, path := openReportClockStore(t)
	hotPath := filepath.Join(filepath.Dir(path), "hot.db")
	if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	login := func(id string, at time.Time) NotifyDelivery {
		row := noRouteRow(id, "ssh.login", at)
		row.Title = "SSH login " + id
		return row
	}
	if err := s.RecordNotifyNoRoute(login("nd-1", base)); err != nil {
		t.Fatal(err)
	}
	// Two repeats inside the first minute: memory only.
	for i, at := range []time.Time{base.Add(10 * time.Second), base.Add(20 * time.Second)} {
		if err := s.RecordNotifyNoRoute(login(fmt.Sprintf("nd-r%d", i), at)); err != nil {
			t.Fatal(err)
		}
	}
	rows := s.NotifyDeliveries(NotifyDeliveryFilter{EventType: "ssh.login"})
	if len(rows) != 1 || rows[0].ID != "nd-1" || rows[0].Repeats != 2 || !rows[0].LastSeenAt.Equal(base.Add(20*time.Second)) || rows[0].Title != "SSH login nd-r1" {
		t.Fatalf("rows = %+v", rows)
	}
	// A repeat a minute after the last write is written.
	if err := s.RecordNotifyNoRoute(login("nd-r2", base.Add(90*time.Second))); err != nil {
		t.Fatal(err)
	}
	// And one more inside the next minute stays in memory.
	if err := s.RecordNotifyNoRoute(login("nd-r3", base.Add(100*time.Second))); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.NotifyDelivery("nd-1"); got.Repeats != 4 {
		t.Fatalf("repeats in memory = %d", got.Repeats)
	}
	// Another type, and the same type an hour on, each start a row.
	if err := s.RecordNotifyNoRoute(noRouteRow("nd-quota", "proxy.quota", base.Add(2*time.Minute))); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordNotifyNoRoute(login("nd-2", base.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if rows := s.NotifyDeliveries(NotifyDeliveryFilter{EventType: "ssh.login"}); len(rows) != 2 || rows[0].ID != "nd-2" || rows[0].Repeats != 0 {
		t.Fatalf("after the window = %+v", rows)
	}

	s = reopenReportClockStore(t, s, path)
	if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
		t.Fatal(err)
	}
	got, ok := s.NotifyDelivery("nd-1")
	if !ok || got.Repeats != 3 || !got.LastSeenAt.Equal(base.Add(90*time.Second)) {
		t.Fatalf("after reopen = %v %+v, want the count last written (3)", ok, got)
	}
	// The first repeat after a reopen is written, since nothing paces it yet,
	// and it folds into the newest row of its kind.
	if err := s.RecordNotifyNoRoute(login("nd-r4", base.Add(time.Hour+10*time.Second))); err != nil {
		t.Fatal(err)
	}
	s = reopenReportClockStore(t, s, path)
	if err := s.EnableRuntimeBoltHotStore(hotPath); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.NotifyDelivery("nd-2"); got.Repeats != 1 {
		t.Fatalf("repeats after the second reopen = %d", got.Repeats)
	}
}

// Stored text is bounded on every write path, cut on a character boundary,
// and the row says so.
func TestNotifyOutboxBoundsStoredText(t *testing.T) {
	s, _ := openReportClockStore(t)
	at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	long := strings.Repeat("节点离线", 2000) // 3 bytes a character
	row := outboxRow("nd-long", NotifySourcePlugin, "p", at, NotifyOutcomePlanned)
	row.Title, row.Body = long, long
	if err := s.RecordNotifyDeliveries([]NotifyDelivery{row}); err != nil {
		t.Fatal(err)
	}
	nr := noRouteRow("nd-nr", "plugin.p.message", at)
	nr.Body = long
	if err := s.RecordNotifyNoRoute(nr); err != nil {
		t.Fatal(err)
	}
	put := outboxRow("nd-put", NotifySourcePlugin, "p", at, NotifyOutcomeSent)
	put.Body = long
	if err := s.PutNotifyDelivery(put, nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"nd-long", "nd-nr", "nd-put"} {
		got, _ := s.NotifyDelivery(id)
		if len(got.Title) > MaxNotifyTitleBytes || len(got.Body) > MaxNotifyBodyBytes || !got.Truncated {
			t.Fatalf("%s: title %d bytes, body %d bytes, truncated %v", id, len(got.Title), len(got.Body), got.Truncated)
		}
		if !utf8.ValidString(got.Title) || !utf8.ValidString(got.Body) || !strings.HasSuffix(got.Body, " [truncated]") {
			t.Fatalf("%s: cut mid-character or unmarked: %q", id, got.Body[len(got.Body)-20:])
		}
	}
	short := outboxRow("nd-short", NotifySourceServer, "", at, NotifyOutcomeSent)
	short.Body = "fits"
	if err := s.RecordNotifyDeliveries([]NotifyDelivery{short}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.NotifyDelivery("nd-short"); got.Truncated || got.Body != "fits" {
		t.Fatalf("a short message was touched: %+v", got)
	}
	if again, _, cut := ClampNotifyText(strings.Repeat("a", 600), ""); cut != true || len(again) != MaxNotifyTitleBytes {
		t.Fatalf("clamp = %d bytes, cut %v", len(again), cut)
	}
	if clamped, _, _ := ClampNotifyText(strings.Repeat("a", 600), ""); func() bool { c, _, cut := ClampNotifyText(clamped, ""); return cut || c != clamped }() {
		t.Fatal("clamping twice changed the text")
	}
}

// The event and unsettled indexes follow every put and eviction.
func TestNotifyOutboxIndexesFollowWrites(t *testing.T) {
	s, _ := openReportClockStore(t)
	at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	a := outboxRow("nd-a", NotifySourcePlugin, "p", at, NotifyOutcomePlanned)
	b := outboxRow("nd-b", NotifySourcePlugin, "p", at.Add(time.Second), NotifyOutcomePlanned)
	b.EventID = a.EventID
	other := outboxRow("nd-c", NotifySourcePlugin, "q", at.Add(2*time.Second), NotifyOutcomePlanned)
	if err := s.RecordNotifyDeliveries([]NotifyDelivery{a, b, other}); err != nil {
		t.Fatal(err)
	}
	if n := s.NotifyUnsettledCount(NotifySourcePlugin, "p"); n != 2 {
		t.Fatalf("unsettled for p = %d", n)
	}
	if got := s.NotifyDeliveries(NotifyDeliveryFilter{EventID: a.EventID}); len(got) != 2 || got[0].ID != "nd-b" {
		t.Fatalf("event rows = %+v", got)
	}
	a.Outcome = NotifyOutcomeSent
	if err := s.PutNotifyDelivery(a, nil); err != nil {
		t.Fatal(err)
	}
	if n := s.NotifyUnsettledCount(NotifySourcePlugin, "p"); n != 1 {
		t.Fatalf("unsettled for p after a send = %d", n)
	}
	if got := s.UnsettledNotifyDeliveries(); len(got) != 2 || got[0].ID != "nd-b" || got[1].ID != "nd-c" {
		t.Fatalf("unsettled = %+v", got)
	}
}
