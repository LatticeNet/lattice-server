package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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
