package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// An automatic DDNS run that changes nothing, the same provider error again,
// moves only LastRunAt, and that waits in memory. A failing profile is retried
// every interval, and each retry used to rewrite the whole state file to
// record the same error. A changed outcome is written at once, and Close
// writes what waited.
func TestDDNSRunWritesOnlyAChangedOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDDNSProfile(model.DDNSProfile{ID: "d1", Name: "cf", NodeID: "n1", Provider: "webhook",
		WebhookURL: "https://ddns.example.com/h", Domains: []string{"a.example.com"}, EnableIPv4: true}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)
	run := func(at time.Time, lastErr, ipv4 string) int {
		t.Helper()
		p, _ := s.DDNSProfile("d1")
		p.LastRunAt, p.LastError = at, lastErr
		if ipv4 != "" {
			p.LastIPv4 = ipv4
		}
		before := s.testPersistCalls
		if err := s.RecordDDNSRun(p); err != nil {
			t.Fatal(err)
		}
		return s.testPersistCalls - before
	}
	const refused = "webhook: status 403"
	if got := run(t0, refused, ""); got != 1 {
		t.Fatalf("the first failure wrote %d times, want 1", got)
	}
	for i := 1; i <= 5; i++ {
		if got := run(t0.Add(time.Duration(i)*5*time.Minute), refused, ""); got != 0 {
			t.Fatalf("retry %d with the same error wrote %d times, want 0", i, got)
		}
	}
	if p, _ := s.DDNSProfile("d1"); !p.LastRunAt.Equal(t0.Add(25 * time.Minute)) {
		t.Fatalf("the retry clock in memory = %s, want the last retry", p.LastRunAt)
	}
	if got := run(t0.Add(30*time.Minute), "webhook: status 500", ""); got != 1 {
		t.Fatalf("a different error wrote %d times, want 1", got)
	}
	if got := run(t0.Add(35*time.Minute), "", "203.0.113.10"); got != 1 {
		t.Fatalf("a publish wrote %d times, want 1", got)
	}
	if got := run(t0.Add(40*time.Minute), "", ""); got != 0 {
		t.Fatalf("a run that published nothing new wrote %d times, want 0", got)
	}
	before := s.testPersistCalls
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("close with a run clock in memory wrote %d times, want 1", calls)
	}
	reopened, err := OpenWithCipher(path, s.cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	p, _ := reopened.DDNSProfile("d1")
	if !p.LastRunAt.Equal(t0.Add(40*time.Minute)) || p.LastIPv4 != "203.0.113.10" || p.LastError != "" {
		t.Fatalf("after close and reopen: %+v", p)
	}
}
