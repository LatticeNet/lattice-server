package store

import (
	"fmt"
	"path/filepath"
	"strings"
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
		before := s.testPersistCalls
		if err := s.RecordDDNSRun("d1", DDNSRunOutcome{At: at, Err: lastErr, IPv4: ipv4}); err != nil {
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

// A provider error that differs between retries only in a request id, a
// timestamp, a countdown or a Cloudflare ray id is the same failure, and a
// retry of it is not written at once. A different status or message is. The
// profile in memory carries the newest text either way, and Close writes it.
func TestDDNSRunTreatsAnErrorThatDiffersOnlyInIDsAsUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDDNSProfile(model.DDNSProfile{ID: "d1", Name: "mixed", NodeID: "n1", Provider: "webhook",
		WebhookURL: "https://ddns.example.com/h", Domains: []string{"a.example.com"}, EnableIPv4: true, EnableIPv6: true}); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)
	run := func(at time.Time, lastErr string) int {
		t.Helper()
		before := s.testPersistCalls
		if err := s.RecordDDNSRun("d1", DDNSRunOutcome{At: at, Err: lastErr}); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.DDNSProfile("d1"); got.LastError != lastErr {
			t.Fatalf("the profile in memory shows %q, want the newest text %q", got.LastError, lastErr)
		}
		return s.testPersistCalls - before
	}
	// The two shapes the providers return (webhook.go and cloudflare.go), one
	// line per failed record as ddns.Apply joins them.
	failure := func(status int, message, requestID string, retryAfter int, ray string) string {
		return fmt.Sprintf(`A a.example.com: webhook: status %d: {"error":%q,"request_id":%q,"retry_after":%d,"at":"2026-10-04T01:%02d:00Z"}`,
			status, message, requestID, retryAfter, retryAfter) + "\n" +
			fmt.Sprintf(`AAAA a.example.com: cloudflare: api error (status 400): [{"code":1004,"message":"DNS Validation Error","ray":%q}]`, ray)
	}
	if got := run(t0, failure(503, "upstream unavailable", "req_8Kq2xZ71", 30, "7d9a8b6c5e4f3a2b-SJC")); got != 1 {
		t.Fatalf("the first failure wrote %d times, want 1", got)
	}
	for i, retry := range []string{
		failure(503, "upstream unavailable", "req_Zp41mQ09", 17, "8e0b9c7d6f5a4b3c-HKG"),
		failure(503, "upstream unavailable", "3f2504e0-4f89-11d3-9a0c-0305e82c3301", 5, "1a2b3c4d5e6f7a8b-LAX"),
	} {
		if got := run(t0.Add(time.Duration(i+1)*5*time.Minute), retry); got != 0 {
			t.Fatalf("retry %d, the same failure with new ids, wrote %d times, want 0", i+1, got)
		}
	}
	if got := run(t0.Add(15*time.Minute), failure(500, "upstream unavailable", "req_x1", 30, "9f-SJC")); got != 1 {
		t.Fatalf("a different status wrote %d times, want 1", got)
	}
	if got := run(t0.Add(20*time.Minute), failure(500, "invalid credentials", "req_x2", 30, "9e-SJC")); got != 1 {
		t.Fatalf("a different message wrote %d times, want 1", got)
	}
	newest := failure(500, "invalid credentials", "req_x3", 12, "9d-SJC")
	if got := run(t0.Add(25*time.Minute), newest); got != 0 {
		t.Fatalf("a retry of the changed failure wrote %d times, want 0", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(path, s.cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if p, _ := reopened.DDNSProfile("d1"); p.LastError != newest || !p.LastRunAt.Equal(t0.Add(25*time.Minute)) {
		t.Fatalf("after close and reopen the profile shows %q at %s, want the newest full text", p.LastError, p.LastRunAt)
	}
}

func TestDDNSErrorClass(t *testing.T) {
	long := strings.Repeat("upstream refused the update ", 12)
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"", "", true},
		{"", "A a.example.com: webhook: status 503: busy", false},
		{"A a.example.com: webhook: status 503: busy", "A a.example.com: webhook: status 502: busy", false},
		{"A a.example.com: webhook: status 503: busy", "AAAA a.example.com: webhook: status 503: busy", false},
		{"A a.example.com: webhook: status 503: busy", "A b.example.com: webhook: status 503: busy", false},
		{`A a.example.com: Put "https://ddns.example.com/h": dial tcp 203.0.113.5:443: connect: connection refused`,
			`A a.example.com: Put "https://ddns.example.com/h": dial tcp 198.51.100.7:443: connect: connection refused`, true},
		{"A a.example.com: webhook: status 503: " + long + "id 1", "A a.example.com: webhook: status 503: " + long + "ok", true},
	} {
		if got := ddnsErrorClass(c.a) == ddnsErrorClass(c.b); got != c.same {
			t.Errorf("same class = %v, want %v:\n%q -> %q\n%q -> %q", got, c.same, c.a, ddnsErrorClass(c.a), c.b, ddnsErrorClass(c.b))
		}
	}
}

// A run lasts as long as the provider takes, and the profile it started from
// may be edited, switched to the other record type or deleted before it ends.
// Its outcome lands on the profile as stored then: the edit survives, an
// outcome for the other record type is dropped, and a deleted profile is not
// brought back.
func TestDDNSRunOutcomeLandsOnTheStoredProfile(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	ran := model.DDNSProfile{ID: "d1", Name: "frontier", NodeID: "n1", Provider: model.DDNSProviderCloudflare, CFAPIToken: "t",
		Domains: []string{"frontier.example.com"}, RecordType: model.DDNSRecordCNAME, CNAMETarget: "nat-old.example.net"}
	if err := s.UpsertDDNSProfile(ran); err != nil {
		t.Fatal(err)
	}
	// The operator saves a new target and a second domain while the run that
	// published the old target is still waiting on Cloudflare.
	edited := ran
	edited.CNAMETarget = "nat-new.example.net"
	edited.Domains = []string{"frontier.example.com", "frontier2.example.com"}
	if err := s.UpsertDDNSProfile(edited); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	if err := s.RecordDDNSRun("d1", DDNSRunOutcome{At: at, CNAME: true, Target: ran.CNAMETarget}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.DDNSProfile("d1")
	if got.CNAMETarget != "nat-new.example.net" || len(got.Domains) != 2 {
		t.Fatalf("the run wrote back the profile it started from: %+v", got)
	}
	// What the run published is recorded as published, so the sweep sees the
	// new target as not yet published and runs again.
	if got.LastTarget != "nat-old.example.net" || !got.LastRunAt.Equal(at) || got.LastError != "" {
		t.Fatalf("run status: %+v", got)
	}

	// Switched to the address type while a CNAME run was in flight.
	address := got
	address.RecordType, address.LastTarget = model.DDNSRecordAddress, ""
	if err := s.UpsertDDNSProfile(address); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordDDNSRun("d1", DDNSRunOutcome{At: at.Add(time.Minute), CNAME: true, Target: "nat-new.example.net"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.DDNSProfile("d1"); got.LastTarget != "" || !got.LastRunAt.Equal(at) {
		t.Fatalf("a CNAME outcome landed on an address profile: %+v", got)
	}

	if err := s.DeleteDDNSProfile("d1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordDDNSRun("d1", DDNSRunOutcome{At: at.Add(2 * time.Minute), IPv4: "203.0.113.10", WriteNow: true}); err != nil {
		t.Fatal(err)
	}
	if p, ok := s.DDNSProfile("d1"); ok {
		t.Fatalf("a run brought back a deleted profile: %+v", p)
	}
}

// An operator's run is written before the answer even when its outcome
// matches the stored one.
func TestDDNSRunWriteNowWritesAnUnchangedOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UpsertDDNSProfile(model.DDNSProfile{ID: "d1", Name: "cf", NodeID: "n1", Provider: "webhook",
		WebhookURL: "https://ddns.example.com/h", Domains: []string{"a.example.com"}, EnableIPv4: true, LastIPv4: "203.0.113.10"}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	for _, writeNow := range []bool{false, true} {
		before := s.testPersistCalls
		if err := s.RecordDDNSRun("d1", DDNSRunOutcome{At: at, IPv4: "203.0.113.10", WriteNow: writeNow}); err != nil {
			t.Fatal(err)
		}
		want := 0
		if writeNow {
			want = 1
		}
		if got := s.testPersistCalls - before; got != want {
			t.Fatalf("WriteNow %t: an unchanged outcome wrote %d times, want %d", writeNow, got, want)
		}
	}
}
