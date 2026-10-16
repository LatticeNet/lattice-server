package store

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The packet and reason fields of an agent's result, every bound.
func TestNormalizeMonitorResultBody(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		in      model.MonitorResult
		ok      bool
		success bool
		latency float64
		sent    int
	}{
		{"icmp, some echoes back", model.MonitorTypeICMP, model.MonitorResult{Sent: 5, Lost: 2, RTTsMs: []float64{30, 10, 20}, Success: false, LatencyMs: 99}, true, true, 20, 5},
		{"icmp, an even count takes the middle mean", model.MonitorTypeICMP, model.MonitorResult{Sent: 4, RTTsMs: []float64{10, 40, 20, 30}}, true, true, 25, 4},
		{"icmp, all lost", model.MonitorTypeICMP, model.MonitorResult{Sent: 3, Lost: 3, Success: true, LatencyMs: 5}, true, false, 0, 3},
		{"icmp without packets is one probe", model.MonitorTypeICMP, model.MonitorResult{Success: true, LatencyMs: 12}, true, true, 12, 0},
		{"more than ten echoes", model.MonitorTypeICMP, model.MonitorResult{Sent: 11, RTTsMs: make([]float64, 11)}, false, false, 0, 0},
		{"lost above sent", model.MonitorTypeICMP, model.MonitorResult{Sent: 2, Lost: 3}, false, false, 0, 0},
		{"negative lost", model.MonitorTypeICMP, model.MonitorResult{Sent: 2, Lost: -1, RTTsMs: []float64{1, 2, 3}}, false, false, 0, 0},
		{"an RTT per echo that came back", model.MonitorTypeICMP, model.MonitorResult{Sent: 3, Lost: 1, RTTsMs: []float64{1}}, false, false, 0, 0},
		{"RTTs with nothing sent", model.MonitorTypeICMP, model.MonitorResult{RTTsMs: []float64{1}}, false, false, 0, 0},
		{"a NaN RTT", model.MonitorTypeICMP, model.MonitorResult{Sent: 1, RTTsMs: []float64{math.NaN()}}, false, false, 0, 0},
		{"a negative RTT", model.MonitorTypeICMP, model.MonitorResult{Sent: 1, RTTsMs: []float64{-1}}, false, false, 0, 0},
		{"an RTT past any timeout", model.MonitorTypeICMP, model.MonitorResult{Sent: 1, RTTsMs: []float64{monitorRTTMaxMs + 1}}, false, false, 0, 0},
		{"an infinite latency", model.MonitorTypeTCP, model.MonitorResult{Success: true, LatencyMs: math.Inf(1)}, false, false, 0, 0},
		{"tcp carries no packets", model.MonitorTypeTCP, model.MonitorResult{Success: true, LatencyMs: 7, Sent: 5, Lost: 1, RTTsMs: []float64{1, 2, 3, 4}}, true, true, 7, 0},
		{"a reason clears the outcome", model.MonitorTypeICMP, model.MonitorResult{Reason: "icmp_not_permitted", Success: true, LatencyMs: 4, Sent: 5}, true, false, 0, 0},
		{"a reason newer than this server", model.MonitorTypeHTTP, model.MonitorResult{Reason: "beacon_refused_v2"}, true, false, 0, 0},
		{"a reason in the wrong shape", model.MonitorTypeHTTP, model.MonitorResult{Reason: "Not Permitted"}, false, false, 0, 0},
		{"a reason too long", model.MonitorTypeHTTP, model.MonitorResult{Reason: strings.Repeat("a", 41)}, false, false, 0, 0},
	}
	for _, tc := range cases {
		got, ok := normalizeMonitorResultBody(tc.kind, tc.in)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Success != tc.success || got.LatencyMs != tc.latency || got.Sent != tc.sent {
			t.Errorf("%s: success %v latency %v sent %d; want %v %v %d", tc.name, got.Success, got.LatencyMs, got.Sent, tc.success, tc.latency, tc.sent)
		}
	}
	// The stored RTTs are a copy, in send order.
	rtts := []float64{3, 1, 2}
	got, _ := normalizeMonitorResultBody(model.MonitorTypeICMP, model.MonitorResult{Sent: 3, RTTsMs: rtts})
	rtts[0] = 99
	if got.RTTsMs[0] != 3 || got.RTTsMs[1] != 1 {
		t.Fatalf("rtts = %v", got.RTTsMs)
	}
}

func TestSanitizeMonitorError(t *testing.T) {
	cases := map[string]string{
		`Get "https://user:pw@example.com/health?token=abc#frag": dial tcp: refused`: `Get "https://example.com/health": dial tcp: refused`,
		`Get "http://example.com:8080/a?b=c": EOF`:                                   `Get "http://example.com:8080/a": EOF`,
		`redirect to https://evil.example/?session=1 refused`:                        `redirect to https://evil.example/ refused`,
		`dial tcp 203.0.113.1:443: i/o timeout`:                                      `dial tcp 203.0.113.1:443: i/o timeout`,
		`Get "https://a:b@[::1:bad/x?y=z": parse error`:                              `Get "https://[::1:bad/x": parse error`,
	}
	for in, want := range cases {
		if got := SanitizeMonitorError(in); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}

// Buckets count probes: an echo each for icmp, one per run otherwise, so
// loss reads the same across a method switch; a bucket written before the
// counts existed merges as one probe per run.
func TestMonitorRollupCountsProbes(t *testing.T) {
	var b MonitorRollup
	b.addResult(MonitorResultRecord{MonitorResult: model.MonitorResult{Success: true, LatencyMs: 20, Sent: 5, Lost: 1}})
	b.addResult(MonitorResultRecord{MonitorResult: model.MonitorResult{Success: false, Sent: 5, Lost: 5}})
	b.addResult(MonitorResultRecord{MonitorResult: model.MonitorResult{Success: false}})
	b.addResult(MonitorResultRecord{MonitorResult: model.MonitorResult{Success: true, LatencyMs: 30}})
	if b.N != 4 || b.F != 2 || b.S != 12 || b.L != 7 {
		t.Fatalf("bucket = %+v", b)
	}
	if loss, ok := b.Loss(); !ok || math.Abs(loss-7.0/12) > 1e-9 {
		t.Fatalf("loss = %v", loss)
	}
	old := MonitorRollup{N: 4, F: 1}
	if loss, _ := old.Loss(); loss != 0.25 {
		t.Fatalf("a pre-M2a bucket's loss = %v", loss)
	}
	merged := old
	merged.Merge(b)
	if merged.S != 16 || merged.L != 8 {
		t.Fatalf("old merged with new = %+v", merged)
	}
	merged = b
	merged.Merge(old)
	if merged.S != 16 || merged.L != 8 {
		t.Fatalf("new merged with old = %+v", merged)
	}
	var empty MonitorRollup
	empty.Merge(old)
	if empty.S != 0 || empty.N != 4 {
		t.Fatalf("old into empty = %+v", empty)
	}
	if _, ok := (MonitorRollup{}).Loss(); ok {
		t.Fatal("an empty bucket has a loss")
	}
}

// A run with a reason is stored and shown but counted nowhere: not in the
// rollups, not in the streak. Both placements agree.
func TestUnknownRunsCountNowhere(t *testing.T) {
	for _, hot := range []bool{false, true} {
		dir := t.TempDir()
		var s *Store
		if hot {
			s = openHotStore(t, dir)
		} else {
			var err error
			if s, err = Open(filepath.Join(dir, "state.json")); err != nil {
				t.Fatal(err)
			}
		}
		seedMonitor(t, s, model.Monitor{ID: "mon-p", Type: model.MonitorTypeICMP, NodeIDs: []string{"node-a"}})
		now := time.Now().UTC().Truncate(time.Minute)
		results := []model.MonitorResult{
			{MonitorID: "mon-p", At: now.Add(-5 * time.Minute), Reason: model.PathReasonICMPNotPermitted},
			{MonitorID: "mon-p", At: now.Add(-4 * time.Minute), Reason: model.PathReasonICMPNotPermitted},
		}
		if _, err := s.IngestAgentMonitorResults("node-a", results, now); err != nil {
			t.Fatal(err)
		}
		latest, ok, err := s.MonitorLatest("mon-p", "node-a")
		if err != nil || !ok || latest.FailStreak != 0 || latest.Unknown == nil || latest.Reason != model.PathReasonICMPNotPermitted || latest.Held != 2 {
			t.Fatalf("hot=%v only unknown runs: %+v", hot, latest)
		}
		more := []model.MonitorResult{
			{MonitorID: "mon-p", At: now.Add(-3 * time.Minute), Sent: 5, Lost: 5},
			{MonitorID: "mon-p", At: now.Add(-2 * time.Minute), Reason: model.PathReasonICMPNotPermitted},
			{MonitorID: "mon-p", At: now.Add(-time.Minute), Sent: 5, Lost: 5},
		}
		out, err := s.IngestAgentMonitorResults("node-a", more, now)
		if err != nil {
			t.Fatal(err)
		}
		if !out[0].NeverSucceeded || out[0].PriorFailStreak != 0 || out[2].PriorFailStreak != 1 {
			t.Fatalf("hot=%v outcomes = %+v", hot, out)
		}
		latest, _, _ = s.MonitorLatest("mon-p", "node-a")
		if latest.FailStreak != 2 || latest.Unknown != nil || latest.Reason != "" || !latest.LastOKAt.IsZero() {
			t.Fatalf("hot=%v after real runs: %+v", hot, latest)
		}
		rows, _ := s.MonitorPairResults("mon-p", "node-a", 0)
		if len(rows) != 5 || rows[3].Reason != model.PathReasonICMPNotPermitted || rows[4].Sent != 5 {
			t.Fatalf("hot=%v rows = %+v", hot, rows)
		}
		pair := MonitorPair{MonitorID: "mon-p", NodeID: "node-a"}
		sums, err := s.MonitorRollupSummaries([]MonitorPair{pair}, MonitorRollupFine, now.Add(-time.Hour), now.Add(-30*time.Minute), now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if cur := sums[pair].Cur; cur.N != 2 || cur.F != 2 || cur.S != 10 || cur.L != 10 {
			t.Fatalf("hot=%v rollup = %+v", hot, cur)
		}
		raw, err := s.MonitorRowSummaries([]MonitorPair{pair}, now.Add(-time.Hour), now.Add(-30*time.Minute), now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if cur := raw[pair].Cur; cur.N != 2 || cur.S != 10 {
			t.Fatalf("hot=%v row summary = %+v", hot, cur)
		}
		s.Close()
	}
}

// Secret header values are encrypted in the state file and come back on
// reopen; plain headers and every other field stay readable.
func TestMonitorSecretHeadersEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	c := testCipher(t)
	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	const secretValue = "Bearer at-rest-s3cr3t"
	if err := s.UpsertMonitor(model.Monitor{ID: "mon-h", Name: "h", Type: model.MonitorTypeHTTP, Target: "https://example.com/", SecretsOrigin: "https://example.com:443",
		Headers: []model.MonitorHeader{{Name: "Authorization", Value: secretValue, Secret: true}, {Name: "Accept", Value: "text/plain"}}}); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disk), "s3cr3t") || !strings.Contains(string(disk), "text/plain") || !strings.Contains(string(disk), "Authorization") {
		t.Fatalf("state file: secret plaintext present or plain fields missing")
	}
	if live, _ := s.Monitor("mon-h"); live.Headers[0].Value != secretValue {
		t.Fatalf("the live state must stay plaintext: %+v", live.Headers)
	}
	s.Close()
	s2, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	m, ok := s2.Monitor("mon-h")
	if !ok || m.Headers[0].Value != secretValue || m.Headers[1].Value != "text/plain" {
		t.Fatalf("reopened = %+v", m.Headers)
	}
}

// A node's probe facts are written only when they change.
func TestSetNodeProbeFacts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.UpsertNode(model.Node{ID: "n1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeProbeFacts("n1", []string{"icmp", "tcp"}, map[string]string{"beacon": "refused_by_node"}); err != nil {
		t.Fatal(err)
	}
	n, _ := s.Node("n1")
	if len(n.ProbeMethods) != 2 || n.ProbeRefusals["beacon"] != "refused_by_node" {
		t.Fatalf("node = %+v", n)
	}
	if err := s.SetNodeProbeFacts("n1", nil, nil); err != nil {
		t.Fatal(err)
	}
	if n, _ = s.Node("n1"); n.ProbeMethods != nil || n.ProbeRefusals != nil {
		t.Fatalf("an older agent's report keeps %+v", n)
	}
	if err := s.SetNodeProbeFacts("missing", nil, nil); err == nil {
		t.Fatal("a missing node accepted")
	}
}
