package server

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A node whose clock runs behind the control plane by more than
// nodeOfflineThreshold used to have every inventory dropped on arrival:
// liveSingBoxInventories judged freshness by the agent's own stamp, so the
// node's lines never reached the read model (legend-sg, about 130 s behind,
// 2026-10-03). The inventory now carries the time it arrived.
func TestALaggingNodeClockKeepsItsLinesInTheReadModel(t *testing.T) {
	f := openIngestFixture(t, t.TempDir())
	cookies, csrf := loginSession(t, f.handler)
	token := enrollNamedNodeToken(t, f.handler, cookies, csrf, "node-a", "Node A")

	now := time.Date(2026, 10, 3, 16, 24, 32, 0, time.UTC)
	f.srv.now = func() time.Time { return now }
	logs := &bytes.Buffer{}
	f.srv.logger = log.New(logs, "", 0)

	post := func(stamped time.Time) {
		t.Helper()
		body := fmt.Sprintf(`{"node_id":"node-a","inventory":{"status":"ok","at":%q,"nodes":[{"name":"VLESS-REALITY-17891.json","protocol":"vless","port":"17891"}]}}`,
			stamped.Format(time.RFC3339Nano))
		if rec := doAgentRaw(t, f.handler, http.MethodPost, "/api/agent/singbox-inventory", body, token); rec.Code != http.StatusOK {
			t.Fatalf("inventory: %d %s", rec.Code, rec.Body.String())
		}
	}
	linesOf := func(nodeID string) int {
		for _, g := range f.srv.buildLineGroups() {
			if g.NodeID == nodeID {
				return len(g.Lines)
			}
		}
		return 0
	}

	post(now.Add(-130 * time.Second))
	if got := linesOf("node-a"); got != 1 {
		t.Fatalf("lines for a node stamping 130 s behind = %d, want 1", got)
	}
	if n := strings.Count(logs.String(), "stamps its inventory 2m10s behind the control plane"); n != 1 {
		t.Fatalf("skew notices = %d, want 1; log:\n%s", n, logs.String())
	}

	// The next report a minute later is still behind; the notice stays quiet
	// within the hour, and the lines stay.
	now = now.Add(time.Minute)
	post(now.Add(-130 * time.Second))
	if got := linesOf("node-a"); got != 1 {
		t.Fatalf("lines after a second lagging report = %d, want 1", got)
	}
	if n := strings.Count(logs.String(), "stamps its inventory"); n != 1 {
		t.Fatalf("skew notices within the hour = %d, want 1", n)
	}

	// An hour on, the notice repeats once.
	now = now.Add(time.Hour)
	post(now.Add(-130 * time.Second))
	if n := strings.Count(logs.String(), "stamps its inventory"); n != 2 {
		t.Fatalf("skew notices after an hour = %d, want 2", n)
	}

	// The mirror still expires a node that stops reporting, judged by the
	// control plane's clock.
	now = now.Add(nodeOfflineThreshold + time.Second)
	if got := linesOf("node-a"); got != 0 {
		t.Fatalf("lines after %s without a report = %d, want 0", nodeOfflineThreshold, got)
	}
}

// A clock within the notice band says nothing, and a clock ahead of the
// control plane is named as ahead.
func TestInventoryClockNoticeBandAndDirection(t *testing.T) {
	srv := openIngestFixture(t, t.TempDir()).srv
	logs := &bytes.Buffer{}
	srv.logger = log.New(logs, "", 0)
	now := time.Date(2026, 10, 3, 16, 0, 0, 0, time.UTC)

	srv.noteSingBoxInventoryClock("node-ok", now.Add(-29*time.Second), now)
	srv.noteSingBoxInventoryClock("node-zero", time.Time{}, now)
	if logs.Len() != 0 {
		t.Fatalf("notice inside the band or without a stamp: %s", logs.String())
	}
	srv.noteSingBoxInventoryClock("node-fast", now.Add(45*time.Second), now)
	if !strings.Contains(logs.String(), "node node-fast stamps its inventory 45s ahead of the control plane") {
		t.Fatalf("ahead notice missing: %s", logs.String())
	}
}
