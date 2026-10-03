package server

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func fleetNodeID(i int) string   { return fmt.Sprintf("node-%02d", i) }
func fleetNodeName(i int) string { return fmt.Sprintf("edge-%02d", i) }

// seedFleetNode stores an enrolled node whose token hash takes one PBKDF2
// iteration instead of 210,000. Enrollment is not what the fleet test
// measures, and at full cost 34 enrollments and 34 first verifications take
// over a minute under the race detector. VerifySecret honours the iteration
// count the hash names, so authentication still runs for real.
func seedFleetNode(t *testing.T, st *store.Store, id, name string) string {
	t.Helper()
	token := "fleet-token-" + id
	salt := []byte("fleet-salt-" + id)
	key, err := pbkdf2.Key(sha256.New, token, salt, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("pbkdf2-sha256$1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	if err := st.UpsertNode(model.Node{ID: id, Name: name, TokenHash: hash, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	return token
}

// TestFleetWideMonitorNeverRewritesStateFile runs one monitor on every node
// of a 34-node fleet at the 30 s default for ten minutes of probes, on the
// production storage layout (state.json with the bolt hot store). Half the
// nodes post one result per request, as every released agent does; the
// other half post through the batch route. Results flap, fail for good, and
// recover, and not one of the 680 results rewrites state.json: before the
// move every pair owed a whole-file save on each flip, on its second
// failure, and every five minutes.
//
// The alert hold behaves as a104 shipped it (two failures in a row, one
// recovery after a page, nodes named by name), and its streaks survive a
// crash: a node still down when the control plane dies is owed its recovery
// afterwards and is not paged again.
func TestFleetWideMonitorNeverRewritesStateFile(t *testing.T) {
	const fleet, rounds = 34, 20
	dir := t.TempDir()
	f := openIngestFixture(t, dir)
	t.Cleanup(func() { _ = f.st.Close() })
	cookies, csrf := loginSession(t, f.handler)
	tokens := make([]string, fleet)
	for i := range tokens {
		tokens[i] = seedFleetNode(t, f.st, fleetNodeID(i), fleetNodeName(i))
	}
	monID := createAllNodesMonitor(t, f.handler, cookies, csrf, "api")
	notices := captureTypedNotices(f.srv)

	healthy := func(node, round int) bool {
		switch node {
		case 3: // flaps every probe: never two failures in a row
			return round%2 == 0
		case 5: // down for good from round 6
			return round < 6
		case 8: // down for rounds 10 to 14
			return round < 10 || round >= 15
		}
		return true
	}
	send := func(handler http.Handler, node int, at time.Time, ok bool) {
		t.Helper()
		result := resultJSON(monID, at, ok, map[bool]string{false: "conn refused"}[ok])
		if node%2 == 0 {
			rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/monitor-result", `{"node_id":"`+fleetNodeID(node)+`","result":`+result+`}`, tokens[node])
			if rec.Code != http.StatusOK || decodeIngest(t, rec.Body.Bytes()).Accepted != 1 {
				t.Fatalf("single result from %s: %d %s", fleetNodeID(node), rec.Code, rec.Body.String())
			}
			return
		}
		postBatch(t, handler, fleetNodeID(node), tokens[node], result)
	}
	type page struct {
		round int
		event string
		title string
	}
	var pages []page
	takePages := func(srv *Server, round int) {
		srv.flushAlertDigests()
		for _, n := range *notices {
			pages = append(pages, page{round: round, event: n.eventType, title: n.title})
		}
		*notices = nil
	}

	// Each agent fetches its monitors before it probes. That first
	// authenticated request records the token's last use, a whole-state write
	// every agent request owes once per nodeTokenTouchInterval whether or not
	// it runs monitors, so it is made before the watch starts.
	for i, token := range tokens {
		req, _ := http.NewRequest(http.MethodGet, "/api/agent/monitors?node_id="+fleetNodeID(i), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if rec := serveReq(f.handler, req); rec.Code != http.StatusOK {
			t.Fatalf("monitor fetch for %s: %d", fleetNodeID(i), rec.Code)
		}
	}

	writes := watchStateFile(t, f.statePath())
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for round := 0; round < rounds; round++ {
		at := base.Add(time.Duration(round) * 30 * time.Second)
		for node := 0; node < fleet; node++ {
			send(f.handler, node, at, healthy(node, round))
			writes.check()
		}
		takePages(f.srv, round)
	}
	if n := writes.take(); n != 0 {
		t.Fatalf("%d results rewrote state.json %d times, want 0", fleet*rounds, n)
	}
	want := []page{
		{7, EventMonitorDown, "Monitor down: api on edge-05"},
		{11, EventMonitorDown, "Monitor down: api on edge-08"},
		{15, EventMonitorRecovered, "Monitor recovered: api on edge-08"},
	}
	if fmt.Sprint(pages) != fmt.Sprint(want) {
		t.Fatalf("pages = %+v\nwant  %+v", pages, want)
	}

	// The list reads every pair's latest record from the hot store.
	res := doJSON(t, f.handler, http.MethodGet, "/api/monitors", "", cookies, "")
	var list []monitorListEntry
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil || len(list) != 1 {
		t.Fatalf("monitors list: %v %+v", err, list)
	}
	res.Body.Close()
	latest := list[0].Latest
	if len(latest) != fleet {
		t.Fatalf("latest pairs = %d, want %d", len(latest), fleet)
	}
	if l := latest[5]; l.NodeID != fleetNodeID(5) || l.Success || l.FailStreak != rounds-6 || !l.Since.Equal(base.Add(6*30*time.Second)) {
		t.Fatalf("edge-05 latest: %+v", l)
	}
	if rows, err := f.st.MonitorPairResults(monID, fleetNodeID(5), 0); err != nil || len(rows) != rounds {
		t.Fatalf("edge-05 holds %d rows (err=%v), want %d", len(rows), err, rounds)
	}

	// Crash: the files as they stand, copied while the store is still open.
	crashDir := t.TempDir()
	copyStateFiles(t, dir, crashDir)
	restarted := openIngestFixture(t, crashDir)
	defer restarted.st.Close()
	notices = captureTypedNotices(restarted.srv)
	pages = nil
	writes = watchStateFile(t, restarted.statePath())
	at := base.Add(rounds * 30 * time.Second)
	send(restarted.handler, 5, at, false) // still down: no second page
	send(restarted.handler, 9, at, false) // one failure on a healthy node: held
	takePages(restarted.srv, rounds)
	at = at.Add(30 * time.Second)
	send(restarted.handler, 5, at, true) // owed its recovery
	takePages(restarted.srv, rounds+1)
	if n := writes.take(); n != 0 {
		t.Fatalf("results after the restart rewrote state.json %d times", n)
	}
	want = []page{{rounds + 1, EventMonitorRecovered, "Monitor recovered: api on edge-05"}}
	if fmt.Sprint(pages) != fmt.Sprint(want) {
		t.Fatalf("pages after the crash = %+v\nwant  %+v", pages, want)
	}
}
