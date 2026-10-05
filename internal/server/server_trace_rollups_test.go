package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/tracestore"
)

// Rollups read tests (design 26 R1, V6). The rollups are fleet-wide
// aggregates, so the cases that matter are scope (a token confined to one
// node must never see another node's counts) and honesty (sums add up, the
// unattributed user stays in the answer, and no destination ever leaves).

// rollupsT0 is on a day boundary, so every step size starts a step there.
var rollupsT0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func rollupRecord(nodeID string, logID uint32, at time.Time, userID, reason string) model.ConnRecord {
	return model.ConnRecord{
		NodeID: nodeID, CoreGeneration: 1, LogID: logID, UserID: userID,
		LineUUID: "line-1", DstHost: "secret.example.org", DstPort: 443,
		StartedAt: at, EndedAt: at.Add(time.Second), CloseReason: reason,
		BytesKnown: true, Upload: 10, Download: 100,
	}
}

func appendRollupRecords(t *testing.T, ts *tracestore.Store, records ...model.ConnRecord) {
	t.Helper()
	if _, err := ts.AppendRecords(records); err != nil {
		t.Fatal(err)
	}
}

func getRollups(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string, q url.Values) (int, traceRollupsView, string) {
	t.Helper()
	res := doTrace(t, handler, http.MethodGet, "/api/trace/rollups?"+q.Encode(), cookies, csrf, nil)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var view traceRollupsView
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
	}
	return res.StatusCode, view, string(body)
}

func rollupsQuery(groupBy string, since, until time.Time) url.Values {
	q := url.Values{"group_by": {groupBy}}
	if !since.IsZero() {
		q.Set("since", since.Format(time.RFC3339))
	}
	if !until.IsZero() {
		q.Set("until", until.Format(time.RFC3339))
	}
	return q
}

func seriesByKey(view traceRollupsView) map[string]traceRollupSeriesView {
	out := map[string]traceRollupSeriesView{}
	for _, s := range view.Series {
		out[s.Key] = s
	}
	return out
}

func TestRollupsNeedLogRead(t *testing.T) {
	handler, st, _ := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"node:read"}, nil)
	res := doBearerJSON(t, handler, http.MethodGet, "/api/trace/rollups?group_by=node", "", token)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a token without log:read read rollups: %d", res.StatusCode)
	}
}

func TestRollupsHideNodesOutsideTheCallersScope(t *testing.T) {
	handler, st, ts := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	traceNode(t, st, "node-b")
	appendRollupRecords(t, ts,
		rollupRecord("node-a", 1, rollupsT0.Add(time.Minute), "u1", model.CloseEOF),
		rollupRecord("node-b", 2, rollupsT0.Add(-48*time.Hour), "u1", model.CloseEOF),
		rollupRecord("node-b", 3, rollupsT0.Add(2*time.Minute), "u1", model.CloseEOF),
	)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"log:read"}, []string{"node-a"})
	read := func(q url.Values) traceRollupsView {
		t.Helper()
		res := doBearerJSON(t, handler, http.MethodGet, "/api/trace/rollups?"+q.Encode(), "", token)
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("scoped read: %d %s", res.StatusCode, body)
		}
		if strings.Contains(string(body), "node-b") {
			t.Fatalf("a node-a token sees node-b: %s", body)
		}
		var view traceRollupsView
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	q := rollupsQuery("node", rollupsT0, rollupsT0.Add(time.Hour))
	view := read(q)
	if len(view.Series) != 1 || view.Series[0].Key != "node-a" {
		t.Fatalf("series = %+v, want node-a only", view.Series)
	}
	// The horizon is node-a's, not node-b's older history.
	if !view.RetainedFrom.Equal(rollupsT0) {
		t.Fatalf("retained_from = %v, want node-a's oldest bucket %v", view.RetainedFrom, rollupsT0)
	}
	// Grouped by user, node-b's traffic for the same user is not counted.
	view = read(rollupsQuery("user", rollupsT0, rollupsT0.Add(time.Hour)))
	if len(view.Series) != 1 || view.Series[0].Connections[0] != 1 {
		t.Fatalf("user series = %+v, want one connection from node-a", view.Series)
	}
	// Naming node-b is refused before the handler, as on every route that
	// takes node_id, and the refusal does not name it back.
	q.Set("node_id", "node-b")
	res := doBearerJSON(t, handler, http.MethodGet, "/api/trace/rollups?"+q.Encode(), "", token)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || strings.Contains(string(body), "node-b") {
		t.Fatalf("a node-a token naming node-b: %d %s", res.StatusCode, body)
	}

	// A caller whose allowlist matches no node gets an empty answer, not a 403:
	// a narrow allowlist is legitimate.
	nobody := createPAT(t, handler, cookies, csrf, []string{"log:read"}, []string{"node-gone"})
	res = doBearerJSON(t, handler, http.MethodGet, "/api/trace/rollups?group_by=node", "", nobody)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	var empty traceRollupsView
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &empty) != nil || len(empty.Series) != 0 || !empty.RetainedFrom.IsZero() {
		t.Fatalf("a token that sees no node: %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), `"series":[]`) {
		t.Fatalf("series must be an empty array, not null: %s", body)
	}
}

func TestRollupsStepFollowsTheWindow(t *testing.T) {
	handler, _, _ := newTraceTestServer(t)
	cookies, csrf := loginSession(t, handler)
	until := rollupsT0
	for window, want := range map[time.Duration]int64{
		24 * time.Hour:       300,
		7 * 24 * time.Hour:   300,
		30 * 24 * time.Hour:  3600,
		90 * 24 * time.Hour:  3600,
		120 * 24 * time.Hour: 86400,
		400 * 24 * time.Hour: 86400,
	} {
		code, view, body := getRollups(t, handler, cookies, csrf, rollupsQuery("node", until.Add(-window), until))
		if code != http.StatusOK {
			t.Fatalf("window %s: %d %s", window, code, body)
		}
		if view.StepSeconds != want || view.ResolutionSeconds != 300 || view.Tier != "5m" {
			t.Errorf("window %s: step %d resolution %d tier %q, want step %d from the 5m tier", window, view.StepSeconds, view.ResolutionSeconds, view.Tier, want)
		}
	}
	// Without since and until the window is the last day.
	code, view, _ := getRollups(t, handler, cookies, csrf, url.Values{"group_by": {"node"}})
	if code != http.StatusOK || view.Until.Sub(view.Since) > 24*time.Hour+5*time.Minute || view.StepSeconds != 300 {
		t.Fatalf("default window: %d %v to %v step %d", code, view.Since, view.Until, view.StepSeconds)
	}
}

func TestRollupsGroupByNodeSumsBucketsIntoSteps(t *testing.T) {
	handler, st, ts := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	traceNode(t, st, "node-b")
	// Thirty days back gives an hourly step. Three buckets inside one hour on
	// node-a, one an hour later, one on node-b.
	at := rollupsT0.Add(-24 * time.Hour)
	appendRollupRecords(t, ts,
		rollupRecord("node-a", 1, at.Add(1*time.Minute), "u1", model.CloseEOF),
		rollupRecord("node-a", 2, at.Add(20*time.Minute), "u1", model.CloseReset),
		rollupRecord("node-a", 3, at.Add(55*time.Minute), "u2", model.CloseEOF),
		rollupRecord("node-a", 4, at.Add(65*time.Minute), "u2", model.CloseEOF),
		rollupRecord("node-b", 5, at.Add(10*time.Minute), "u1", model.CloseTimeout),
	)
	cookies, csrf := loginSession(t, handler)
	// Since mid-step: the leading step is still whole.
	code, view, body := getRollups(t, handler, cookies, csrf, rollupsQuery("node", rollupsT0.Add(-30*24*time.Hour+30*time.Minute), rollupsT0))
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if view.StepSeconds != 3600 || !view.Since.Equal(rollupsT0.Add(-30*24*time.Hour)) {
		t.Fatalf("step %d since %v, want 3600 from the truncated start", view.StepSeconds, view.Since)
	}
	series := seriesByKey(view)
	a, b := series["node-a"], series["node-b"]
	if len(view.Series) != 2 || view.Series[0].Key != "node-a" {
		t.Fatalf("series order = %+v, want node-a (four connections) first", view.Series)
	}
	if fmt.Sprint(a.T) != fmt.Sprint([]int64{at.Unix(), at.Add(time.Hour).Unix()}) {
		t.Fatalf("node-a t = %v", a.T)
	}
	if fmt.Sprint(a.Connections) != "[3 1]" || fmt.Sprint(a.BytesKnownCount) != "[3 1]" ||
		fmt.Sprint(a.Upload) != "[30 10]" || fmt.Sprint(a.Download) != "[300 100]" {
		t.Fatalf("node-a = %+v", a)
	}
	if fmt.Sprint(a.CloseReasons[model.CloseEOF]) != "[2 1]" || fmt.Sprint(a.CloseReasons[model.CloseReset]) != "[1 0]" {
		t.Fatalf("node-a reasons = %v; a reason absent from a step reads zero there", a.CloseReasons)
	}
	if fmt.Sprint(b.Connections) != "[1]" || fmt.Sprint(b.CloseReasons[model.CloseTimeout]) != "[1]" {
		t.Fatalf("node-b = %+v", b)
	}
}

func TestRollupsReasonsSumToConnections(t *testing.T) {
	handler, st, ts := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	reasons := []string{model.CloseEOF, model.CloseReset, model.CloseTimeout, ""}
	records := []model.ConnRecord{}
	for i := range 20 {
		records = append(records, rollupRecord("node-a", uint32(i+1), rollupsT0.Add(time.Duration(i)*4*time.Minute), "u1", reasons[i%len(reasons)]))
	}
	appendRollupRecords(t, ts, records...)
	cookies, csrf := loginSession(t, handler)
	q := rollupsQuery("reason", rollupsT0, rollupsT0.Add(2*time.Hour))
	code, byReason, body := getRollups(t, handler, cookies, csrf, q)
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	var reasonTotal int64
	for _, s := range byReason.Series {
		if s.BytesKnownCount != nil || s.Upload != nil || s.Download != nil || s.CloseReasons != nil {
			t.Fatalf("a reason series carries more than t and connections: %+v", s)
		}
		if len(s.T) != len(s.Connections) {
			t.Fatalf("reason %q: t and connections are not aligned", s.Key)
		}
		for _, n := range s.Connections {
			reasonTotal += n
		}
	}
	q.Set("group_by", "node")
	_, byNode, _ := getRollups(t, handler, cookies, csrf, q)
	var nodeTotal, nodeReasonTotal int64
	for _, s := range byNode.Series {
		for _, n := range s.Connections {
			nodeTotal += n
		}
		for _, col := range s.CloseReasons {
			for _, n := range col {
				nodeReasonTotal += n
			}
		}
	}
	if reasonTotal != 20 || nodeTotal != 20 || nodeReasonTotal != 20 {
		t.Fatalf("reason series sum to %d, node series to %d with reasons %d; want 20 each", reasonTotal, nodeTotal, nodeReasonTotal)
	}
}

func TestRollupsKeepUnattributedUsers(t *testing.T) {
	handler, st, ts := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	appendRollupRecords(t, ts,
		rollupRecord("node-a", 1, rollupsT0, "u1", model.CloseEOF),
		rollupRecord("node-a", 2, rollupsT0, "", model.CloseEOF),
		rollupRecord("node-a", 3, rollupsT0, "", model.CloseEOF),
	)
	cookies, csrf := loginSession(t, handler)
	code, view, body := getRollups(t, handler, cookies, csrf, rollupsQuery("user", rollupsT0, rollupsT0.Add(time.Hour)))
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if !strings.Contains(body, `"key":""`) {
		t.Fatalf("the unattributed key is missing from the wire: %s", body)
	}
	series := seriesByKey(view)
	if fmt.Sprint(series[""].Connections) != "[2]" || fmt.Sprint(series["u1"].Connections) != "[1]" {
		t.Fatalf("series = %+v, want the unattributed two beside u1's one", view.Series)
	}
}

func TestRollupsRefuseABadWindowOrGrouping(t *testing.T) {
	handler, _, _ := newTraceTestServer(t)
	cookies, csrf := loginSession(t, handler)
	for name, q := range map[string]url.Values{
		"no grouping":          {"since": {rollupsT0.Format(time.RFC3339)}},
		"a destination":        rollupsQuery("dst_host", rollupsT0, rollupsT0.Add(time.Hour)),
		"since after until":    rollupsQuery("node", rollupsT0.Add(time.Hour), rollupsT0),
		"since equal to until": rollupsQuery("node", rollupsT0, rollupsT0),
		"over 400 days":        rollupsQuery("node", rollupsT0.Add(-401*24*time.Hour), rollupsT0),
		"since not RFC 3339":   {"group_by": {"node"}, "since": {"yesterday"}},
		"until not RFC 3339":   {"group_by": {"node"}, "until": {"1783382400"}},
		"until past 2200":      rollupsQuery("node", time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2300, 1, 2, 0, 0, 0, 0, time.UTC)),
		"since before 1970":    rollupsQuery("node", time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(1970, 1, 2, 0, 0, 0, 0, time.UTC)),
	} {
		if code, _, body := getRollups(t, handler, cookies, csrf, q); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, code, body)
		}
	}
	res := doTrace(t, handler, http.MethodPost, "/api/trace/rollups?group_by=node", cookies, csrf, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", res.StatusCode)
	}
}

func TestRollupsTruncateToTheLargestSeries(t *testing.T) {
	handler, st, ts := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	records := []model.ConnRecord{}
	id := uint32(0)
	for u := range tracestore.DefaultRollupMaxSeries + 5 {
		n := 1
		if u == 0 {
			n = 3 // the largest series
		}
		for range n {
			id++
			records = append(records, rollupRecord("node-a", id, rollupsT0.Add(time.Duration(id)*time.Second), fmt.Sprintf("user-%03d", u), model.CloseEOF))
		}
	}
	appendRollupRecords(t, ts, records...)
	cookies, csrf := loginSession(t, handler)
	code, view, body := getRollups(t, handler, cookies, csrf, rollupsQuery("user", rollupsT0, rollupsT0.Add(time.Hour)))
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if !view.Truncated || len(view.Series) != tracestore.DefaultRollupMaxSeries {
		t.Fatalf("truncated=%v series=%d, want true and %d", view.Truncated, len(view.Series), tracestore.DefaultRollupMaxSeries)
	}
	if view.Series[0].Key != "user-000" {
		t.Fatalf("first series %q, want the largest, user-000", view.Series[0].Key)
	}
}

func TestRollupsCarryNoDestination(t *testing.T) {
	handler, st, ts := newTraceTestServer(t)
	traceNode(t, st, "node-a")
	appendRollupRecords(t, ts, rollupRecord("node-a", 1, rollupsT0, "u1", model.CloseEOF))
	cookies, csrf := loginSession(t, handler)
	for _, groupBy := range []string{"node", "line", "user", "reason"} {
		code, view, body := getRollups(t, handler, cookies, csrf, rollupsQuery(groupBy, rollupsT0, rollupsT0.Add(time.Hour)))
		if code != http.StatusOK || len(view.Series) == 0 {
			t.Fatalf("%s: %d %s", groupBy, code, body)
		}
		if strings.Contains(body, "dst") || strings.Contains(body, "secret.example.org") {
			t.Fatalf("group_by=%s carries a destination: %s", groupBy, body)
		}
	}
}
