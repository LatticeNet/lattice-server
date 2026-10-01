package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Design 23 section 5: the home tile and the Tasks head read counts instead of
// every task, the Tasks list asks the server for one filtered page, the
// results poll asks for the tasks on screen, and the audit Changes layer
// drops node flips inside the scan. Every read keeps the confinement of the
// endpoint it extends.

// taskFixtureQueueDeadline is long enough that only the fixture meant to
// expire does.
const taskFixtureQueueDeadline = 72 * time.Hour

// seedTaskStates writes one task in every state the console can show, plus
// runs whose outcome depends on their reruns, plus two tasks that touch
// node-c, which the confined principal in these tests may not read. Times are
// relative to now because the view derives stalled and expired from the
// server's clock.
func seedTaskStates(t *testing.T, st *store.Store, now time.Time) {
	t.Helper()
	st.SetTaskQueueDeadline(taskFixtureQueueDeadline)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	create := func(task model.Task) {
		t.Helper()
		if task.Interpreter == "" {
			task.Interpreter = "sh"
		}
		if task.Script == "" {
			task.Script = "echo " + task.ID
		}
		if task.Status == "" {
			task.Status = model.TaskLeased
		}
		if err := st.CreateTask(task); err != nil {
			t.Fatal(err)
		}
	}
	result := func(taskID, nodeID string, exit int, finished time.Time) {
		t.Helper()
		if err := st.AddTaskResult(model.TaskResult{
			TaskID: taskID, NodeID: nodeID, ExitCode: exit,
			Stdout: "out " + taskID, StartedAt: finished.Add(-time.Second), FinishedAt: finished,
		}); err != nil {
			t.Fatal(err)
		}
	}
	a := []string{"node-a"}

	create(model.Task{ID: "t-queued", Targets: a, Status: model.TaskQueued, CreatedAt: ago(time.Hour)})
	create(model.Task{ID: "t-running", Targets: a, TimeoutSec: 3600, CreatedAt: ago(10 * time.Minute),
		TargetLeases: map[string]model.TaskLease{"node-a": {LeaseID: "l-run", StartedAt: ago(5 * time.Minute)}}})
	// Leased two hours ago with a 60 s timeout and no answer: the lease is
	// dead and nothing else runs it, which the lease logic calls stalled.
	create(model.Task{ID: "t-stalled", Targets: a, TimeoutSec: 60, CreatedAt: ago(2 * time.Hour),
		TargetLeases: map[string]model.TaskLease{"node-a": {LeaseID: "l-dead", StartedAt: ago(2 * time.Hour)}}})
	// Never delivered and past the 72 h queue deadline eight hours ago.
	create(model.Task{ID: "t-expired", Targets: a, Status: model.TaskQueued, CreatedAt: ago(80 * time.Hour)})
	create(model.Task{ID: "t-finished", Targets: a, ApprovalID: "ap-1", CreatedAt: ago(3 * time.Hour)})
	result("t-finished", "node-a", 0, ago(2*time.Hour))
	create(model.Task{ID: "t-failed", Targets: a, CreatedAt: ago(4 * time.Hour)})
	result("t-failed", "node-a", 1, ago(3*time.Hour))
	create(model.Task{ID: "t-failed-25h", Targets: a, CreatedAt: ago(26 * time.Hour)})
	result("t-failed-25h", "node-a", 2, ago(25*time.Hour))
	create(model.Task{ID: "t-cancelled", Targets: a, Status: model.TaskQueued, CreatedAt: ago(30 * time.Minute)})
	if _, err := st.CancelTask("t-cancelled"); err != nil {
		t.Fatal(err)
	}

	// A fan-out that failed on node-b, whose rerun on node-b then succeeded.
	create(model.Task{ID: "t-fixed", Targets: []string{"node-a", "node-b"}, CreatedAt: ago(5 * time.Hour)})
	result("t-fixed", "node-a", 0, ago(4*time.Hour))
	result("t-fixed", "node-b", 1, ago(4*time.Hour))
	create(model.Task{ID: "t-fixed-rerun", Targets: []string{"node-b"}, RerunOfTaskID: "t-fixed", RerunOfNodeID: "node-b", CreatedAt: ago(2 * time.Hour)})
	result("t-fixed-rerun", "node-b", 0, ago(time.Hour))

	// A failure whose rerun failed again.
	create(model.Task{ID: "t-refailed", Targets: a, CreatedAt: ago(6 * time.Hour)})
	result("t-refailed", "node-a", 1, ago(5*time.Hour))
	create(model.Task{ID: "t-refailed-rerun", Targets: a, RerunOfTaskID: "t-refailed", CreatedAt: ago(3 * time.Hour)})
	result("t-refailed-rerun", "node-a", 1, ago(2*time.Hour))

	// A failure whose rerun is still waiting: the run is not over.
	create(model.Task{ID: "t-retrying", Targets: a, CreatedAt: ago(7 * time.Hour)})
	result("t-retrying", "node-a", 1, ago(6*time.Hour))
	create(model.Task{ID: "t-retrying-rerun", Targets: a, RerunOfTaskID: "t-retrying", Status: model.TaskQueued, CreatedAt: ago(30 * time.Minute)})

	// Outside the confined principal's scope.
	create(model.Task{ID: "t-c-failed", Targets: []string{"node-c"}, CreatedAt: ago(2 * time.Hour)})
	result("t-c-failed", "node-c", 1, ago(time.Hour))
	create(model.Task{ID: "t-c-queued", Targets: []string{"node-c"}, Status: model.TaskQueued, CreatedAt: ago(time.Hour)})
	create(model.Task{ID: "t-ac-failed", Targets: []string{"node-a", "node-c"}, CreatedAt: ago(3 * time.Hour)})
	result("t-ac-failed", "node-a", 0, ago(2*time.Hour))
	result("t-ac-failed", "node-c", 1, ago(2*time.Hour))
}

// taskQueryReader issues GET requests as either the admin session or a
// node-confined bearer token.
type taskQueryReader struct {
	handler http.Handler
	cookies []*http.Cookie
	token   string
}

func (r taskQueryReader) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	var res *http.Response
	if r.token != "" {
		res = doBearerJSON(t, r.handler, http.MethodGet, path, "", r.token)
	} else {
		res = doJSON(t, r.handler, http.MethodGet, path, "", r.cookies, "")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, body
}

func (r taskQueryReader) counts(t *testing.T) taskCountsResponse {
	t.Helper()
	code, body := r.get(t, "/api/tasks/counts")
	if code != http.StatusOK {
		t.Fatalf("GET /api/tasks/counts = %d: %s", code, body)
	}
	var out taskCountsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("counts body: %v: %s", err, body)
	}
	return out
}

func (r taskQueryReader) tasks(t *testing.T, query string) tasksQueryResponse {
	t.Helper()
	code, body := r.get(t, "/api/tasks?"+query)
	if code != http.StatusOK {
		t.Fatalf("GET /api/tasks?%s = %d: %s", query, code, body)
	}
	var out tasksQueryResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("tasks query must be enveloped: %v: %s", err, body)
	}
	return out
}

func newTaskQueryFixture(t *testing.T) (admin, confined taskQueryReader, st *store.Store, now time.Time) {
	t.Helper()
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	token := createPAT(t, handler, cookies, csrf, []string{"task:read", "audit:read"}, []string{"node-a", "node-b"})
	now = time.Now().UTC()
	seedTaskStates(t, st, now)
	return taskQueryReader{handler: handler, cookies: cookies}, taskQueryReader{handler: handler, token: token}, st, now
}

func sortedTaskIDs(views []taskView) []string {
	out := make([]string, 0, len(views))
	for _, v := range views {
		out = append(out, v.ID)
	}
	sort.Strings(out)
	return out
}

func TestTaskCountsCoverEveryStateAndStayConfined(t *testing.T) {
	admin, confined, _, now := newTaskQueryFixture(t)

	cases := []struct {
		name   string
		reader taskQueryReader
		want   taskCountsResponse
	}{
		{
			// Rows: t-queued, t-retrying-rerun and t-c-queued wait; t-running
			// runs; t-stalled stalls. Runs inside 24 h: t-expired, t-finished,
			// t-failed, t-cancelled, t-fixed (its rerun fixed it), t-refailed,
			// t-c-failed and t-ac-failed; of those, four failed. t-failed-25h
			// is outside the window and t-retrying is still going.
			name: "admin", reader: admin,
			want: taskCountsResponse{Queued: 3, Running: 1, Stalled: 1, Failed24h: 4, Finished24h: 8, Total: 17},
		},
		{
			// The same store without every task that touches node-c, including
			// the fan-out whose other target is node-a.
			name: "confined to node-a and node-b", reader: confined,
			want: taskCountsResponse{Queued: 2, Running: 1, Stalled: 1, Failed24h: 2, Finished24h: 6, Total: 14},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.reader.counts(t)
			if got.GeneratedAt.IsZero() || got.GeneratedAt.Before(now) {
				t.Fatalf("generated_at = %v, want the read's own time", got.GeneratedAt)
			}
			got.GeneratedAt = time.Time{}
			if got != tc.want {
				t.Fatalf("counts = %+v\nwant     %+v", got, tc.want)
			}
			// queued, running and stalled are row counts under the list's own
			// status names, so the list must agree with them exactly.
			for status, want := range map[string]int{"queued": tc.want.Queued, "leased": tc.want.Running, "stalled": tc.want.Stalled} {
				if total := tc.reader.tasks(t, "status="+status+"&limit=1").Total; total != want {
					t.Fatalf("GET /api/tasks?status=%s total = %d, counts say %d", status, total, want)
				}
			}
			if total := tc.reader.tasks(t, "limit=1").Total; total != tc.want.Total {
				t.Fatalf("GET /api/tasks total = %d, counts say %d", total, tc.want.Total)
			}
		})
	}
}

func TestTaskCountsWireNamesAndScope(t *testing.T) {
	admin, _, _, _ := newTaskQueryFixture(t)
	code, body := admin.get(t, "/api/tasks/counts")
	if code != http.StatusOK {
		t.Fatalf("counts = %d: %s", code, body)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	want := []string{"queued", "running", "stalled", "pending", "failed_24h", "finished_24h", "total", "generated_at"}
	if len(raw) != len(want) {
		t.Fatalf("counts carries %d fields, want exactly %v: %s", len(raw), want, body)
	}
	for _, key := range want {
		if _, ok := raw[key]; !ok {
			t.Fatalf("counts lacks %q: %s", key, body)
		}
	}

	res := doJSON(t, admin.handler, http.MethodPost, "/api/tasks/counts", "{}", admin.cookies, "")
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed && res.StatusCode != http.StatusForbidden {
		t.Fatalf("POST counts = %d, want a refusal", res.StatusCode)
	}

	// A token without task:read learns nothing, not even a zero.
	cookies, csrf := loginSession(t, admin.handler)
	noRead := createPAT(t, admin.handler, cookies, csrf, []string{"audit:read"}, nil)
	res = doBearerJSON(t, admin.handler, http.MethodGet, "/api/tasks/counts", "", noRead)
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("counts without task:read = %d, want 403", res.StatusCode)
	}
}

func TestTaskListFilters(t *testing.T) {
	admin, confined, _, now := newTaskQueryFixture(t)
	since := url.QueryEscape(now.Add(-90 * time.Minute).Format(time.RFC3339))
	// The same instant written with a +08:00 offset, its plus sign sent as %2B.
	sinceOffset := strings.Replace(now.Add(-90*time.Minute).In(time.FixedZone("UTC+8", 8*3600)).Format(time.RFC3339), "+", "%2B", 1)

	cases := []struct {
		name   string
		reader taskQueryReader
		query  string
		want   []string
	}{
		{"one status", admin, "status=stalled", []string{"t-stalled"}},
		{"status list", admin, "status=queued,leased", []string{"t-c-queued", "t-queued", "t-retrying-rerun", "t-running"}},
		{"derived expired", admin, "status=expired", []string{"t-expired"}},
		{"trailing comma", admin, "status=cancelled,", []string{"t-cancelled"}},
		{"origin rerun", admin, "origin=rerun", []string{"t-fixed-rerun", "t-refailed-rerun", "t-retrying-rerun"}},
		{"origin approval", admin, "origin=approval", []string{"t-finished"}},
		{"status and origin", admin, "status=failed&origin=rerun", []string{"t-refailed-rerun"}},
		// Changed within 90 minutes: created, leased, finished or cancelled
		// since then. t-stalled's lease began two hours ago.
		{"since", admin, "since=" + since, []string{"t-c-failed", "t-c-queued", "t-cancelled", "t-fixed-rerun", "t-queued", "t-retrying-rerun", "t-running"}},
		{"since with an encoded offset", admin, "since=" + sinceOffset, []string{"t-c-failed", "t-c-queued", "t-cancelled", "t-fixed-rerun", "t-queued", "t-retrying-rerun", "t-running"}},
		{"since and node", admin, "since=" + since + "&node_id=node-b", []string{"t-fixed-rerun"}},
		{"node", admin, "node_id=node-c", []string{"t-ac-failed", "t-c-failed", "t-c-queued"}},
		// A confined reader asking about a node outside its scope gets the
		// answer a node with no tasks gets.
		{"confined foreign node", confined, "node_id=node-c", []string{}},
		{"confined failed", confined, "status=failed", []string{"t-failed", "t-failed-25h", "t-fixed", "t-refailed", "t-refailed-rerun", "t-retrying"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.reader.tasks(t, tc.query+"&limit=500")
			ids := sortedTaskIDs(got.Tasks)
			if strings.Join(ids, ",") != strings.Join(tc.want, ",") || got.Total != len(tc.want) {
				t.Fatalf("GET /api/tasks?%s = %v (total %d), want %v", tc.query, ids, got.Total, tc.want)
			}
		})
	}
}

func TestTaskListFiltersRejectUnknownValues(t *testing.T) {
	admin, _, _, _ := newTaskQueryFixture(t)
	for _, query := range []string{
		"status=bogus",
		"status=queued,bogus",
		// The count is named running; the row status it counts is leased.
		"status=running",
		"origin=plugin",
		"since=yesterday",
		"since=2026-09-30",
		// A bare "+" decodes to a space, so an unencoded offset is refused.
		"since=2026-09-30T10:00:00+08:00",
		"limit=0",
		"limit=501",
		"offset=-1",
	} {
		t.Run(query, func(t *testing.T) {
			code, body := admin.get(t, "/api/tasks?"+query)
			if code != http.StatusBadRequest {
				t.Fatalf("GET /api/tasks?%s = %d, want 400: %s", query, code, body)
			}
		})
	}
}

func TestTaskListShapeUnchanged(t *testing.T) {
	admin, _, _, _ := newTaskQueryFixture(t)
	// No parameters: the bare array the dashboard has always unwrapped.
	code, body := admin.get(t, "/api/tasks")
	if code != http.StatusOK {
		t.Fatalf("bare list = %d", code)
	}
	var bare []taskView
	if err := json.Unmarshal(body, &bare); err != nil {
		t.Fatalf("bare list must stay an array: %v", err)
	}
	if len(bare) != 17 {
		t.Fatalf("bare list = %d rows, want 17", len(bare))
	}
	// Counting skips the script digest; every row a list returns carries it.
	for _, v := range append(bare, admin.tasks(t, "status=failed").Tasks...) {
		if v.ScriptSHA256 != scriptSHA256("echo "+v.ID) {
			t.Fatalf("row %s script_sha256 = %q", v.ID, v.ScriptSHA256)
		}
	}
	// Filters and paging: the envelope node_id already used, total before
	// paging.
	page := admin.tasks(t, "status=failed&limit=2&offset=1")
	if page.Total != 8 || len(page.Tasks) != 2 || page.Limit != 2 || page.Offset != 1 {
		t.Fatalf("paged envelope = total %d, %d rows, limit %d, offset %d", page.Total, len(page.Tasks), page.Limit, page.Offset)
	}
}

func TestTaskRunStatusFollowsTheTasksPage(t *testing.T) {
	row := func(id, status string, targets ...string) taskRow {
		return taskRow{task: model.Task{ID: id, Targets: targets}, view: taskView{ID: id, Status: status, Targets: targets}}
	}
	withTarget := func(r taskRow, node, status string) taskRow {
		if r.view.TargetStates == nil {
			r.view.TargetStates = map[string]taskTargetView{}
		}
		r.view.TargetStates[node] = taskTargetView{Status: status}
		return r
	}
	res := func(taskID, nodeID string, exit int) map[taskResultKey]model.TaskResult {
		return map[taskResultKey]model.TaskResult{{taskID, nodeID}: {TaskID: taskID, NodeID: nodeID, ExitCode: exit}}
	}
	cases := []struct {
		name     string
		root     taskRow
		reruns   []taskRow
		results  map[taskResultKey]model.TaskResult
		expected string
	}{
		{"expired outranks everything", row("r", store.TaskExpired, "a"), nil, nil, store.TaskExpired},
		{"a live node keeps the run running", withTarget(withTarget(row("r", model.TaskLeased, "a", "b"), "a", store.TaskStalled), "b", model.TaskLeased), nil, nil, model.TaskLeased},
		{"stalled node", withTarget(row("r", store.TaskStalled, "a"), "a", store.TaskStalled), nil, nil, store.TaskStalled},
		{"cancelled root whose rerun waits", row("r", model.TaskCancelled, "a"), []taskRow{row("r2", model.TaskQueued, "a")}, nil, model.TaskCancelled},
		{"every node cancelled", row("r", model.TaskCancelled, "a"), nil, nil, model.TaskCancelled},
		{"failed result", row("r", model.TaskFailed, "a"), nil, res("r", "a", 3), model.TaskFailed},
		{"failed task without results", row("r", model.TaskFailed, "a", "b"), nil, nil, model.TaskFailed},
		{"rerun fixed the node", row("r", model.TaskFailed, "a"), []taskRow{row("r2", model.TaskFinished, "a")}, res("r2", "a", 0), model.TaskFinished},
		{"rerun still queued", row("r", model.TaskFailed, "a"), []taskRow{row("r2", model.TaskQueued, "a")}, res("r", "a", 1), model.TaskQueued},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attempts := append([]taskRow{tc.root}, tc.reruns...)
			if got := taskRunStatus(tc.root, attempts, tc.results); got != tc.expected {
				t.Fatalf("taskRunStatus = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestTaskRowsCarryOriginAndOnlyReadableApprovalIDs(t *testing.T) {
	admin, confined, st, _ := newTaskQueryFixture(t)
	cookies, csrf := loginSession(t, admin.handler)
	planReader := taskQueryReader{handler: admin.handler, token: createPAT(t, admin.handler, cookies, csrf,
		[]string{"task:read", "netpolicy:admin"}, []string{"node-a", "node-b"})}

	rowsByID := func(r taskQueryReader) map[string]taskView {
		t.Helper()
		code, body := r.get(t, "/api/tasks")
		if code != http.StatusOK {
			t.Fatalf("GET /api/tasks = %d: %s", code, body)
		}
		var rows []taskView
		if err := json.Unmarshal(body, &rows); err != nil {
			t.Fatal(err)
		}
		out := map[string]taskView{}
		for _, row := range rows {
			out[row.ID] = row
		}
		// The enveloped form builds its rows the same way.
		for _, row := range r.tasks(t, "origin=approval").Tasks {
			if row.ApprovalID != out[row.ID].ApprovalID {
				t.Fatalf("envelope row %s approval_id %q, bare row %q", row.ID, row.ApprovalID, out[row.ID].ApprovalID)
			}
		}
		return out
	}

	// ap-1 is not in the store yet: a row names no approval nobody can open.
	if got := rowsByID(admin)["t-finished"]; got.Origin != taskOriginApproval || got.ApprovalID != "" {
		t.Fatalf("task of a missing approval = origin %q approval_id %q", got.Origin, got.ApprovalID)
	}
	if err := st.UpsertApproval(model.Approval{
		ID: "ap-1", NodeID: "node-a", Plugin: "nftpolicy", Action: "apply", Status: model.ApprovalApplied, Plan: "plan",
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		reader       taskQueryReader
		wantApproval string
	}{
		{"admin", admin, "ap-1"},
		// task:read on node-a but no netpolicy:admin: the approval read would
		// answer 404, so the row must not confirm the approval exists.
		{"task reader without the plan's scope", confined, ""},
		{"task reader who may read the plan", planReader, "ap-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := rowsByID(tc.reader)
			if got := rows["t-finished"]; got.Origin != taskOriginApproval || got.ApprovalID != tc.wantApproval {
				t.Fatalf("t-finished = origin %q approval_id %q, want approval and %q", got.Origin, got.ApprovalID, tc.wantApproval)
			}
			for id, want := range map[string]string{"t-fixed-rerun": taskOriginRerun, "t-queued": taskOriginDirect} {
				if got := rows[id]; got.Origin != want || got.ApprovalID != "" {
					t.Fatalf("%s = origin %q approval_id %q, want %q and none", id, got.Origin, got.ApprovalID, want)
				}
			}
		})
	}
}

// Rows the plugin task host stored as "pending" before its fix were never
// delivered. They are not migrated or delivered late; the list finds them,
// the counts name them, and cancel closes them.
func TestPendingRowsAreFoundCountedAndCancellable(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	admin := taskQueryReader{handler: handler, cookies: cookies}
	now := time.Now().UTC()
	for _, task := range []model.Task{
		{ID: "t-pending", Targets: []string{"node-a"}, ApprovalID: "ap-x", ActorID: "plugin:demo", Status: store.TaskPending, CreatedAt: now.Add(-30 * 24 * time.Hour)},
		{ID: "t-queued", Targets: []string{"node-a"}, Status: model.TaskQueued, CreatedAt: now.Add(-time.Minute)},
	} {
		task.Interpreter, task.Script = "sh", "echo "+task.ID
		if err := st.CreateTask(task); err != nil {
			t.Fatal(err)
		}
	}

	got := admin.counts(t)
	if got.Pending != 1 || got.Queued != 1 || got.Total != 2 {
		t.Fatalf("counts = %+v, want pending 1, queued 1, total 2", got)
	}
	if ids := sortedTaskIDs(admin.tasks(t, "status=pending").Tasks); strings.Join(ids, ",") != "t-pending" {
		t.Fatalf("status=pending = %v", ids)
	}
	// Still never delivered: only the queued task reaches the agent.
	leased, err := st.LeaseTasks("node-a", 10)
	if err != nil || len(leased) != 1 || leased[0].ID != "t-queued" {
		t.Fatalf("node-a leased %d tasks (err %v), want only t-queued", len(leased), err)
	}

	res := doJSON(t, handler, http.MethodPost, "/api/tasks/cancel", `{"id":"t-pending"}`, cookies, csrf)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cancel pending = %d: %s", res.StatusCode, body)
	}
	var view taskView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if view.Status != model.TaskCancelled || view.FinishedAt.IsZero() {
		t.Fatalf("cancelled view = status %q finished_at %v", view.Status, view.FinishedAt)
	}
	if got := admin.counts(t); got.Pending != 0 {
		t.Fatalf("pending after cancel = %d, want 0", got.Pending)
	}
	if total := admin.tasks(t, "status=cancelled").Total; total != 1 {
		t.Fatalf("status=cancelled total = %d, want the closed row", total)
	}
}
