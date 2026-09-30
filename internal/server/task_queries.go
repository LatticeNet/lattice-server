package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// taskListStatuses are the values a task row's status takes on the wire: the
// stored statuses plus the two the view derives, expired and stalled, plus
// pending, which only rows the plugin task host stored before its fix carry
// (store.TaskPending: never delivered). The status filter accepts exactly
// these, so a filter can only ask for something a row can say.
var taskListStatuses = []string{
	model.TaskQueued, model.TaskLeased, store.TaskStalled, store.TaskExpired,
	model.TaskFinished, model.TaskFailed, model.TaskCancelled, store.TaskPending,
}

// Task origins partition every task by how it was queued. They are derived
// from the stored record rather than stored, so rows written before the filter
// existed answer it too.
const (
	// taskOriginRerun is a task that repeats an earlier one (rerun_of_task_id
	// is set). A rerun never carries an approval id of its own.
	taskOriginRerun = "rerun"
	// taskOriginApproval is a task queued by an approved plan, including the
	// ones a plugin enqueues against its operation grant.
	taskOriginApproval = "approval"
	// taskOriginDirect is a task a principal queued without a plan: the
	// console's composer, an API token, or a server read such as a sing-box
	// probe.
	taskOriginDirect = "direct"
)

var taskOrigins = []string{taskOriginApproval, taskOriginRerun, taskOriginDirect}

// taskCountsWindow is the window failed_24h and finished_24h look back over.
const taskCountsWindow = 24 * time.Hour

// maxStderrHeadBytes bounds stderr_head: one line a table cell can show.
const maxStderrHeadBytes = 200

// taskResultReadable is the check that admits a task result to a caller,
// and with it the full stdout and stderr: task:read on the node that ran
// it. Every result read (the bare array, the query page, and stderr_head on
// a bodyless row) goes through it, so none can show more than another.
func taskResultReadable(p principal, result model.TaskResult) bool {
	return rbac.Allows(p.Principal, "task:read", result.NodeID)
}

// taskStderrHead is the first non-blank line of stderr, so a failed run can
// say why in one line ("sh: curl: not found") without the body. A carriage
// return ends a line as a newline does (progress meters rewrite a line with
// it), invalid UTF-8 becomes U+FFFD, ANSI escape sequences are removed whole
// (stripANSI), remaining control characters are dropped, and the line is
// trimmed and cut to at most maxStderrHeadBytes on a UTF-8 boundary. It is
// empty when stderr holds nothing but blank lines.
func taskStderrHead(stderr string) string {
	for _, line := range strings.FieldsFunc(stderr, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.Map(func(r rune) rune {
			switch {
			case r == '\t':
				return ' '
			case r < 0x20 || r == 0x7f:
				return -1
			}
			return r
		}, stripANSI(strings.ToValidUTF8(line, "�")))
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > maxStderrHeadBytes {
			cut := maxStderrHeadBytes
			for cut > 0 && !utf8.RuneStart(line[cut]) {
				cut--
			}
			line = strings.TrimSpace(line[:cut])
		}
		return line
	}
	return ""
}

// stripANSI removes ANSI escape sequences whole, so "\x1b[31mfailed\x1b[0m"
// reads "failed" rather than "[31mfailed[0m":
//   - CSI: ESC [ then parameter bytes 0x30-0x3F, intermediate bytes 0x20-0x2F
//     and one final byte 0x40-0x7E (colours, ESC [ 2 K, ESC [ ? 25 l);
//   - OSC, DCS, SOS, PM and APC: ESC ] (or P, X, ^, _) up to BEL or ST
//     (ESC \), such as a window title or an OSC 8 hyperlink; an unterminated
//     one runs to the end of the text;
//   - any other escape: ESC, intermediate bytes 0x20-0x2F, one final byte
//     0x30-0x7E (ESC ( B, ESC 7).
//
// A sequence cut short by a byte outside its grammar ends there and scanning
// resumes at that byte. Every byte that starts, delimits or ends a sequence is
// ASCII, and no UTF-8 multibyte character contains an ASCII byte, so the text
// around a sequence keeps its UTF-8 intact.
func stripANSI(s string) string {
	if strings.IndexByte(s, 0x1b) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != 0x1b {
			b.WriteByte(s[i])
			i++
			continue
		}
		i++ // ESC
		if i >= len(s) {
			break
		}
		switch c := s[i]; {
		case c == '[':
			i++
			for i < len(s) && s[i] >= 0x30 && s[i] <= 0x3f {
				i++
			}
			for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
				i++
			}
			if i < len(s) && s[i] >= 0x40 && s[i] <= 0x7e {
				i++
			}
		case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_':
			i++
			for i < len(s) {
				if s[i] == 0x07 {
					i++
					break
				}
				if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
		default:
			for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
				i++
			}
			if i < len(s) && s[i] >= 0x30 && s[i] <= 0x7e {
				i++
			}
		}
	}
	return b.String()
}

func taskOrigin(t model.Task) string {
	switch {
	case strings.TrimSpace(t.RerunOfTaskID) != "":
		return taskOriginRerun
	case strings.TrimSpace(t.ApprovalID) != "":
		return taskOriginApproval
	default:
		return taskOriginDirect
	}
}

// taskRow is one task the caller may read, with the view the console sees.
// The stored record rides along because origin and the change times are read
// from fields the view does not carry. The view has no script digest yet;
// taskRowViews adds it to the rows a response actually returns.
type taskRow struct {
	task model.Task
	view taskView
}

// visibleTaskRows is every task the principal may read, newest first. A task
// is visible only when the caller holds task:read on every one of its
// targets, the rule GET /api/tasks has always applied; the counts and every
// filter start from this set, so none of them can describe a task on a node
// outside the caller's scope.
func (s *Server) visibleTaskRows(p principal) []taskRow {
	tasks := s.store.Tasks() // newest-first
	rows := make([]taskRow, 0, len(tasks))
	for _, task := range tasks {
		if taskTargetsAllowed(p, "task:read", task.Targets) {
			rows = append(rows, taskRow{task: task, view: s.taskStateView(task)})
		}
	}
	return rows
}

// taskRowViews is the response form of rows: each view completed with its
// script digest, as toTaskView returns it, and with the approval id when p may
// read that approval. The approval read answers 404 alike for a missing plan
// and one outside the caller's scope, so a row must not name an approval the
// caller could not open; origin still says the task came from one.
func (s *Server) taskRowViews(p principal, rows []taskRow) []taskView {
	var named []string
	for _, row := range rows {
		if id := row.task.ApprovalID; id != "" {
			named = append(named, id)
		}
	}
	readable := s.readableApprovalIDs(p, named)
	views := make([]taskView, 0, len(rows))
	for _, row := range rows {
		view := row.view
		view.ScriptSHA256 = scriptSHA256(row.task.Script)
		if readable[row.task.ApprovalID] {
			view.ApprovalID = row.task.ApprovalID
		}
		views = append(views, view)
	}
	return views
}

// readableApprovalIDs resolves, once per response, which of the named
// approvals p may read. The approvals come from one store read, and each is
// judged by approvalVisibleToPrincipal, the rule the approvals read applies,
// so the two cannot drift. Both the approval_id a row shows and the
// approval_id filter go through here. That rule still reads the store for
// the plan reach of an nftpolicy or WireGuard mesh approval whose primary
// scope the caller holds. An unknown id is not readable.
func (s *Server) readableApprovalIDs(p principal, named []string) map[string]bool {
	if len(named) == 0 {
		return nil
	}
	approvals := s.store.ApprovalsByID(named)
	readable := make(map[string]bool, len(approvals))
	for _, approval := range approvals {
		if s.approvalVisibleToPrincipal(p, approval) {
			readable[approval.ID] = true
		}
	}
	return readable
}

// taskLastChangedAt is the last time a task row changed, as far as the record
// can say: the latest of its created, started and finished times and of every
// per-target lease start. A row the view reports as expired changed when the
// queue deadline passed, which no stored field records, so that instant is
// computed from the same rule the store applies.
func taskLastChangedAt(t model.Task, status string, deadline time.Duration) time.Time {
	latest := t.CreatedAt
	for _, at := range []time.Time{t.StartedAt, t.FinishedAt} {
		if at.After(latest) {
			latest = at
		}
	}
	for _, lease := range t.TargetLeases {
		if lease.StartedAt.After(latest) {
			latest = lease.StartedAt
		}
	}
	if status == store.TaskExpired && deadline > 0 && !t.CreatedAt.IsZero() {
		if expiredAt := t.CreatedAt.Add(deadline); expiredAt.After(latest) {
			latest = expiredAt
		}
	}
	return latest
}

// taskListFilter is the parsed row filter of GET /api/tasks. Every field
// matches something the row itself says, so a URL maps to one question.
type taskListFilter struct {
	statuses   map[string]bool
	origins    map[string]bool
	nodeID     string
	since      time.Time
	approvalID string
}

// maxApprovalIDParam bounds approval_id. Approval ids are "approval_" plus
// 16 base32 characters (id.New), so 128 leaves room for any older shape.
const maxApprovalIDParam = 128

func parseTaskListFilter(q url.Values) (taskListFilter, error) {
	f := taskListFilter{
		nodeID:     strings.TrimSpace(q.Get("node_id")),
		approvalID: strings.TrimSpace(q.Get("approval_id")),
	}
	if !validApprovalIDParam(f.approvalID) {
		return f, fmt.Errorf("approval_id must be one id of at most %d characters from A-Z, a-z, 0-9, _ and -", maxApprovalIDParam)
	}
	var err error
	if f.statuses, err = parseEnumList(q.Get("status"), "status", taskListStatuses); err != nil {
		return f, err
	}
	if f.origins, err = parseEnumList(q.Get("origin"), "origin", taskOrigins); err != nil {
		return f, err
	}
	if raw := strings.TrimSpace(q.Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return f, errors.New("since must be an RFC3339 timestamp")
		}
		f.since = since
	}
	return f, nil
}

// validApprovalIDParam accepts an empty value (no filter) or one id in the
// character set id.New produces. A comma list, a wildcard or anything longer
// than maxApprovalIDParam is refused rather than matched against nothing.
func validApprovalIDParam(raw string) bool {
	if len(raw) > maxApprovalIDParam {
		return false
	}
	for _, c := range raw {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// parseEnumList reads a comma list whose every entry must be one of allowed.
// Blank entries (a trailing comma) are skipped; an unknown value is an error
// rather than a filter that silently matches nothing. A nil set means the
// parameter was absent or empty and filters nothing.
func parseEnumList(raw, name string, allowed []string) (map[string]bool, error) {
	var set map[string]bool
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		known := false
		for _, candidate := range allowed {
			if value == candidate {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("%s must be a comma list of %s, got %q", name, strings.Join(allowed, ", "), value)
		}
		if set == nil {
			set = map[string]bool{}
		}
		set[value] = true
	}
	return set, nil
}

// matches applies every filter; since is inclusive and compares instants, so
// the caller's zone does not matter.
func (f taskListFilter) matches(row taskRow, deadline time.Duration) bool {
	if f.statuses != nil && !f.statuses[row.view.Status] {
		return false
	}
	if f.origins != nil && !f.origins[taskOrigin(row.task)] {
		return false
	}
	if f.nodeID != "" && !taskViewTargetsNode(row.view, f.nodeID) {
		return false
	}
	if !f.since.IsZero() && taskLastChangedAt(row.task, row.view.Status, deadline).Before(f.since) {
		return false
	}
	// The caller must also be able to read the approval; handleTasks checks
	// that once before any row is matched.
	if f.approvalID != "" && row.task.ApprovalID != f.approvalID {
		return false
	}
	return true
}

type taskCountsResponse struct {
	Queued      int       `json:"queued"`
	Running     int       `json:"running"`
	Stalled     int       `json:"stalled"`
	Pending     int       `json:"pending"`
	Failed24h   int       `json:"failed_24h"`
	Finished24h int       `json:"finished_24h"`
	Total       int       `json:"total"`
	GeneratedAt time.Time `json:"generated_at"`
}

// handleTaskCounts serves GET /api/tasks/counts: the queue's health as
// numbers, so the home tile and the Tasks head stop reading every task (1,771
// rows on 2026-09-30) to count them.
//
//	{"queued","running","stalled","pending","failed_24h","finished_24h","total","generated_at"}
//
// It needs task:read and counts only the tasks GET /api/tasks would list for
// the same caller: a task counts when the caller may read every one of its
// targets. A node-confined principal therefore learns nothing about tasks
// that touch a node outside its scope, not even that they exist.
//
// queued, running and stalled count task rows by the status the list shows:
// queued, leased (reported here as running) and stalled, where stalled is the
// view the lease logic derives (store.TaskProgress: a target still owes a
// result and no target holds a live lease). A rerun is its own row and counts
// here while it waits or runs, so each of these equals the total of GET
// /api/tasks?status=<the same status>. total is every row the caller may read.
//
// pending counts rows stored before the fix, never delivered: tasks the
// plugin task host wrote with status "pending" (store.TaskPending), which no
// agent is ever handed. They are not in queued, because nothing will run
// them; POST /api/tasks/cancel closes one. Production held none on
// 2026-09-30, so this is 0 there.
//
// failed_24h and finished_24h count runs, not rows. A run is a root task
// (one that is not a rerun, or whose original the caller cannot see) together
// with every rerun of it, and its outcome is the one the Tasks page shows:
// each target is judged by its latest attempt, root or rerun, and
// taskRunStatus folds those into one status. So a run whose failed node was
// rerun to success is finished, not failed, and a rerun that failed again
// keeps it failed; reruns never add to either count on their own.
// finished_24h counts runs whose outcome is terminal (finished, failed,
// cancelled or expired) and failed_24h the failed ones among them, when the
// run last changed (taskLastChangedAt over all its attempts) within the 24
// hours before generated_at.
func (s *Server) handleTaskCounts(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "task:read") {
		return
	}
	now := s.now().UTC()
	rows := s.visibleTaskRows(p)
	out := taskCountsResponse{Total: len(rows), GeneratedAt: now}
	for _, row := range rows {
		switch row.view.Status {
		case model.TaskQueued:
			out.Queued++
		case model.TaskLeased:
			out.Running++
		case store.TaskStalled:
			out.Stalled++
		case store.TaskPending:
			out.Pending++
		}
	}
	out.Failed24h, out.Finished24h = s.countTaskRunOutcomes(rows, now.Add(-taskCountsWindow))
	writeJSON(w, http.StatusOK, out)
}

type taskResultKey struct{ taskID, nodeID string }

// countTaskRunOutcomes counts the runs among rows whose outcome is terminal
// and that last changed at or after windowStart, and the failed ones among
// them. Results are read only when some run falls inside the window.
func (s *Server) countTaskRunOutcomes(rows []taskRow, windowStart time.Time) (failed, finished int) {
	deadline := s.store.TaskQueueDeadline()
	byID := make(map[string]int, len(rows))
	for i, row := range rows {
		byID[row.task.ID] = i
	}
	children := map[string][]taskRow{}
	var roots []taskRow
	for _, row := range rows {
		if parent := row.task.RerunOfTaskID; parent != "" {
			if _, visible := byID[parent]; visible {
				children[parent] = append(children[parent], row)
				continue
			}
		}
		roots = append(roots, row)
	}
	var results map[taskResultKey]model.TaskResult
	for _, root := range roots {
		attempts := taskRunAttempts(root, children[root.task.ID])
		changed := time.Time{}
		for _, attempt := range attempts {
			if at := taskLastChangedAt(attempt.task, attempt.view.Status, deadline); at.After(changed) {
				changed = at
			}
		}
		if changed.Before(windowStart) {
			continue
		}
		if results == nil {
			results = latestTaskResults(s.store.Results())
		}
		switch taskRunStatus(root, attempts, results) {
		case model.TaskFailed:
			failed++
			finished++
		case model.TaskFinished, model.TaskCancelled, store.TaskExpired:
			finished++
		}
	}
	return failed, finished
}

// taskRunAttempts is a run's attempts in the order they were created, the
// root first when times tie.
func taskRunAttempts(root taskRow, reruns []taskRow) []taskRow {
	attempts := append([]taskRow{root}, reruns...)
	sort.SliceStable(attempts, func(i, j int) bool {
		return attempts[i].task.CreatedAt.Before(attempts[j].task.CreatedAt)
	})
	return attempts
}

// latestTaskResults indexes the newest result per task and node, by finish
// time, which is the result the Tasks page reads for a node.
func latestTaskResults(results []model.TaskResult) map[taskResultKey]model.TaskResult {
	latest := make(map[taskResultKey]model.TaskResult, len(results))
	for _, result := range results {
		key := taskResultKey{result.TaskID, result.NodeID}
		if prev, ok := latest[key]; !ok || result.FinishedAt.After(prev.FinishedAt) {
			latest[key] = result
		}
	}
	return latest
}

// taskRunStatus is a run's status as the Tasks page derives it
// (TasksView.vue nodeRows and groupStatus). It is ported rather than
// redefined so that the counts and the page cannot disagree about which runs
// failed; change both together.
func taskRunStatus(root taskRow, attempts []taskRow, results map[taskResultKey]model.TaskResult) string {
	targets := uniqueStrings(root.task.Targets)
	nodes := make([]string, 0, len(targets))
	for _, nodeID := range targets {
		nodes = append(nodes, taskRunNodeStatus(root, attempts, nodeID, results))
	}
	has := func(status string) bool {
		for _, node := range nodes {
			if node == status {
				return true
			}
		}
		return false
	}
	rootStatus := root.view.Status
	switch {
	// The server withdrew delivery; that outranks whatever the nodes say.
	case rootStatus == store.TaskExpired:
		return store.TaskExpired
	case has(model.TaskLeased):
		return model.TaskLeased
	case has(store.TaskStalled):
		return store.TaskStalled
	case has(model.TaskQueued):
		if rootStatus == model.TaskCancelled {
			return model.TaskCancelled
		}
		return model.TaskQueued
	case has(model.TaskFailed):
		return model.TaskFailed
	}
	allCancelled := len(nodes) > 0
	for _, node := range nodes {
		if node != model.TaskCancelled {
			allCancelled = false
			break
		}
	}
	if allCancelled || rootStatus == model.TaskCancelled {
		return model.TaskCancelled
	}
	return model.TaskFinished
}

// taskRunNodeStatus is one target's status inside a run: its latest
// attempt's result when one is recorded, otherwise what that attempt says
// about the node.
func taskRunNodeStatus(root taskRow, attempts []taskRow, nodeID string, results map[taskResultKey]model.TaskResult) string {
	var latest *taskRow
	for i := range attempts {
		if taskTargetContains(attempts[i].task.Targets, nodeID) {
			latest = &attempts[i]
		}
	}
	if latest == nil {
		return model.TaskQueued
	}
	if result, ok := results[taskResultKey{latest.task.ID, nodeID}]; ok {
		if result.Error != "" || result.ExitCode != 0 {
			return model.TaskFailed
		}
		return model.TaskFinished
	}
	// Withdrawn before this node answered: no run is coming.
	if root.view.Status == store.TaskExpired {
		return store.TaskExpired
	}
	switch latest.view.Status {
	case model.TaskFailed, model.TaskCancelled:
		return latest.view.Status
	}
	// A fan-out stays leased while any node still runs it, so the node's own
	// record, when the view carries one, is what this node is doing.
	status := latest.view.Status
	if target, ok := latest.view.TargetStates[nodeID]; ok {
		status = target.Status
	}
	switch status {
	case store.TaskStalled, model.TaskLeased, model.TaskFailed, model.TaskFinished:
		return status
	}
	return model.TaskQueued
}
