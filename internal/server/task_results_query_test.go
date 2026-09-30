package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestTaskResultsTaskIDListAndPaging(t *testing.T) {
	admin, confined, st, now := newTaskQueryFixture(t)

	got := func(r taskQueryReader, query string) taskResultsQueryResponse {
		t.Helper()
		code, body := r.get(t, "/api/task-results?"+query)
		if code != http.StatusOK {
			t.Fatalf("GET /api/task-results?%s = %d: %s", query, code, body)
		}
		var out taskResultsQueryResponse
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	resultKeys := func(env taskResultsQueryResponse) string {
		keys := make([]string, 0, len(env.Results))
		for _, r := range env.Results {
			keys = append(keys, r.TaskID+"/"+r.NodeID)
		}
		sort.Strings(keys)
		return strings.Join(keys, ",")
	}

	cases := []struct {
		name   string
		reader taskQueryReader
		query  string
		want   string
	}{
		{"one id", admin, "task_id=t-fixed", "t-fixed/node-a,t-fixed/node-b"},
		{"a run with its rerun", admin, "task_id=t-fixed,t-fixed-rerun", "t-fixed-rerun/node-b,t-fixed/node-a,t-fixed/node-b"},
		{"ids and node", admin, "task_id=t-fixed,t-fixed-rerun&node_id=node-b", "t-fixed-rerun/node-b,t-fixed/node-b"},
		{"blank and repeated ids", admin, "task_id=t-failed,,t-failed", "t-failed/node-a"},
		// Results are confined per node: node-c's half of a fan-out stays
		// hidden from a reader without node-c.
		{"confined", confined, "task_id=t-ac-failed,t-c-failed", "t-ac-failed/node-a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := got(tc.reader, tc.query)
			if keys := resultKeys(env); keys != tc.want || env.Total != len(env.Results) {
				t.Fatalf("results?%s = %s (total %d), want %s", tc.query, keys, env.Total, tc.want)
			}
		})
	}

	// The cap is on distinct ids: exactly 100 is fine, 101 is refused.
	ids := make([]string, 0, maxTaskResultIDs+1)
	for i := 0; i < maxTaskResultIDs; i++ {
		ids = append(ids, fmt.Sprintf("task_%016d", i))
	}
	if env := got(admin, "task_id="+strings.Join(ids, ",")); env.Total != 0 {
		t.Fatalf("100 unknown ids matched %d results", env.Total)
	}
	ids = append(ids, "task_extra")
	if code, body := admin.get(t, "/api/task-results?task_id="+strings.Join(ids, ",")); code != http.StatusBadRequest {
		t.Fatalf("101 ids = %d, want 400: %s", code, body)
	}

	// Since design 23 wave 2 the Tasks page always sends task_id or a limit,
	// so omit_output no longer lifts the page size: without a limit it
	// returns the default page of 100 (the fixture holds more), with one it
	// returns that many, and total still counts every match.
	for i := 0; i < 130; i++ {
		if err := st.AddTaskResult(model.TaskResult{
			TaskID: "t-bulk", NodeID: "node-a", Stdout: "bulk", FinishedAt: now.Add(-time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	all := len(st.Results())
	if all <= defaultTaskQueryLimit {
		t.Fatalf("fixture holds %d results; it must exceed the default page to test paging", all)
	}
	for query, wantRows := range map[string]int{
		"omit_output=1":           defaultTaskQueryLimit,
		"omit_output=1&limit=7":   7,
		"omit_output=1&limit=500": all,
	} {
		env := got(admin, query)
		if len(env.Results) != wantRows || env.Total != all {
			t.Fatalf("results?%s = %d rows of total %d, want %d of %d", query, len(env.Results), env.Total, wantRows, all)
		}
		for _, r := range env.Results {
			if r.Stdout != "" {
				t.Fatalf("results?%s sent a body", query)
			}
		}
	}
}

func TestTaskStderrHead(t *testing.T) {
	cases := []struct {
		name, stderr, want string
	}{
		{"empty", "", ""},
		{"only blank lines", "\n \n\t\n", ""},
		{"one line", "sh: curl: not found\n", "sh: curl: not found"},
		{"first non-blank line, trimmed", "\n\n   warn: disk 91% full  \nsecond line", "warn: disk 91% full"},
		{"carriage returns end a line", "\r\n  \r100  5120\rcurl: (22) 404\n", "100  5120"},
		{"tabs become spaces, control characters go", "\x1b[31mfailed\x1b[0m\tcode\x07 7", "[31mfailed[0m code 7"},
		{"invalid UTF-8 is replaced", "bad \xff byte", "bad � byte"},
		{"long ASCII is cut at 200 bytes", strings.Repeat("a", 300), strings.Repeat("a", 200)},
		// 199 bytes then a 3-byte rune: the cut must not split it.
		{"a rune across the boundary is left out", strings.Repeat("a", 199) + "中文", strings.Repeat("a", 199)},
		{"a rune that ends on the boundary stays", strings.Repeat("a", 197) + "中文", strings.Repeat("a", 197) + "中"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := taskStderrHead(tc.stderr)
			if got != tc.want {
				t.Fatalf("taskStderrHead(%q) = %q, want %q", tc.stderr, got, tc.want)
			}
			if len(got) > maxStderrHeadBytes || !utf8.ValidString(got) {
				t.Fatalf("head %q is %d bytes, valid UTF-8 %v", got, len(got), utf8.ValidString(got))
			}
		})
	}
}

func TestTaskResultsStderrHeadFollowsTheFullReadCheck(t *testing.T) {
	admin, confined, st, now := newTaskQueryFixture(t)
	for _, r := range []model.TaskResult{
		{TaskID: "t-head", NodeID: "node-a", ExitCode: 127, Stderr: "\nsh: curl: not found\nsecond line", FinishedAt: now},
		{TaskID: "t-head", NodeID: "node-c", ExitCode: 1, Stderr: "node-c only: permission denied", FinishedAt: now},
		{TaskID: "t-head", NodeID: "node-b", ExitCode: 0, Stdout: "ok", FinishedAt: now},
	} {
		if err := st.AddTaskResult(r); err != nil {
			t.Fatal(err)
		}
	}
	heads := func(r taskQueryReader, query string) map[string]string {
		t.Helper()
		code, body := r.get(t, "/api/task-results?"+query)
		if code != http.StatusOK {
			t.Fatalf("results?%s = %d: %s", query, code, body)
		}
		var raw struct {
			Results []map[string]any `json:"results"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, row := range raw.Results {
			head, present := row["stderr_head"]
			if !present {
				out[row["node_id"].(string)] = "<absent>"
				continue
			}
			out[row["node_id"].(string)] = head.(string)
		}
		return out
	}

	cases := []struct {
		name   string
		reader taskQueryReader
		query  string
		want   map[string]string
	}{
		{"admin", admin, "task_id=t-head&omit_output=1", map[string]string{
			"node-a": "sh: curl: not found", "node-c": "node-c only: permission denied", "node-b": "<absent>",
		}},
		// No task:read on node-c: that result is not this caller's to read in
		// full, so neither the row nor its head comes back.
		{"confined to node-a and node-b", confined, "task_id=t-head&omit_output=1", map[string]string{
			"node-a": "sh: curl: not found", "node-b": "<absent>",
		}},
		// Rows with bodies carry the full stderr and no head.
		{"bodies instead of heads", admin, "task_id=t-head", map[string]string{
			"node-a": "<absent>", "node-c": "<absent>", "node-b": "<absent>",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := heads(tc.reader, tc.query); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("stderr_head by node = %v, want %v", got, tc.want)
			}
		})
	}

	cookies, csrf := loginSession(t, admin.handler)
	noRead := createPAT(t, admin.handler, cookies, csrf, []string{"audit:read"}, nil)
	res := doBearerJSON(t, admin.handler, http.MethodGet, "/api/task-results?task_id=t-head&omit_output=1", "", noRead)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("results without task:read = %d, want 403", res.StatusCode)
	}
}
