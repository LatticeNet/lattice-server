package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

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
