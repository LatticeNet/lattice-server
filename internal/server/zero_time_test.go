package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// readZeroTimeBody reads a response and fails the test if any member carries
// the Go zero time. omitempty never omits a time.Time, so an unset instant
// used to ship as "0001-01-01T00:00:00Z" and the console printed year 1.
func readZeroTimeBody(t *testing.T, res *http.Response, what string) any {
	t.Helper()
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: status %d: %s", what, res.StatusCode, raw)
	}
	if strings.Contains(string(raw), "0001-01-01") {
		t.Fatalf("%s carries year 1: %s", what, raw)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return doc
}

// zeroTimeObjects is the list a response carries, either bare or under key.
func zeroTimeObjects(t *testing.T, doc any, key string) []map[string]any {
	t.Helper()
	list, ok := doc.([]any)
	if !ok {
		obj, _ := doc.(map[string]any)
		if list, ok = obj[key].([]any); !ok {
			t.Fatalf("response is neither a list nor carries a %q list: %v", key, doc)
		}
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if obj, ok := item.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

func assertAbsentKeys(t *testing.T, what string, obj map[string]any, paths ...string) {
	t.Helper()
	for _, path := range paths {
		var cur any = obj
		present := true
		for _, part := range strings.Split(path, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				present = false
				break
			}
			if cur, ok = m[part]; !ok {
				present = false
				break
			}
		}
		if present {
			t.Errorf("%s: %s is on the wire as %v before anything set it", what, path, cur)
		}
	}
}

// A node that has never reported and a task that has not started are the two
// objects the console renders most, and both used to carry year 1: the node
// in last_seen and in the metrics, host facts and debug policy it embeds, the
// task in started_at and finished_at (GET /api/tasks in production).
func TestNeverSeenNodeAndUnfinishedTaskCarryNoYearOne(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeID := enrollTestNode(t, handler, cookies, csrf, `{"name":"fresh-box"}`)

	nodes := readZeroTimeBody(t, doJSON(t, handler, http.MethodGet, "/api/nodes", "", cookies, ""), "GET /api/nodes")
	var node map[string]any
	for _, n := range zeroTimeObjects(t, nodes, "nodes") {
		if n["id"] == nodeID {
			node = n
		}
	}
	if node == nil {
		t.Fatalf("enrolled node %s is not listed: %v", nodeID, nodes)
	}
	assertAbsentKeys(t, "never-seen node", node,
		"last_seen", "token_last_used_at", "online_since",
		"metrics.collected_at", "host_facts.boot_time", "host_facts.reported_at", "agent_debug.updated_at")
	if _, ok := node["created_at"].(string); !ok {
		t.Fatalf("never-seen node lost created_at, which is always set: %v", node)
	}

	created, _ := readZeroTimeBody(t, doJSON(t, handler, http.MethodPost, "/api/tasks",
		`{"targets":["`+nodeID+`"],"interpreter":"sh","script":"echo ok"}`, cookies, csrf), "POST /api/tasks").(map[string]any)
	assertAbsentKeys(t, "created task", created, "started_at", "finished_at")
	taskID, _ := created["id"].(string)
	if taskID == "" {
		t.Fatalf("task create returned no id: %v", created)
	}

	tasks := readZeroTimeBody(t, doJSON(t, handler, http.MethodGet, "/api/tasks", "", cookies, ""), "GET /api/tasks")
	found := false
	for _, task := range zeroTimeObjects(t, tasks, "tasks") {
		if task["id"] != taskID {
			continue
		}
		found = true
		assertAbsentKeys(t, "unfinished task", task, "started_at", "finished_at")
		if _, ok := task["created_at"].(string); !ok {
			t.Fatalf("unfinished task lost created_at: %v", task)
		}
	}
	if !found {
		t.Fatalf("task %s is not listed: %v", taskID, tasks)
	}
	// The inventory and geo views embed the same host facts.
	for _, path := range []string{"/api/machines", "/api/nodes/geo"} {
		readZeroTimeBody(t, doJSON(t, handler, http.MethodGet, path, "", cookies, ""), "GET "+path)
	}
}
