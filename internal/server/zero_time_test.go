package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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

// assertStampedTimes fails unless each named member is a real time. The store
// stamps created_at and updated_at on its own copy of a row, and a handler
// that answered from the copy it handed in sent year 1 for both.
func assertStampedTimes(t *testing.T, what string, obj map[string]any, keys ...string) {
	t.Helper()
	for _, key := range keys {
		raw, ok := obj[key].(string)
		if !ok {
			t.Errorf("%s: %s missing: %v", what, key, obj)
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || at.Year() < 2000 {
			t.Errorf("%s: %s = %q, want the time the store wrote", what, key, raw)
		}
	}
}

// Every create or update answers with the row the store holds, so the times
// the store stamped are in the response. Each of these handlers used to write
// the copy it passed to the store, whose created_at and updated_at were zero.
func TestCreateAndUpdateAnswerWithTheStoredTimes(t *testing.T) {
	handler, _ := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	for _, tc := range []struct {
		path, body string
		keys       []string
	}{
		{"/api/kv", `{"bucket":"zero","key":"k","value":"v"}`, []string{"updated_at"}},
		{"/api/static", `{"bucket":"zero","path":"/index.html","content":"hi","content_type":"text/html"}`, []string{"updated_at"}},
		{"/api/storage/buckets?kind=kv", `{"name":"zero","display_name":"Zero"}`, []string{"created_at", "updated_at"}},
		{"/api/notify/channels", `{"id":"nc-zero","name":"Zero","kind":"telegram","config":{"token":"t","chat_id":"1"}}`, []string{"created_at", "updated_at"}},
		{"/api/tunnels", `{"name":"zero","node_id":"n1","tunnel_id":"tun-zero","ingress":[{"hostname":"zero.example.com","service":"http://localhost:8088"}]}`, []string{"created_at", "updated_at"}},
	} {
		obj, _ := readZeroTimeBody(t, doJSON(t, handler, http.MethodPost, tc.path, tc.body, cookies, csrf), "POST "+tc.path).(map[string]any)
		assertStampedTimes(t, "POST "+tc.path, obj, tc.keys...)
		if tc.path != "/api/tunnels" {
			continue
		}
		// A plan answers with the approval submitApproval stored.
		id, _ := obj["id"].(string)
		approval, _ := readZeroTimeBody(t, doJSON(t, handler, http.MethodPost, "/api/tunnels/plan", `{"id":"`+id+`"}`, cookies, csrf), "POST /api/tunnels/plan").(map[string]any)
		assertStampedTimes(t, "tunnel plan approval", approval, "created_at", "updated_at")
	}

	_, ddnsHandler, _ := newDDNSServer(t)
	ddnsCookies, ddnsCSRF := loginSession(t, ddnsHandler)
	profile, _ := readZeroTimeBody(t, doJSON(t, ddnsHandler, http.MethodPost, "/api/ddns",
		`{"name":"cf","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"cf_api_token":"secret","enable_ipv4":true}`, ddnsCookies, ddnsCSRF), "POST /api/ddns").(map[string]any)
	assertStampedTimes(t, "POST /api/ddns", profile, "created_at", "updated_at")
	assertAbsentKeys(t, "a DDNS profile that has never run", profile, "last_run_at")
}
