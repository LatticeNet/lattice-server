package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func newManageTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler()
}

func TestSingBoxManageAddValidatesAndQueues(t *testing.T) {
	srv, handler := newManageTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	// Valid add -> 200 + a queued task.
	resp := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/add",
		`{"node_id":"node-a","protocol":"reality","port":28443,"args":["www.example.com"]}`, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("add: want 200, got %d (%s)", resp.StatusCode, b)
	}
	var out struct {
		TaskID string `json:"task_id"`
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = json.Unmarshal(body, &out)
	if out.TaskID == "" {
		t.Fatalf("no task id: %s", body)
	}
	// The queued task targets the node and uses sh.
	var task *model.Task
	for _, tk := range srv.store.Tasks() {
		if tk.ID == out.TaskID {
			tt := tk
			task = &tt
		}
	}
	if task == nil || len(task.Targets) != 1 || task.Targets[0] != "node-a" || task.Interpreter != "sh" {
		t.Fatalf("unexpected task: %+v", task)
	}
	// The script is a safe, quoted `sb --json add reality 28443 'www.example.com'`.
	for _, needle := range []string{"sb ", "--json", "add", "'reality'", "28443", "'www.example.com'"} {
		if !strings.Contains(task.Script, needle) {
			t.Fatalf("script missing %q:\n%s", needle, task.Script)
		}
	}

	// Allowlist + validation rejections.
	for _, bad := range []string{
		`{"node_id":"node-a","protocol":"evil; rm -rf /","port":443}`,
		`{"node_id":"node-a","protocol":"reality","port":70000}`,
		`{"node_id":"node-a","protocol":"reality","args":["x; touch /tmp/pwn"]}`,
	} {
		r := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/add", bad, cookies, csrf)
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", bad, r.StatusCode)
		}
		r.Body.Close()
	}
}

func TestSingBoxManageProbeQueuesReadOnlyTask(t *testing.T) {
	srv, handler := newManageTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	resp := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/probe",
		`{"node_id":"node-a"}`, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("probe: want 200, got %d (%s)", resp.StatusCode, b)
	}
	var out struct {
		TaskID string `json:"task_id"`
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = json.Unmarshal(body, &out)
	if out.TaskID == "" {
		t.Fatalf("no task id: %s", body)
	}
	var task *model.Task
	for _, tk := range srv.store.Tasks() {
		if tk.ID == out.TaskID {
			tt := tk
			task = &tt
		}
	}
	if task == nil {
		t.Fatal("probe task not queued")
	}
	for _, needle := range []string{singBoxProbeScriptMarker + task.ID, "--json", " list", " provision"} {
		if !strings.Contains(task.Script, needle) {
			t.Fatalf("probe script missing %q:\n%s", needle, task.Script)
		}
	}
	for _, forbidden := range []string{" add ", " del "} {
		if strings.Contains(task.Script, forbidden) {
			t.Fatalf("probe script must be read-only, found %q:\n%s", forbidden, task.Script)
		}
	}
}

func TestSingBoxProbeTaskResultRefreshesInventory(t *testing.T) {
	_, handler := newManageTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	resp := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/probe",
		`{"node_id":"node-a"}`, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("probe: want 200, got %d (%s)", resp.StatusCode, b)
	}
	resp.Body.Close()

	tasksRec := doAgentRaw(t, handler, http.MethodGet, "/api/agent/tasks?node_id=node-a", "", nodeToken)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease failed: %d %s", tasksRec.Code, tasksRec.Body.String())
	}
	var tasks []struct {
		ID      string `json:"id"`
		LeaseID string `json:"lease_id"`
	}
	if err := json.NewDecoder(tasksRec.Body).Decode(&tasks); err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("want one task, got %+v", tasks)
	}
	stdout := singBoxProbeListMarker + `
{"ok":true,"count":1,"nodes":[{"name":"VLESS-REALITY-443.json","protocol":"vless","network":"tcp","address":"203.0.113.10","port":"443","sni":"example.com","share_url":"vless://secret"}]}
` + singBoxProbeProvisionMarker + `
{"version":"1.12.12"}
`
	result := `{"node_id":"node-a","result":{"task_id":"` + tasks[0].ID + `","lease_id":"` + tasks[0].LeaseID + `","exit_code":0,"stdout":` + string(mustJSON(t, stdout)) + `}}`
	resultRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", result, nodeToken)
	if resultRec.Code != http.StatusOK {
		t.Fatalf("task result failed: %d %s", resultRec.Code, resultRec.Body.String())
	}

	discovered := doJSON(t, handler, http.MethodGet, "/api/proxy/discovered", "", cookies, csrf)
	if discovered.StatusCode != http.StatusOK {
		t.Fatalf("discovered failed: %d", discovered.StatusCode)
	}
	var out struct {
		Inventories []model.SingBoxInventory `json:"inventories"`
	}
	if err := json.NewDecoder(discovered.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	discovered.Body.Close()
	if len(out.Inventories) != 1 || out.Inventories[0].CoreVersion != "1.12.12" || len(out.Inventories[0].Nodes) != 1 {
		t.Fatalf("unexpected inventory: %+v", out.Inventories)
	}
	if got := out.Inventories[0].Nodes[0].Name; got != "VLESS-REALITY-443.json" {
		t.Fatalf("node name = %q", got)
	}
}

func TestSingBoxManageProbeDeduplicates(t *testing.T) {
	_, handler := newManageTestServer(t)
	cookies, csrf := loginSession(t, handler)
	nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	// First probe: must be accepted.
	r1 := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/probe",
		`{"node_id":"node-a"}`, cookies, csrf)
	if r1.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r1.Body)
		t.Fatalf("first probe: want 200, got %d (%s)", r1.StatusCode, b)
	}
	r1.Body.Close()

	// Second probe while first is still pending: must be rejected with 409.
	r2 := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/probe",
		`{"node_id":"node-a"}`, cookies, csrf)
	if r2.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(r2.Body)
		t.Fatalf("second probe: want 409, got %d (%s)", r2.StatusCode, b)
	}
	r2.Body.Close()

	// Agent picks up the task and reports a result, which clears the pending slot.
	tasksRec := doAgentRaw(t, handler, http.MethodGet, "/api/agent/tasks?node_id=node-a", "", nodeToken)
	if tasksRec.Code != http.StatusOK {
		t.Fatalf("lease: %d %s", tasksRec.Code, tasksRec.Body.String())
	}
	var tasks []struct {
		ID      string `json:"id"`
		LeaseID string `json:"lease_id"`
	}
	if err := json.NewDecoder(tasksRec.Body).Decode(&tasks); err != nil || len(tasks) != 1 {
		t.Fatalf("want one task: err=%v tasks=%+v", err, tasks)
	}
	result := `{"node_id":"node-a","result":{"task_id":` + string(mustJSON(t, tasks[0].ID)) +
		`,"lease_id":` + string(mustJSON(t, tasks[0].LeaseID)) + `,"exit_code":0,"stdout":""}}`
	resultRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", result, nodeToken)
	if resultRec.Code != http.StatusOK {
		t.Fatalf("task result: %d %s", resultRec.Code, resultRec.Body.String())
	}

	// Third probe after slot is cleared: must be accepted again.
	r3 := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/probe",
		`{"node_id":"node-a"}`, cookies, csrf)
	if r3.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r3.Body)
		t.Fatalf("third probe after result: want 200, got %d (%s)", r3.StatusCode, b)
	}
	r3.Body.Close()
}

func TestSingBoxProbeTaskResultErrorPaths(t *testing.T) {
	tests := []struct {
		name            string
		exitCode        int
		stdout          string
		wantStatus      string
		wantErrContains string
	}{
		{
			name:       "nonzero exit code",
			exitCode:   1,
			stdout:     "",
			wantStatus: "error",
		},
		{
			name:            "stdout missing list marker",
			exitCode:        0,
			stdout:          "sb: some output with no sentinel markers",
			wantStatus:      "error",
			wantErrContains: "missing list marker",
		},
		{
			name:            "list marker present but non-JSON body",
			exitCode:        0,
			stdout:          singBoxProbeListMarker + "\n" + "not valid json\n" + singBoxProbeProvisionMarker + "\n",
			wantStatus:      "error",
			wantErrContains: "decode probe list",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, handler := newManageTestServer(t)
			cookies, csrf := loginSession(t, handler)
			nodeToken := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

			resp := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/probe",
				`{"node_id":"node-a"}`, cookies, csrf)
			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("probe: want 200, got %d (%s)", resp.StatusCode, b)
			}
			resp.Body.Close()

			tasksRec := doAgentRaw(t, handler, http.MethodGet, "/api/agent/tasks?node_id=node-a", "", nodeToken)
			if tasksRec.Code != http.StatusOK {
				t.Fatalf("lease: %d %s", tasksRec.Code, tasksRec.Body.String())
			}
			var tasks []struct {
				ID      string `json:"id"`
				LeaseID string `json:"lease_id"`
			}
			if err := json.NewDecoder(tasksRec.Body).Decode(&tasks); err != nil || len(tasks) != 1 {
				t.Fatalf("want one task: err=%v tasks=%+v", err, tasks)
			}

			result := `{"node_id":"node-a","result":{"task_id":` + string(mustJSON(t, tasks[0].ID)) +
				`,"lease_id":` + string(mustJSON(t, tasks[0].LeaseID)) +
				`,"exit_code":` + strconv.Itoa(tc.exitCode) +
				`,"stdout":` + string(mustJSON(t, tc.stdout)) + `}}`
			resultRec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/task-result", result, nodeToken)
			if resultRec.Code != http.StatusOK {
				t.Fatalf("task result: %d %s", resultRec.Code, resultRec.Body.String())
			}

			disc := doJSON(t, handler, http.MethodGet, "/api/proxy/discovered", "", cookies, csrf)
			if disc.StatusCode != http.StatusOK {
				t.Fatalf("discovered: %d", disc.StatusCode)
			}
			var out struct {
				Inventories []model.SingBoxInventory `json:"inventories"`
			}
			if err := json.NewDecoder(disc.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			disc.Body.Close()
			if len(out.Inventories) != 1 {
				t.Fatalf("want 1 inventory entry, got %d: %+v", len(out.Inventories), out.Inventories)
			}
			inv := out.Inventories[0]
			if inv.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", inv.Status, tc.wantStatus)
			}
			if tc.wantErrContains != "" && !strings.Contains(inv.Error, tc.wantErrContains) {
				t.Errorf("error field = %q, want it to contain %q", inv.Error, tc.wantErrContains)
			}
		})
	}
}

func TestSingBoxManageDeleteRequiresDiscoveredName(t *testing.T) {
	srv, handler := newManageTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	// Undiscovered name -> 400.
	r := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/delete",
		`{"node_id":"node-a","name":"VLESS-REALITY-17891.json"}`, cookies, csrf)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("undiscovered: want 400, got %d", r.StatusCode)
	}
	r.Body.Close()

	// After discovery, the name is deletable.
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {NodeID: "node-a", Status: "ok", Nodes: []model.SingBoxNode{{Name: "VLESS-REALITY-17891.json"}}},
	}
	srv.singboxInvMu.Unlock()
	ok := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/delete",
		`{"node_id":"node-a","name":"VLESS-REALITY-17891.json"}`, cookies, csrf)
	if ok.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(ok.Body)
		t.Fatalf("discovered delete: want 200, got %d (%s)", ok.StatusCode, b)
	}
	ok.Body.Close()

	// Shell metacharacters in name -> 400 (regex guard, before the discovery check).
	bad := doJSON(t, handler, http.MethodPost, "/api/proxy/managed/delete",
		`{"node_id":"node-a","name":"x; rm -rf /"}`, cookies, csrf)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad name: want 400, got %d", bad.StatusCode)
	}
	bad.Body.Close()
}
