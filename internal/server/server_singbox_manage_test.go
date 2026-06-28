package server

import (
	"encoding/json"
	"io"
	"net/http"
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
