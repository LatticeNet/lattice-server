package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestTaskCreateRefusesAgentKillingFirstCommand(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)

	cases := []struct {
		name    string
		script  string
		refused bool
	}{
		{name: "systemctl stop", script: "systemctl stop lattice-agent", refused: true},
		{name: "the KI-20 diagnostic, restart first then more commands", script: "systemctl restart lattice-agent; sleep 8; sb --json list", refused: true},
		{name: "after a shebang, comments and blank lines, with the unit suffix", script: "#!/bin/sh\n# bounce first\n\n  systemctl   restart lattice-agent.service && echo ok", refused: true},
		{name: "launchd kickstart", script: "launchctl kickstart -k system/net.lattice.agent", refused: true},
		{name: "set -e first leaves the restart allowed", script: "set -e\nsystemctl restart lattice-agent"},
		{name: "restart after the output is allowed", script: "echo hi\nsystemctl restart lattice-agent"},
		{name: "another unit is allowed", script: "systemctl restart sing-box"},
		{name: "deferred through a transient unit is allowed", script: "systemd-run --on-active=3s systemctl restart lattice-agent"},
		{name: "mentioned but not run is allowed", script: "echo systemctl stop lattice-agent"},
		{name: "a different launchd service is allowed", script: "launchctl kickstart -k system/com.example.other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := string(mustJSON(t, map[string]any{"targets": []string{"n1"}, "interpreter": "sh", "script": tc.script}))
			res := doJSON(t, handler, http.MethodPost, "/api/tasks", body, cookies, csrf)
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			if tc.refused {
				if res.StatusCode != http.StatusBadRequest {
					t.Fatalf("expected 400, got %d: %s", res.StatusCode, raw)
				}
				if !strings.Contains(string(raw), "transient unit") {
					t.Fatalf("refusal should say how to schedule the restart, got: %s", raw)
				}
				return
			}
			if res.StatusCode != http.StatusOK {
				t.Fatalf("expected the script to be accepted, got %d: %s", res.StatusCode, raw)
			}
		})
	}

	// A rerun creates a task too, and the original loop task predates the
	// guard, so rerunning it has to be refused the same way.
	if err := st.CreateTask(model.Task{ID: "task-loop", Targets: []string{"n1"}, Interpreter: "sh", Script: "systemctl restart lattice-agent; sleep 8", TimeoutSec: 60, OutputLimit: 1024, Status: model.TaskFailed, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	res := doJSON(t, handler, http.MethodPost, "/api/tasks/rerun", `{"id":"task-loop"}`, cookies, csrf)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "transient unit") {
		t.Fatalf("rerun of an agent-killing script should be refused, got %d: %s", res.StatusCode, raw)
	}
}

func TestTaskViewExposesAttemptsAndLeaseAge(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	cookies, _ := loginSession(t, handler)
	for _, task := range []model.Task{
		{ID: "task-leased", Targets: []string{"n1"}, Interpreter: "sh", Script: "echo hi", TimeoutSec: 3600, Status: model.TaskQueued, CreatedAt: time.Now().UTC()},
		{ID: "task-queued", Targets: []string{"n2"}, Interpreter: "sh", Script: "echo hi", TimeoutSec: 3600, Status: model.TaskQueued, CreatedAt: time.Now().UTC()},
	} {
		if err := st.CreateTask(task); err != nil {
			t.Fatal(err)
		}
	}
	if leased, err := st.LeaseTasks("n1", 3); err != nil || len(leased) != 1 {
		t.Fatalf("lease: len=%d err=%v", len(leased), err)
	}
	views := func() map[string]taskView {
		res := doJSON(t, handler, http.MethodGet, "/api/tasks", "", cookies, "")
		defer res.Body.Close()
		var list []taskView
		if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
			t.Fatalf("decode tasks: %v", err)
		}
		out := map[string]taskView{}
		for _, view := range list {
			out[view.ID] = view
		}
		return out
	}

	// 41 minutes into a one-hour lease the task is running on its first try.
	srv.now = func() time.Time { return time.Now().UTC().Add(41 * time.Minute) }
	cases := []struct {
		id             string
		wantStatus     string
		wantAttempts   int
		wantLeaseAge   int64
		wantTargetSeen bool
	}{
		{id: "task-leased", wantStatus: model.TaskLeased, wantAttempts: 1, wantLeaseAge: 41 * 60, wantTargetSeen: true},
		{id: "task-queued", wantStatus: model.TaskQueued},
	}
	got := views()
	for _, tc := range cases {
		view := got[tc.id]
		if view.Status != tc.wantStatus || view.Attempts != tc.wantAttempts {
			t.Fatalf("%s: status=%q attempts=%d want %q/%d", tc.id, view.Status, view.Attempts, tc.wantStatus, tc.wantAttempts)
		}
		if tc.wantAttempts > 0 && view.MaxAttempts != store.MaxTaskLeaseAttempts {
			t.Fatalf("%s: max_attempts=%d want %d", tc.id, view.MaxAttempts, store.MaxTaskLeaseAttempts)
		}
		if view.LeaseAgeSeconds < tc.wantLeaseAge-5 || view.LeaseAgeSeconds > tc.wantLeaseAge+5 {
			t.Fatalf("%s: lease_age_seconds=%d want about %d", tc.id, view.LeaseAgeSeconds, tc.wantLeaseAge)
		}
		if _, seen := view.TargetStates[view.Targets[0]]; seen != tc.wantTargetSeen {
			t.Fatalf("%s: target_states present=%v want %v (%+v)", tc.id, seen, tc.wantTargetSeen, view.TargetStates)
		}
	}
	if target := got["task-leased"].TargetStates["n1"]; target.Status != model.TaskLeased || target.Attempts != 1 {
		t.Fatalf("per-target view = %+v", target)
	}

	// Two hours in, the lease is past timeout and margin: nothing is running.
	srv.now = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }
	view := views()["task-leased"]
	if view.Status != store.TaskStalled || view.TargetStates["n1"].Status != store.TaskStalled {
		t.Fatalf("dead lease should read stalled: %+v", view)
	}
	if view.LeaseAgeSeconds < 2*3600-5 {
		t.Fatalf("lease age should keep growing on a dead lease: %d", view.LeaseAgeSeconds)
	}
}
