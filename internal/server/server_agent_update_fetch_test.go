package server

import (
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func fetchSeconds(n int64) *int64 { return &n }

// The record the policy keeps is the same fields the audit line carries, read
// into types: the first-pass place or the second pass, the kind, the exit
// status, the bytes, and the seconds or their absence.
func TestParseAgentFetchSummaryReadsTheRecord(t *testing.T) {
	for _, tc := range []struct {
		output string
		want   model.AgentUpdateFetch
	}{
		{
			"lattice-agent-fetch v1 1:cp.gz:28:524288:30 2:up:0:13512866:200 result:0:done",
			model.AgentUpdateFetch{
				Fetches: []model.AgentUpdateFetchAttempt{
					{Source: 1, Kind: model.AgentFetchKindControlPlaneGzip, ExitCode: 28, Bytes: 524288, Seconds: fetchSeconds(30)},
					{Source: 2, Kind: model.AgentFetchKindUpstream, ExitCode: 0, Bytes: 13512866, Seconds: fetchSeconds(200)},
				},
				ExitCode: 0, Stage: model.AgentFetchStageDone,
			},
		},
		{
			"lattice-agent-fetch v1 1:cp:18:5:- p2:cp:0:0:0 result:1:verify",
			model.AgentUpdateFetch{
				Fetches: []model.AgentUpdateFetchAttempt{
					{Source: 1, Kind: model.AgentFetchKindControlPlane, ExitCode: 18, Bytes: 5},
					{SecondPass: true, Kind: model.AgentFetchKindControlPlane, ExitCode: 0, Bytes: 0, Seconds: fetchSeconds(0)},
				},
				ExitCode: 1, Stage: model.AgentFetchStageVerify,
			},
		},
		{"lattice-agent-fetch v1 result:1:prepare", model.AgentUpdateFetch{ExitCode: 1, Stage: model.AgentFetchStagePrepare}},
	} {
		_, got, ok := parseAgentFetchSummary(tc.output)
		if !ok || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("parse %q = %+v %t, want %+v", tc.output, got, ok, tc.want)
		}
	}
	if _, got, ok := parseAgentFetchSummary("lattice-agent-fetch v1 1:cp:0:1:1 2:evil result:0:done"); ok || !reflect.DeepEqual(got, model.AgentUpdateFetch{}) {
		t.Fatalf("a refused line must yield no record, got %+v %t", got, ok)
	}
}

// The policy keeps the last fetch a result reported: on success, on failure,
// and on a result that lands after the node's own report applied the
// approval. A result without the line leaves the record it had, and the late
// path writes last_fetch alone, so the applied version the report wrote
// stays.
func TestAgentUpdateTaskResultKeepsTheLastFetchOnThePolicy(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, ok := controlPlaneApprovalFor(st, "node-a")
	if !ok {
		t.Fatal("no planned approval")
	}
	at := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	srv.now = func() time.Time { return at }
	req := httptest.NewRequest("POST", "/api/tasks/results", nil)
	lastFetch := func() *model.AgentUpdateFetch {
		t.Helper()
		policy, ok := st.AgentUpdatePolicy("node-a")
		if !ok {
			t.Fatal("policy gone")
		}
		return policy.LastFetch
	}
	run := func(status string, result model.TaskResult) {
		t.Helper()
		approval.Status = status
		if err := st.UpsertApproval(approval); err != nil {
			t.Fatal(err)
		}
		if err := srv.handleAgentUpdateTaskResult(req, approval, result); err != nil {
			t.Fatal(err)
		}
	}

	if got := lastFetch(); got != nil {
		t.Fatalf("a policy no result reported on carries no fetch, got %+v", got)
	}

	run(model.ApprovalApproved, model.TaskResult{Stderr: "lattice agent update: x\nlattice-agent-fetch v1 1:cp:28:1000:30 2:up:0:9000:12 result:0:done\n"})
	want := &model.AgentUpdateFetch{
		ApprovalID: approval.ID, TargetVersion: "0.3.4", At: at,
		Fetches: []model.AgentUpdateFetchAttempt{
			{Source: 1, Kind: "cp", ExitCode: 28, Bytes: 1000, Seconds: fetchSeconds(30)},
			{Source: 2, Kind: "up", ExitCode: 0, Bytes: 9000, Seconds: fetchSeconds(12)},
		},
		ExitCode: 0, Stage: "done",
	}
	if got := lastFetch(); !reflect.DeepEqual(got, want) {
		t.Fatalf("success: last_fetch = %+v, want %+v", got, want)
	}

	at = at.Add(time.Hour)
	run(model.ApprovalApproved, model.TaskResult{ExitCode: 1, Stderr: "lattice-agent-fetch v1 1:cp:0:9000:20 result:1:verify\n"})
	failed := lastFetch()
	if failed == nil || failed.Stage != "verify" || failed.ExitCode != 1 || !failed.At.Equal(at) || len(failed.Fetches) != 1 {
		t.Fatalf("failure: last_fetch = %+v", failed)
	}
	if policy, _ := st.AgentUpdatePolicy("node-a"); policy.LastError == "" {
		t.Fatal("the failure must still set last_error")
	}

	// An approval planned before the walk prints no line; what was recorded
	// stays.
	run(model.ApprovalApproved, model.TaskResult{ExitCode: 1, Stderr: "lattice agent update: download failed\n"})
	if got := lastFetch(); !reflect.DeepEqual(got, failed) {
		t.Fatalf("a result without a summary changed last_fetch to %+v", got)
	}

	// The late path, both ways in: the approval already applied when the
	// result is read, and applied between that read and the write.
	for _, tc := range []struct {
		name          string
		stored, given string
	}{
		{"applied before the read", model.ApprovalApplied, model.ApprovalApplied},
		{"applied before the write", model.ApprovalApplied, model.ApprovalApproved},
	} {
		at = at.Add(time.Hour)
		policy, _ := st.AgentUpdatePolicy("node-a")
		policy.LastAppliedVersion, policy.LastAppliedAt = "0.3.4", at
		if err := st.UpsertAgentUpdatePolicy(policy); err != nil {
			t.Fatal(err)
		}
		approval.Status = tc.stored
		if err := st.UpsertApproval(approval); err != nil {
			t.Fatal(err)
		}
		given := approval
		given.Status = tc.given
		if err := srv.handleAgentUpdateTaskResult(req, given, model.TaskResult{Stderr: "lattice-agent-fetch v1 1:cp.gz:0:5552813:41 result:0:done\n"}); err != nil {
			t.Fatal(err)
		}
		after, _ := st.AgentUpdatePolicy("node-a")
		if after.LastFetch == nil || !after.LastFetch.At.Equal(at) || after.LastFetch.Fetches[0].Kind != "cp.gz" {
			t.Fatalf("%s: last_fetch = %+v", tc.name, after.LastFetch)
		}
		if after.LastAppliedVersion != "0.3.4" || !after.LastAppliedAt.Equal(at) || after.LastError != policy.LastError {
			t.Fatalf("%s: the late fetch record changed other policy fields: %+v", tc.name, after)
		}
		if current, _ := st.Approval(approval.ID); current.Status != model.ApprovalApplied {
			t.Fatalf("%s: the applied approval became %s", tc.name, current.Status)
		}
	}

	// A policy deleted before a late result lands is not re-created for it.
	if err := st.DeleteAgentUpdatePolicy("node-a"); err != nil {
		t.Fatal(err)
	}
	approval.Status = model.ApprovalApplied
	if err := srv.handleAgentUpdateTaskResult(req, approval, model.TaskResult{Stderr: "lattice-agent-fetch v1 1:cp:0:1:1 result:0:done\n"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.AgentUpdatePolicy("node-a"); ok {
		t.Fatal("a late fetch record re-created a deleted policy")
	}
}

// The agent's outbox can deliver an older approval's result after a newer
// approval's, so the record a policy keeps is the one from the approval
// planned last, whatever order the results land in.
func TestAgentUpdateLastFetchKeepsTheNewerApprovalsRecord(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	older, ok := controlPlaneApprovalFor(st, "node-a")
	if !ok {
		t.Fatal("no planned approval")
	}
	newer := older
	newer.ID = "approval_newerplan"
	newer.CreatedAt = older.CreatedAt.Add(time.Hour)
	newer.Status = model.ApprovalApproved
	if err := st.UpsertApproval(newer); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/tasks/results", nil)
	if err := srv.handleAgentUpdateTaskResult(req, newer, model.TaskResult{Stderr: "lattice-agent-fetch v1 1:cp.gz:0:5552813:6 result:0:done\n"}); err != nil {
		t.Fatal(err)
	}

	// The older approval's result, replayed late, on both of its paths.
	older.Status = model.ApprovalApplied
	if err := st.UpsertApproval(older); err != nil {
		t.Fatal(err)
	}
	if err := srv.handleAgentUpdateTaskResult(req, older, model.TaskResult{Stderr: "lattice-agent-fetch v1 1:cp:28:1:30 result:28:fetch\n"}); err != nil {
		t.Fatal(err)
	}
	older.Status = model.ApprovalApproved
	if err := st.UpsertApproval(older); err != nil {
		t.Fatal(err)
	}
	if err := srv.handleAgentUpdateTaskResult(req, older, model.TaskResult{ExitCode: 28, Stderr: "lattice-agent-fetch v1 1:cp:28:1:30 result:28:fetch\n"}); err != nil {
		t.Fatal(err)
	}
	policy, _ := st.AgentUpdatePolicy("node-a")
	if policy.LastFetch == nil || policy.LastFetch.ApprovalID != newer.ID {
		t.Fatalf("an older approval's late result replaced the newer record: %+v", policy.LastFetch)
	}
	if policy.LastError == "" {
		t.Fatal("the older approval's failure must still set last_error")
	}

	// The other way round, the newer approval's record replaces the older.
	if _, err := st.MutateAgentUpdatePolicy("node-a", false, func(p *model.AgentUpdatePolicy) bool {
		p.LastFetch = &model.AgentUpdateFetch{ApprovalID: older.ID, Stage: "fetch", ExitCode: 28}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.handleAgentUpdateTaskResult(req, newer, model.TaskResult{Stderr: "lattice-agent-fetch v1 1:cp.gz:0:5552813:6 result:0:done\n"}); err != nil {
		t.Fatal(err)
	}
	if policy, _ := st.AgentUpdatePolicy("node-a"); policy.LastFetch == nil || policy.LastFetch.ApprovalID != newer.ID {
		t.Fatalf("the newer approval's record must replace the older one: %+v", policy.LastFetch)
	}
}

// The node's report can confirm the update between the result's approval
// write and its policy write. The policy then already says the target is
// applied, and the result must neither put "awaiting confirmation" back nor
// touch the applied version.
func TestAgentUpdateSuccessAfterConfirmationKeepsThePolicyConfirmed(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedControlPlaneUpdate(t, srv, st)
	approval, ok := controlPlaneApprovalFor(st, "node-a")
	if !ok {
		t.Fatal("no planned approval")
	}
	approval.Status = model.ApprovalApproved
	if err := st.UpsertApproval(approval); err != nil {
		t.Fatal(err)
	}
	confirmedAt := approval.CreatedAt.Add(time.Minute)
	if _, err := st.MutateAgentUpdatePolicy("node-a", false, func(p *model.AgentUpdatePolicy) bool {
		p.LastAppliedVersion, p.LastAppliedAt, p.LastError = "0.3.4", confirmedAt, ""
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.handleAgentUpdateTaskResult(httptest.NewRequest("POST", "/api/tasks/results", nil), approval, model.TaskResult{Stderr: "lattice-agent-fetch v1 1:cp.gz:0:5552813:6 result:0:done\n"}); err != nil {
		t.Fatal(err)
	}
	policy, _ := st.AgentUpdatePolicy("node-a")
	if policy.LastError != "" || policy.LastAppliedVersion != "0.3.4" || !policy.LastAppliedAt.Equal(confirmedAt) {
		t.Fatalf("a confirmed policy was rolled back: last_error=%q applied=%s at %s", policy.LastError, policy.LastAppliedVersion, policy.LastAppliedAt)
	}
	if policy.LastFetch == nil || policy.LastFetch.ApprovalID != approval.ID {
		t.Fatalf("the fetch record must still be kept: %+v", policy.LastFetch)
	}
}

// last_fetch is the control plane's to write. A policy save that carries one
// keeps the stored record, and a new policy starts without one.
func TestAgentUpdatePolicySaveIgnoresAClientLastFetch(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	forged := &model.AgentUpdateFetch{ApprovalID: "approval_forged", Stage: "done"}
	req := model.AgentUpdatePolicy{NodeID: "node-a", Enabled: true, TargetVersion: "0.2.0", BinaryURL: "https://downloads.example.com/lattice-agent-linux-amd64", SHA256: agentUpdateTestSHA, LastFetch: forged}
	fresh, err := srv.normalizeAgentUpdatePolicy(req)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.LastFetch != nil {
		t.Fatalf("a new policy took the client's last_fetch: %+v", fresh.LastFetch)
	}
	stored := &model.AgentUpdateFetch{ApprovalID: "approval_real", Stage: "fetch", ExitCode: 28}
	fresh.LastFetch = stored
	if err := st.UpsertAgentUpdatePolicy(fresh); err != nil {
		t.Fatal(err)
	}
	edited, err := srv.normalizeAgentUpdatePolicy(req)
	if err != nil {
		t.Fatal(err)
	}
	if edited.LastFetch == nil || edited.LastFetch.ApprovalID != "approval_real" {
		t.Fatalf("an edit must keep the stored last_fetch, got %+v", edited.LastFetch)
	}
}
