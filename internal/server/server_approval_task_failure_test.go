package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestApprovalTaskFailureClosesApprovalWithReason(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	now := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)
	configSHA := strings.Repeat("a", 64)

	cases := []struct {
		name     string
		approval model.Approval
		setup    func(t *testing.T, approval model.Approval)
	}{
		{
			name: "netpolicy",
			approval: model.Approval{
				ID: "approval-netpolicy", NodeID: "node-a", Plugin: "nftpolicy", Action: nftPolicyApplyAction, Plan: "table inet lattice_policy {}\n",
			},
			setup: func(t *testing.T, approval model.Approval) {
				t.Helper()
				if err := st.UpsertNetPolicy(model.NetPolicy{
					ID: "policy-a", TargetNodeID: approval.NodeID, Enabled: true, LastPlanSHA: approvalPlanSHA(approval),
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "selfdns",
			approval: model.Approval{
				ID: "approval-selfdns", NodeID: "node-a", Plugin: "selfdns", Action: selfDNSApprovalAction("dns-a"), Plan: "zone config\n",
			},
			setup: func(t *testing.T, approval model.Approval) {
				t.Helper()
				if err := st.UpsertDNSDeployment(model.DNSDeployment{ID: "dns-a", NodeID: approval.NodeID, Status: model.DNSStatusApplying}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "proxycore",
			approval: model.Approval{
				ID: "approval-proxycore", NodeID: "node-a", Plugin: proxyCorePlugin, Action: proxyCoreApprovalAction(configSHA), Plan: "sing-box config\n",
			},
			setup: func(t *testing.T, approval model.Approval) {
				t.Helper()
				if err := st.UpsertProxyNodeProfile(model.ProxyNodeProfile{ID: "proxy-a", NodeID: approval.NodeID, Core: "sing-box"}); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			approval := tc.approval
			approval.Status = model.ApprovalApproved
			approval.CreatedAt = now
			approval.UpdatedAt = now
			tc.setup(t, approval)
			if err := st.UpsertApproval(approval); err != nil {
				t.Fatal(err)
			}
			task := model.Task{ID: "task-" + tc.name, ApprovalID: approval.ID}
			result := model.TaskResult{
				TaskID: task.ID, NodeID: approval.NodeID, ExitCode: 1, Stderr: tc.name + " apply failed", FinishedAt: now.Add(time.Minute),
			}
			if err := srv.handleApprovalTaskResult(httptest.NewRequest(http.MethodPost, "/api/agent/task-result", nil), task, result); err != nil {
				t.Fatal(err)
			}
			stored, ok := st.Approval(approval.ID)
			if !ok || stored.Status != model.ApprovalRejected {
				t.Fatalf("failed task should close approval as rejected: ok=%v approval=%+v", ok, stored)
			}
			if !strings.Contains(stored.Reason, tc.name+" apply failed") {
				t.Fatalf("failed task should expose approval reason, got %q", stored.Reason)
			}
		})
	}
}

func TestTaskFailureSummaryIncludesDebugOutput(t *testing.T) {
	result := model.TaskResult{
		ExitCode: 1,
		Error:    "exit status 1",
		Stderr:   "line one\npermission denied while moving binary",
		Stdout:   "lattice agent update: downloaded candidate",
	}
	summary := taskFailureSummary(result)
	for _, want := range []string{
		"error=exit status 1",
		"exit_code=1",
		"stderr=line one permission denied while moving binary",
		"stdout=lattice agent update: downloaded candidate",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q: %q", want, summary)
		}
	}
}
