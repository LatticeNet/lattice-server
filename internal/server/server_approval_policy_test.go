package server

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestParseApprovalAutoRules(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantLen int
		wantErr bool
	}{
		{name: "empty disables", raw: "", wantLen: 0},
		{name: "whitespace disables", raw: "  \n\t ", wantLen: 0},
		{
			name:    "valid rule list",
			raw:     `[{"name":"linemeta-fleet","writer":"lattice-server","plugin":"singbox-linemeta","action_prefix":"apply-metadata","queue":true,"daily_cap":100}]`,
			wantLen: 1,
		},
		{name: "empty array is valid and disabled", raw: `[]`, wantLen: 0},
		{name: "invalid JSON", raw: `[{"name":`, wantErr: true},
		{name: "rule without name is rejected", raw: `[{"plugin":"nft"}]`, wantErr: true},
		{name: "whitespace-only name is rejected", raw: `[{"name":"  "}]`, wantErr: true},
		{name: "negative daily cap is rejected", raw: `[{"name":"x","daily_cap":-1}]`, wantErr: true},
		{name: "match-everything rule is rejected", raw: `[{"name":"all"}]`, wantErr: true},
		{name: "single matcher is enough", raw: `[{"name":"only-writer","writer":"lattice-server"}]`, wantLen: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := parseApprovalAutoRules(tt.raw)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q, got rules %+v", tt.raw, rules)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.raw, err)
			}
			if len(rules) != tt.wantLen {
				t.Fatalf("got %d rules, want %d", len(rules), tt.wantLen)
			}
		})
	}
}

// TestNewServerIgnoresInvalidApprovalAutoRules pins the never-fail-startup
// contract: malformed policy config logs a warning and leaves the server with
// zero rules (fully manual approvals).
func TestNewServerIgnoresInvalidApprovalAutoRules(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:             st,
		AdminPassword:     testAdminPass,
		ApprovalAutoRules: `[{"plugin":"nft"}]`,
		Logger:            log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New must not fail on invalid approval rules: %v", err)
	}
	if len(srv.approvalAutoRules) != 0 {
		t.Fatalf("expected zero rules after invalid config, got %+v", srv.approvalAutoRules)
	}
}

func TestApprovalAutoRuleMatches(t *testing.T) {
	rule := approvalAutoRule{Name: "r", Writer: "lattice-server", Plugin: "singbox-linemeta", ActionPrefix: "apply-metadata"}
	tests := []struct {
		name     string
		rule     approvalAutoRule
		approval model.Approval
		want     bool
	}{
		{name: "exact match", rule: rule, approval: model.Approval{ActorID: "lattice-server", Plugin: "singbox-linemeta", Action: "apply-metadata:abc"}, want: true},
		{name: "action prefix matches parameterized action", rule: rule, approval: model.Approval{ActorID: "lattice-server", Plugin: "singbox-linemeta", Action: "apply-metadata:0123456789abcdef"}, want: true},
		{name: "different writer rejected", rule: rule, approval: model.Approval{ActorID: "user-admin", Plugin: "singbox-linemeta", Action: "apply-metadata:abc"}, want: false},
		{name: "different plugin rejected", rule: rule, approval: model.Approval{ActorID: "lattice-server", Plugin: "nft", Action: "apply-metadata:abc"}, want: false},
		{name: "different action rejected", rule: rule, approval: model.Approval{ActorID: "lattice-server", Plugin: "singbox-linemeta", Action: "delete-metadata:abc"}, want: false},
		{name: "empty writer matches any", rule: approvalAutoRule{Name: "r", Plugin: "nft"}, approval: model.Approval{ActorID: "user-admin", Plugin: "nft", Action: "apply-ruleset"}, want: true},
		{name: "empty prefix matches any action", rule: approvalAutoRule{Name: "r", Plugin: "nft"}, approval: model.Approval{ActorID: "user-admin", Plugin: "nft", Action: "apply-ruleset"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.matches(tt.approval); got != tt.want {
				t.Fatalf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newTestServerWithApprovalRules(t *testing.T, rulesJSON string) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:             st,
		AdminPassword:     testAdminPass,
		ApprovalAutoRules: rulesJSON,
		Logger:            log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func pendingTestApproval(id, actor, plugin, action string) model.Approval {
	return model.Approval{
		ID:        id,
		NodeID:    "node-1",
		Plugin:    plugin,
		Action:    action,
		Plan:      "table inet lattice_guard {}",
		Status:    model.ApprovalPending,
		ActorID:   actor,
		CreatedAt: time.Now().UTC(),
	}
}

func auditActions(st *store.Store) []string {
	out := []string{}
	for _, ev := range st.AuditEvents() {
		out = append(out, ev.Action)
	}
	return out
}

func TestApprovalAutoApproveDefaultOff(t *testing.T) {
	srv, st := newTestServerWithApprovalRules(t, "")
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-1", "lattice-server", "nft", "apply-ruleset"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalPending {
		t.Fatalf("no rules configured: approval must stay pending, got %q", stored.Status)
	}
	for _, action := range auditActions(st) {
		if strings.HasPrefix(action, "approval.auto_") {
			t.Fatalf("no rules configured: unexpected auto audit event %q", action)
		}
	}
}

// TestApprovalAutoApproveNeverTouchesUserSubmissions pins the trust boundary:
// a plan submitted by an interactive user must stay manual even when a rule
// covers its plugin and action.
func TestApprovalAutoApproveNeverTouchesUserSubmissions(t *testing.T) {
	srv, st := newTestServerWithApprovalRules(t,
		`[{"name":"fleet-nft","writer":"lattice-server","plugin":"nft","action_prefix":"apply-ruleset","queue":true}]`)
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-user", "user-admin", "nft", "apply-ruleset"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalPending {
		t.Fatalf("user-submitted plan must stay pending, got %q", stored.Status)
	}
	if tasks := st.Tasks(); len(tasks) != 0 {
		t.Fatalf("user-submitted plan must not queue tasks, got %d", len(tasks))
	}
	for _, action := range auditActions(st) {
		if strings.HasPrefix(action, "approval.auto_") {
			t.Fatalf("unexpected auto audit event %q", action)
		}
	}
}

func TestApprovalAutoApproveAndQueue(t *testing.T) {
	srv, st := newTestServerWithApprovalRules(t,
		`[{"name":"linemeta-fleet","writer":"lattice-server","plugin":"singbox-linemeta","action_prefix":"apply-metadata","queue":true,"daily_cap":100}]`)
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-auto", "lattice-server", "singbox-linemeta", "apply-metadata:0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalApproved {
		t.Fatalf("expected approved, got %q", stored.Status)
	}
	if stored.ActorID != "lattice-server" {
		t.Fatalf("creator identity must be preserved, got %q", stored.ActorID)
	}
	if stored.ApprovedBy != "policy:linemeta-fleet" {
		t.Fatalf("expected policy approver identity, got %q", stored.ApprovedBy)
	}
	persisted, ok := st.Approval("ap-auto")
	if !ok || persisted.Status != model.ApprovalApproved || persisted.ActorID != "lattice-server" || persisted.ApprovedBy != "policy:linemeta-fleet" {
		t.Fatalf("stored row mismatch: %+v", persisted)
	}
	tasks := st.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("expected one queued apply task, got %d", len(tasks))
	}
	if tasks[0].ApprovalID != "ap-auto" || tasks[0].Status != model.TaskQueued {
		t.Fatalf("unexpected task: %+v", tasks[0])
	}
	found := false
	for _, ev := range st.AuditEvents() {
		if ev.Action != "approval.auto_approve" {
			continue
		}
		found = true
		if ev.Metadata["policy"] != "linemeta-fleet" || ev.Metadata["approval_id"] != "ap-auto" || ev.Metadata["queued"] != "true" {
			t.Fatalf("unexpected auto_approve metadata: %+v", ev.Metadata)
		}
	}
	if !found {
		t.Fatal("expected an approval.auto_approve audit event")
	}
}

func TestApprovalAutoApproveOnlyDoesNotQueue(t *testing.T) {
	srv, st := newTestServerWithApprovalRules(t,
		`[{"name":"linemeta-fleet","writer":"lattice-server","plugin":"singbox-linemeta","action_prefix":"apply-metadata","queue":false}]`)
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-only", "lattice-server", "singbox-linemeta", "apply-metadata:abc"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalApproved {
		t.Fatalf("expected approved, got %q", stored.Status)
	}
	if tasks := st.Tasks(); len(tasks) != 0 {
		t.Fatalf("approve-only rule must not queue tasks, got %d", len(tasks))
	}
	for _, ev := range st.AuditEvents() {
		if ev.Action == "approval.auto_approve" && ev.Metadata["queued"] != "false" {
			t.Fatalf("expected queued=false in audit metadata, got %+v", ev.Metadata)
		}
	}
}

func TestApprovalAutoApproveFirstMatchWins(t *testing.T) {
	srv, st := newTestServerWithApprovalRules(t,
		`[{"name":"first","writer":"lattice-server","plugin":"singbox-linemeta","queue":false},`+
			`{"name":"second","writer":"lattice-server","plugin":"singbox-linemeta","queue":true}]`)
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-prec", "lattice-server", "singbox-linemeta", "apply-metadata:abc"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalApproved {
		t.Fatalf("expected approved, got %q", stored.Status)
	}
	if stored.ApprovedBy != "policy:first" {
		t.Fatalf("first matching rule must win, got approver %q", stored.ApprovedBy)
	}
	if tasks := st.Tasks(); len(tasks) != 0 {
		t.Fatalf("first rule is approve-only; expected no tasks, got %d", len(tasks))
	}
}

func TestApprovalAutoApproveDailyCap(t *testing.T) {
	srv, st := newTestServerWithApprovalRules(t,
		`[{"name":"capped","writer":"lattice-server","plugin":"singbox-linemeta","queue":false,"daily_cap":1}]`)
	// A decision from a previous UTC day must not consume today's budget.
	if err := st.UpsertApproval(model.Approval{
		ID:         "ap-old",
		NodeID:     "node-1",
		Plugin:     "singbox-linemeta",
		Action:     "apply-metadata:old",
		Status:     model.ApprovalApproved,
		ActorID:    "lattice-server",
		ApprovedBy: "policy:capped",
		CreatedAt:  time.Now().UTC().Add(-25 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	first, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-cap-1", "lattice-server", "singbox-linemeta", "apply-metadata:1"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != model.ApprovalApproved {
		t.Fatalf("first approval within cap must be approved, got %q", first.Status)
	}
	second, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-cap-2", "lattice-server", "singbox-linemeta", "apply-metadata:2"))
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != model.ApprovalPending {
		t.Fatalf("second approval beyond cap must stay pending, got %q", second.Status)
	}
	skips := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == "approval.auto_skip" {
			skips++
			if ev.Metadata["policy"] != "capped" || ev.Metadata["reason"] != "daily_cap" {
				t.Fatalf("unexpected auto_skip metadata: %+v", ev.Metadata)
			}
		}
	}
	if skips != 1 {
		t.Fatalf("expected exactly one approval.auto_skip event, got %d", skips)
	}
}

// TestApprovalAutoApproveLeavesPendingOnDecisionFailure ensures a policy whose
// decision path fails (here: the fleet kill switch blocks queueing) leaves the
// approval pending for a human instead of failing the submission.
func TestApprovalAutoApproveLeavesPendingOnDecisionFailure(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{
		Store:                 st,
		AdminPassword:         testAdminPass,
		ApprovalAutoRules:     `[{"name":"q","writer":"lattice-server","plugin":"nft","queue":true}]`,
		TaskExecutionDisabled: true,
		Logger:                log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-kill", "lattice-server", "nft", "apply-ruleset"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalPending {
		t.Fatalf("kill switch on: queueing fails, approval must stay pending, got %q", stored.Status)
	}
	if stored.ActorID != "lattice-server" {
		t.Fatalf("failed auto-approve must not restamp the actor, got %q", stored.ActorID)
	}
}
