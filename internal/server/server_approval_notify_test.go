package server

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type approvalNotice struct {
	eventType string
	msg       notify.Message
}

func captureApprovalNotices(srv *Server) *[]approvalNotice {
	got := []approvalNotice{}
	srv.emitNotifyMessage = func(eventType string, m notify.Message) {
		got = append(got, approvalNotice{eventType, m})
	}
	return &got
}

func TestApprovalPendingNotifyEmitsForHumanPending(t *testing.T) {
	srv, _ := newTestServerWithApprovalRules(t, "")
	notices := captureApprovalNotices(srv)
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-human", "user-admin", "nft", "apply-ruleset"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalPending {
		t.Fatalf("expected pending, got %q", stored.Status)
	}
	if len(*notices) != 1 {
		t.Fatalf("expected one approval.pending, got %+v", *notices)
	}
	n := (*notices)[0]
	if n.eventType != EventApprovalPending {
		t.Fatalf("event type = %q, want %q", n.eventType, EventApprovalPending)
	}
	if n.msg.Title != "Approval pending" {
		t.Fatalf("title = %q", n.msg.Title)
	}
	if !strings.Contains(n.msg.Body, "Apply nftables ruleset") || !strings.Contains(n.msg.Body, "node-1") {
		t.Fatalf("body must name the plan and the node, got %q", n.msg.Body)
	}
	if n.msg.URL != "/approvals/ap-human" {
		t.Fatalf("url = %q, want /approvals/ap-human", n.msg.URL)
	}
}

func TestApprovalPendingNotifySkippedForAutoApprovedLinemeta(t *testing.T) {
	srv, _ := newTestServerWithApprovalRules(t,
		`[{"name":"linemeta-fleet","writer":"lattice-server","plugin":"singbox-linemeta","action_prefix":"apply-metadata","queue":true,"daily_cap":100}]`)
	notices := captureApprovalNotices(srv)
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-auto", "lattice-server", "singbox-linemeta", "apply-metadata:abc"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalApproved {
		t.Fatalf("expected approved, got %q", stored.Status)
	}
	if len(*notices) != 0 {
		t.Fatalf("auto-approved linemeta must not notify, got %+v", *notices)
	}
}

func TestApprovalPendingNotifyWhenLinemetaCapLeavesHumanPending(t *testing.T) {
	srv, st := newTestServerWithApprovalRules(t,
		`[{"name":"capped","writer":"lattice-server","plugin":"singbox-linemeta","queue":false,"daily_cap":1}]`)
	notices := captureApprovalNotices(srv)
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
	if len(*notices) != 1 {
		t.Fatalf("only the cap-skipped pending row should notify, got %+v", *notices)
	}
	if (*notices)[0].eventType != EventApprovalPending || (*notices)[0].msg.URL != "/approvals/ap-cap-2" {
		t.Fatalf("unexpected notice: %+v", (*notices)[0])
	}
}

func TestApprovalPendingNotifyWhenAutoApproveLeavesPending(t *testing.T) {
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
	notices := captureApprovalNotices(srv)
	stored, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-kill", "lattice-server", "nft", "apply-ruleset"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != model.ApprovalPending {
		t.Fatalf("kill switch on: approval must stay pending, got %q", stored.Status)
	}
	if len(*notices) != 1 || (*notices)[0].eventType != EventApprovalPending {
		t.Fatalf("a pending leftover after a failed auto-approve still needs a human, got %+v", *notices)
	}
}

func TestApprovalPendingNotifyUsesPublicOrigin(t *testing.T) {
	srv, _ := newTestServerWithApprovalRules(t, "")
	srv.publicURL = "https://lattice.example"
	notices := captureApprovalNotices(srv)
	if _, err := srv.submitApproval(context.Background(), pendingTestApproval("ap-abs", "user-admin", "nft", "apply-ruleset")); err != nil {
		t.Fatal(err)
	}
	if len(*notices) != 1 || (*notices)[0].msg.URL != "https://lattice.example/approvals/ap-abs" {
		t.Fatalf("expected absolute click URL, got %+v", *notices)
	}
}

func TestApprovalNotifyClickURL(t *testing.T) {
	tests := []struct {
		public, id, want string
	}{
		{public: "", id: "ap-1", want: "/approvals/ap-1"},
		{public: "https://lattice.roobli.org", id: "ap-1", want: "https://lattice.roobli.org/approvals/ap-1"},
		{public: "https://lattice.roobli.org/", id: "ap-1", want: "https://lattice.roobli.org/approvals/ap-1"},
		{public: "https://lattice.example", id: "", want: ""},
		{public: "", id: "ap id", want: "/approvals/ap%20id"},
	}
	for _, tt := range tests {
		if got := approvalNotifyClickURL(tt.public, tt.id); got != tt.want {
			t.Fatalf("approvalNotifyClickURL(%q, %q) = %q, want %q", tt.public, tt.id, got, tt.want)
		}
	}
}

func TestPlanNotifyDeliveriesPreserveClickURL(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "ch-a", Name: "A", Kind: "webhook", Config: map[string]string{"url": "https://example.com/a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	msg := notify.Message{Title: "Approval pending", Body: "needs review", URL: "/approvals/ap-1"}
	broadcast := srv.planNotifyDeliveriesMsg(EventApprovalPending, msg, st.EnabledNotifyChannels(), st.EnabledNotifyRules())
	if len(broadcast) != 1 || broadcast[0].Message.URL != "/approvals/ap-1" {
		t.Fatalf("broadcast must keep the click URL, got %+v", broadcast)
	}
	if err := st.UpsertNotifyRule(model.NotifyRule{ID: "rule-ap", Name: "Approvals", EventTypes: []string{EventApprovalPending}, ChannelIDs: []string{"ch-a"}, TitleTemplate: "[{{event_type}}] {{title}}", BodyTemplate: "{{body}} {{url}}", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	routed := srv.planNotifyDeliveriesMsg(EventApprovalPending, msg, st.EnabledNotifyChannels(), st.EnabledNotifyRules())
	if len(routed) != 1 {
		t.Fatalf("expected one routed delivery, got %+v", routed)
	}
	if routed[0].Message.URL != "/approvals/ap-1" {
		t.Fatalf("rule rendering must keep Message.URL, got %+v", routed[0].Message)
	}
	if routed[0].Message.Title != "[approval.pending] Approval pending" || routed[0].Message.Body != "needs review /approvals/ap-1" {
		t.Fatalf("template should expand url, got %+v", routed[0].Message)
	}
}
