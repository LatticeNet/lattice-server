package server

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/notify"
)

// EventApprovalPending fires when a newly filed approval still needs a human.
// Auto-approved rows (KI-6 linemeta among them) do not emit, so the phone
// Inbox is not flooded by metadata sync.
const EventApprovalPending = "approval.pending"

// notifyApprovalPending emits a typed approval.pending event for a freshly
// submitted approval that is still pending after auto-approve evaluation.
func (s *Server) notifyApprovalPending(a model.Approval) {
	if a.Status != model.ApprovalPending {
		return
	}
	id := strings.TrimSpace(a.ID)
	if id == "" {
		return
	}
	msg := notify.Message{
		Title: "Approval pending",
		Body:  fmt.Sprintf("%s on %s needs review.", approvalDisplayReason(a), s.nodeDisplayName(a.NodeID)),
		URL:   approvalNotifyClickURL(s.publicURL, id),
	}
	if s.emitNotifyMessage != nil {
		s.emitNotifyMessage(EventApprovalPending, msg)
		return
	}
	s.sendNotifyMessage(EventApprovalPending, msg)
}

// approvalNotifyClickURL is the Bark tap target for one approval: an
// absolute URL when the server knows its public origin, otherwise the path
// /approvals/{id} a channel can join.
func approvalNotifyClickURL(publicURL, approvalID string) string {
	id := strings.TrimSpace(approvalID)
	if id == "" {
		return ""
	}
	path := "/approvals/" + url.PathEscape(id)
	base := strings.TrimRight(strings.TrimSpace(publicURL), "/")
	if base == "" {
		return path
	}
	return base + path
}
