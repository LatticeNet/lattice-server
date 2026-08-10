package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// approvalPolicyActorPrefix prefixes the synthetic actor identity stamped on
// auto-approved records, so they are distinguishable from human decisions and
// countable for the per-rule daily cap.
const approvalPolicyActorPrefix = "policy:"

// approvalAutoRule is one operator-configured auto-approve rule. Rules are
// opt-in (empty config = fully manual approvals) and match freshly submitted
// pending approvals; the first matching rule wins.
type approvalAutoRule struct {
	// Name is required: it identifies the rule in audit events, logs, and the
	// synthetic actor identity used for the daily cap.
	Name string `json:"name"`
	// Writer exact-matches the approval's creator (ActorID); empty matches any.
	Writer string `json:"writer"`
	// Plugin exact-matches the approval's plugin; empty matches any.
	Plugin string `json:"plugin"`
	// ActionPrefix prefix-matches the approval's action; empty matches any.
	ActionPrefix string `json:"action_prefix"`
	// Queue selects approve-and-queue (true) over approve-only (false).
	Queue bool `json:"queue"`
	// DailyCap bounds how many approvals this rule may auto-approve per UTC
	// day; 0 means no cap.
	DailyCap int `json:"daily_cap"`
}

// parseApprovalAutoRules decodes the operator's JSON rule list. The empty
// string is the disabled default and yields no rules; any malformed input is
// an error so the caller can warn and start with zero rules.
func parseApprovalAutoRules(raw string) ([]approvalAutoRule, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var rules []approvalAutoRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil, fmt.Errorf("invalid approval auto rules JSON: %w", err)
	}
	for i := range rules {
		rules[i].Name = strings.TrimSpace(rules[i].Name)
		if rules[i].Name == "" {
			return nil, fmt.Errorf("approval auto rule #%d is missing its required name", i+1)
		}
		if rules[i].DailyCap < 0 {
			return nil, fmt.Errorf("approval auto rule %q has a negative daily_cap", rules[i].Name)
		}
	}
	return rules, nil
}

// matches reports whether the rule applies to a freshly submitted approval.
func (r approvalAutoRule) matches(a model.Approval) bool {
	if r.Writer != "" && r.Writer != a.ActorID {
		return false
	}
	if r.Plugin != "" && r.Plugin != a.Plugin {
		return false
	}
	if r.ActionPrefix != "" && !strings.HasPrefix(a.Action, r.ActionPrefix) {
		return false
	}
	return true
}

// submitApproval is the single chokepoint for recording a NEW approval: it
// persists the plan, then lets the opt-in auto-approve policy engine evaluate
// it. It returns the approval as stored after evaluation so HTTP callers
// answer the terminal state (e.g. already auto-approved) instead of the
// pre-evaluation pending one. Status transitions of existing approvals
// (approve/reject/dismiss/apply) keep calling store.UpsertApproval directly —
// policies only ever act on fresh pending submissions.
func (s *Server) submitApproval(a model.Approval) (model.Approval, error) {
	if err := s.store.UpsertApproval(a); err != nil {
		return model.Approval{}, err
	}
	return s.evaluateApprovalAutoRules(a), nil
}

// evaluateApprovalAutoRules runs the first matching auto-approve rule against
// a freshly submitted approval. With no rules configured (the default) it is
// a pure pass-through, so an unconfigured server behaves exactly as before.
func (s *Server) evaluateApprovalAutoRules(a model.Approval) model.Approval {
	if a.Status != model.ApprovalPending || len(s.approvalAutoRules) == 0 {
		return a
	}
	for _, rule := range s.approvalAutoRules {
		if !rule.matches(a) {
			continue
		}
		// First matching rule wins; later rules never see the approval.
		return s.applyApprovalAutoRule(a, rule)
	}
	return a
}

// applyApprovalAutoRule auto-approves a fresh pending approval through the
// same decision path as the manual approve endpoint, crediting the decision to
// the rule's synthetic policy identity. Any failure leaves the approval
// pending for a human; a policy engine must never lose a submitted plan.
func (s *Server) applyApprovalAutoRule(a model.Approval, rule approvalAutoRule) model.Approval {
	actor := approvalPolicyActorPrefix + rule.Name
	if rule.DailyCap > 0 && s.countPolicyApprovalsToday(actor, s.now()) >= rule.DailyCap {
		s.recordAudit(model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   a.NodeID,
			ActorID:  actor,
			Action:   "approval.auto_skip",
			Scope:    approvalDecisionAuditScope(a),
			Metadata: map[string]string{"policy": rule.Name, "approval_id": a.ID, "reason": "daily_cap"},
		})
		return a
	}
	// Bind the decision to the exact stored plan, mirroring the manual
	// endpoint's plan_sha256 check: the hash is computed over the plan bytes we
	// just persisted, so the auto path can never approve a different plan than
	// the one recorded for review.
	sum := sha256.Sum256([]byte(a.Plan))
	p := principal{Principal: rbac.Principal{ActorID: actor}}
	updated, err := s.approveApprovalCore(p, a, rule.Queue, hex.EncodeToString(sum[:]))
	if err != nil {
		s.logger.Printf("approval auto-approve policy %q left approval %s pending: %v", rule.Name, a.ID, err)
		// The in-memory copy may lag what the decision path persisted (e.g. a
		// stale agent-update plan is auto-rejected there); answer the stored row.
		if stored, ok := s.store.Approval(a.ID); ok {
			return stored
		}
		return a
	}
	// Stamp the policy identity as the record's actor so the daily cap can
	// count policy-driven approvals without a new store index, and so readers
	// can tell an automated decision from a human one. Done after the decision
	// path so a failed auto-approve never poisons the cap, and so the original
	// writer remains on the creation audit event.
	updated.ActorID = actor
	if err := s.store.UpsertApproval(updated); err != nil {
		s.logger.Printf("approval auto-approve policy %q: restamp actor on %s: %v", rule.Name, a.ID, err)
	}
	s.recordAudit(model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   updated.NodeID,
		ActorID:  actor,
		Action:   "approval.auto_approve",
		Scope:    approvalDecisionAuditScope(updated),
		Metadata: map[string]string{"policy": rule.Name, "approval_id": updated.ID, "queued": fmt.Sprintf("%t", rule.Queue)},
	})
	return updated
}

// countPolicyApprovalsToday counts approvals the policy actor already decided
// on the same UTC day as now. It is an O(N) scan over the approvals table;
// acceptable at the current scale of tens of approvals, and worth revisiting
// only if approval volume grows substantially.
func (s *Server) countPolicyApprovalsToday(actor string, now time.Time) int {
	year, month, day := now.UTC().Date()
	count := 0
	for _, a := range s.store.Approvals() {
		if a.ActorID != actor {
			continue
		}
		ay, am, ad := a.CreatedAt.UTC().Date()
		if ay == year && am == month && ad == day {
			count++
		}
	}
	return count
}
