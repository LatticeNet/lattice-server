package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The host-risk operation protocol (spec §9.3).
//
// A plugin may compile domain intent into a plan, but it may never apply one. Between
// intent and effect sits an operator: the plugin returns a deterministic plan, the
// server binds that plan to everything that could change under it, a human approves
// exactly what they read, and only then is the plugin invoked — once — with a grant
// narrow enough that the worst it can do is the thing that was approved.
//
// The binding lives in typed columns on the approval (Approval.PluginVersion,
// ArtifactDigest, Service, Method, RequestSHA256, Targets), not in the reviewable plan
// text. Each column records the exact code and inputs that produced the plan, and each
// is compared to live state at execution: a plugin that was upgraded, re-signed, or
// disabled between approval and execute no longer matches what the operator approved.
// The plan text itself — what the operator reads — is covered by the existing approval
// plan-hash gate.

const (
	maxOperationSteps      = 128
	maxOperationTargets    = 64
	maxOperationSummary    = 4096
	maxOperationPreview    = 64 * 1024
	maxOperationScriptSize = 64 * 1024
	maxOperationPlanData   = 256 * 1024
)

// PluginOperationPlan is what a plugin's `plan`-effect method returns: a deterministic,
// reviewable description of what an apply would do. It is authored by the plugin and
// never trusted as authorization — only as a proposal. It is what the server stores in
// Approval.Plan and what the operator reads.
type PluginOperationPlan struct {
	// Summary is the one-line intent an operator sees first.
	Summary string `json:"summary"`
	// Targets are the node IDs this operation would touch. The server authorizes each
	// one against the approving principal and records them as Approval.Targets; a plugin
	// cannot widen its own blast radius by naming extra nodes.
	Targets []string `json:"targets"`
	// Preview is the redacted, human-reviewable body of the change. It is what the
	// operator actually reads, so it must not contain secrets — the plugin redacts it,
	// and the server never reconstructs the unredacted form (§9.4).
	Preview string `json:"preview,omitempty"`
	// Steps are the ordered actions the plugin intends to take.
	Steps []string `json:"steps,omitempty"`
	// Rollback states what undoing this looks like. A plan that cannot say how it is
	// undone is a plan an operator cannot safely approve.
	Rollback string `json:"rollback,omitempty"`
	// Data is opaque plugin-owned state carried through approval back into execute. The
	// server does not interpret it; it hands back exactly what was approved.
	Data json.RawMessage `json:"data,omitempty"`
}

// CanonicalOperationPlan renders the reviewable plan deterministically. This string is
// stored in Approval.Plan and hashed by the approval plan-hash gate, so the operator
// approves exactly these bytes; any ambiguity in the encoding would be an ambiguity in
// what was approved.
func CanonicalOperationPlan(plan PluginOperationPlan) (string, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("canonicalize operation plan: %w", err)
	}
	return string(raw), nil
}

// ParseOperationPlan reads back a stored plan.
func ParseOperationPlan(plan string) (PluginOperationPlan, error) {
	var out PluginOperationPlan
	decoder := json.NewDecoder(strings.NewReader(plan))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return PluginOperationPlan{}, fmt.Errorf("parse operation plan: %w", err)
	}
	return out, nil
}

// ValidateOperationPlan bounds what a plugin may propose. A plan is plugin-authored
// input crossing into the operator's review surface, so it is checked like any other
// untrusted input — before a human is asked to read it.
func ValidateOperationPlan(plan PluginOperationPlan) error {
	if strings.TrimSpace(plan.Summary) == "" {
		return errors.New("operation plan requires a summary")
	}
	if len(plan.Summary) > maxOperationSummary {
		return fmt.Errorf("operation plan summary exceeds %d bytes", maxOperationSummary)
	}
	if len(plan.Targets) == 0 {
		return errors.New("operation plan must name at least one target node")
	}
	if len(plan.Targets) > maxOperationTargets {
		return fmt.Errorf("operation plan exceeds %d targets", maxOperationTargets)
	}
	seen := map[string]bool{}
	for _, target := range plan.Targets {
		if strings.TrimSpace(target) == "" {
			return errors.New("operation plan target must not be empty")
		}
		if seen[target] {
			return fmt.Errorf("operation plan repeats target %q", target)
		}
		seen[target] = true
	}
	if len(plan.Preview) > maxOperationPreview {
		return fmt.Errorf("operation plan preview exceeds %d bytes", maxOperationPreview)
	}
	if len(plan.Steps) > maxOperationSteps {
		return fmt.Errorf("operation plan exceeds %d steps", maxOperationSteps)
	}
	if len(plan.Data) > maxOperationPlanData {
		return fmt.Errorf("operation plan data exceeds %d bytes", maxOperationPlanData)
	}
	return nil
}

// SHA256Hex is the one hashing helper the operation protocol uses, so plan hashes and
// request hashes are computed the same way.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// OperationExecuteRequest is what the approval executor hands the plugin's `execute`
// action: the approved plan's opaque data and the approved targets. The plugin acts on
// this, but every task it then tries to enqueue is checked by the broker against the
// grant — so this payload is a convenience, not an authority.
type OperationExecuteRequest struct {
	ApprovalID string          `json:"approval_id"`
	Targets    []string        `json:"targets"`
	Data       json.RawMessage `json:"data,omitempty"`
}

// OperationGrant is the one-time, invocation-scoped authority handed to a plugin when
// the approval executor invokes it. It is bound into the invocation's context and is
// NEVER serialized to the child process: the plugin cannot read it, forge it, or widen
// it — it can only cause the broker to consult it by making a host call.
//
// This mirrors how operator targets are bound (InvokeConstraints.OperatorTargets): the
// grant lives on the host side of the boundary, and the plugin's only interaction with
// it is that the broker checks a request against it.
type OperationGrant struct {
	ApprovalID string
	PluginID   string
	// PlanSHA256 is the hash of the exact approved plan text. Carried for audit so a
	// task can be tied back to the approval it ran under.
	PlanSHA256 string
	// Targets is the approved node set. The broker refuses any task aimed elsewhere, so
	// a plugin holding a legitimate grant still cannot reach an unapproved node.
	Targets []string
	// Remaining bounds how many tasks this single approved operation may enqueue.
	Remaining int
}

// AllowsTarget reports whether a node was in the approved set.
func (g *OperationGrant) AllowsTarget(nodeID string) bool {
	for _, target := range g.Targets {
		if target == nodeID {
			return true
		}
	}
	return false
}
