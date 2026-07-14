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
// The binding is the whole point. An approval that names only "plugin X, action Y" can
// be honoured by a different version of X, or a re-signed artifact, or against nodes the
// reviewer never saw, or after the plan was swapped underneath it. So the approval binds
// the plugin ID, its version, the exact artifact digest, the service and method, a hash
// of the request that produced the plan, the target nodes, and a hash of the plan itself
// — and every one of those is re-checked at execution.

const (
	// OperationPlanKind marks the canonical envelope stored in Approval.Plan. The
	// approval's existing plan-hash gate hashes that string, so putting the whole
	// binding tuple inside it means the operator's approval covers all of it — the
	// reviewer cannot approve a plan and have a different plugin, version, artifact,
	// or target set executed under it.
	OperationPlanKind = "lattice.plugin.operation.v1"

	maxOperationSteps      = 128
	maxOperationTargets    = 64
	maxOperationSummary    = 4096
	maxOperationPreview    = 64 * 1024
	maxOperationPlanData   = 256 * 1024
	maxOperationScriptSize = 64 * 1024
)

// PluginOperationPlan is what a plugin's `plan`-effect method returns: a deterministic,
// reviewable description of what an apply would do. It is authored by the plugin and
// never trusted as authorization — only as a proposal.
type PluginOperationPlan struct {
	// Summary is the one-line intent an operator sees first.
	Summary string `json:"summary"`
	// Targets are the node IDs this operation would touch. The server authorizes each
	// one against the approving principal; a plugin cannot widen its own blast radius
	// by naming extra nodes, because the approval binds this exact set.
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
	// Data is opaque plugin-owned state carried through approval back into execute.
	// The server does not interpret it; it only guarantees it is exactly what was
	// approved, byte for byte.
	Data json.RawMessage `json:"data,omitempty"`
}

// OperationEnvelope is the canonical, signed-by-approval binding tuple. It is what gets
// serialized into Approval.Plan, so the approval's plan hash covers every field.
type OperationEnvelope struct {
	Kind string `json:"kind"`

	PluginID       string `json:"plugin_id"`
	PluginVersion  string `json:"plugin_version"`
	ArtifactDigest string `json:"artifact_digest"`
	Service        string `json:"service"`
	Method         string `json:"method"`
	// RequestSHA256 hashes the request that produced this plan. Re-planning with
	// different inputs produces a different approval; an approval cannot be replayed
	// against a request the operator never saw.
	RequestSHA256 string `json:"request_sha256"`

	Plan PluginOperationPlan `json:"plan"`
}

// CanonicalOperationEnvelope renders the envelope deterministically. Determinism is
// load-bearing: the approval's plan hash is taken over these bytes, so any ambiguity in
// the encoding would be an ambiguity in what the operator approved.
func CanonicalOperationEnvelope(env OperationEnvelope) (string, error) {
	env.Kind = OperationPlanKind
	// json.Marshal sorts struct fields by declaration and map keys lexically, and the
	// envelope contains no maps except the plugin's opaque Data, which is passed
	// through verbatim as the bytes the plugin produced.
	raw, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("canonicalize operation envelope: %w", err)
	}
	return string(raw), nil
}

// ParseOperationEnvelope reads back what CanonicalOperationEnvelope wrote.
func ParseOperationEnvelope(plan string) (OperationEnvelope, error) {
	var env OperationEnvelope
	decoder := json.NewDecoder(strings.NewReader(plan))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&env); err != nil {
		return OperationEnvelope{}, fmt.Errorf("parse operation envelope: %w", err)
	}
	if env.Kind != OperationPlanKind {
		return OperationEnvelope{}, fmt.Errorf("approval is not a plugin operation (kind %q)", env.Kind)
	}
	return env, nil
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

// SHA256Hex is the one hashing helper the operation protocol uses, so plan hashes,
// request hashes, and task payload hashes are all computed the same way.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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
	// PlanSHA256 is the hash of the exact approved envelope. Every task the plugin
	// tries to enqueue is checked against this, so a plugin cannot execute one approval
	// and enqueue work belonging to another.
	PlanSHA256 string
	// Targets is the approved node set. The broker refuses any task aimed elsewhere,
	// so a plugin holding a legitimate grant still cannot reach an unapproved node.
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
