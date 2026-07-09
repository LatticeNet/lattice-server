package netguard

import (
	"fmt"

	"github.com/LatticeNet/lattice-server/internal/network"
)

// Plan linting turns the dmit-eb-wee failure class from a post-apply rollback
// into a pre-plan refusal. The guard chain is policy drop, so a plan that
// accepts nothing on the node's management port severs the operator's own SSH
// path the moment it commits; only the 60s dead-man watchdog would save it.
// (design-13 §4.4)

const (
	// FindingLockoutRiskSSH fires when no compiled rule can accept traffic on
	// the management port from anywhere.
	FindingLockoutRiskSSH = "lockout_risk_ssh"
	// FindingUnverifiedApply fires when the server has no public URL, so the
	// node-side apply cannot run a control-plane selfcheck after committing.
	FindingUnverifiedApply = "unverified_apply"

	SeverityBlock = "block"
	SeverityWarn  = "warn"

	// ManagementPort is the port the lockout lint protects. Until reality
	// reporting lands (design-13 G3 surfaces the node's real sshd listener),
	// tcp/22 is the safe universal assumption.
	ManagementPort = 22
)

// Finding is one lint result. Blocking findings refuse the plan unless the
// operator explicitly accepts the risk, which is audited.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// LintOptions carries the plan-time context the compiled ruleset cannot know.
type LintOptions struct {
	// PublicURLConfigured reports whether the node-side apply will be able to
	// run `lattice-agent --selfcheck-controlplane` after committing.
	PublicURLConfigured bool
}

// Lint inspects a compiled plan for the failure modes that make a guard apply
// unsafe. It never mutates the plan.
func Lint(plan network.NFTPlan, opts LintOptions) []Finding {
	var findings []Finding
	if !acceptsManagementPort(plan) {
		findings = append(findings, Finding{
			Code:     FindingLockoutRiskSSH,
			Severity: SeverityBlock,
			Message: fmt.Sprintf(
				"no rule accepts inbound tcp/%d: committing this default-drop ruleset would cut the operator's SSH path. Add a management-port allow, trust an overlay zone, or explicitly accept the lockout risk.",
				ManagementPort),
		})
	}
	if !opts.PublicURLConfigured {
		findings = append(findings, Finding{
			Code:     FindingUnverifiedApply,
			Severity: SeverityWarn,
			Message:  "the server has no public URL configured, so the node cannot run a control-plane selfcheck after committing. The apply will be protected only by the dead-man watchdog.",
		})
	}
	return findings
}

// Blocking reports whether any finding blocks the plan.
func Blocking(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityBlock {
			return true
		}
	}
	return false
}

// acceptsManagementPort reports whether some compiled rule could accept a new
// inbound connection on the management port. It is deliberately generous: a
// trusted-zone accept, an any-protocol accept, or a tcp accept whose port list
// is empty (all ports) or contains the management port all count. Being
// generous means the lint only fires when the plan really has no path, so it
// stays a signal rather than noise.
func acceptsManagementPort(plan network.NFTPlan) bool {
	if containsPort(plan.PublicTCP, ManagementPort) || containsPort(plan.WireGuardTCP, ManagementPort) {
		return true
	}
	for _, rule := range plan.InputRules {
		if rule.Action != network.NFTActionAccept {
			continue
		}
		switch rule.Protocol {
		case network.NFTProtoAny:
			return true
		case network.NFTProtoTCP:
			if len(rule.Ports) == 0 || containsPort(rule.Ports, ManagementPort) {
				return true
			}
		}
	}
	return false
}

func containsPort(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}
