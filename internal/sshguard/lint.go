package sshguard

import "fmt"

// Plan linting exists here rather than being borrowed from netguard because
// the two are calibrated on opposite assumptions.
//
// netguard's acceptsAnyPort is deliberately generous: any accept rule mentioning
// a management port counts as a way in, and it never looks at the rule's source.
// That generosity is defensible where accepts are broad, and its own comment
// says so. Knocking inverts the premise. Under a knock policy the normal state
// of the management port is closed, and acceptance is conditional on a set whose
// membership is empty until someone knocks. Handed a knock ruleset, netguard's
// lint would report a way in that does not exist yet, turning an occasional
// false negative into a systematic one.
//
// So this lint asks a different question: after BOTH tables have had their say,
// is there still a path that does not depend on knocking working?
const (
	// FindingOverriddenByGuard fires when the node is managed by netguard and
	// its lattice_guard chain would not accept a port this profile gates.
	//
	// This is the failure that is hardest to diagnose from the outside. An
	// accept verdict in one chain does NOT let a packet skip later chains at a
	// higher priority in the same hook, so a policy-drop lattice_guard silently
	// discards what the knock table just admitted. The operator sees a knock
	// that reports success followed by a connection that never opens.
	FindingOverriddenByGuard = "sshguard_overridden_by_guard"

	// FindingPortInUse fires when something already listens on the target port.
	// sshd -t does not catch this: binding happens at reload, not at parse.
	FindingPortInUse = "sshguard_port_in_use"

	// FindingNoReality fires when the node has never reported listeners, so the
	// checks above ran against nothing. It is a warning because a first-time
	// node is a normal state, not an error.
	FindingNoReality = "sshguard_no_reality"

	// FindingSingleWayIn fires when every management source is a single host
	// address AND knocking is enabled, meaning the fallback is one IP. It is a
	// warning: it is often exactly what an operator wants, but it should be a
	// decision rather than an accident.
	FindingSingleWayIn = "sshguard_narrow_fallback"

	// FindingFallbackUnavailable fires when a profile claims an out-of-band
	// fallback and the node cannot actually provide one. A claimed fallback
	// that does not exist is worse than an admitted absence, because it is the
	// reason the profile was allowed to gate SSH in the first place.
	FindingFallbackUnavailable = "sshguard_fallback_unavailable"

	// FindingAssumedSSHPort fires when the profile had to fall back to tcp/22
	// because the node never reported where sshd listens. Three machines in
	// this fleet run it on 3434, so the assumption is not safe to make
	// silently: gating the wrong port protects nothing and looks like success.
	FindingAssumedSSHPort = "sshguard_assumed_ssh_port"

	// FindingHardeningOnly fires when the profile has neither a management
	// source nor a knock policy, so Profile.GatesFirewall is false and the
	// apply renders no firewall at all.
	//
	// That is a legitimate profile and the safest one to apply, but it is not
	// what "SSH Guard" sounds like, and a fleet of them reads as protected on
	// the rollout screen while every one of those nodes is still reachable
	// from the whole internet. Say it, so it is a choice.
	FindingHardeningOnly = "sshguard_hardening_only"
)

type Severity string

const (
	SeverityBlock Severity = "block"
	SeverityWarn  Severity = "warn"
)

type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// NodeReality is the subset of observed node state this lint reasons about. It
// is a plain struct rather than the model type so this package keeps no
// dependency on the server's model or store.
type NodeReality struct {
	// Reported is false when the node has never sent a reality snapshot.
	Reported bool
	// ListeningTCPPorts is what the node currently has bound.
	ListeningTCPPorts []int
	// ManagedByNetGuard is true when a guard binding exists for this node, so
	// a lattice_guard table is or will be present.
	ManagedByNetGuard bool
	// GuardAcceptedTCPPorts is what that guard ruleset would accept. Only
	// meaningful when ManagedByNetGuard is true.
	GuardAcceptedTCPPorts []int
	// GuardAcceptsAllTCP is set when the guard has a rule that accepts every
	// TCP port (an any-protocol accept, or a tcp accept with no port list).
	// It is a flag rather than a 65535-entry slice because this is assembled on
	// a request path.
	GuardAcceptsAllTCP bool
	// GuardPolicyDrop reports whether the guard chain's policy is drop. A guard
	// with an accept policy cannot override this table's accepts, so the
	// override check does not apply.
	GuardPolicyDrop bool

	// SSHPorts are the ports a shell daemon is observed bound to. The caller
	// copies these into the profile so the gate covers where sshd is rather
	// than where it is assumed to be.
	SSHPorts []int

	// TerminalAvailable is true when this node can currently give an operator a
	// shell without SSH: it is online and its agent reports the terminal
	// capability. Both halves matter. A capability flag on a node that stopped
	// reporting is a fallback on paper.
	TerminalAvailable bool
}

// Blocking reports whether any finding must stop the plan.
func Blocking(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityBlock {
			return true
		}
	}
	return false
}

// LintProfile checks a profile against what the node actually looks like.
func LintProfile(p Profile, r NodeReality) []Finding {
	findings := []Finding{}
	gated := p.GatedPorts()

	if !r.Reported {
		findings = append(findings, Finding{
			Code: FindingNoReality, Severity: SeverityWarn,
			Message: "this node has never reported its listeners, so the port-conflict and firewall-override checks could not run. The apply verifies the port is listening before it gates anything, but that is a later and more expensive place to find out.",
		})
	} else if p.SSHPort != 0 {
		// sshd holding the port is not a conflict, it is the node already being
		// where the profile wants it. Counting it as one made a node
		// unplannable onto its own port, which is exactly the plan you need
		// when re-arming a node whose current port came from the drop-in this
		// apply replaces.
		alreadySSH := false
		for _, port := range r.SSHPorts {
			if port == p.SSHPort {
				alreadySSH = true
				break
			}
		}
		if !alreadySSH {
			for _, port := range r.ListeningTCPPorts {
				if port == p.SSHPort {
					findings = append(findings, Finding{
						Code: FindingPortInUse, Severity: SeverityBlock,
						Message: fmt.Sprintf("something already listens on tcp/%d. sshd -t does not catch this because binding happens at reload, so the apply would gate a port sshd never got.", p.SSHPort),
					})
					break
				}
			}
		}
	}

	if r.ManagedByNetGuard && r.GuardPolicyDrop && !r.GuardAcceptsAllTCP {
		accepted := make(map[int]bool, len(r.GuardAcceptedTCPPorts))
		for _, port := range r.GuardAcceptedTCPPorts {
			accepted[port] = true
		}
		for _, port := range gated {
			if !accepted[port] {
				findings = append(findings, Finding{
					Code: FindingOverriddenByGuard, Severity: SeverityBlock,
					Message: fmt.Sprintf("this node's lattice_guard ruleset is policy drop and does not accept tcp/%d. An accept in the knock table does not let a packet skip lattice_guard, so knocking would appear to succeed and the connection would still never open. Open tcp/%d in netguard first.", port, port),
				})
			}
		}
	}

	if p.SSHPort == 0 && len(p.ExistingSSHPorts) == 0 {
		findings = append(findings, Finding{
			Code: FindingAssumedSSHPort, Severity: SeverityWarn,
			Message: "this node has not reported where sshd listens, so the gate falls back to tcp/22. Three machines in this fleet run sshd on 3434, where gating 22 protects nothing and still reports success. Check the port before confirming.",
		})
	}

	if p.OutOfBandFallback && !r.TerminalAvailable {
		findings = append(findings, Finding{
			Code: FindingFallbackUnavailable, Severity: SeverityBlock,
			Message: "this profile gates SSH on the grounds that the node's Lattice terminal is the fallback, and that node is either offline or not reporting the terminal capability. Gating SSH now would leave no way in that does not depend on knocking working.",
		})
	}

	if !p.GatesFirewall() {
		findings = append(findings, Finding{
			Code: FindingHardeningOnly, Severity: SeverityWarn,
			Message: "this profile has no management source and no knock sequence, so it installs no firewall: it changes sshd's settings and leaves who can reach the port exactly as it is. Password login stops, the brute force does not. Add a management source if the intent was to narrow access.",
		})
	}

	if p.Knock != nil && len(p.MgmtSources) > 0 {
		narrow := true
		for _, src := range p.MgmtSources {
			norm, err := normalizeCIDR(src)
			if err != nil {
				continue
			}
			if !isSingleHost(norm) {
				narrow = false
				break
			}
		}
		if narrow {
			findings = append(findings, Finding{
				Code: FindingSingleWayIn, Severity: SeverityWarn,
				Message: "every management source is a single host address, so the fallback that does not depend on knocking is one IP. That is often intended, but it should be a decision: if that address changes, the only way back in is the knock sequence.",
			})
		}
	}
	return findings
}

func isSingleHost(prefix string) bool {
	for i := len(prefix) - 1; i >= 0; i-- {
		if prefix[i] == '/' {
			suffix := prefix[i+1:]
			return suffix == "32" || suffix == "128"
		}
	}
	return false
}
