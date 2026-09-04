package netguard

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

// Plan linting turns the dmit-eb-wee failure class from a post-apply rollback
// into a pre-plan refusal. The guard chain is policy drop, so a plan that
// accepts nothing on the node's management port severs the operator's own SSH
// path the moment it commits. (design-13 §4.4)
//
// The lint is the ONLY protection against that class, which is worth stating
// plainly because it is easy to assume the apply watchdog covers it. It does
// not. The node-side apply arms a 60s dead-man watchdog and then verifies with
// `lattice-agent --selfcheck-controlplane`, which is an OUTBOUND connection to
// the control plane. A default-drop INPUT ruleset does not block outbound
// traffic, so the selfcheck passes, the watchdog is disarmed, and the ruleset
// that just cut every inbound shell path is committed permanently. Nothing
// downstream of this file will catch it.

const (
	// FindingLockoutRiskSSH fires when no compiled rule can accept traffic on
	// any of the node's management ports.
	FindingLockoutRiskSSH = "lockout_risk_ssh"
	// FindingUnverifiedApply fires when the server has no public URL, so the
	// node-side apply cannot run a control-plane selfcheck after committing.
	FindingUnverifiedApply = "unverified_apply"
	// FindingManagementPortAssumed fires when the lockout check had no reported
	// reality to learn the node's real shell port from and fell back to tcp/22.
	// It is a warning rather than a block because tcp/22 is usually right; it
	// exists so an operator can tell a checked plan from a guessed one.
	FindingManagementPortAssumed = "management_port_assumed"
	// FindingInterfaceMissing fires when a rule matches an inbound interface
	// the node does not report. The public zone defaults to eth0, and twelve
	// fleet nodes have no eth0 (ens17, ens5, enp2s0, wlo1): every accept on
	// that interface matches nothing, the default drop takes over, and the
	// lockout check above still counts those accepts as a way in.
	FindingInterfaceMissing = "interface_missing"
	// FindingInterfaceUnverified fires when a rule matches an inbound interface
	// but the node has never reported which interfaces it has, so the lint
	// cannot tell a right name from a wrong one. It blocks rather than warns
	// because the wrong name is the lockout above, and a node that has not
	// reported is exactly the node most likely to be running an agent old
	// enough to have been enrolled with the eth0 guess.
	FindingInterfaceUnverified = "interface_unverified"

	SeverityBlock = "block"
	SeverityWarn  = "warn"

	// ManagementPort is the port the lockout lint falls back to when the node
	// has never reported which port its shell daemon actually listens on.
	ManagementPort = 22
)

// shellDaemons are the process-name prefixes that identify a remote shell
// daemon in a reality snapshot. The list is deliberately short: a false match
// would let the lint protect a port that is not the operator's way in, which
// is worse than falling back to tcp/22 and saying so.
var shellDaemons = []string{"sshd", "dropbear"}

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
	// Reality is the node's last reported firewall reality, or nil when the
	// node has never reported one. Its listeners are what let the lockout check
	// protect the port the operator actually reaches this box on, instead of
	// assuming every fleet member runs sshd on 22. A node whose sshd moved to
	// 2222 used to pass this lint with tcp/22 open and tcp/2222 dropped, which
	// is the exact plan that locks the operator out for good.
	Reality *model.GuardNodeReality
}

// Lint inspects a compiled plan for the failure modes that make a guard apply
// unsafe. It never mutates the plan.
func Lint(plan network.NFTPlan, opts LintOptions) []Finding {
	var findings []Finding
	ports, evidence := managementPorts(opts.Reality)
	if !acceptsAnyPort(plan, ports) {
		findings = append(findings, Finding{
			Code:     FindingLockoutRiskSSH,
			Severity: SeverityBlock,
			Message: fmt.Sprintf(
				"no rule accepts inbound tcp on the management %s (%s): committing this default-drop ruleset would cut the operator's shell path, and the node-side apply cannot detect it because its selfcheck is an outbound connection. Add a management-port allow, trust an overlay zone, or explicitly accept the lockout risk.",
				pluralPort(len(ports)), joinManagementPorts(ports)),
		})
	}
	if named := planInterfaces(plan); len(named) > 0 && !reportsInterfaces(opts.Reality) {
		// Fail closed. With nothing to compare against the lint cannot say the
		// interface exists, and "cannot confirm" has to read as a block: the
		// plan that names eth0 on an ens17 box is indistinguishable from a
		// correct one until the node reports.
		findings = append(findings, Finding{
			Code:     FindingInterfaceUnverified,
			Severity: SeverityBlock,
			Message: fmt.Sprintf(
				"rules in this plan match inbound %s %s, but the node has never reported its interfaces, so the lint cannot confirm %s. An accept on an interface the node does not have matches nothing, the default drop applies in its place, and the management-port check still counts it, which is how a wrong interface name becomes a lockout. Upgrade the node agent so interfaces are reported, or explicitly accept the lockout risk.",
				pluralInterface(len(named)), joinQuoted(named), existsPhrase(len(named))),
		})
	} else {
		for _, name := range missingInterfaces(named, opts.Reality) {
			findings = append(findings, Finding{
				Code:     FindingInterfaceMissing,
				Severity: SeverityBlock,
				Message: fmt.Sprintf(
					"rules in this plan match inbound interface %q, but the node reports %s. They match nothing on this box, so every accept they carry is dead and the default drop applies in its place; the management-port check still counts them, which is how a wrong interface name becomes a lockout. Point the zone at an interface the node actually has.",
					name, joinInterfaceNames(opts.Reality)),
			})
		}
	}
	if !evidence {
		findings = append(findings, Finding{
			Code:     FindingManagementPortAssumed,
			Severity: SeverityWarn,
			Message:  managementPortAssumedMessage(opts.Reality),
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

// managementPorts returns the TCP ports whose loss would cut the operator's
// shell path, and whether that answer came from reported evidence.
//
// Only listeners owned by an identifiable shell daemon count. Loopback-only
// listeners are skipped: the compiled scaffold always emits `iif lo accept`, so
// no plan can drop them and treating them as a lockout risk would be noise.
// When nothing qualifies the answer falls back to tcp/22 with evidence=false,
// which is what drives FindingManagementPortAssumed.
func managementPorts(reality *model.GuardNodeReality) ([]int, bool) {
	if reality == nil {
		return []int{ManagementPort}, false
	}
	seen := map[int]bool{}
	ports := make([]int, 0, 2)
	for _, listener := range reality.Listeners {
		if !strings.EqualFold(strings.TrimSpace(listener.Protocol), "tcp") {
			continue
		}
		if listener.Port < 1 || listener.Port > 65535 {
			continue
		}
		if !isShellDaemon(listener.Process) {
			continue
		}
		if isLoopbackAddress(listener.Address) {
			continue
		}
		if seen[listener.Port] {
			continue
		}
		seen[listener.Port] = true
		ports = append(ports, listener.Port)
	}
	if len(ports) == 0 {
		return []int{ManagementPort}, false
	}
	sort.Ints(ports)
	return ports, true
}

// isShellDaemon matches the `name(pid)` form the node agent reports, and the
// bare name for anything that reports without a pid.
func isShellDaemon(process string) bool {
	name := strings.ToLower(strings.TrimSpace(process))
	if name == "" {
		return false
	}
	if idx := strings.IndexByte(name, '('); idx >= 0 {
		name = strings.TrimSpace(name[:idx])
	}
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		name = name[idx+1:]
	}
	for _, daemon := range shellDaemons {
		// Prefix rather than equality: OpenSSH 9.8 splits the listener into
		// `sshd-session`, and a match there is still the operator's way in.
		if strings.HasPrefix(name, daemon) {
			return true
		}
	}
	return false
}

// isLoopbackAddress reports whether a listener is bound only to loopback. An
// empty address means "all addresses" in a reality snapshot, not loopback.
func isLoopbackAddress(address string) bool {
	address = strings.TrimSpace(address)
	if address == "" {
		return false
	}
	return address == "::1" || strings.HasPrefix(address, "127.")
}

func managementPortAssumedMessage(reality *model.GuardNodeReality) string {
	if reality == nil {
		return fmt.Sprintf(
			"this node has never reported its firewall reality, so the lockout check assumed the shell daemon listens on tcp/%d. If it listens elsewhere, this plan can lock the operator out without tripping any check. Upgrade the node agent so the port is verified rather than assumed.",
			ManagementPort)
	}
	return fmt.Sprintf(
		"the node reported %d listening %s but none is an identifiable shell daemon (reading the owning process needs root on the node), so the lockout check assumed tcp/%d. If the shell daemon listens elsewhere, this plan can lock the operator out without tripping any check.",
		len(reality.Listeners), pluralSocket(len(reality.Listeners)), ManagementPort)
}

// acceptsAnyPort reports whether some compiled rule could accept a new inbound
// connection on at least one of the given ports. One surviving path is enough:
// the lint fires on "no way in", not on "fewer ways in than before".
//
// It is deliberately generous: a trusted-zone accept, an any-protocol accept,
// or a tcp accept whose port list is empty (all ports) all count. Being
// generous means the lint only fires when the plan really has no path, so it
// stays a signal rather than noise an operator learns to click past.
func acceptsAnyPort(plan network.NFTPlan, ports []int) bool {
	for _, port := range ports {
		if slices.Contains(plan.PublicTCP, port) || slices.Contains(plan.WireGuardTCP, port) {
			return true
		}
	}
	for _, rule := range plan.InputRules {
		if rule.Action != network.NFTActionAccept {
			continue
		}
		switch rule.Protocol {
		case network.NFTProtoAny:
			return true
		case network.NFTProtoTCP:
			if len(rule.Ports) == 0 {
				return true
			}
			for _, port := range ports {
				if slices.Contains(rule.Ports, port) {
					return true
				}
			}
		}
	}
	return false
}

// planInterfaces returns, sorted and unique, every interface name the plan
// renders an iifname match for. The public interface counts only when a public
// port list renders it; a plan with no public rules never emits it, so its name
// cannot hurt anyone.
func planInterfaces(plan network.NFTPlan) []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(plan.PublicTCP) > 0 || len(plan.PublicUDP) > 0 {
		add(plan.InterfaceName)
	}
	for _, rule := range plan.InputRules {
		add(rule.Interface)
	}
	sort.Strings(names)
	return names
}

// reportsInterfaces reports whether the node has told us which interfaces it
// has. Nil reality and an interface-less snapshot from an older agent are the
// same answer: no evidence.
func reportsInterfaces(reality *model.GuardNodeReality) bool {
	return reality != nil && len(reality.Interfaces) > 0
}

// missingInterfaces returns, sorted, the named interfaces the node's reported
// interfaces do not include. Only meaningful once reportsInterfaces is true.
func missingInterfaces(named []string, reality *model.GuardNodeReality) []string {
	if !reportsInterfaces(reality) {
		return nil
	}
	reported := make(map[string]bool, len(reality.Interfaces))
	for _, iface := range reality.Interfaces {
		reported[strings.TrimSpace(iface.Name)] = true
	}
	var missing []string
	for _, name := range named {
		if !reported[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

func joinInterfaceNames(reality *model.GuardNodeReality) string {
	names := make([]string, 0, len(reality.Interfaces))
	for _, iface := range reality.Interfaces {
		names = append(names, iface.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func joinManagementPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("tcp/%d", port))
	}
	return strings.Join(parts, ", ")
}

func joinQuoted(names []string) string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%q", name))
	}
	return strings.Join(parts, ", ")
}

func pluralInterface(n int) string {
	if n == 1 {
		return "interface"
	}
	return "interfaces"
}

func existsPhrase(n int) string {
	if n == 1 {
		return "it exists"
	}
	return "they exist"
}

func pluralPort(n int) string {
	if n == 1 {
		return "port"
	}
	return "ports"
}

func pluralSocket(n int) string {
	if n == 1 {
		return "socket"
	}
	return "sockets"
}
