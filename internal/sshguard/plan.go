package sshguard

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The approval plan is the contract between the reviewer and the host.
//
// It is one human-readable document that carries the exact bytes that will be
// written, and the apply script is derived from that same document rather than
// from the model. Anything a reviewer cannot see in the plan cannot reach the
// host, and a plan that was approved cannot quietly render into something else
// because the model moved underneath it.
const (
	planHeader  = "# Lattice SSH Guard plan"
	fenceSSHD   = "sshd"
	fenceNFT    = "nft"
	fenceKnockd = "knockd"
)

// Artifacts is what a plan parses back into: the literal file contents plus the
// few scalars the script needs to sequence itself.
type Artifacts struct {
	Stage            Stage
	NodeID           string
	SSHPort          int
	KeepLegacyPort   bool
	ConfirmWindowSec int
	// Durable is the plan's claim that this arm needs no confirm: it installs
	// no firewall and the node showed a key path in at plan time. The arm
	// script re-checks the key on the host before it honours the claim.
	Durable bool

	SSHDDropIn string
	KnockNFT   string
	KnockdConf string
	GatedPorts []int
}

// RenderArmPlan produces the reviewable document for the stage that makes every
// change and arms the automatic revert.
func RenderArmPlan(p Profile, nodeName string) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	dropIn, err := p.RenderSSHDDropIn()
	if err != nil {
		return "", err
	}
	ruleset := ""
	if p.GatesFirewall() {
		if ruleset, err = p.RenderKnockRuleset(); err != nil {
			return "", err
		}
	}
	knockd := ""
	if p.Knock != nil {
		if knockd, err = p.RenderKnockdConf(); err != nil {
			return "", err
		}
	}
	window := p.ConfirmWindowSec
	if window == 0 {
		window = DefaultConfirmWindowSec
	}

	var b strings.Builder
	b.WriteString(planHeader + "\n\n")
	fmt.Fprintf(&b, "stage: %s\n", StageArm)
	fmt.Fprintf(&b, "node_id: %s\n", p.NodeID)
	if clean := SanitizeDisplayText(nodeName); clean != "" {
		fmt.Fprintf(&b, "node_name: %s\n", clean)
	}
	fmt.Fprintf(&b, "ssh_port: %d\n", p.SSHPort)
	fmt.Fprintf(&b, "keep_legacy_port: %t\n", p.KeepLegacyPort)
	fmt.Fprintf(&b, "knock: %t\n", p.Knock != nil)
	if p.GatesFirewall() {
		fmt.Fprintf(&b, "gated_ports: %s\n", joinInts(p.GatedPorts()))
	}
	fmt.Fprintf(&b, "confirm_window_sec: %d\n", window)
	durable := p.Durable()
	if durable {
		fmt.Fprintf(&b, "durable: %t\n", durable)
	}

	// Every sentence below has to describe the artifacts this same function is
	// about to render, not the shape of a profile in general. A profile with no
	// management sources and no knock policy renders no firewall at all
	// (Profile.GatesFirewall), and the prose used to claim otherwise: it told
	// the reviewer that port 22 was being narrowed to the sources listed below
	// and then listed "(none)". Both readings of that were wrong, and the
	// dangerous one is the reassuring one, because it says brute force stops
	// reaching sshd when nothing about reachability changed.
	gates := p.GatesFirewall()

	b.WriteString("\n## What this does, and why it cannot strand you\n\n")
	if durable {
		b.WriteString("The apply changes no port and installs no firewall: it edits sshd's\n")
		b.WriteString("configuration and nothing else. Who can reach SSH is exactly what it was.\n")
		b.WriteString("\nThis node already reports a key path in, and the settings below take\n")
		b.WriteString("nothing away from anyone holding that key. There is therefore no lockout\n")
		b.WriteString("risk to prove against, and no revert timer is armed: the change is\n")
		b.WriteString("permanent as soon as sshd verifies it, and no confirm approval follows.\n")
		b.WriteString("The apply checks for an authorized key on the host before it trusts this;\n")
		b.WriteString("if it finds none it arms the usual timer after all and says so.\n")
		b.WriteString("\nThe settings below stop password and keyboard-interactive login and shrink\n")
		b.WriteString("the login grace window. They do not stop anyone from reaching sshd, so the\n")
		b.WriteString("brute force in the auth log continues, failing sooner.\n")
	} else {
		switch {
		case p.SSHPort != 0:
			b.WriteString("The apply adds a port before it takes anything away, so at every instant\n")
			b.WriteString("during the change every path that worked before still works. It then arms a\n")
		case gates:
			b.WriteString("The apply changes no port: it hardens sshd and narrows who may reach the\n")
			b.WriteString("existing one. It arms a\n")
		default:
			b.WriteString("The apply changes no port and installs no firewall: it edits sshd's\n")
			b.WriteString("configuration and nothing else. Who can reach SSH is exactly what it was.\n")
			b.WriteString("It arms a\n")
		}
		fmt.Fprintf(&b, "systemd timer that undoes all of it in %d seconds unless a second, separate\n", window)
		b.WriteString("approval confirms. That second approval is the point: it is how you say you\n")
		b.WriteString("logged in over the new path and got a shell. If you cannot, do nothing and\n")
		b.WriteString("the node returns to its previous state on its own.\n")
	}
	if gates {
		b.WriteString("\nThe firewall rules below start with `ct state established,related accept`,\n")
		b.WriteString("so applying them does not cut the session watching the apply.\n")
		if p.KeepLegacyPort && p.SSHPort != 0 {
			b.WriteString("\nPort 22 is not closed. It is shrunk to the management sources and to\n")
			b.WriteString("knocked-open sources, which stops the brute force from reaching sshd while\n")
			b.WriteString("keeping a way in that does not depend on knocking working.\n")
		} else if p.Knock == nil {
			b.WriteString("\nPort 22 is not closed. It is narrowed to the management sources listed\n")
			b.WriteString("below, so brute force stops reaching sshd. There is no knock sequence in\n")
			b.WriteString("this profile, which means those sources are the only way in: check them.\n")
		}
	} else if !durable {
		b.WriteString("\nThe settings below stop password and keyboard-interactive login and shrink\n")
		b.WriteString("the login grace window. They do not stop anyone from reaching sshd, so the\n")
		b.WriteString("brute force in the auth log continues, failing sooner. Narrowing the source\n")
		b.WriteString("addresses needs a management source or a knock policy; this profile has\n")
		b.WriteString("neither.\n")
		b.WriteString("\nThe lockout risk here is the sshd settings themselves: an account that\n")
		b.WriteString("logs in by password, or a root login that uses one, stops working at the\n")
		b.WriteString("reload. That is what the revert timer is for.\n")
	}

	if gates {
		if p.Knock != nil {
			b.WriteString("\n## Management sources (reach SSH without knocking, no expiry)\n\n")
		} else {
			b.WriteString("\n## Management sources (the only sources that may reach SSH)\n\n")
		}
		if len(p.MgmtSources) == 0 {
			b.WriteString("- (none)\n")
		}
		for _, src := range p.MgmtSources {
			norm, nErr := normalizeCIDR(src)
			if nErr != nil {
				return "", fmt.Errorf("mgmt_source %q: %w", src, nErr)
			}
			fmt.Fprintf(&b, "- %s\n", norm)
		}
	}

	if p.Knock != nil {
		b.WriteString(knockInstructions(p))
	}

	fmt.Fprintf(&b, "\n## sshd drop-in: %s\n\n", DropInPath)
	writeFence(&b, fenceSSHD, dropIn)
	if ruleset != "" {
		fmt.Fprintf(&b, "\n## nftables `table inet %s`: %s\n\n", KnockTable, KnockNFTPath)
		writeFence(&b, fenceNFT, ruleset)
	}
	if knockd != "" {
		fmt.Fprintf(&b, "\n## knockd sequence: %s\n\n", KnockdConf)
		writeFence(&b, fenceKnockd, knockd)
	}
	return b.String(), nil
}

// RenderConfirmPlan produces the document for the stage that cancels the
// pending revert. It carries no artifacts because it writes no files: its whole
// effect is to stop a timer, and it should be trivially reviewable.
func RenderConfirmPlan(nodeID, nodeName string) (string, error) {
	if err := validateNodeID(nodeID); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(planHeader + "\n\n")
	fmt.Fprintf(&b, "stage: %s\n", StageConfirm)
	fmt.Fprintf(&b, "node_id: %s\n", nodeID)
	if clean := SanitizeDisplayText(nodeName); clean != "" {
		fmt.Fprintf(&b, "node_name: %s\n", clean)
	}
	b.WriteString("\n## What this does\n\n")
	b.WriteString("Cancels the pending automatic revert on this node and nothing else. It\n")
	b.WriteString("writes no files and touches no service.\n\n")
	b.WriteString("Approve this only after you have opened a NEW connection over the new path\n")
	b.WriteString("and gotten a shell. The session you already have does not prove anything:\n")
	b.WriteString("established connections are accepted by the first firewall rule regardless\n")
	b.WriteString("of whether new ones can get in.\n\n")
	b.WriteString("If the arm was a knock rotation, knockd.conf still carries the previous\n")
	b.WriteString("sequence as a second stanza. Confirming removes that stanza, restarts knockd\n")
	b.WriteString("and empties the set it opened, so from then on only the new sequence opens\n")
	b.WriteString("the gate. On a node that is not mid-rotation this step finds nothing to do.\n")
	return b.String(), nil
}

// ParseApprovalPlan reads back exactly what RenderArmPlan or RenderConfirmPlan
// wrote. It is strict: an unknown stage, a missing artifact, or a header it
// cannot read is an error rather than a default, because every one of those
// would produce a script that does something other than what was reviewed.
func ParseApprovalPlan(plan string) (Artifacts, error) {
	if !strings.HasPrefix(strings.TrimSpace(plan), planHeader) {
		return Artifacts{}, fmt.Errorf("not an SSH Guard plan")
	}
	out := Artifacts{}
	// Read only the contiguous header block, and refuse a key that appears
	// twice. Both rules exist for the same reason: the header carries text from
	// elsewhere (a node's display name), and a value containing a newline would
	// otherwise be able to add a key the reviewer never saw. Sanitizing that
	// text at render time is the first defense; these two are the ones that
	// hold even if a future caller forgets.
	seen := map[string]bool{}
	inHeader := false
	for _, line := range strings.Split(plan, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			break
		}
		key, value, ok := strings.Cut(trimmed, ": ")
		if !ok {
			if inHeader && trimmed == "" {
				break
			}
			continue
		}
		inHeader = true
		if seen[key] {
			return Artifacts{}, fmt.Errorf("plan header carries %q more than once", key)
		}
		seen[key] = true
		switch key {
		case "stage":
			out.Stage = Stage(strings.TrimSpace(value))
		case "node_id":
			out.NodeID = strings.TrimSpace(value)
		case "ssh_port":
			n, err := parseUint(value)
			if err != nil {
				return Artifacts{}, fmt.Errorf("ssh_port %q is not a number", value)
			}
			out.SSHPort = n
		case "keep_legacy_port":
			out.KeepLegacyPort = strings.TrimSpace(value) == "true"
		case "durable":
			out.Durable = strings.TrimSpace(value) == "true"
		case "confirm_window_sec":
			n, err := parseUint(value)
			if err != nil {
				return Artifacts{}, fmt.Errorf("confirm_window_sec %q is not a number", value)
			}
			out.ConfirmWindowSec = n
		case "gated_ports":
			ports, err := parseInts(value)
			if err != nil {
				return Artifacts{}, fmt.Errorf("gated_ports %q: %w", value, err)
			}
			out.GatedPorts = ports
		}
	}
	if strings.TrimSpace(out.NodeID) == "" {
		return Artifacts{}, fmt.Errorf("plan has no node_id")
	}

	switch out.Stage {
	case StageConfirm:
		return out, nil
	case StageArm:
	default:
		return Artifacts{}, fmt.Errorf("unknown stage %q", out.Stage)
	}

	var err error
	if out.SSHDDropIn, err = readFence(plan, fenceSSHD); err != nil {
		return Artifacts{}, fmt.Errorf("sshd block: %w", err)
	}
	// The nft block is optional: a hardening-only profile installs no firewall,
	// which is the only shape that changes no path in or out at all.
	if hasFence(plan, fenceNFT) {
		if out.KnockNFT, err = readFence(plan, fenceNFT); err != nil {
			return Artifacts{}, fmt.Errorf("nft block: %w", err)
		}
	}
	// knockd is optional: a profile may harden and shrink the firewall without
	// enabling a knock sequence at all.
	if hasFence(plan, fenceKnockd) {
		if out.KnockdConf, err = readFence(plan, fenceKnockd); err != nil {
			return Artifacts{}, fmt.Errorf("knockd block: %w", err)
		}
	}
	if out.KnockNFT != "" && len(out.GatedPorts) == 0 {
		return Artifacts{}, fmt.Errorf("plan installs a firewall but names no gated_ports")
	}
	if out.KnockdConf != "" && out.KnockNFT == "" {
		return Artifacts{}, fmt.Errorf("plan carries a knock sequence with no firewall for it to open")
	}
	if out.Durable && out.KnockNFT != "" {
		// A firewall is the lockout risk the timer exists for. A plan that
		// installs one and also claims to need no confirm is not a plan this
		// renderer wrote, and it must not become a script that skips the timer.
		return Artifacts{}, fmt.Errorf("plan installs a firewall and claims to be durable; a firewall arm always keeps its revert timer")
	}
	if out.ConfirmWindowSec < MinConfirmWindowSec || out.ConfirmWindowSec > MaxConfirmWindowSec {
		return Artifacts{}, fmt.Errorf("confirm_window_sec %d is outside [%d, %d]",
			out.ConfirmWindowSec, MinConfirmWindowSec, MaxConfirmWindowSec)
	}
	return out, nil
}

func writeFence(b *strings.Builder, lang, content string) {
	b.WriteString("```" + lang + "\n")
	b.WriteString(content)
	if !strings.HasSuffix(content, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("```\n")
}

// A fence marker only opens a block at the start of a line. Anchoring it there
// is what stops a value interpolated into the header from producing one: a
// display name is collapsed to a single line before it is written, so the same
// characters appearing mid-line are text, not structure.
func fenceOffsets(plan, lang string) []int {
	open := "```" + lang + "\n"
	offsets := []int{}
	for i := 0; ; {
		j := strings.Index(plan[i:], open)
		if j < 0 {
			return offsets
		}
		at := i + j
		if at == 0 || plan[at-1] == '\n' {
			offsets = append(offsets, at+len(open))
		}
		i = at + len(open)
	}
}

func hasFence(plan, lang string) bool {
	return len(fenceOffsets(plan, lang)) > 0
}

// readFence extracts exactly one fenced block. Two blocks with the same tag is
// an error rather than "take the first": a plan carrying two candidate sshd
// configs is ambiguous about which one was reviewed.
func readFence(plan, lang string) (string, error) {
	offsets := fenceOffsets(plan, lang)
	switch len(offsets) {
	case 0:
		return "", fmt.Errorf("missing")
	case 1:
	default:
		return "", fmt.Errorf("appears more than once")
	}
	rest := plan[offsets[0]:]
	end := strings.Index(rest, "\n```")
	if end < 0 {
		return "", fmt.Errorf("is not closed")
	}
	body := rest[:end+1]
	if strings.TrimSpace(body) == "" {
		return "", fmt.Errorf("is empty")
	}
	return body, nil
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ",")
}

func parseInts(value string) ([]int, error) {
	out := []int{}
	for _, part := range strings.Split(value, ",") {
		n, err := parseUint(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// knockInstructions is the section that was missing, and its absence cost a
// rollout. The document listed the sequence and nothing else, so the obvious
// way to send it is `nc -u -z` -- which sends an empty datagram that advances
// knockd to stage 1 and then silently never advances again. The failure has no
// error anywhere: the knock "succeeds", the port stays shut, and the only
// evidence is a repeated "Stage 1" line in the node's own knockd log, which is
// behind the port that will not open. Stating the payload requirement here is
// the difference between a two-minute step and an hour of misattribution.
func knockInstructions(p Profile) string {
	var b strings.Builder
	b.WriteString("\n## How to knock\n\n")
	b.WriteString("The sequence is UDP and each datagram must carry a payload. An empty\n")
	b.WriteString("datagram advances knockd to stage 1 and no further, with no error on\n")
	b.WriteString("either side, so `nc -u -z` and anything else that sends nothing will\n")
	b.WriteString("look like it worked and leave the port shut.\n\n")

	addr := p.knockDisplayAddress()
	ports := make([]string, 0, len(p.Knock.Ports))
	for _, port := range p.Knock.Ports {
		ports = append(ports, strconv.Itoa(port))
	}
	sshPort := p.loginPort()

	b.WriteString("```sh\n")
	fmt.Fprintf(&b, "for p in %s; do printf k | nc -u -w1 %s $p; sleep 1; done\n",
		strings.Join(ports, " "), addr)
	fmt.Fprintf(&b, "ssh -p %d root@%s\n", sshPort, addr)
	b.WriteString("```\n\n")

	b.WriteString("The knock and the login must leave from the same address. The gate opens\n")
	b.WriteString("for the source the knock arrived from, so sending one through a proxy and\n")
	b.WriteString("the other direct opens a door you are not standing at.\n")
	fmt.Fprintf(&b, "Membership lasts %s and then expires on its own.\n", p.Knock.OpenFor)
	if p.Knock.SeqTimeoutSec > 0 {
		fmt.Fprintf(&b, "The whole sequence must arrive within %d seconds.\n", p.Knock.SeqTimeoutSec)
	}
	if len(p.Knock.PreviousPorts) > 0 {
		b.WriteString("\n## Rotation\n\n")
		b.WriteString("This arm rotates the sequence. The previous one stays in knockd.conf as a\n")
		b.WriteString("second stanza and keeps opening the gate until the confirm approval removes\n")
		b.WriteString("it, so the knock you already have works through the whole window. The\n")
		b.WriteString("confirm counts only entries the NEW sequence admitted as evidence: prove\n")
		b.WriteString("the new one from a source this node sees before confirming.\n")
	}
	return b.String()
}

// knockDisplayAddress returns an address safe to paste into the document. The
// value is reported by the agent, so it is accepted only if it parses as an IP
// literal; anything else becomes a placeholder rather than reaching a document
// a human reads to decide whether to approve.
func (p Profile) knockDisplayAddress() string {
	if a, err := netip.ParseAddr(strings.TrimSpace(p.Address)); err == nil {
		if a.Is6() {
			return "[" + a.String() + "]"
		}
		return a.String()
	}
	return "<node-address>"
}

// loginPort is the port the operator should actually connect to after knocking:
// the new port when the profile moves sshd, otherwise the lowest gated port.
func (p Profile) loginPort() int {
	if p.SSHPort != 0 {
		return p.SSHPort
	}
	if gated := p.GatedPorts(); len(gated) > 0 {
		return gated[0]
	}
	return 22
}
