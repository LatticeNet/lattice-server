package sshguard

import (
	"fmt"
	"sort"
	"strings"
)

// Absolute paths, not bare names. The task runner narrows PATH to
// /usr/bin:/bin:/usr/local/bin, which excludes every sbin directory, so a
// script that says `nft` works only by accident of usr-merge on some distros
// and fails on others. Every binary this package invokes is spelled out.
const (
	BinNFT        = "/usr/sbin/nft"
	BinSSHD       = "/usr/sbin/sshd"
	BinSystemctl  = "/usr/bin/systemctl"
	BinSystemdRun = "/usr/bin/systemd-run"
	BinSS         = "/usr/bin/ss"
)

// GatedPorts is the set of TCP ports the knock table guards, in rule order.
//
// ExistingSSHPorts is where the ports sshd is ACTUALLY on come from, and it
// matters more than it looks. Assuming 22 was wrong on this fleet: measuring it
// found three machines whose sshd listens on 3434, where gating 22 installs a
// door nobody uses and leaves the real one open while reporting success. That
// is the same failure as writing a drop-in and not checking it took effect,
// one layer up.
//
// The ports sshd is on are always gated, whether or not the profile moves it,
// because an ungated listening port makes every other control cosmetic: the
// brute force simply keeps using whatever is open.
func (p Profile) GatedPorts() []int {
	seen := map[int]bool{}
	ports := []int{}
	add := func(port int) {
		if port <= 0 || port > 65535 || seen[port] {
			return
		}
		seen[port] = true
		ports = append(ports, port)
	}
	if len(p.GatePorts) > 0 {
		// An explicit list is taken as stated, including its omissions. The
		// operator who sets it has looked at the host; the derivation below has
		// only looked at a report.
		for _, port := range p.GatePorts {
			add(port)
		}
		sort.Ints(ports)
		return ports
	}
	if p.SSHPort != 0 {
		add(p.SSHPort)
		if p.KeepLegacyPort {
			// The drop-in keeps sshd on 22, so 22 is a live listening port and
			// must be gated whether or not the node reported it.
			add(22)
		}
	}
	for _, port := range p.ExistingSSHPorts {
		// A port the profile moves away from is only gated when the profile
		// keeps sshd there; otherwise nothing will be listening and gating it
		// is noise.
		if p.SSHPort != 0 && port == 22 && !p.KeepLegacyPort {
			continue
		}
		add(port)
	}
	if len(ports) == 0 {
		// Nothing reported and no port requested. 22 is the right guess, and
		// the lint says out loud that it is a guess.
		add(22)
	}
	sort.Ints(ports)
	return ports
}

// RenderSSHDDropIn produces the only sshd file this package owns.
//
// Both ports are listed while KeepLegacyPort holds. Adding a port before
// taking one away is the entire reason the arm stage carries no lockout risk:
// at every instant during the change, every path that worked before still
// works.
func (p Profile) RenderSSHDDropIn() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Lattice SSH Guard. Do not edit by hand.\n")
	b.WriteString("# This drop-in is the only sshd file Lattice writes; removing it\n")
	b.WriteString("# reverts every setting below to whatever sshd_config says.\n")
	fmt.Fprintf(&b, "# node: %s\n\n", p.NodeID)

	if p.SSHPort != 0 {
		if p.KeepLegacyPort {
			// The comment has to match what this profile actually installs. A
			// hardening-only profile renders no firewall, so telling the reader
			// that one shrinks port 22 describes a control that is not there.
			if p.GatesFirewall() {
				b.WriteString("# 22 stays listening on purpose. The firewall shrinks it to the\n")
				b.WriteString("# management sources instead of closing it, so brute force stops\n")
				b.WriteString("# reaching sshd without removing a way back in when knocking breaks.\n")
			} else {
				b.WriteString("# 22 stays listening. This profile installs no firewall, so both\n")
				b.WriteString("# ports are reachable from anywhere; the port below is listed so\n")
				b.WriteString("# that replacing an older drop-in does not take the listener away.\n")
			}
			b.WriteString("Port 22\n")
		}
		fmt.Fprintf(&b, "Port %d\n", p.SSHPort)
	}
	b.WriteString("\n")

	b.WriteString("# The sshd default is 120s. Brute-force clients hold that window open to\n")
	b.WriteString("# occupy connection slots, so shortening it removes more noise than any\n")
	b.WriteString("# ban list and costs nothing to a real login.\n")
	fmt.Fprintf(&b, "LoginGraceTime %d\n", p.Hardening.LoginGraceTimeSec)
	fmt.Fprintf(&b, "MaxAuthTries %d\n", p.Hardening.MaxAuthTries)
	fmt.Fprintf(&b, "MaxStartups %s\n", strings.TrimSpace(p.Hardening.MaxStartups))
	fmt.Fprintf(&b, "PermitRootLogin %s\n", p.Hardening.PermitRootLogin)
	fmt.Fprintf(&b, "PasswordAuthentication %s\n", yesNo(p.Hardening.PasswordAuth))
	fmt.Fprintf(&b, "KbdInteractiveAuthentication %s\n", yesNo(p.Hardening.KbdInteractiveAuth))
	b.WriteString("PermitEmptyPasswords no\n")
	fmt.Fprintf(&b, "X11Forwarding %s\n", yesNo(p.Hardening.X11Forwarding))
	fmt.Fprintf(&b, "AllowAgentForwarding %s\n", yesNo(p.Hardening.AllowAgentForwarding))
	return b.String(), nil
}

// RenderKnockRuleset produces the independent nftables table.
//
// Shape notes that are load-bearing rather than stylistic:
//
//   - `ct state established,related accept` is the first rule. It is what makes
//     applying this ruleset safe from inside an SSH session, and therefore what
//     makes an automatic revert timer possible at all: the operator watching the
//     apply does not get cut by the apply.
//   - The table is created and deleted before being defined so the file is
//     idempotent; re-applying it replaces rather than merges.
//   - policy accept, not drop. This table's job is to gate specific ports, not
//     to be the node's firewall. A policy-drop chain here would silently become
//     a second, competing default-deny alongside lattice_guard.
func (p Profile) RenderKnockRuleset() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if !p.GatesFirewall() {
		return "", fmt.Errorf("this profile installs no firewall: it has neither a management source nor a knock policy")
	}
	v4, v6, err := splitMgmtSources(p.MgmtSources)
	if err != nil {
		return "", err
	}
	ports := p.GatedPorts()
	if len(ports) == 0 {
		return "", fmt.Errorf("no ports to gate")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "#!/usr/sbin/nft -f\n")
	b.WriteString("# Managed by Lattice SSH Guard.\n")
	b.WriteString("# A table of its own, not lattice_guard, which is re-rendered whole from the\n")
	b.WriteString("# model on every apply.\n")
	if p.Knock != nil {
		b.WriteString("# That matters here because the allow set below gains a member every time\n")
		b.WriteString("# someone knocks, and a re-render would drop everyone who had just knocked in.\n")
	} else {
		b.WriteString("# Keeping it separate means an unrelated firewall change cannot silently\n")
		b.WriteString("# take the management gate with it.\n")
	}
	fmt.Fprintf(&b, "# node: %s\n", p.NodeID)
	fmt.Fprintf(&b, "table inet %s\n", KnockTable)
	fmt.Fprintf(&b, "delete table inet %s\n\n", KnockTable)
	fmt.Fprintf(&b, "table inet %s {\n", KnockTable)

	if p.Knock != nil {
		fmt.Fprintf(&b, "  set %s {\n", KnockAllowedSet)
		b.WriteString("    type ipv4_addr\n")
		b.WriteString("    flags timeout\n")
		fmt.Fprintf(&b, "    timeout %s\n", strings.TrimSpace(p.Knock.OpenFor))
		b.WriteString("    comment \"knock-opened sources; entries expire on their own, so a forgotten close leaves nothing open\"\n")
		b.WriteString("  }\n")
		if len(p.Knock.PreviousPorts) > 0 {
			// Its own set rather than a second writer into `allowed`, so the
			// confirm can require evidence from the NEW sequence: an entry
			// opened by the old one proves only that the old one still works,
			// which the operator already knew. The set outlives the confirm in
			// this file, empty and unwritten, until the next arm re-renders
			// without it.
			fmt.Fprintf(&b, "  set %s {\n", KnockPreviousSet)
			b.WriteString("    type ipv4_addr\n")
			b.WriteString("    flags timeout\n")
			fmt.Fprintf(&b, "    timeout %s\n", strings.TrimSpace(p.Knock.OpenFor))
			b.WriteString("    comment \"sources opened by the sequence being rotated out; retired at confirm\"\n")
			b.WriteString("  }\n")
		}
	}
	if len(v4) > 0 {
		b.WriteString("  set mgmt {\n    type ipv4_addr\n    flags interval\n")
		fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(v4, ", "))
		b.WriteString("    comment \"permanent management sources; no timeout by design\"\n  }\n")
	}
	if len(v6) > 0 {
		b.WriteString("  set mgmt6 {\n    type ipv6_addr\n    flags interval\n")
		fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(v6, ", "))
		b.WriteString("  }\n")
	}

	b.WriteString("  chain input {\n")
	fmt.Fprintf(&b, "    type filter hook input priority filter %d; policy accept;\n", KnockHookPriority)
	b.WriteString("    ct state established,related accept\n")
	for _, port := range ports {
		b.WriteString("\n")
		if len(v4) > 0 {
			fmt.Fprintf(&b, "    tcp dport %d ip saddr @mgmt counter accept\n", port)
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "    tcp dport %d ip6 saddr @mgmt6 counter accept\n", port)
		}
		if p.Knock != nil {
			fmt.Fprintf(&b, "    tcp dport %d ip saddr @%s counter accept\n", port, KnockAllowedSet)
			if len(p.Knock.PreviousPorts) > 0 {
				fmt.Fprintf(&b, "    tcp dport %d ip saddr @%s counter accept\n", port, KnockPreviousSet)
			}
		}
		fmt.Fprintf(&b, "    tcp dport %d counter drop\n", port)
	}
	b.WriteString("  }\n}\n")
	return b.String(), nil
}

// RenderKnockdConf produces the knockd sequence definition.
//
// The sequence is UDP because a TCP knock does not survive the kernel's own
// retransmission: a capture on gomami-hkg showed nine SYN retransmissions to a
// single unanswered port, which advances knockd's state machine on the wrong
// port and strands it at stage one forever.
//
// Known limitation, stated rather than hidden: knockd opens the v4 set only.
// An operator arriving over IPv6 must be in mgmt6, which Validate already
// requires to be non-empty in spirit by requiring a management source at all.
func (p Profile) RenderKnockdConf() (string, error) {
	if p.Knock == nil {
		return "", fmt.Errorf("profile has no knock policy")
	}
	if err := p.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Managed by Lattice SSH Guard. Do not edit by hand.\n")
	fmt.Fprintf(&b, "# node: %s\n\n", p.NodeID)
	b.WriteString("[options]\n    UseSyslog\n\n")
	fmt.Fprintf(&b, "[%s]\n", KnockdSection)
	b.WriteString("    # UDP, not TCP. Knocking an unanswered TCP port makes the kernel\n")
	b.WriteString("    # retransmit the SYN, which replays the same port into the state\n")
	b.WriteString("    # machine and never advances it. One UDP datagram is one datagram.\n")
	fmt.Fprintf(&b, "    sequence      = %s\n", udpSequence(p.Knock.Ports))
	fmt.Fprintf(&b, "    seq_timeout   = %d\n", p.Knock.SeqTimeoutSec)
	b.WriteString("    # No stop_command and no closing sequence: the set entry expires by\n")
	b.WriteString("    # itself, so there is nothing to forget to close.\n")
	fmt.Fprintf(&b, "    start_command = %s add element inet %s %s { %%IP%% timeout %s }\n",
		BinNFT, KnockTable, KnockAllowedSet, strings.TrimSpace(p.Knock.OpenFor))
	b.WriteString("    cmd_timeout   = 10\n")
	if len(p.Knock.PreviousPorts) > 0 {
		// The stanza the confirm removes. Until then both sequences open the
		// gate, into different sets, so the operator's existing knock keeps
		// working through the whole window and the confirm can still tell
		// which one admitted him.
		fmt.Fprintf(&b, "\n[%s]\n", KnockdPreviousSection)
		b.WriteString("    # The sequence being rotated out. It keeps opening the gate until the\n")
		b.WriteString("    # confirm approval removes this stanza, so an operator holding the\n")
		b.WriteString("    # old sequence is never locked out by the arm.\n")
		fmt.Fprintf(&b, "    sequence      = %s\n", udpSequence(p.Knock.PreviousPorts))
		fmt.Fprintf(&b, "    seq_timeout   = %d\n", p.Knock.SeqTimeoutSec)
		fmt.Fprintf(&b, "    start_command = %s add element inet %s %s { %%IP%% timeout %s }\n",
			BinNFT, KnockTable, KnockPreviousSet, strings.TrimSpace(p.Knock.OpenFor))
		b.WriteString("    cmd_timeout   = 10\n")
	}
	return b.String(), nil
}

func udpSequence(ports []int) string {
	seq := make([]string, 0, len(ports))
	for _, port := range ports {
		seq = append(seq, fmt.Sprintf("%d:udp", port))
	}
	return strings.Join(seq, ",")
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
