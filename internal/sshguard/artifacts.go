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
// Port 22 is included whenever it stays open, because leaving it ungated would
// make every other control cosmetic: the brute force simply keeps using 22.
func (p Profile) GatedPorts() []int {
	ports := make([]int, 0, 2)
	if p.SSHPort != 0 {
		ports = append(ports, p.SSHPort)
	}
	if p.KeepLegacyPort || p.SSHPort == 0 {
		ports = append(ports, 22)
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
			b.WriteString("# 22 stays listening on purpose. The firewall shrinks it to the\n")
			b.WriteString("# management sources instead of closing it, so brute force stops\n")
			b.WriteString("# reaching sshd without removing a way back in when knocking breaks.\n")
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
		b.WriteString("  set allowed {\n")
		b.WriteString("    type ipv4_addr\n")
		b.WriteString("    flags timeout\n")
		fmt.Fprintf(&b, "    timeout %s\n", strings.TrimSpace(p.Knock.OpenFor))
		b.WriteString("    comment \"knock-opened sources; entries expire on their own, so a forgotten close leaves nothing open\"\n")
		b.WriteString("  }\n")
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
			fmt.Fprintf(&b, "    tcp dport %d ip saddr @allowed counter accept\n", port)
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
	seq := make([]string, 0, len(p.Knock.Ports))
	for _, port := range p.Knock.Ports {
		seq = append(seq, fmt.Sprintf("%d:udp", port))
	}
	var b strings.Builder
	b.WriteString("# Managed by Lattice SSH Guard. Do not edit by hand.\n")
	fmt.Fprintf(&b, "# node: %s\n\n", p.NodeID)
	b.WriteString("[options]\n    UseSyslog\n\n")
	b.WriteString("[openSSH]\n")
	b.WriteString("    # UDP, not TCP. Knocking an unanswered TCP port makes the kernel\n")
	b.WriteString("    # retransmit the SYN, which replays the same port into the state\n")
	b.WriteString("    # machine and never advances it. One UDP datagram is one datagram.\n")
	fmt.Fprintf(&b, "    sequence      = %s\n", strings.Join(seq, ","))
	fmt.Fprintf(&b, "    seq_timeout   = %d\n", p.Knock.SeqTimeoutSec)
	b.WriteString("    # No stop_command and no closing sequence: the set entry expires by\n")
	b.WriteString("    # itself, so there is nothing to forget to close.\n")
	fmt.Fprintf(&b, "    start_command = %s add element inet %s allowed { %%IP%% timeout %s }\n",
		BinNFT, KnockTable, strings.TrimSpace(p.Knock.OpenFor))
	b.WriteString("    cmd_timeout   = 10\n")
	return b.String(), nil
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
