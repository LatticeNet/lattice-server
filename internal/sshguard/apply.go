package sshguard

import (
	"fmt"
	"strings"
)

// ApplyScriptFromPlan renders the bounded shell that puts an approved plan on a
// host. It derives everything from the plan text, so the bytes that were
// reviewed are the bytes that land.
//
// Ordering in the arm script is load-bearing, not stylistic:
//
//  1. Snapshot, then write the revert script, then arm the timer, all BEFORE
//     the first change. A failure at any later point therefore has a working
//     undo already on disk and already scheduled.
//  2. sshd gains the new port while keeping the old one. Adding before removing
//     is what makes this stage carry no lockout risk of its own.
//  3. knockd starts BEFORE the firewall goes up. The gate and the thing that
//     opens the gate must not be applied in the other order, or the window
//     between them is a window where nobody can get in.
//  4. The nftables table lands last, and its first rule accepts established
//     connections, so the session watching the apply is not cut by it.
func ApplyScriptFromPlan(plan string) (string, error) {
	art, err := ParseApprovalPlan(plan)
	if err != nil {
		return "", err
	}
	switch art.Stage {
	case StageConfirm:
		return confirmScript(art), nil
	case StageArm:
		return armScript(art)
	default:
		return "", fmt.Errorf("unknown stage %q", art.Stage)
	}
}

func armScript(art Artifacts) (string, error) {
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("umask 077\n\n")

	b.WriteString("# Absolute paths throughout. The task runner narrows PATH to\n")
	b.WriteString("# /usr/bin:/bin:/usr/local/bin, which contains no sbin, so a bare `nft`\n")
	b.WriteString("# or `sshd` resolves only by accident of usr-merge and not at all elsewhere.\n")
	if art.KnockNFT != "" {
		fmt.Fprintf(&b, "NFT=%s\n", BinNFT)
	}
	fmt.Fprintf(&b, "SSHD=%s\n", BinSSHD)
	fmt.Fprintf(&b, "SYSTEMCTL=%s\n", BinSystemctl)
	fmt.Fprintf(&b, "SYSTEMD_RUN=%s\n", BinSystemdRun)
	fmt.Fprintf(&b, "STATE=%s\n", StateDir)
	fmt.Fprintf(&b, "DROPIN=%s\n", DropInPath)
	if art.KnockNFT != "" {
		fmt.Fprintf(&b, "KNOCK_NFT=%s\n", KnockNFTPath)
	}
	b.WriteString("REVERT=\"$STATE/revert.sh\"\n")
	b.WriteString("DROPIN_BACKUP=\"$STATE/sshd-dropin.rollback\"\n")
	b.WriteString("DROPIN_ABSENT=\"$STATE/sshd-dropin.was-absent\"\n")
	if art.KnockdConf != "" {
		fmt.Fprintf(&b, "KNOCKD_CONF=%s\n", KnockdConf)
		b.WriteString("KNOCKD_BACKUP=\"$STATE/knockd.rollback\"\n")
		b.WriteString("KNOCKD_ABSENT=\"$STATE/knockd.was-absent\"\n")
	}
	b.WriteString("\n")

	// Only require what this profile actually uses. A hardening-only apply must
	// work on a host with no nftables at all.
	required := "\"$SSHD\" \"$SYSTEMCTL\" \"$SYSTEMD_RUN\""
	if art.KnockNFT != "" {
		required = "\"$NFT\" " + required
	}
	fmt.Fprintf(&b, "for bin in %s; do\n", required)
	b.WriteString("  [ -x \"$bin\" ] || { echo \"lattice sshguard: $bin not found or not executable\" >&2; exit 1; }\n")
	b.WriteString("done\n")
	if art.KnockNFT != "" {
		b.WriteString("mkdir -p \"$STATE\" \"$(dirname \"$KNOCK_NFT\")\" \"$(dirname \"$DROPIN\")\"\n\n")
	} else {
		b.WriteString("mkdir -p \"$STATE\" \"$(dirname \"$DROPIN\")\"\n\n")
	}

	b.WriteString("# Snapshot BEFORE anything changes, so the revert below is exact rather\n")
	b.WriteString("# than a guess about what used to be here.\n")
	b.WriteString("rm -f \"$DROPIN_BACKUP\" \"$DROPIN_ABSENT\"\n")
	b.WriteString("if [ -f \"$DROPIN\" ]; then cp -a \"$DROPIN\" \"$DROPIN_BACKUP\"; else : > \"$DROPIN_ABSENT\"; fi\n")
	touchesKnockd := art.KnockdConf != ""
	if touchesKnockd {
		b.WriteString("rm -f \"$KNOCKD_BACKUP\" \"$KNOCKD_ABSENT\"\n")
		b.WriteString("if [ -f \"$KNOCKD_CONF\" ]; then cp -a \"$KNOCKD_CONF\" \"$KNOCKD_BACKUP\"; else : > \"$KNOCKD_ABSENT\"; fi\n")
	}
	b.WriteString("\n")

	// A profile without knocking never touches knockd, so its undo must not
	// either. A revert that restarts a service the apply never configured is a
	// side effect nobody reviewed.
	b.WriteString(revertScriptHeredoc(touchesKnockd, art.KnockNFT != ""))
	b.WriteString("chmod 0700 \"$REVERT\"\n\n")

	b.WriteString("# Arm the automatic revert BEFORE the first change.\n")
	b.WriteString("# This is a systemd transient timer rather than the in-script setsid\n")
	b.WriteString("# watchdog the other apply paths use, for two reasons: the window has to\n")
	b.WriteString("# outlive the task so a human can try to log in, and a task cgroup teardown\n")
	b.WriteString("# kills a setsid child but not a systemd unit.\n")
	fmt.Fprintf(&b, "\"$SYSTEMCTL\" stop %s.timer 2>/dev/null || true\n", RevertUnit)
	fmt.Fprintf(&b, "\"$SYSTEMCTL\" reset-failed %s.timer 2>/dev/null || true\n", RevertUnit)
	fmt.Fprintf(&b, "\"$SYSTEMD_RUN\" --on-active=%d --unit=%s --description='Lattice SSH Guard automatic revert' /bin/sh \"$REVERT\" >/dev/null 2>&1\n",
		art.ConfirmWindowSec, RevertUnit)
	fmt.Fprintf(&b, "\"$SYSTEMCTL\" list-timers %s --no-pager 2>/dev/null | grep -q %s || { echo 'lattice sshguard: revert timer did not arm; refusing to change anything' >&2; exit 1; }\n",
		RevertUnit, RevertUnit)
	b.WriteString("echo 'lattice sshguard: automatic revert armed'\n\n")

	b.WriteString("# From here on, any failure reverts immediately instead of waiting out the\n")
	b.WriteString("# timer. The timer stays as the backstop for the case where this shell dies\n")
	b.WriteString("# without running its trap at all.\n")
	b.WriteString("#\n")
	b.WriteString("# This is an EXIT trap guarded by a success marker, not `trap ... ERR`.\n")
	b.WriteString("# Approval applies run under interpreter \"sh\", which is dash on Debian, and\n")
	b.WriteString("# dash answers `trap ... ERR` with \"trap: ERR: bad trap\" and then keeps\n")
	b.WriteString("# going, so an ERR trap here would be silently absent exactly when it is\n")
	b.WriteString("# needed. EXIT is POSIX and fires on the `set -e` exit as well.\n")
	b.WriteString("LATTICE_SSHGUARD_OK=0\n")
	b.WriteString("on_exit() {\n")
	b.WriteString("  [ \"$LATTICE_SSHGUARD_OK\" = 1 ] && return 0\n")
	b.WriteString("  echo 'lattice sshguard: apply did not complete, reverting now' >&2\n")
	b.WriteString("  /bin/sh \"$REVERT\" || true\n")
	b.WriteString("}\n")
	b.WriteString("trap on_exit EXIT INT TERM HUP\n\n")

	b.WriteString("# Step 1: sshd gains a port; it loses nothing.\n")
	b.WriteString(heredoc("\"$DROPIN\"", "LATTICE_SSHGUARD_SSHD", art.SSHDDropIn))
	b.WriteString("chmod 0644 \"$DROPIN\"\n")
	b.WriteString("if ! \"$SSHD\" -t; then\n")
	b.WriteString("  echo 'lattice sshguard: sshd rejected the candidate config; nothing was reloaded' >&2\n")
	b.WriteString("  exit 1\n")
	b.WriteString("fi\n")
	b.WriteString("# reload, never restart: a restart drops every established session, which\n")
	b.WriteString("# would cut the operator watching this apply and remove the very fallback\n")
	b.WriteString("# the staged rollout depends on.\n")
	b.WriteString("\"$SYSTEMCTL\" reload sshd 2>/dev/null || \"$SYSTEMCTL\" reload ssh\n")
	b.WriteString("echo 'lattice sshguard: sshd reloaded'\n\n")
	b.WriteString(effectiveConfigCheck(art.SSHDDropIn))

	if art.SSHPort != 0 {
		b.WriteString("# Step 2: prove the new port is actually listening before gating anything.\n")
		b.WriteString("# Server-side evidence only. A client-side connect test is not proof: a\n")
		b.WriteString("# local transparent proxy can complete a handshake before the upstream\n")
		b.WriteString("# connection exists, which has produced false positives on this fleet.\n")
		fmt.Fprintf(&b, "listening=0\nfor _ in 1 2 3 4 5 6 7 8 9 10; do\n  if %s -tlnH 2>/dev/null | grep -qE '[:.]%d ' ; then listening=1; break; fi\n  sleep 1\ndone\n", BinSS, art.SSHPort)
		fmt.Fprintf(&b, "[ \"$listening\" = 1 ] || { echo 'lattice sshguard: sshd is not listening on %d after reload' >&2; exit 1; }\n", art.SSHPort)
		fmt.Fprintf(&b, "echo 'lattice sshguard: sshd is listening on %d'\n\n", art.SSHPort)
	}

	if art.KnockdConf != "" {
		b.WriteString("# Step 3: knockd goes up BEFORE the gate does. Reversing these two leaves\n")
		b.WriteString("# a window in which the port is closed and nothing can open it.\n")
		b.WriteString(knockdInstallSnippet())
		b.WriteString(heredoc("\"$KNOCKD_CONF\"", "LATTICE_SSHGUARD_KNOCKD", art.KnockdConf))
		b.WriteString("chmod 0600 \"$KNOCKD_CONF\"\n")
		b.WriteString("if [ -f /etc/default/knockd ]; then\n")
		b.WriteString("  sed -i 's/^START_KNOCKD=.*/START_KNOCKD=1/' /etc/default/knockd\n")
		b.WriteString("  grep -q '^START_KNOCKD=' /etc/default/knockd || echo 'START_KNOCKD=1' >> /etc/default/knockd\n")
		b.WriteString("  # Bind knockd to the interface carrying the default route. The Debian\n")
		b.WriteString("  # default is eth0, which is wrong on any host that names it otherwise.\n")
		b.WriteString("  iface=$(/usr/sbin/ip route show default 2>/dev/null | /usr/bin/awk '/^default/{for(i=1;i<NF;i++) if($i==\"dev\") print $(i+1); exit}')\n")
		b.WriteString("  if [ -n \"$iface\" ]; then\n")
		b.WriteString("    sed -i '/^KNOCKD_OPTS=/d' /etc/default/knockd\n")
		b.WriteString("    echo \"KNOCKD_OPTS=\\\"-i $iface\\\"\" >> /etc/default/knockd\n")
		b.WriteString("  fi\n")
		b.WriteString("fi\n")
		b.WriteString("\"$SYSTEMCTL\" enable knockd >/dev/null 2>&1 || true\n")
		b.WriteString("\"$SYSTEMCTL\" restart knockd\n")
		b.WriteString("\"$SYSTEMCTL\" is-active --quiet knockd || { echo 'lattice sshguard: knockd did not come up' >&2; exit 1; }\n")
		b.WriteString("echo 'lattice sshguard: knockd active'\n\n")
	}

	if art.KnockNFT != "" {
		b.WriteString("# Step 4: the gate. Validated before it is applied, and its first rule\n")
		b.WriteString("# accepts established connections so this does not cut the session above.\n")
		b.WriteString(heredoc("\"$KNOCK_NFT\"", "LATTICE_SSHGUARD_NFT", art.KnockNFT))
		b.WriteString("chmod 0600 \"$KNOCK_NFT\"\n")
		b.WriteString("\"$NFT\" -c -f \"$KNOCK_NFT\" || { echo 'lattice sshguard: candidate ruleset failed validation' >&2; exit 1; }\n")
		b.WriteString("\"$NFT\" -f \"$KNOCK_NFT\"\n")
		fmt.Fprintf(&b, "\"$NFT\" list table inet %s >/dev/null 2>&1 || { echo 'lattice sshguard: knock table missing after apply' >&2; exit 1; }\n", KnockTable)
		b.WriteString("echo 'lattice sshguard: firewall applied'\n\n")
		// Boot persistence is deliberately NOT enabled here. The revert timer is
		// a systemd transient unit and does not survive a reboot, so a node that
		// restarts inside the confirmation window would come back with the gate
		// rebuilt and nothing left to undo it: permanent, unconfirmed, and
		// unreachable if the sources were wrong. Enabling persistence only at
		// confirm makes a reboot lose the gate instead of losing the revert,
		// which is the direction a failure has to fall.
		b.WriteString("echo 'lattice sshguard: gate is NOT yet persistent across reboot; confirm makes it so'\n\n")
	} else {
		b.WriteString("# This profile installs no firewall: it hardens sshd and leaves every path\n")
		b.WriteString("# in and out exactly as it was. The revert still exists and is still armed,\n")
		b.WriteString("# because a bad sshd config is its own way to lose a node.\n")
		b.WriteString("echo 'lattice sshguard: hardening only, firewall untouched'\n\n")
	}

	b.WriteString("LATTICE_SSHGUARD_OK=1\n")
	b.WriteString("echo '--- lattice sshguard: armed, NOT yet permanent ---'\n")
	fmt.Fprintf(&b, "echo 'An automatic revert runs in %d seconds unless a confirm approval cancels it.'\n", art.ConfirmWindowSec)
	b.WriteString("echo 'Open a NEW connection over the new path and get a shell before confirming.'\n")
	if art.KnockNFT != "" {
		// Print the counters so the operator reading the task output sees the
		// gate's own account of what it admitted and dropped, rather than
		// having to trust a client-side connection test.
		fmt.Fprintf(&b, "\"$NFT\" list chain inet %s input 2>/dev/null | grep -E 'counter' || true\n", KnockTable)
	}
	return b.String(), nil
}

func confirmScript(_ Artifacts) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	fmt.Fprintf(&b, "SYSTEMCTL=%s\n", BinSystemctl)
	fmt.Fprintf(&b, "NFT=%s\n", BinNFT)
	b.WriteString("[ -x \"$SYSTEMCTL\" ] || { echo 'lattice sshguard: systemctl not found' >&2; exit 1; }\n")
	b.WriteString("# Refuse to confirm a node that is not actually armed. Otherwise a confirm\n")
	b.WriteString("# reads as success on a node where the arm never landed, and the operator\n")
	b.WriteString("# believes a configuration is in place that is not.\n")
	// Armed-ness is proven by the pending revert timer, not by the firewall: a
	// hardening-only profile installs no table, and requiring one here would
	// make its confirm always fail.
	fmt.Fprintf(&b, "if ! \"$SYSTEMCTL\" list-timers %s --no-pager 2>/dev/null | grep -q %s; then\n", RevertUnit, RevertUnit)
	b.WriteString("  echo 'lattice sshguard: this node has no pending revert; there is nothing to confirm' >&2\n")
	b.WriteString("  exit 1\n")
	b.WriteString("fi\n")
	// Require evidence, not an assertion. The gate counts what it admits, and a
	// zero on every accept rule means nobody has come through it since it went
	// up. The session running this confirm does not count: the first rule
	// accepts established connections, so an operator who never opened a new
	// one would confirm a gate that has admitted nothing and find out at the
	// next login.
	//
	// A hardening-only profile installs no table and therefore has no counters;
	// its risk is a bad sshd config, which the arm already proved against by
	// validating and by checking the listener.
	fmt.Fprintf(&b, "if \"$NFT\" list table inet %s >/dev/null 2>&1; then\n", KnockTable)
	// Match the text form rather than the JSON: the counter has to be on an
	// ACCEPT rule, and picking that apart in the JSON means walking a nested
	// expression array in shell. A gate that has only dropped things is not
	// evidence that anyone can get in.
	//
	// The `ct state established,related accept` rule carries no counter, so it
	// cannot be mistaken for evidence. That is the exact case this check exists
	// to catch: the operator's current session is established and proves
	// nothing about new ones.
	fmt.Fprintf(&b, "  admitted=$(\"$NFT\" list chain inet %s input 2>/dev/null | grep -cE 'counter packets [1-9][0-9]* bytes [0-9]+ accept' || true)\n", KnockTable)
	fmt.Fprintf(&b, "  if [ \"${admitted:-0}\" = 0 ]; then\n")
	b.WriteString("    echo 'lattice sshguard: the gate has admitted nothing since it went up.' >&2\n")
	b.WriteString("    echo 'Open a NEW connection over the new path first; the session you are' >&2\n")
	b.WriteString("    echo 'reading this from is already established and proves nothing.' >&2\n")
	b.WriteString("    exit 1\n")
	b.WriteString("  fi\n")
	b.WriteString("fi\n")
	fmt.Fprintf(&b, "\"$SYSTEMCTL\" stop %s.timer 2>/dev/null || true\n", RevertUnit)
	fmt.Fprintf(&b, "\"$SYSTEMCTL\" reset-failed %s.timer 2>/dev/null || true\n", RevertUnit)
	fmt.Fprintf(&b, "if \"$SYSTEMCTL\" list-timers %s --no-pager 2>/dev/null | grep -q %s; then\n", RevertUnit, RevertUnit)
	b.WriteString("  echo 'lattice sshguard: revert timer is still armed after cancel' >&2\n")
	b.WriteString("  exit 1\n")
	b.WriteString("fi\n")
	fmt.Fprintf(&b, "if [ -f %s ]; then\n", KnockNFTPath)
	b.WriteString(indentLines(bootPersistenceSnippet(true), "  "))
	b.WriteString("fi\n")
	b.WriteString("echo 'lattice sshguard: confirmed, configuration is now permanent and survives reboot'\n")
	return b.String()
}

// revertScriptHeredoc writes the undo as a standalone file rather than a shell
// function, because the systemd timer runs it in a process that shares nothing
// with this script. It restores the exact prior state recorded in the snapshot
// above, and it deletes only the one table this package owns: a `flush ruleset`
// here would take Docker's tables and every other tenant of nftables with it.
// touchesFirewall is separate from touchesKnockd because a profile can install
// a gate without a knock sequence, and a hardening-only profile installs
// neither. An undo that removes something the apply never created is a side
// effect nobody reviewed.
func revertScriptHeredoc(touchesKnockd, touchesFirewall bool) string {
	var s strings.Builder
	s.WriteString("cat > \"$REVERT\" <<'LATTICE_SSHGUARD_REVERT'\n")
	s.WriteString("#!/bin/sh\n")
	s.WriteString("# Written by Lattice SSH Guard before any change was made.\n")
	s.WriteString("# Restores the exact prior state. Safe to run by hand at any time.\n")
	s.WriteString("set +e\n")
	fmt.Fprintf(&s, "STATE=%s\n", StateDir)
	fmt.Fprintf(&s, "DROPIN=%s\n", DropInPath)
	if touchesKnockd {
		fmt.Fprintf(&s, "KNOCKD_CONF=%s\n", KnockdConf)
	}
	if touchesFirewall {
		fmt.Fprintf(&s, "NFT=%s\n", BinNFT)
	}
	fmt.Fprintf(&s, "SYSTEMCTL=%s\n", BinSystemctl)
	s.WriteString("echo 'lattice sshguard: reverting' >&2\n")
	s.WriteString("if [ -f \"$STATE/sshd-dropin.rollback\" ]; then\n")
	s.WriteString("  cp -a \"$STATE/sshd-dropin.rollback\" \"$DROPIN\"\n")
	s.WriteString("elif [ -f \"$STATE/sshd-dropin.was-absent\" ]; then\n")
	s.WriteString("  rm -f \"$DROPIN\"\n")
	s.WriteString("fi\n")
	s.WriteString("# Only reload if the restored config parses. A revert that reloads a broken\n")
	s.WriteString("# sshd is worse than one that leaves the running daemon alone.\n")
	fmt.Fprintf(&s, "if %s -t 2>/dev/null; then \"$SYSTEMCTL\" reload sshd 2>/dev/null || \"$SYSTEMCTL\" reload ssh 2>/dev/null; fi\n", BinSSHD)
	if touchesFirewall {
		fmt.Fprintf(&s, "\"$NFT\" delete table inet %s 2>/dev/null\n", KnockTable)
	}
	if touchesKnockd {
		s.WriteString("if [ -f \"$STATE/knockd.rollback\" ]; then\n")
		s.WriteString("  cp -a \"$STATE/knockd.rollback\" \"$KNOCKD_CONF\"\n")
		s.WriteString("  \"$SYSTEMCTL\" restart knockd 2>/dev/null\n")
		s.WriteString("elif [ -f \"$STATE/knockd.was-absent\" ]; then\n")
		s.WriteString("  rm -f \"$KNOCKD_CONF\"\n")
		s.WriteString("  \"$SYSTEMCTL\" stop knockd 2>/dev/null\n")
		s.WriteString("  \"$SYSTEMCTL\" disable knockd 2>/dev/null\n")
		s.WriteString("fi\n")
	}
	if touchesFirewall {
		// Both names. A node confirmed before the rename still carries the
		// legacy unit, and a revert that leaves it enabled would reinstate the
		// gate at the next boot after having just torn it down.
		for _, unit := range []string{FirewallUnit, LegacyBootUnit} {
			fmt.Fprintf(&s, "\"$SYSTEMCTL\" disable %s 2>/dev/null\n", unit)
			fmt.Fprintf(&s, "rm -f /etc/systemd/system/%s.service\n", unit)
		}
	}
	s.WriteString("\"$SYSTEMCTL\" daemon-reload 2>/dev/null\n")
	s.WriteString("echo 'lattice sshguard: revert complete' >&2\n")
	s.WriteString("LATTICE_SSHGUARD_REVERT\n")
	return s.String()
}

// knockdInstallSnippet installs the package. There is no precedent for package
// installation anywhere else in this codebase, so the shape is stated plainly:
// it prefers an already-present binary, tries the two package managers this
// fleet actually runs, and fails loudly rather than continuing without the one
// component that can open the gate it is about to close.
func knockdInstallSnippet() string {
	var s strings.Builder
	s.WriteString("if [ ! -x /usr/sbin/knockd ]; then\n")
	s.WriteString("  echo 'lattice sshguard: installing knockd'\n")
	s.WriteString("  if [ -x /usr/bin/apt-get ]; then\n")
	s.WriteString("    DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update -qq >/dev/null 2>&1 || true\n")
	s.WriteString("    DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y -qq knockd >/dev/null 2>&1 || true\n")
	s.WriteString("  elif [ -x /usr/bin/dnf ]; then\n")
	s.WriteString("    /usr/bin/dnf install -y knock-server >/dev/null 2>&1 || true\n")
	s.WriteString("  elif [ -x /usr/bin/yum ]; then\n")
	s.WriteString("    /usr/bin/yum install -y knock-server >/dev/null 2>&1 || true\n")
	s.WriteString("  fi\n")
	s.WriteString("fi\n")
	s.WriteString("[ -x /usr/sbin/knockd ] || { echo 'lattice sshguard: knockd is not installed and could not be installed; refusing to gate a port with nothing able to open it' >&2; exit 1; }\n")
	return s.String()
}

// bootPersistenceSnippet makes the gate survive a reboot.
//
// The allow set deliberately does NOT survive: it is rebuilt empty, so a reboot
// means everyone knocks again. That is the correct default for a credential
// with a timeout, and it is also what was observed on the reference host.
func bootPersistenceSnippet(touchesKnockd bool) string {
	var s strings.Builder
	s.WriteString("# Make the gate survive a reboot. The allow set is intentionally not\n")
	s.WriteString("# persisted: after a reboot everyone knocks again, which is the right\n")
	s.WriteString("# default for a membership that already expires on a timer.\n")
	// Remove the pre-rename unit first. Leaving it enabled alongside the new
	// one means two units loading the same ruleset, and the one an operator
	// finds first is called "revert" while doing the opposite.
	fmt.Fprintf(&s, "\"$SYSTEMCTL\" disable %s 2>/dev/null || true\n", LegacyBootUnit)
	fmt.Fprintf(&s, "rm -f /etc/systemd/system/%s.service\n", LegacyBootUnit)
	fmt.Fprintf(&s, "cat > /etc/systemd/system/%s.service <<'LATTICE_SSHGUARD_UNIT'\n", FirewallUnit)
	s.WriteString("[Unit]\n")
	s.WriteString("Description=Lattice SSH Guard firewall (restores the knock gate at boot)\n")
	if touchesKnockd {
		// The gate must exist before the thing that opens it starts, or knockd
		// spends its first moments adding elements to a set that is not there.
		s.WriteString("Before=knockd.service\n")
	}
	s.WriteString("After=network-pre.target\n")
	s.WriteString("Wants=network-pre.target\n")
	s.WriteString("[Service]\n")
	s.WriteString("Type=oneshot\n")
	s.WriteString("RemainAfterExit=yes\n")
	fmt.Fprintf(&s, "ExecStart=%s -f %s\n", BinNFT, KnockNFTPath)
	s.WriteString("[Install]\n")
	s.WriteString("WantedBy=multi-user.target\n")
	s.WriteString("LATTICE_SSHGUARD_UNIT\n")
	s.WriteString("\"$SYSTEMCTL\" daemon-reload\n")
	fmt.Fprintf(&s, "\"$SYSTEMCTL\" enable %s >/dev/null 2>&1 || true\n", FirewallUnit)
	return s.String()
}

// heredoc writes content to dst with a quoted delimiter so nothing inside is
// expanded by the shell. The delimiter is rejected if it appears in the body,
// which is the one way a heredoc can be escaped.
func heredoc(dst, delim, content string) string {
	if strings.Contains(content, "\n"+delim) {
		// Callers render this content themselves, so this is a programming
		// error rather than untrusted input; failing loudly in the emitted
		// script keeps it from silently truncating a config file.
		return "echo 'lattice sshguard: refusing to write content containing its own heredoc delimiter' >&2\nexit 1\n"
	}
	out := "cat > " + dst + " <<'" + delim + "'\n" + content
	if !strings.HasSuffix(content, "\n") {
		out += "\n"
	}
	return out + delim + "\n"
}

// indentLines shifts a rendered snippet so it can sit inside a shell `if`. It
// leaves heredoc bodies alone by indenting only lines outside them, because a
// quoted heredoc reproduces its content byte for byte and indenting it would
// change the file being written.
func indentLines(snippet, prefix string) string {
	lines := strings.Split(snippet, "\n")
	out := make([]string, 0, len(lines))
	inHeredoc := false
	for _, line := range lines {
		switch {
		case inHeredoc:
			out = append(out, line)
			if strings.TrimSpace(line) == "LATTICE_SSHGUARD_UNIT" {
				inHeredoc = false
			}
		case strings.Contains(line, "<<'LATTICE_SSHGUARD_UNIT'"):
			out = append(out, prefix+line)
			inHeredoc = true
		case strings.TrimSpace(line) == "":
			out = append(out, line)
		default:
			out = append(out, prefix+line)
		}
	}
	return strings.Join(out, "\n")
}

// effectiveConfigCheck compares what the drop-in asked for against what sshd
// actually resolved, and fails the apply on any disagreement.
//
// Writing a drop-in does not mean it takes effect. sshd reads
// /etc/ssh/sshd_config.d/*.conf in lexical order and keeps the FIRST value it
// sees for each keyword, so any file sorting before ours wins. Most of the time
// that is harmless because the earlier file says the same thing; sometimes it
// is a file named 00-permit-root-password-auth.conf that says the opposite.
//
// Without this check the apply writes the file, reloads, reports success, and
// leaves password authentication on. Half-applied while claiming success is
// the worst outcome available here, because the operator then believes a
// hardening is in place that is not. Observed on a real node on 2026-08-20.
//
// The check names the file that won, because "it did not take effect" is not
// actionable and "this file declares it before yours" is.
func effectiveConfigCheck(dropIn string) string {
	// Keywords sshd -T renames or spells differently from sshd_config.
	alias := map[string]string{"prohibit-password": "without-password"}
	watched := map[string]bool{
		"LoginGraceTime": true, "MaxAuthTries": true, "PasswordAuthentication": true,
		"PermitRootLogin": true, "X11Forwarding": true, "AllowAgentForwarding": true,
		"KbdInteractiveAuthentication": true, "PermitEmptyPasswords": true,
	}
	type want struct{ key, value string }
	wants := []want{}
	for _, line := range strings.Split(dropIn, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !watched[fields[0]] {
			continue
		}
		value := fields[1]
		if mapped, ok := alias[value]; ok {
			value = mapped
		}
		wants = append(wants, want{strings.ToLower(fields[0]), value})
	}
	if len(wants) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("# Verify what sshd actually resolved. Writing a drop-in is not the same as\n")
	b.WriteString("# it taking effect: sshd keeps the FIRST value it sees for each keyword and\n")
	b.WriteString("# reads /etc/ssh/sshd_config.d/*.conf in lexical order, so an earlier file\n")
	b.WriteString("# silently wins. Reporting success on a half-applied hardening is worse than\n")
	b.WriteString("# failing, because it leaves the operator believing in a control that is off.\n")
	b.WriteString("sshguard_mismatch=0\n")
	b.WriteString("sshguard_check() {\n")
	b.WriteString("  got=$(\"$SSHD\" -T 2>/dev/null | awk -v k=\"$1\" '$1==k{print $2; exit}')\n")
	b.WriteString("  [ \"$got\" = \"$2\" ] && return 0\n")
	b.WriteString("  echo \"lattice sshguard: $1 is effectively '${got:-unset}', not '$2'\" >&2\n")
	// Only files sorting BEFORE ours can win, plus whatever the main config
	// declares above its Include. Naming our own file would be noise.
	fmt.Fprintf(&b, "  for f in $(ls /etc/ssh/sshd_config.d/ 2>/dev/null | awk '$0 < \"%s\"'); do\n", dropInBasename())
	b.WriteString("    grep -qiE \"^[[:space:]]*$1\" \"/etc/ssh/sshd_config.d/$f\" 2>/dev/null && echo \"  declared earlier in /etc/ssh/sshd_config.d/$f\" >&2\n")
	b.WriteString("  done\n")
	b.WriteString("  grep -qiE \"^[[:space:]]*$1\" /etc/ssh/sshd_config 2>/dev/null && echo \"  also declared in /etc/ssh/sshd_config\" >&2\n")
	b.WriteString("  sshguard_mismatch=1\n")
	b.WriteString("}\n")
	for _, w := range wants {
		fmt.Fprintf(&b, "sshguard_check %s %s\n", shellSingleQuote(w.key), shellSingleQuote(w.value))
	}
	b.WriteString("if [ \"$sshguard_mismatch\" = 1 ]; then\n")
	b.WriteString("  echo 'lattice sshguard: the drop-in did not fully take effect; reverting rather than reporting a hardening that is not in place' >&2\n")
	b.WriteString("  exit 1\n")
	b.WriteString("fi\n")
	b.WriteString("echo 'lattice sshguard: every setting verified effective'\n\n")
	return b.String()
}

// shellSingleQuote quotes a value for a single-quoted shell word. The values
// come from a rendered config this package produced, so this is belt and
// braces rather than untrusted input handling.
func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// dropInBasename is the filename sshd sees, used to reason about which other
// drop-ins sort before it.
func dropInBasename() string {
	i := strings.LastIndexByte(DropInPath, '/')
	return DropInPath[i+1:]
}
