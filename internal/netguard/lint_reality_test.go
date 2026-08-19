package netguard

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

// The failure this file exists for: a node whose sshd moved off 22. Before the
// lint could read reality it protected tcp/22 unconditionally, so a plan that
// accepted 22 and dropped the real shell port passed, the node-side apply
// verified itself over an outbound connection, the watchdog disarmed, and the
// operator lost the box.

func realityWithSSH(port int, process, address string) *model.GuardNodeReality {
	return &model.GuardNodeReality{
		NodeID:      "n1",
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Listeners: []model.GuardListener{
			{Protocol: "tcp", Port: port, Address: address, Process: process},
			{Protocol: "tcp", Port: 443, Address: "0.0.0.0", Process: "caddy(910)"},
		},
	}
}

func codes(findings []Finding) map[string]Finding {
	out := make(map[string]Finding, len(findings))
	for _, f := range findings {
		out[f.Code] = f
	}
	return out
}

func TestLintBlocksWhenTheRealManagementPortIsDropped(t *testing.T) {
	// The plan opens 22 and 443. The node's sshd is on 2222.
	plan := network.NFTPlan{PublicTCP: []int{22, 443}}
	findings := Lint(plan, LintOptions{
		PublicURLConfigured: true,
		Reality:             realityWithSSH(2222, "sshd(701)", "0.0.0.0"),
	})
	if !Blocking(findings) {
		t.Fatalf("a plan that drops the node's real sshd port must block: %+v", findings)
	}
	found := codes(findings)
	if _, ok := found[FindingLockoutRiskSSH]; !ok {
		t.Fatalf("expected %s: %+v", FindingLockoutRiskSSH, findings)
	}
	if _, ok := found[FindingManagementPortAssumed]; ok {
		t.Fatalf("evidence was available, so the assumed-port warning must not fire: %+v", findings)
	}
}

func TestLintAcceptsThePlanThatOpensTheRealManagementPort(t *testing.T) {
	plan := network.NFTPlan{PublicTCP: []int{2222, 443}}
	findings := Lint(plan, LintOptions{
		PublicURLConfigured: true,
		Reality:             realityWithSSH(2222, "sshd(701)", "0.0.0.0"),
	})
	if Blocking(findings) {
		t.Fatalf("a plan that opens the reported sshd port must not block: %+v", findings)
	}
}

func TestLintNeedsOnlyOneSurvivingManagementPath(t *testing.T) {
	// Two shell daemons. Keeping either one is not a lockout.
	reality := realityWithSSH(2222, "sshd(701)", "0.0.0.0")
	reality.Listeners = append(reality.Listeners, model.GuardListener{
		Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "dropbear(88)",
	})
	if Blocking(Lint(network.NFTPlan{PublicTCP: []int{22}}, LintOptions{PublicURLConfigured: true, Reality: reality})) {
		t.Fatal("one surviving management path must satisfy the lint")
	}
	if !Blocking(Lint(network.NFTPlan{PublicTCP: []int{443}}, LintOptions{PublicURLConfigured: true, Reality: reality})) {
		t.Fatal("dropping every management path must block")
	}
}

func TestLintIgnoresLoopbackOnlyAndNonShellListeners(t *testing.T) {
	// sshd bound to loopback only cannot be cut: the scaffold always emits
	// `iif lo accept`. A postgres listener is not a management path either.
	reality := &model.GuardNodeReality{
		NodeID:      "n1",
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Listeners: []model.GuardListener{
			{Protocol: "tcp", Port: 2222, Address: "127.0.0.1", Process: "sshd(701)"},
			{Protocol: "tcp", Port: 5432, Address: "0.0.0.0", Process: "postgres(9)"},
		},
	}
	findings := Lint(network.NFTPlan{PublicTCP: []int{22}}, LintOptions{PublicURLConfigured: true, Reality: reality})
	if Blocking(findings) {
		t.Fatalf("falling back to tcp/22 must accept a plan that opens 22: %+v", findings)
	}
	if _, ok := codes(findings)[FindingManagementPortAssumed]; !ok {
		t.Fatalf("no identifiable shell daemon means the port was assumed, and that must be said: %+v", findings)
	}
}

func TestLintSaysWhenTheManagementPortWasAssumed(t *testing.T) {
	// A node that has never reported. tcp/22 is still the best guess, but the
	// operator has to be able to tell a checked plan from a guessed one.
	findings := Lint(network.NFTPlan{PublicTCP: []int{22}}, LintOptions{PublicURLConfigured: true})
	if Blocking(findings) {
		t.Fatalf("assuming the port is a warning, never a block: %+v", findings)
	}
	warning, ok := codes(findings)[FindingManagementPortAssumed]
	if !ok {
		t.Fatalf("expected %s: %+v", FindingManagementPortAssumed, findings)
	}
	if warning.Severity != SeverityWarn {
		t.Fatalf("severity = %q", warning.Severity)
	}
}

func TestLintMatchesSplitSSHDProcessNames(t *testing.T) {
	// OpenSSH 9.8 splits the listener process into sshd-session.
	for _, process := range []string{"sshd-session(12)", "SSHD(4)", "/usr/sbin/sshd(4)", "dropbearmulti(7)"} {
		findings := Lint(network.NFTPlan{PublicTCP: []int{22}}, LintOptions{
			PublicURLConfigured: true,
			Reality:             realityWithSSH(2222, process, "0.0.0.0"),
		})
		if !Blocking(findings) {
			t.Fatalf("process %q must be recognised as a shell daemon: %+v", process, findings)
		}
	}
}

func TestLintTreatsUDPAndOutOfRangeListenersAsIrrelevant(t *testing.T) {
	reality := &model.GuardNodeReality{
		NodeID:      "n1",
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Listeners: []model.GuardListener{
			{Protocol: "udp", Port: 2222, Address: "0.0.0.0", Process: "sshd(701)"},
			{Protocol: "tcp", Port: 0, Address: "0.0.0.0", Process: "sshd(702)"},
		},
	}
	findings := Lint(network.NFTPlan{PublicTCP: []int{22}}, LintOptions{PublicURLConfigured: true, Reality: reality})
	if Blocking(findings) {
		t.Fatalf("a udp or invalid-port listener is not a management path: %+v", findings)
	}
}
