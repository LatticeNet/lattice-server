package sshguard

import (
	"strings"
	"testing"
)

func knockTestProfile(ports []int) Profile {
	return Profile{
		NodeID: "node-a", SSHPort: 58394, KeepLegacyPort: true,
		Hardening:   DefaultHardening(),
		MgmtSources: []string{"203.0.113.5"},
		Knock: &KnockPolicy{
			Ports: ports, SeqTimeoutSec: 15, OpenFor: "12h",
		},
		ConfirmWindowSec: 900,
	}
}

// The parser and the renderer must agree, because they are the two halves of
// the only record the control plane keeps of a node's sequence. A parser that
// drifts reports a sequence the node is not listening for, and an operator
// knocking it gets silence rather than an error.
func TestParseKnockdConfRoundTripsTheRenderer(t *testing.T) {
	want := []int{23853, 36932, 24556}
	conf, err := knockTestProfile(want).RenderKnockdConf()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKnockdConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Ports) != len(want) {
		t.Fatalf("port count: want %d, got %d", len(want), len(got.Ports))
	}
	for i := range want {
		if got.Ports[i] != want[i] {
			t.Fatalf("port %d: want %d, got %d (order is part of the secret)", i, want[i], got.Ports[i])
		}
	}
	if got.SeqTimeoutSec != 15 {
		t.Fatalf("seq_timeout: want 15, got %d", got.SeqTimeoutSec)
	}
	if got.OpenFor != "12h" {
		t.Fatalf("open_for: want 12h, got %q", got.OpenFor)
	}
}

// RenderKnockdConf writes a comment above the sequence explaining why the
// knock is UDP, and that comment contains the word. A reader that matches on
// substring finds the comment first and reports no ports at all.
func TestParseKnockdConfIgnoresComments(t *testing.T) {
	conf, err := knockTestProfile([]int{20001, 20002, 20003}).RenderKnockdConf()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "#") {
		t.Fatal("this test is only meaningful if the renderer writes comments")
	}
	got, err := ParseKnockdConf("# sequence = 1:udp,2:udp,3:udp\n" + conf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ports[0] != 20001 {
		t.Fatalf("a commented sequence must not win: got %v", got.Ports)
	}
}

// A conf this code cannot vouch for must be an error, not a partial answer. A
// half-read sequence sends an operator to knock ports that will not open the
// gate, and the failure looks identical to the sequence being wrong.
func TestParseKnockdConfRefusesWhatItCannotVouchFor(t *testing.T) {
	for name, conf := range map[string]string{
		"no sequence":   "[options]\n    UseSyslog\n",
		"wrong length":  "[openSSH]\n    sequence = 100:udp,200:udp\n",
		"tcp":           "[openSSH]\n    sequence = 100:tcp,200:tcp,300:tcp\n",
		"no protocol":   "[openSSH]\n    sequence = 100,200,300\n",
		"not a port":    "[openSSH]\n    sequence = ssh:udp,200:udp,300:udp\n",
		"out of range":  "[openSSH]\n    sequence = 99999:udp,200:udp,300:udp\n",
		"bad seq_timeo": "[openSSH]\n    sequence = 100:udp,200:udp,300:udp\n    seq_timeout = soon\n",
	} {
		if _, err := ParseKnockdConf(conf); err == nil {
			t.Fatalf("%s: expected an error, got a sequence", name)
		}
	}
}

// The command the console shows and the command the plan prints have to be the
// same command. Two spellings of how to knock is how an operator ends up
// believing the sequence is wrong when the syntax was.
func TestKnockCommandMatchesThePlanInstructions(t *testing.T) {
	profile := knockTestProfile([]int{23853, 36932, 24556})
	profile.Address = "203.0.113.9"
	plan, err := RenderArmPlan(profile, "Node A")
	if err != nil {
		t.Fatal(err)
	}
	seq, err := ParseKnockdConf(mustRender(t, profile))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(seq.KnockCommand("203.0.113.9", profile.SSHPort), "\n") {
		if !strings.Contains(plan, line) {
			t.Fatalf("the console command is not the plan's command:\n  console: %s", line)
		}
	}
}

// An empty datagram advances knockd to stage one and no further, so a command
// that sends nothing looks like it worked and leaves the port shut.
func TestKnockCommandSendsAPayload(t *testing.T) {
	seq := KnockSequence{Ports: []int{1, 2, 3}}
	cmd := seq.KnockCommand("198.51.100.4", 22)
	if !strings.Contains(cmd, "printf k") {
		t.Fatalf("the knock must carry a payload: %s", cmd)
	}
	if strings.Contains(cmd, "-z") {
		t.Fatalf("nc -z sends nothing and silently fails: %s", cmd)
	}
}

// An address the node never reported must not render as an empty host, which
// would produce a command that silently knocks the local machine.
func TestKnockCommandWithoutAnAddressIsObviouslyIncomplete(t *testing.T) {
	cmd := KnockSequence{Ports: []int{1, 2, 3}}.KnockCommand("  ", 0)
	if !strings.Contains(cmd, "HOST") {
		t.Fatalf("a missing address must be visible in the command: %s", cmd)
	}
	if strings.Contains(cmd, "ssh -p 0") {
		t.Fatalf("an unknown ssh port must not render as port 0: %s", cmd)
	}
}

func mustRender(t *testing.T, p Profile) string {
	t.Helper()
	conf, err := p.RenderKnockdConf()
	if err != nil {
		t.Fatal(err)
	}
	return conf
}
