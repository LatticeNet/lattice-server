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

// The commands the console shows and the commands the plan prints have to be
// the same commands. Two spellings of how to knock is how an operator ends up
// believing the sequence is wrong when the syntax was.
func TestKnockCommandsMatchThePlanInstructions(t *testing.T) {
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
	commands := seq.KnockCommands("203.0.113.9", profile.SSHPort)
	if len(commands) != 2 {
		t.Fatalf("want the knock client and the bash form, got %d commands", len(commands))
	}
	for _, c := range commands {
		if !strings.Contains(plan, c.Command) {
			t.Fatalf("the console command is not the plan's command:\n  console: %s", c.Command)
		}
		for _, in := range c.Install {
			if !strings.Contains(plan, in.Command) {
				t.Fatalf("the plan does not say how to install what %s runs: %s", c.ID, in.Command)
			}
		}
	}
}

// An empty datagram advances knockd to stage one and no further, so a command
// that sends nothing looks like it worked and leaves the port shut. The knock
// client sends one byte per hit and only has to be told UDP. The exact strings
// are pinned because every flag is a compatibility claim: knock 0.7, still the
// Ubuntu 22.04 package, rejects -4.
func TestKnockCommandsSendAPayloadOverUDP(t *testing.T) {
	commands := KnockSequence{Ports: []int{20001, 20002, 20003}}.KnockCommands("198.51.100.4", 22)
	byID := map[string]string{}
	for _, c := range commands {
		byID[c.ID] = c.Command
		if strings.Contains(c.Command, "-z") {
			t.Fatalf("nc -z sends nothing and silently fails: %s", c.Command)
		}
	}
	if want := "knock -u -d 500 198.51.100.4 20001 20002 20003 && ssh -p 22 root@198.51.100.4"; byID["knock"] != want {
		t.Fatalf("knock client command:\n  got  %s\n  want %s", byID["knock"], want)
	}
	if want := "bash -c 'for p in 20001 20002 20003; do printf k >/dev/udp/198.51.100.4/$p; sleep 0.5; done' && ssh -p 22 root@198.51.100.4"; byID["bash"] != want {
		t.Fatalf("bash command:\n  got  %s\n  want %s", byID["bash"], want)
	}
}

// The address comes from the node's own report and lands in text a person
// pastes into a shell. Anything that is not an IP literal, including nothing
// at all, becomes a placeholder, and an unknown ssh port renders no login.
func TestKnockCommandsRefuseAnAddressThatIsNotAnIP(t *testing.T) {
	for _, bad := range []string{"", "  ", "evil.example.com", "1.2.3.4; rm -rf /", "$(id)", "`id`"} {
		for _, c := range (KnockSequence{Ports: []int{20001, 20002, 20003}}).KnockCommands(bad, 0) {
			if !strings.Contains(c.Command, "<node-address>") {
				t.Fatalf("address %q: a missing address must be visible in the command: %s", bad, c.Command)
			}
			if strings.TrimSpace(bad) != "" && strings.Contains(c.Command, bad) {
				t.Fatalf("address %q reached the command verbatim: %s", bad, c.Command)
			}
			if strings.Contains(c.Command, "ssh -p") {
				t.Fatalf("an unknown ssh port must not render a login: %s", c.Command)
			}
		}
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
