package sshguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func rotatingProfile() Profile {
	p := hkProfile()
	p.Knock.PreviousPorts = []int{27431, 45902, 38117}
	return p
}

// A rotation is lockout-free only if the sequence the operator already holds
// keeps opening the gate until the new one is proven. That means two knockd
// stanzas and two nftables sets while the arm is unconfirmed, and one of each
// once the confirm has run.
func TestRotationKeepsThePreviousSequenceUntilConfirm(t *testing.T) {
	p := rotatingProfile()
	conf, err := p.RenderKnockdConf()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "["+KnockdSection+"]") || !strings.Contains(conf, "["+KnockdPreviousSection+"]") {
		t.Fatalf("an unconfirmed rotation must carry both stanzas:\n%s", conf)
	}
	if strings.Count(conf, "sequence      = ") != 2 {
		t.Fatalf("expected exactly two sequence lines before confirm:\n%s", conf)
	}
	seq, err := ParseKnockdConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if joinInts(seq.Ports) != joinInts(p.Knock.Ports) || joinInts(seq.PreviousPorts) != joinInts(p.Knock.PreviousPorts) {
		t.Fatalf("the reader must keep new and previous apart, got new=%v previous=%v", seq.Ports, seq.PreviousPorts)
	}

	// Each sequence opens its own set, so the confirm can tell which one
	// admitted the operator.
	ruleset, err := p.RenderKnockRuleset()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, "set "+KnockPreviousSet+" {") || !strings.Contains(ruleset, "ip saddr @"+KnockPreviousSet+" counter accept") {
		t.Fatalf("the previous sequence must open a set of its own:\n%s", ruleset)
	}
	if !strings.Contains(conf, "add element inet "+KnockTable+" "+KnockPreviousSet+" {") {
		t.Fatalf("the previous stanza must write into its own set:\n%s", conf)
	}

	// The plan carries the whole rotation and parses back to the same bytes.
	plan, err := RenderArmPlan(p, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "## Rotation") {
		t.Fatal("the reviewer must be told this arm is a rotation and what confirm will retire")
	}
	art, err := ParseApprovalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if art.KnockdConf != conf {
		t.Fatal("the reviewed knockd.conf must be the applied knockd.conf")
	}

	// Confirm retires the stanza. Proven by running the snippet the confirm
	// script embeds against the rendered conf, not by reading the script.
	confirmPlan, _ := RenderConfirmPlan(p.NodeID, p.Name)
	script, err := ApplyScriptFromPlan(confirmPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, retirePreviousKnockSnippet()) {
		t.Fatal("the confirm script must retire the previous stanza")
	}
	if strings.Index(script, retirePreviousKnockSnippet()) > strings.Index(script, "stop "+RevertUnit+".timer") {
		t.Fatal("the stanza must be retired while the revert is still armed, so a knockd that does not come back is undone rather than made permanent")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "knockd.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	for pass := 1; pass <= 2; pass++ {
		cmd := exec.Command("sh", "-c", retirePreviousKnockSnippet())
		cmd.Env = append(os.Environ(), "KNOCKD_CONF="+path, "SYSTEMCTL=/usr/bin/true", "NFT=/usr/bin/true")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pass %d: retire snippet failed: %v\n%s", pass, err, out)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(after), "["+KnockdPreviousSection+"]") {
			t.Fatalf("pass %d: the previous stanza survived confirm:\n%s", pass, after)
		}
		if strings.Count(string(after), "sequence      = ") != 1 {
			t.Fatalf("pass %d: expected exactly one sequence line after confirm:\n%s", pass, after)
		}
		got, err := ParseKnockdConf(string(after))
		if err != nil {
			t.Fatalf("pass %d: conf after confirm does not parse: %v", pass, err)
		}
		if joinInts(got.Ports) != joinInts(p.Knock.Ports) || len(got.PreviousPorts) != 0 {
			t.Fatalf("pass %d: the surviving stanza must be the new sequence, got new=%v previous=%v", pass, got.Ports, got.PreviousPorts)
		}
		if !strings.Contains(string(after), "["+KnockdSection+"]") {
			t.Fatalf("pass %d: the live stanza was damaged:\n%s", pass, after)
		}
	}
	// A profile that is not rotating renders no second stanza and no second
	// set, so nothing here changes for an ordinary arm.
	plain, _ := hkProfile().RenderKnockdConf()
	if strings.Contains(plain, KnockdPreviousSection) {
		t.Fatal("a plain arm must not carry a previous stanza")
	}
	plainRules, _ := hkProfile().RenderKnockRuleset()
	if strings.Contains(plainRules, KnockPreviousSet) {
		t.Fatal("a plain arm must not declare the previous set")
	}
}

// An entry the old sequence opened proves the old sequence works, which the
// operator already knew. Confirm evidence has to come from the new one.
func TestConfirmEvidenceIgnoresThePreviousSequence(t *testing.T) {
	confirmPlan, _ := RenderConfirmPlan("gomami-hkg", "")
	script, err := ApplyScriptFromPlan(confirmPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "grep -vc '@"+KnockPreviousSet+"'") {
		t.Fatalf("the admitted count must exclude the previous sequence's set:\n%s", script)
	}
	if !strings.Contains(script, "flush set inet "+KnockTable+" "+KnockPreviousSet) {
		t.Fatal("confirm must empty the set the previous sequence opened")
	}
}

// The rotation validation refuses the two shapes that would make the plan lie:
// a previous sequence that is not a sequence, and one that equals the new one.
func TestRotationValidation(t *testing.T) {
	p := rotatingProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("the rotating profile must validate: %v", err)
	}
	p.Knock.PreviousPorts = []int{27431, 45902}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "previous") {
		t.Fatalf("a short previous sequence must be refused and named, got %v", err)
	}
	p.Knock.PreviousPorts = append([]int{}, p.Knock.Ports...)
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "same as the new one") {
		t.Fatalf("rotating a sequence onto itself must be refused, got %v", err)
	}
}

func TestKnockSequenceDigestIsStableAndOrderSensitive(t *testing.T) {
	a := KnockSequenceDigest([]int{27431, 45902, 38117})
	if a != KnockSequenceDigest([]int{27431, 45902, 38117}) || len(a) != 64 {
		t.Fatal("the digest must be deterministic hex")
	}
	if a == KnockSequenceDigest([]int{45902, 27431, 38117}) {
		t.Fatal("order is part of the secret, so it must be part of the digest")
	}
}
