package sshguard

import (
	"os/exec"
	"strings"
	"testing"
)

func intPtr(n int) *int { return &n }

// Posture comes from what sshd says, never from what an approval said. Each
// row is a node shape the fleet has actually shown.
func TestDerivePostureReadsTheNodeNotTheApproval(t *testing.T) {
	cases := []struct {
		name  string
		facts *SSHDFacts
		want  Posture
		key   bool
	}{
		{name: "never reported", facts: nil, want: PostureUnknown},
		{
			name:  "key-only with prohibit-password root (the fleet's 18 targets)",
			facts: &SSHDFacts{PasswordAuthentication: false, PubkeyAuthentication: true, PermitRootLogin: "without-password"},
			want:  PostureSecured, key: true,
		},
		{
			name:  "password on, even with a key present",
			facts: &SSHDFacts{PasswordAuthentication: true, PubkeyAuthentication: true, PermitRootLogin: "without-password"},
			want:  PosturePasswordOpen, key: true,
		},
		{
			name:  "password off but root yes",
			facts: &SSHDFacts{PasswordAuthentication: false, PubkeyAuthentication: true, PermitRootLogin: "yes"},
			want:  PosturePartial, key: true,
		},
		{
			name:  "password off, pubkey off, nothing can get in",
			facts: &SSHDFacts{PasswordAuthentication: false, PubkeyAuthentication: false, PermitRootLogin: "no"},
			want:  PosturePartial, key: false,
		},
		{
			name:  "a reported key count of zero overrides pubkey auth being on",
			facts: &SSHDFacts{PasswordAuthentication: false, PubkeyAuthentication: true, PermitRootLogin: "no", AuthorizedKeys: intPtr(0)},
			want:  PosturePartial, key: false,
		},
		{
			name:  "a reported key count proves the key",
			facts: &SSHDFacts{PasswordAuthentication: false, PubkeyAuthentication: true, PermitRootLogin: "no", AuthorizedKeys: intPtr(2)},
			want:  PostureSecured, key: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DerivePosture(tc.facts)
			if got.State != tc.want {
				t.Fatalf("state: want %s, got %s (%s)", tc.want, got.State, got.Reason)
			}
			if got.KeyAccess != tc.key {
				t.Fatalf("key access: want %v, got %v", tc.key, got.KeyAccess)
			}
			if strings.TrimSpace(got.Reason) == "" {
				t.Fatal("every posture carries the sentence the console shows")
			}
		})
	}
	if got := DerivePosture(&SSHDFacts{PubkeyAuthentication: true, AuthorizedKeys: intPtr(1)}); got.KeyEvidence != KeyEvidenceAuthorizedKeys {
		t.Fatalf("a key count is stronger evidence than the auth method: %+v", got)
	}
	if got := DerivePosture(&SSHDFacts{PubkeyAuthentication: true}); got.KeyEvidence != KeyEvidencePubkeyAuth {
		t.Fatalf("without a count, pubkey auth is the evidence and must say so: %+v", got)
	}
}

func hardeningOnlyProfile(keyObserved bool) Profile {
	return Profile{
		NodeID: "dmit-2", KeepLegacyPort: true,
		Hardening:         DefaultHardening(),
		KeyAccessObserved: keyObserved,
		ConfirmWindowSec:  900,
	}
}

// A hardening-only arm on a node that already shows a key path in changes no
// path in or out and takes nothing from the key holder. Arming a timer there
// is how thirteen correctly hardened nodes ended up reading "reverted", so
// the plan says durable and the script arms the timer only if the host
// disagrees about the key.
func TestHardeningOnlyArmIsDurableWhenTheNodeShowsAKey(t *testing.T) {
	p := hardeningOnlyProfile(true)
	if !p.Durable() {
		t.Fatal("no firewall plus an observed key is the durable shape")
	}
	plan, err := RenderArmPlan(p, "DMIT 2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "\ndurable: true\n") {
		t.Fatalf("the plan header must carry the claim the reviewer approves:\n%s", plan)
	}
	if strings.Contains(plan, "systemd timer that undoes all of it") {
		t.Fatal("a durable plan must not promise a revert it will not arm")
	}
	if !strings.Contains(plan, "no revert timer is armed") {
		t.Fatal("the reviewer has to be told there is no confirm step")
	}
	art, err := ParseApprovalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !art.Durable {
		t.Fatal("durable must survive the round trip, or the script arms the timer anyway")
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	keyCheck := strings.Index(script, "sshguard_key_found=0")
	timer := strings.Index(script, "--on-active=")
	dropIn := strings.Index(script, "cat > \"$DROPIN\"")
	if keyCheck < 0 || timer < 0 || dropIn < 0 {
		t.Fatalf("script is missing the key check, the fallback timer, or the drop-in:\n%s", script)
	}
	if !(keyCheck < timer && timer < dropIn) {
		t.Fatal("the host is asked about the key, then the timer is armed or skipped, all before the first change")
	}
	if !strings.Contains(script, "if [ \"$LATTICE_SSHGUARD_DURABLE\" = 0 ]; then\n  \"$SYSTEMD_RUN\" --on-active=") {
		t.Fatal("the timer must be armed only when the host showed no key")
	}
	if !strings.Contains(script, "authorizedkeysfile") {
		t.Fatal("the key check must look where sshd actually reads keys, not a hardcoded path")
	}
	if !strings.Contains(script, "hardening applied and permanent; no confirm is needed") {
		t.Fatal("the durable outcome has to be said in the task output")
	}
	// The revert helper is still written and the EXIT trap still uses it: a
	// failure halfway through must undo itself immediately even when no
	// timer is armed.
	if !strings.Contains(script, "cat > \"$REVERT\"") || !strings.Contains(script, "trap on_exit EXIT") {
		t.Fatal("durable removes the timer, not the immediate undo on failure")
	}
	shellSyntaxCheck(t, script)
}

// The other half of the rule: the same profile on a node that has not shown
// a key keeps the timer, and a firewall arm keeps it unconditionally.
func TestTimerStaysForFirewallArmsAndForNodesWithoutAKey(t *testing.T) {
	noKey := hardeningOnlyProfile(false)
	if noKey.Durable() {
		t.Fatal("with no observed key the hardening arm is not durable")
	}
	plan, err := RenderArmPlan(noKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan, "durable:") {
		t.Fatal("a non-durable plan must not carry the key at all")
	}
	if !strings.Contains(plan, "systemd timer that undoes all of it") {
		t.Fatal("the reviewer must still be told about the revert")
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "sshguard_key_found") {
		t.Fatal("a non-durable arm must not consult the host about keys; the timer is unconditional")
	}
	if !strings.Contains(script, "--on-active=") {
		t.Fatal("the timer must be armed")
	}
	shellSyntaxCheck(t, script)

	// Firewall: the observed key changes nothing, because the lockout risk is
	// the gate, not the password.
	fw := hkProfile()
	fw.KeyAccessObserved = true
	if fw.Durable() {
		t.Fatal("a firewall arm is never durable")
	}
	fwPlan, err := RenderArmPlan(fw, fw.Name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fwPlan, "durable:") {
		t.Fatal("a firewall plan must not claim durability")
	}
	fwScript, err := ApplyScriptFromPlan(fwPlan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fwScript, "sshguard_key_found") || !strings.Contains(fwScript, "--on-active=") {
		t.Fatal("a firewall arm keeps the confirm-or-revert dance unconditionally")
	}
	// The mgmt-only gate (no knock) is a firewall too.
	gate := Profile{NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(),
		MgmtSources: []string{"203.0.113.5"}, KeyAccessObserved: true, ConfirmWindowSec: 900}
	if gate.Durable() {
		t.Fatal("a management-source gate is a firewall and is never durable")
	}
}

// A durable plan that also installs a firewall did not come from this
// renderer. The parser refuses it so a hand-edited plan cannot become a
// script that installs a gate with no revert behind it.
func TestParserRefusesADurableClaimOnAFirewallPlan(t *testing.T) {
	plan, err := RenderArmPlan(hkProfile(), "hk")
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(plan, "confirm_window_sec: 900\n", "confirm_window_sec: 900\ndurable: true\n", 1)
	if _, err := ParseApprovalPlan(forged); err == nil || !strings.Contains(err.Error(), "durable") {
		t.Fatalf("want a refusal naming the durable claim, got %v", err)
	}
}

// shellSyntaxCheck parses the script with the system sh. It cannot run it,
// but a script that will not parse is the one failure that no trap can catch.
func shellSyntaxCheck(t *testing.T, script string) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on this host")
	}
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n rejected the script: %v\n%s", err, out)
	}
}

// A port change is a change to how the node is reached, and that is the one
// risk the timer exists for. The observed key says nothing about whether the
// new port is reachable from outside: a security group, a NAT that only
// forwards 22, or a middlebox can leave sshd listening locally on a port
// nobody can get to. The script's own listen check passes in that case, so
// without the timer a migration that drops 22 is a permanent lockout with
// no path back. Every port change therefore keeps the confirm-or-revert
// path, whether or not 22 is kept.
func TestPortMigrationIsNeverDurable(t *testing.T) {
	for _, keep := range []bool{false, true} {
		p := hardeningOnlyProfile(true)
		p.SSHPort = 2222
		p.KeepLegacyPort = keep
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		if p.Durable() {
			t.Fatalf("keep_legacy_port=%t: a port change is never durable, key or no key", keep)
		}
		plan, err := RenderArmPlan(p, "nat-node")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(plan, "durable:") {
			t.Fatalf("keep_legacy_port=%t: the plan must not claim durability:\n%s", keep, plan)
		}
		if strings.Contains(plan, "changes no port") || strings.Contains(plan, "no revert timer is armed") {
			t.Fatalf("keep_legacy_port=%t: the prose describes a port change as no change:\n%s", keep, plan)
		}
		if !strings.Contains(plan, "adds a port before it takes anything away") || !strings.Contains(plan, "systemd timer that undoes all of it") {
			t.Fatalf("keep_legacy_port=%t: the reviewer must be told about the port change and the revert:\n%s", keep, plan)
		}
		art, err := ParseApprovalPlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		if art.Durable {
			t.Fatal("durable must not survive the round trip on a port change")
		}
		script, err := ApplyScriptFromPlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		// LATTICE_SSHGUARD_DURABLE is set to 0 and only the key check can
		// raise it, so no key check means the timer branch always runs.
		if strings.Contains(script, "sshguard_key_found") || strings.Contains(script, "LATTICE_SSHGUARD_DURABLE=1") {
			t.Fatal("a port change must not consult the host about keys; the timer is unconditional")
		}
		if !strings.Contains(script, "\"$SYSTEMD_RUN\" --on-active=") {
			t.Fatalf("the timer must be armed on a port change:\n%s", script)
		}
		shellSyntaxCheck(t, script)
	}
}

// The parser is the last line: a plan that changes the port and claims
// durability did not come from this renderer, and must not become a script
// that migrates sshd with no revert behind it.
func TestParserRefusesADurableClaimOnAPortChange(t *testing.T) {
	p := hardeningOnlyProfile(true)
	p.SSHPort = 2222
	p.KeepLegacyPort = false
	plan, err := RenderArmPlan(p, "nat-node")
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(plan, "confirm_window_sec: 900\n", "confirm_window_sec: 900\ndurable: true\n", 1)
	if forged == plan {
		t.Fatal("test setup: the durable line was not inserted")
	}
	if _, err := ParseApprovalPlan(forged); err == nil || !strings.Contains(err.Error(), "durable") {
		t.Fatalf("want a refusal naming the durable claim, got %v", err)
	}
}
