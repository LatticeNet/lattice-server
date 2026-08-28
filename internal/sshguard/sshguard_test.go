package sshguard

import (
	"strings"
	"testing"
)

func hkProfile() Profile {
	return Profile{
		NodeID: "gomami-hkg", Name: "hk",
		SSHPort: 58394, KeepLegacyPort: true,
		Hardening:        DefaultHardening(),
		MgmtSources:      []string{"154.17.12.165"},
		Knock:            &KnockPolicy{Ports: []int{34719, 51283, 42906}, SeqTimeoutSec: 15, OpenFor: "12h"},
		ConfirmWindowSec: 900,
	}
}

// Every case here is a way to strand an operator, which is why Validate fails
// closed on all of them rather than warning.
func TestValidateRefusesProfilesThatCanStrandTheOperator(t *testing.T) {
	cases := []struct {
		name string
		want string
		mut  func(*Profile)
	}{
		{"knock with no second path at all", "out-of-band fallback",
			func(p *Profile) { p.MgmtSources = nil }},

		{"ssh_port 22 is not a move", "legacy port",
			func(p *Profile) { p.SSHPort = 22 }},
		{"repeated knock port shortens the secret", "appears twice",
			func(p *Profile) { p.Knock.Ports = []int{34719, 34719, 42906} }},
		{"short sequence", "exactly 3 ports",
			func(p *Profile) { p.Knock.Ports = []int{34719, 42906} }},
		{"unsupported nft timeout literal", "not one of the supported",
			func(p *Profile) { p.Knock.OpenFor = "12 hours" }},
		{"confirm window below the floor", "outside",
			func(p *Profile) { p.ConfirmWindowSec = 30 }},
		{"unparseable mgmt source", "mgmt_source",
			func(p *Profile) { p.MgmtSources = []string{"not-an-address"} }},
		{"login grace out of range", "login_grace_time",
			func(p *Profile) { p.Hardening.LoginGraceTimeSec = 0 }},
		{"permit_root_login not an sshd value", "permit_root_login",
			func(p *Profile) { p.Hardening.PermitRootLogin = "maybe" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := hkProfile()
			tc.mut(&p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("profile must be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
	if err := hkProfile().Validate(); err != nil {
		t.Fatalf("the reference profile must validate: %v", err)
	}
}

// The established-connections rule has to be first. If it moves, applying a
// ruleset cuts the session applying it, and every staged-rollback guarantee
// built on "you can watch this happen" stops holding.
func TestKnockRulesetAcceptsEstablishedBeforeAnythingElse(t *testing.T) {
	ruleset, err := hkProfile().RenderKnockRuleset()
	if err != nil {
		t.Fatal(err)
	}
	body := ruleset[strings.Index(ruleset, "chain input {"):]
	lines := []string{}
	for _, line := range strings.Split(body, "\n")[1:] {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if !strings.HasPrefix(lines[0], "type filter hook input") {
		t.Fatalf("first chain line is %q", lines[0])
	}
	if lines[1] != "ct state established,related accept" {
		t.Fatalf("second chain line must accept established connections, got %q", lines[1])
	}
	if strings.Contains(ruleset, "policy drop") {
		t.Fatal("this table gates specific ports; a policy-drop chain here becomes a second competing default-deny")
	}
	if strings.Contains(ruleset, "table inet lattice_guard") {
		t.Fatal("the knock table must not be lattice_guard: its set membership changes at runtime and lattice_guard is re-rendered whole")
	}
}

// Port 22 is gated, not left open. Leaving it ungated would make every other
// control cosmetic because the brute force just keeps using 22.
func TestLegacyPortIsGatedRatherThanIgnored(t *testing.T) {
	ruleset, err := hkProfile().RenderKnockRuleset()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tcp dport 22 ip saddr @mgmt counter accept",
		"tcp dport 22 ip saddr @allowed counter accept",
		"tcp dport 22 counter drop",
		"tcp dport 58394 counter drop",
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("ruleset is missing %q", want)
		}
	}
	dropIn, err := hkProfile().RenderSSHDDropIn()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dropIn, "\nPort 22\n") || !strings.Contains(dropIn, "\nPort 58394\n") {
		t.Fatal("sshd must gain the new port while keeping the old one")
	}
}

// A TCP sequence does not survive the kernel's SYN retransmission, which
// replays one port into knockd's state machine and strands it at stage one.
func TestKnockSequenceIsUDP(t *testing.T) {
	conf, err := hkProfile().RenderKnockdConf()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "sequence      = 34719:udp,51283:udp,42906:udp") {
		t.Fatalf("sequence is not the expected UDP triple:\n%s", conf)
	}
	if strings.Contains(conf, ":tcp") {
		t.Fatal("a TCP knock port is retransmitted by the kernel and breaks the sequence")
	}
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "stop_command") {
			t.Fatal("there is no close sequence by design; the set entry expires on its own")
		}
	}
	if !strings.Contains(conf, "timeout 12h }") {
		t.Fatal("the added element must carry the expiry, or a knock opens the port forever")
	}
}

func TestPlanRoundTrips(t *testing.T) {
	p := hkProfile()
	plan, err := RenderArmPlan(p, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	art, err := ParseApprovalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if art.Stage != StageArm || art.NodeID != p.NodeID || art.SSHPort != p.SSHPort {
		t.Fatalf("header did not round-trip: %+v", art)
	}
	if art.ConfirmWindowSec != 900 || !art.KeepLegacyPort {
		t.Fatalf("scalars did not round-trip: %+v", art)
	}
	wantDropIn, _ := p.RenderSSHDDropIn()
	wantNFT, _ := p.RenderKnockRuleset()
	wantKnockd, _ := p.RenderKnockdConf()
	if art.SSHDDropIn != wantDropIn || art.KnockNFT != wantNFT || art.KnockdConf != wantKnockd {
		t.Fatal("an artifact changed between render and parse; the reviewed bytes must be the applied bytes")
	}

	confirm, err := RenderConfirmPlan(p.NodeID, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	cart, err := ParseApprovalPlan(confirm)
	if err != nil {
		t.Fatal(err)
	}
	if cart.Stage != StageConfirm || cart.NodeID != p.NodeID {
		t.Fatalf("confirm plan did not round-trip: %+v", cart)
	}
}

// A plan carrying two candidate configs is ambiguous about which one a human
// actually read, so it is refused rather than resolved by position.
func TestParseRefusesAmbiguousOrTruncatedPlans(t *testing.T) {
	p := hkProfile()
	plan, err := RenderArmPlan(p, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"not a plan":           "# something else\nstage: arm\n",
		"unknown stage":        strings.Replace(plan, "stage: arm", "stage: sideways", 1),
		"duplicate sshd block": plan + "\n```sshd\nPort 1234\n```\n",
		"unclosed block":       strings.Replace(plan, "```nft\n", "```nft\n# truncated", 1)[:len(plan)/2],
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseApprovalPlan(bad); err == nil {
				t.Fatal("plan must be refused")
			}
		})
	}
}

// Ordering in the apply script is the safety property, so it is asserted by
// position rather than trusted to survive future edits.
func TestArmScriptOrderingInvariants(t *testing.T) {
	p := hkProfile()
	plan, err := RenderArmPlan(p, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	// The revert heredoc is written near the top and mentions several of the
	// same commands, so ordering is asserted over the operational half only.
	revertDone := strings.Index(script, "chmod 0700 \"$REVERT\"")
	if revertDone < 0 {
		t.Fatal("script does not write the revert helper")
	}
	idx := func(needle string) int {
		i := strings.Index(script, needle)
		if i < 0 {
			t.Fatalf("script is missing %q", needle)
		}
		return i
	}
	idxAfterRevert := func(needle string) int {
		i := strings.Index(script[revertDone:], needle)
		if i < 0 {
			t.Fatalf("script is missing %q after the revert helper", needle)
		}
		return revertDone + i
	}
	snapshot := idx("sshd-dropin.rollback\"")
	writeRevert := idx("cat > \"$REVERT\"")
	armTimer := idx("--on-active=")
	writeDropIn := idx("cat > \"$DROPIN\"")
	startKnockd := idxAfterRevert("restart knockd")
	applyNFT := idx("\"$NFT\" -f \"$KNOCK_NFT\"")

	if !(snapshot < writeRevert && writeRevert < armTimer && armTimer < writeDropIn) {
		t.Fatal("the undo must be recorded and scheduled before the first change, or a mid-script death leaves no way back")
	}
	if !(writeDropIn < startKnockd && startKnockd < applyNFT) {
		t.Fatal("knockd must be up before the gate goes up, or nothing can open the port that just closed")
	}
	if strings.Index(script, "-c -f \"$KNOCK_NFT\"") > applyNFT {
		t.Fatal("the candidate ruleset must be validated before it is applied")
	}
}

// Approval applies run under interpreter "sh", which is dash on Debian. dash
// answers `trap ... ERR` with "trap: ERR: bad trap" and carries on, so an ERR
// trap would be silently absent exactly when it is needed.
func TestScriptAvoidsConstructsDashDoesNotSupport(t *testing.T) {
	p := hkProfile()
	plan, _ := RenderArmPlan(p, p.Name)
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "ERR INT") || strings.Contains(script, "trap 'rollback' ERR") {
		t.Fatal("dash does not support trap ERR; use an EXIT trap guarded by a success marker")
	}
	if !strings.Contains(script, "trap on_exit EXIT") {
		t.Fatal("the failure path must be armed with an EXIT trap")
	}
	if !strings.Contains(script, "LATTICE_SSHGUARD_OK=1") {
		t.Fatal("the success marker must be set, or a clean run reverts itself")
	}
}

// The task runner narrows PATH to /usr/bin:/bin:/usr/local/bin, which has no
// sbin, so every binary must be spelled out.
func TestScriptCallsBinariesByAbsolutePath(t *testing.T) {
	p := hkProfile()
	plan, _ := RenderArmPlan(p, p.Name)
	script, _ := ApplyScriptFromPlan(plan)
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		for _, bare := range []string{"nft ", "sshd ", "knockd ", "systemd-run ", "apt-get "} {
			if strings.HasPrefix(trimmed, bare) {
				t.Fatalf("bare binary invocation %q in: %s", bare, trimmed)
			}
		}
	}
	for _, want := range []string{BinNFT, BinSSHD, BinSystemctl, BinSystemdRun} {
		if !strings.Contains(script, want) {
			t.Fatalf("script does not reference %s by absolute path", want)
		}
	}
}

// The netguard rollback flushes the whole machine's ruleset and replays a
// snapshot, which takes every other tenant of nftables with it. This one
// deletes exactly the table it created.
func TestRevertTouchesOnlyItsOwnTable(t *testing.T) {
	p := hkProfile()
	plan, _ := RenderArmPlan(p, p.Name)
	script, _ := ApplyScriptFromPlan(plan)
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("a whole-machine flush would take Docker's tables and every other nftables tenant with it")
	}
	if !strings.Contains(script, "delete table inet "+KnockTable) {
		t.Fatal("revert must delete the table it created")
	}
	if !strings.Contains(script, "was-absent") {
		t.Fatal("revert must distinguish restoring a previous file from removing one that never existed")
	}
}

func TestConfirmRefusesANodeThatIsNotArmed(t *testing.T) {
	confirm, _ := RenderConfirmPlan("gomami-hkg", "hk")
	script, err := ApplyScriptFromPlan(confirm)
	if err != nil {
		t.Fatal(err)
	}
	// Armed-ness is proven by the pending revert timer rather than by the
	// firewall, because a hardening-only profile installs no table and would
	// otherwise never be confirmable.
	if !strings.Contains(script, "list-timers "+RevertUnit) {
		t.Fatal("confirm must verify the node is actually armed, or it reports success on a node where the arm never landed")
	}
	if !strings.Contains(script, "stop "+RevertUnit+".timer") {
		t.Fatal("confirm must cancel the revert timer")
	}
	// Confirm writes exactly one thing: the boot unit that makes the gate
	// survive a reboot. That is deliberately part of confirming rather than of
	// arming, because the revert timer is transient and does not survive a
	// reboot; enabling persistence at arm would mean a node restarted inside
	// the window came back with the gate rebuilt and nothing left to undo it.
	if strings.Contains(script, "$DROPIN") || strings.Contains(script, "KNOCKD_CONF") {
		t.Fatal("confirm must not rewrite the sshd or knockd configuration")
	}
	if !strings.Contains(script, "admitted=") {
		t.Fatal("confirm must require evidence that the gate admitted something, not just an operator's word")
	}
	if !strings.Contains(script, FirewallUnit) {
		t.Fatal("confirm is where boot persistence is installed")
	}
}

// A derived sequence is only as secret as the derivation, and the derivation
// lives in a repository. These are drawn.
func TestNewKnockSequenceIsDistinctAndInRange(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		ports, err := NewKnockSequence()
		if err != nil {
			t.Fatal(err)
		}
		if len(ports) != KnockSequenceLen {
			t.Fatalf("got %d ports", len(ports))
		}
		uniq := map[int]bool{}
		for _, port := range ports {
			if port < knockPortMin || port > knockPortMax {
				t.Fatalf("port %d out of range", port)
			}
			if uniq[port] {
				t.Fatalf("duplicate port %d within one sequence", port)
			}
			uniq[port] = true
		}
		seen[joinInts(ports)] = true
	}
	if len(seen) < 45 {
		t.Fatalf("only %d distinct sequences in 50 draws; this should not repeat", len(seen))
	}
}

// A profile with no knock policy is a valid, useful state: harden sshd and
// shrink the ports to the management sources without any knocking at all.
func TestProfileWithoutKnockStillGatesAndRenders(t *testing.T) {
	p := hkProfile()
	p.Knock = nil
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	ruleset, err := p.RenderKnockRuleset()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ruleset, "@allowed") {
		t.Fatal("no knock policy means no knock-opened set")
	}
	if !strings.Contains(ruleset, "tcp dport 58394 ip saddr @mgmt counter accept") {
		t.Fatal("management sources must still reach SSH")
	}
	plan, err := RenderArmPlan(p, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "knockd") {
		t.Fatal("a profile without knocking must not mention knockd anywhere, including in its revert")
	}
}

// The two-table override is the failure this lint exists to catch, and it is
// the one an operator cannot diagnose from the outside: the knock reports
// success and the connection still never opens.
func TestLintCatchesTheGuardOverride(t *testing.T) {
	p := hkProfile()
	reality := NodeReality{
		Reported:              true,
		ListeningTCPPorts:     []int{22},
		ManagedByNetGuard:     true,
		GuardPolicyDrop:       true,
		GuardAcceptedTCPPorts: []int{22, 443},
	}
	findings := LintProfile(p, reality)
	if !Blocking(findings) {
		t.Fatal("a policy-drop guard that does not accept the new port must block the plan")
	}
	var got *Finding
	for i := range findings {
		if findings[i].Code == FindingOverriddenByGuard {
			got = &findings[i]
		}
	}
	if got == nil {
		t.Fatalf("expected %s, got %+v", FindingOverriddenByGuard, findings)
	}
	if !strings.Contains(got.Message, "58394") {
		t.Fatalf("the finding must name the port that would be dropped: %q", got.Message)
	}

	// A guard that already accepts the port is fine, and so is a guard whose
	// policy is accept: it cannot override anything.
	reality.GuardAcceptedTCPPorts = []int{22, 58394}
	if Blocking(LintProfile(p, reality)) {
		t.Fatal("a guard that accepts the gated ports must not block")
	}
	reality.GuardAcceptedTCPPorts = []int{22}
	reality.GuardPolicyDrop = false
	if Blocking(LintProfile(p, reality)) {
		t.Fatal("an accept-policy guard cannot override this table, so it must not block")
	}
}

func TestLintCatchesAPortAlreadyInUse(t *testing.T) {
	p := hkProfile()
	findings := LintProfile(p, NodeReality{Reported: true, ListeningTCPPorts: []int{22, 58394}})
	if !Blocking(findings) {
		t.Fatal("a port that is already bound must block: sshd -t does not catch it because binding happens at reload")
	}
	if findings[0].Code != FindingPortInUse {
		t.Fatalf("expected %s, got %+v", FindingPortInUse, findings)
	}
}

func TestLintWarnsRatherThanBlocksOnThinEvidence(t *testing.T) {
	p := hkProfile()
	findings := LintProfile(p, NodeReality{Reported: false})
	if Blocking(findings) {
		t.Fatal("a node that has never reported is a normal first-time state, not an error")
	}
	codes := map[string]bool{}
	for _, f := range findings {
		codes[f.Code] = true
	}
	if !codes[FindingNoReality] {
		t.Fatal("missing evidence must still be said out loud")
	}
	// One single-host management source with knocking enabled is a narrow
	// fallback: legitimate, but it should be a decision rather than a surprise.
	if !codes[FindingSingleWayIn] {
		t.Fatal("a single-host-only fallback must be surfaced")
	}
	p.MgmtSources = []string{"154.17.12.0/24"}
	for _, f := range LintProfile(p, NodeReality{Reported: true}) {
		if f.Code == FindingSingleWayIn {
			t.Fatal("a network-range fallback is not narrow")
		}
	}
}

// The contract of this whole design is that the document a reviewer reads is
// the bytes that land on the host. Anything that lets the two drift, a
// re-render between plan and apply, a helpful normalization on one side only,
// turns the approval into a rubber stamp for something else.
func TestReviewedBytesAreTheAppliedBytes(t *testing.T) {
	p := hkProfile()
	plan, err := RenderArmPlan(p, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	between := func(text, start, end string) string {
		i := strings.Index(text, start)
		if i < 0 {
			t.Fatalf("missing %q", start)
		}
		rest := text[i+len(start):]
		j := strings.Index(rest, end)
		if j < 0 {
			t.Fatalf("unterminated %q", start)
		}
		return strings.TrimSpace(rest[:j])
	}
	cases := []struct {
		name                   string
		planStart, planEnd     string
		scriptStart, scriptEnd string
	}{
		{"sshd drop-in", "```sshd\n", "\n```",
			"cat > \"$DROPIN\" <<'LATTICE_SSHGUARD_SSHD'\n", "\nLATTICE_SSHGUARD_SSHD\n"},
		{"nft ruleset", "```nft\n", "\n```",
			"cat > \"$KNOCK_NFT\" <<'LATTICE_SSHGUARD_NFT'\n", "\nLATTICE_SSHGUARD_NFT\n"},
		{"knockd sequence", "```knockd\n", "\n```",
			"cat > \"$KNOCKD_CONF\" <<'LATTICE_SSHGUARD_KNOCKD'\n", "\nLATTICE_SSHGUARD_KNOCKD\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reviewed := between(plan, tc.planStart, tc.planEnd)
			applied := between(script, tc.scriptStart, tc.scriptEnd)
			if reviewed != applied {
				t.Fatalf("the reviewed bytes and the applied bytes differ.\nreviewed:\n%s\n\napplied:\n%s", reviewed, applied)
			}
			if reviewed == "" {
				t.Fatal("empty artifact")
			}
		})
	}
}

// Both of these were live injections found by probing the renderer, not
// hypotheticals. They are kept as tests because the shape of the bug survives a
// rewrite: any field interpolated into a rendered document can add a line to it.
func TestNodeIDCannotInjectDirectivesIntoRenderedConfigs(t *testing.T) {
	cases := []string{
		"x\nPermitRootLogin yes",
		"x\n}\ntable inet evil {",
		"x\rPort 2222",
		"x\x00y",
		strings.Repeat("a", 65),
		"",
		" ",
		"-leading-dash",
	}
	for _, bad := range cases {
		t.Run(strings.ReplaceAll(bad, "\n", "\\n"), func(t *testing.T) {
			p := hkProfile()
			p.NodeID = bad
			if err := p.Validate(); err == nil {
				t.Fatalf("node_id %q must be refused: it is interpolated into the sshd drop-in and the nftables ruleset", bad)
			}
			if _, err := p.RenderSSHDDropIn(); err == nil {
				t.Fatal("rendering must refuse the same input")
			}
			if _, err := p.RenderKnockRuleset(); err == nil {
				t.Fatal("rendering must refuse the same input")
			}
		})
	}
	if err := (Profile{NodeID: "gomami-hkg"}).Validate(); err != nil && strings.Contains(err.Error(), "node_id") {
		t.Fatalf("a normal node id must pass: %v", err)
	}
}

// A display name reaches the plan header from another subsystem. A newline in
// it used to be able to add a header key, and the parser took the last value
// for a key, so "friendly\nstage: confirm" turned an arm plan into a confirm
// plan: the apply would cancel a revert timer instead of arming one.
func TestDisplayNameCannotForgeAHeaderKey(t *testing.T) {
	p := hkProfile()
	plan, err := RenderArmPlan(p, "friendly\nstage: confirm\nssh_port: 22")
	if err != nil {
		t.Fatal(err)
	}
	art, err := ParseApprovalPlan(plan)
	if err != nil {
		t.Fatalf("a sanitized name must still render a parseable plan: %v", err)
	}
	if art.Stage != StageArm {
		t.Fatalf("stage was hijacked to %q", art.Stage)
	}
	if art.SSHPort != p.SSHPort {
		t.Fatalf("ssh_port was hijacked to %d", art.SSHPort)
	}
	if strings.Contains(plan, "\nstage: confirm") {
		t.Fatal("the forged line survived into the document")
	}

	// The parser holds even if a future caller forgets to sanitize.
	forged := strings.Replace(plan, "stage: arm", "stage: arm\nstage: confirm", 1)
	if _, err := ParseApprovalPlan(forged); err == nil {
		t.Fatal("a duplicated header key must be refused rather than resolved by position")
	}
}

func TestSanitizeDisplayTextKeepsRealisticNames(t *testing.T) {
	for _, name := range []string{"[Metix]-gomami-hk-turin-mini", "节点 A / 香港", "dmit-eb-wee"} {
		if got := SanitizeDisplayText(name); got != name {
			t.Fatalf("a legitimate name must survive intact: %q became %q", name, got)
		}
	}
	if got := SanitizeDisplayText("a\nb\tc"); got != "a b c" {
		t.Fatalf("line breaks must become spaces, got %q", got)
	}
	if got := SanitizeDisplayText(strings.Repeat("x", 200)); len(got) != 120 {
		t.Fatalf("length must be bounded, got %d", len(got))
	}
}

// The dangerous configuration is not refused, it is unreachable: a profile with
// neither a management source nor a knock policy means "harden sshd, leave
// reachability alone" instead of rendering a chain whose only rule for the SSH
// port is `counter drop`. That earlier shape was a guaranteed permanent lockout
// for anyone who confirmed it without testing, and Validate allowed it.
func TestAProfileWithNoWayInInstallsNoFirewallRatherThanADenyAll(t *testing.T) {
	p := Profile{
		NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(),
		ConfirmWindowSec: 900,
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("hardening-only is a legitimate profile: %v", err)
	}
	if p.GatesFirewall() {
		t.Fatal("no management source and no knock policy means no firewall")
	}
	if _, err := p.RenderKnockRuleset(); err == nil {
		t.Fatal("rendering a ruleset for a profile that installs none must be an error, not a deny-all")
	}

	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan, "```nft") {
		t.Fatal("the plan must not carry a firewall artifact")
	}
	art, err := ParseApprovalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if art.KnockNFT != "" {
		t.Fatal("no firewall artifact must parse out")
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"counter drop", "$NFT\" -f", "lattice_knock"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("a hardening-only apply must not touch nftables, found %q", forbidden)
		}
	}
	// The revert is still armed: a bad sshd config is its own way to lose a node.
	if !strings.Contains(script, "--on-active=") || !strings.Contains(script, "trap on_exit EXIT") {
		t.Fatal("hardening-only must still arm the revert and the failure path")
	}
	if !strings.Contains(script, "-t;") && !strings.Contains(script, "\"$SSHD\" -t") {
		t.Fatal("hardening-only must still validate the config before reloading")
	}
}

// A knock sequence with no firewall for it to open is a plan that reads as
// protective and protects nothing, so it is refused rather than applied.
func TestPlanRefusesAKnockSequenceWithNoFirewall(t *testing.T) {
	p := hkProfile()
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	stripped := plan[:strings.Index(plan, "## nftables")] +
		plan[strings.Index(plan, "## knockd sequence"):]
	if _, err := ParseApprovalPlan(stripped); err == nil {
		t.Fatal("a knock sequence with no firewall must be refused")
	}
}

// Two lockout paths that survived the first design and were found by walking
// the failure modes rather than by testing the happy path.
func TestARebootInsideTheWindowLosesTheGateNotTheRevert(t *testing.T) {
	p := hkProfile()
	plan, _ := RenderArmPlan(p, "")
	arm, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	// systemd-run creates a transient timer, which does not survive a reboot.
	// If arm also enabled boot persistence, a node restarted inside the window
	// would come back with the gate rebuilt and no revert left: permanently
	// gated, never confirmed, and unreachable if the sources were wrong.
	if strings.Contains(arm, "enable "+FirewallUnit) {
		t.Fatal("arm must not make the gate survive a reboot; that belongs to confirm")
	}
	if !strings.Contains(arm, "NOT yet persistent across reboot") {
		t.Fatal("the operator should be told the gate is not persistent yet")
	}

	confirmPlan, _ := RenderConfirmPlan(p.NodeID, "")
	confirm, err := ApplyScriptFromPlan(confirmPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(confirm, "enable "+FirewallUnit) {
		t.Fatal("confirm must install boot persistence")
	}
}

func TestConfirmRequiresTheGateToHaveAdmittedSomething(t *testing.T) {
	confirmPlan, _ := RenderConfirmPlan("gomami-hkg", "")
	script, err := ApplyScriptFromPlan(confirmPlan)
	if err != nil {
		t.Fatal(err)
	}
	// The check is conditional on a table existing, because a hardening-only
	// profile installs none and would otherwise never be confirmable.
	if !strings.Contains(script, "list table inet "+KnockTable+" >/dev/null 2>&1; then") {
		t.Fatal("the evidence check must be skipped when there is no gate to have counters")
	}
	// Evidence is a non-zero counter on an ACCEPT rule specifically. A gate that
	// has only dropped things proves the opposite of what confirming asserts,
	// and the JSON form makes accept-vs-drop hard to tell apart in shell.
	if !strings.Contains(script, "counter packets [1-9][0-9]* bytes [0-9]+ accept") {
		t.Fatal("evidence must be a non-zero counter on an accept rule, not on any rule")
	}
	if strings.Contains(script, "drop'") || strings.Contains(script, `bytes [0-9]+ drop`) {
		t.Fatal("a drop counter must never be read as evidence that someone got in")
	}
	if !strings.Contains(script, "already established and proves nothing") {
		t.Fatal("the refusal must explain why the operator's current session does not count")
	}
}

// Writing a drop-in is not the same as it taking effect. sshd keeps the FIRST
// value it sees for each keyword and reads /etc/ssh/sshd_config.d/*.conf in
// lexical order, so any file sorting before ours wins. Most of the time that is
// harmless because the earlier file agrees; on one real node it was a file
// named 00-permit-root-password-auth.conf that said the opposite, and the apply
// reported success with password authentication still on.
func TestApplyVerifiesEverySettingActuallyTookEffect(t *testing.T) {
	p := hkProfile()
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Every keyword the drop-in sets and that sshd -T reports must be checked.
	for _, want := range []string{
		"sshguard_check 'logingracetime' '20'",
		"sshguard_check 'maxauthtries' '3'",
		"sshguard_check 'passwordauthentication' 'no'",
		"sshguard_check 'permitrootlogin' 'without-password'",
		"sshguard_check 'x11forwarding' 'no'",
		"sshguard_check 'allowagentforwarding' 'no'",
		"sshguard_check 'kbdinteractiveauthentication' 'no'",
		"sshguard_check 'permitemptypasswords' 'no'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("the apply must verify %q against sshd -T", want)
		}
	}
	// sshd_config spells prohibit-password; sshd -T reports without-password.
	// Comparing the two literally would fail on every node.
	if strings.Contains(script, "sshguard_check 'permitrootlogin' 'prohibit-password'") {
		t.Fatal("the check must compare against the value sshd -T actually prints")
	}
	// A mismatch has to fail, not warn: reporting success on a half-applied
	// hardening leaves the operator believing in a control that is off.
	if !strings.Contains(script, "did not fully take effect") || !strings.Contains(script, "sshguard_mismatch\" = 1 ]; then\n  echo") {
		t.Fatal("a mismatch must abort the apply so the revert runs")
	}
	// "It did not take effect" is not actionable; "this file declares it before
	// yours" is.
	if !strings.Contains(script, "declared earlier in /etc/ssh/sshd_config.d/$f") {
		t.Fatal("the failure must name the file that won")
	}
	// Only files sorting before ours can win, so naming our own would be noise.
	if !strings.Contains(script, `awk '$0 < "`+dropInBasename()+`"'`) {
		t.Fatal("the search must be limited to drop-ins that sort before ours")
	}
	// The verification must sit after the reload; checking before it would read
	// the previous configuration and pass for the wrong reason.
	reload := strings.Index(script, "reload sshd")
	check := strings.Index(script, "sshguard_mismatch=0")
	if reload < 0 || check < 0 || check < reload {
		t.Fatal("the verification must run after the reload, not before it")
	}
}

// A hardening-only profile is exactly the one whose settings are most likely to
// be shadowed, so it must carry the check too.
func TestHardeningOnlyAlsoVerifiesEffectiveSettings(t *testing.T) {
	p := Profile{NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(), ConfirmWindowSec: 900}
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "sshguard_check 'logingracetime' '20'") {
		t.Fatal("hardening-only must verify its settings; it has no firewall to fall back on")
	}
}

// An address allowlist looks like a safety net and is only as good as the
// address staying put. The one written into the reference node's allowlist went
// stale within hours, and a node reached through a proxy sees a source that
// changes with the route. So a knock profile may instead lean on a path that
// does not use SSH at all, and the claim is checked rather than believed.
func TestKnockMayLeanOnAnOutOfBandFallbackInsteadOfAnAddress(t *testing.T) {
	p := hkProfile()
	p.MgmtSources = nil
	p.OutOfBandFallback = true
	if err := p.Validate(); err != nil {
		t.Fatalf("an out-of-band fallback is a legitimate second path: %v", err)
	}

	// Claimed and available: fine.
	if Blocking(LintProfile(p, NodeReality{Reported: true, TerminalAvailable: true})) {
		t.Fatal("a node that can give a shell without SSH must not block")
	}

	// Claimed and NOT available: this is the case the check exists for. A
	// fallback on paper is worse than an admitted absence, because it is the
	// reason the profile was allowed to gate SSH at all.
	findings := LintProfile(p, NodeReality{Reported: true, TerminalAvailable: false})
	if !Blocking(findings) {
		t.Fatal("a claimed fallback that the node cannot provide must block the plan")
	}
	var got *Finding
	for i := range findings {
		if findings[i].Code == FindingFallbackUnavailable {
			got = &findings[i]
		}
	}
	if got == nil {
		t.Fatalf("expected %s, got %+v", FindingFallbackUnavailable, findings)
	}

	// A profile that does not claim it is unaffected by the node's capability.
	q := hkProfile()
	if Blocking(LintProfile(q, NodeReality{Reported: true, TerminalAvailable: false})) {
		t.Fatal("a profile with an address allowlist must not depend on the terminal")
	}
}

// Knocking without moving the port is the shape most of this fleet needs.
// About a third of it is reachable only through a provider's port forward, and
// binding sshd to a port nobody forwards takes SSH away entirely.
func TestKnockCanGateTheExistingPortWithoutMovingIt(t *testing.T) {
	p := hkProfile()
	p.SSHPort = 0
	if err := p.Validate(); err != nil {
		t.Fatalf("gating port 22 in place is a legitimate knock profile: %v", err)
	}
	if got := p.GatedPorts(); len(got) != 1 || got[0] != 22 {
		t.Fatalf("the gated port should be 22 exactly where it is, got %v", got)
	}
	ruleset, err := p.RenderKnockRuleset()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tcp dport 22 ip saddr @allowed counter accept",
		"tcp dport 22 counter drop",
	} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(ruleset, "dport 58394") {
		t.Fatal("no port was requested, so none should be gated")
	}
	dropIn, err := p.RenderSSHDDropIn()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dropIn, "\nPort ") {
		t.Fatal("a profile that moves no port must not write a Port directive at all")
	}
	// The apply must still install knockd and the gate.
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "restart knockd") || !strings.Contains(script, "$NFT\" -f") {
		t.Fatal("knocking without a port move still needs knockd and the ruleset")
	}
}

// Assuming sshd is on 22 was wrong on this fleet. Measuring it found three
// machines running sshd on 3434, where a profile that gates 22 installs a door
// nobody uses, leaves the real one open, and reports success. Same failure as
// writing a config and not checking it took effect, one layer up.
func TestTheGateCoversThePortSSHDIsActuallyOn(t *testing.T) {
	p := hkProfile()
	p.SSHPort = 0
	p.ExistingSSHPorts = []int{3434}
	got := p.GatedPorts()
	if len(got) != 1 || got[0] != 3434 {
		t.Fatalf("the gate must cover the port sshd is on, got %v", got)
	}
	ruleset, err := p.RenderKnockRuleset()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, "tcp dport 3434 counter drop") {
		t.Fatal("the real SSH port must be gated")
	}
	if strings.Contains(ruleset, "dport 22") {
		t.Fatal("gating a port nothing listens on is noise that reads as protection")
	}

	// A node that reports several is gated on all of them: an ungated listener
	// makes the rest cosmetic.
	p.ExistingSSHPorts = []int{22, 3434}
	if got := p.GatedPorts(); len(got) != 2 || got[0] != 22 || got[1] != 3434 {
		t.Fatalf("every listening port must be gated, got %v", got)
	}

	// Moving the port: the old one is gated only while sshd is kept there.
	moved := hkProfile()
	moved.ExistingSSHPorts = []int{22}
	moved.KeepLegacyPort = false
	if got := moved.GatedPorts(); len(got) != 1 || got[0] != 58394 {
		t.Fatalf("a port sshd is leaving must not be gated, got %v", got)
	}
	moved.KeepLegacyPort = true
	if got := moved.GatedPorts(); len(got) != 2 {
		t.Fatalf("a port sshd keeps must stay gated, got %v", got)
	}

	// No report and no request falls back to 22, which the lint flags as a
	// guess rather than presenting as fact.
	bare := Profile{NodeID: "n1", Hardening: DefaultHardening(), MgmtSources: []string{"203.0.113.5"}}
	if got := bare.GatedPorts(); len(got) != 1 || got[0] != 22 {
		t.Fatalf("the fallback is 22, got %v", got)
	}
}

// The escape hatch. The ordinary path derives the gate from what sshd reports,
// which is right for a normal host; this is for the ones that are not, so the
// product does not have to learn about each of them.
func TestAnExplicitPortListIsTakenAsStated(t *testing.T) {
	p := hkProfile()
	p.SSHPort = 0
	p.ExistingSSHPorts = []int{22, 3434}
	p.GatePorts = []int{2222}
	got := p.GatePorts
	if len(got) != 1 || got[0] != 2222 {
		t.Fatalf("an explicit list must be taken as stated, got %v", p.GatedPorts())
	}
	if gated := p.GatedPorts(); len(gated) != 1 || gated[0] != 2222 {
		t.Fatalf("the derivation must be skipped entirely, including its fallback, got %v", gated)
	}
	ruleset, err := p.RenderKnockRuleset()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ruleset, "tcp dport 2222 counter drop") {
		t.Fatal("the stated port must be gated")
	}
	for _, unwanted := range []string{"dport 22 ", "dport 3434"} {
		if strings.Contains(ruleset, unwanted) {
			t.Fatalf("a derived port must not survive an explicit list: %q", unwanted)
		}
	}

	bad := hkProfile()
	bad.GatePorts = []int{70000}
	if err := bad.Validate(); err == nil {
		t.Fatal("an out-of-range port must be refused rather than rendered")
	}
}

// The plan used to list the knock sequence and stop there. That is enough to
// know which ports to hit and not enough to hit them: the obvious command,
// `nc -u -z`, sends an empty datagram, which advances knockd to stage 1 and
// then never again, with no error on either side. A rollout was lost to it.
// These assertions exist so the document cannot regress to listing ports alone.
func TestKnockPlanTellsTheOperatorHowToActuallySendIt(t *testing.T) {
	p := Profile{
		NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(),
		ConfirmWindowSec:  900,
		Address:           "203.0.113.9",
		ExistingSSHPorts:  []int{22},
		OutOfBandFallback: true,
		Knock:             &KnockPolicy{Ports: []int{31537, 27292, 29094}, SeqTimeoutSec: 15, OpenFor: "12h"},
	}
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(plan, "payload") {
		t.Fatal("the plan must state that each datagram carries a payload; without it the obvious command silently does nothing")
	}
	if !strings.Contains(plan, "printf k | nc -u -w1") {
		t.Fatal("the plan must give a command that actually sends a datagram")
	}
	// Naming the broken form is the point: an operator who already typed it
	// needs to recognise it here, not merely be shown a different one.
	if !strings.Contains(plan, "nc -u -z") {
		t.Fatal("the plan must name the command that looks right and does nothing")
	}
	for _, port := range []string{"31537", "27292", "29094"} {
		if !strings.Contains(plan, port) {
			t.Fatalf("knock command is missing port %s", port)
		}
	}
	if i, j, k := strings.Index(plan, "31537"), strings.Index(plan, "27292"), strings.Index(plan, "29094"); !(i < j && j < k) {
		t.Fatal("the ports must appear in sequence order; a knock sent out of order is a knock that fails")
	}
	if !strings.Contains(plan, "203.0.113.9") {
		t.Fatal("the reported address should make the command copyable")
	}
	if !strings.Contains(plan, "same address") {
		t.Fatal("the plan must warn that the knock and the login share a source address")
	}
}

// The address reaches the document from the node's own report, and the document
// is what a human reads to decide whether to approve. Anything that is not an
// IP literal becomes a placeholder rather than text a peer chose.
func TestKnockPlanRefusesAnAddressThatIsNotAnIP(t *testing.T) {
	base := Profile{
		NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(),
		ConfirmWindowSec: 900, ExistingSSHPorts: []int{22}, OutOfBandFallback: true,
		Knock: &KnockPolicy{Ports: []int{20001, 20002, 20003}, SeqTimeoutSec: 15, OpenFor: "12h"},
	}
	for _, bad := range []string{
		"evil.example.com",
		"1.2.3.4; rm -rf /",
		"$(id)",
		"`id`",
		"",
	} {
		p := base
		p.Address = bad
		plan, err := RenderArmPlan(p, "")
		if err != nil {
			t.Fatalf("address %q: %v", bad, err)
		}
		if !strings.Contains(plan, "<node-address>") {
			t.Fatalf("address %q should have been rejected into a placeholder", bad)
		}
		if bad != "" && strings.Contains(plan, bad) {
			t.Fatalf("address %q reached the document verbatim", bad)
		}
	}
}

// A hardening-only profile installs no gate, so a knock section would describe
// a door that is not there.
func TestPlanWithoutKnockHasNoKnockInstructions(t *testing.T) {
	p := Profile{NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(), ConfirmWindowSec: 900}
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan, "How to knock") {
		t.Fatal("a profile with no knock policy must not tell the operator to knock")
	}
}

// The boot unit was called lattice-sshguard-revert-boot while doing the exact
// opposite of reverting. Renaming it is only half the fix: nodes confirmed
// under the old name still have it enabled, so both the installer and the
// revert path have to account for it or a re-armed node carries two units that
// load the same ruleset and disagree about what they are for.
func TestBootUnitIsNamedForWhatItDoesAndClearsTheOldName(t *testing.T) {
	if strings.Contains(FirewallUnit, "revert") {
		t.Fatalf("the unit that restores the gate must not be named %q", FirewallUnit)
	}

	confirmPlan, _ := RenderConfirmPlan("n1", "")
	confirm, err := ApplyScriptFromPlan(confirmPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(confirm, "enable "+FirewallUnit) {
		t.Fatal("confirm must enable the boot unit under its new name")
	}
	if !strings.Contains(confirm, "rm -f /etc/systemd/system/"+LegacyBootUnit+".service") {
		t.Fatal("confirm must remove the pre-rename unit, or a node ends up with both")
	}

	p := Profile{
		NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(),
		ConfirmWindowSec: 900, ExistingSSHPorts: []int{22}, OutOfBandFallback: true,
		Knock: &KnockPolicy{Ports: []int{20001, 20002, 20003}, SeqTimeoutSec: 15, OpenFor: "12h"},
	}
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	arm, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	// The revert has to disable both, including on a node that predates the
	// rename: leaving the legacy unit enabled means the gate it just tore down
	// comes back at the next boot.
	for _, unit := range []string{FirewallUnit, LegacyBootUnit} {
		if !strings.Contains(arm, "disable "+unit) {
			t.Fatalf("revert must disable %s", unit)
		}
	}
}

// The plan is the reviewed artifact, so a claim it makes about what the apply
// does is part of the contract, not commentary. A hardening-only profile used
// to render the narrowing paragraph anyway: it told the reviewer that port 22
// was being restricted to the management sources listed below, and then listed
// "(none)". Thirty-one approved plans on this fleet carry that text while
// installing no firewall at all.
func TestAHardeningOnlyPlanDoesNotClaimToNarrowAnything(t *testing.T) {
	p := Profile{
		NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(),
		ConfirmWindowSec: 900,
	}
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"narrowed to the management sources",
		"narrows who may reach",
		"brute force stops reaching sshd",
		"The firewall rules below",
		"## Management sources",
		"- (none)",
	} {
		if strings.Contains(plan, forbidden) {
			t.Fatalf("a plan that installs no firewall must not say %q:\n%s", forbidden, plan)
		}
	}
	if !strings.Contains(plan, "installs no firewall") {
		t.Fatalf("the plan must say plainly that reachability does not change:\n%s", plan)
	}
	// Changing the prose must not change what the apply derives from it.
	if _, err := ParseApprovalPlan(plan); err != nil {
		t.Fatalf("plan must still parse: %v", err)
	}

	findings := LintProfile(p, NodeReality{Reported: true, ListeningTCPPorts: []int{22}})
	var found bool
	for _, f := range findings {
		if f.Code == FindingHardeningOnly {
			found = true
			if f.Severity != SeverityWarn {
				t.Fatalf("hardening-only is a choice, not a refusal: got severity %q", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("hardening-only must be reported, got %+v", findings)
	}

	// A profile that does gate keeps the paragraph it earned.
	gated := p
	gated.MgmtSources = []string{"203.0.113.5/32"}
	gatedPlan, err := RenderArmPlan(gated, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gatedPlan, "## Management sources") {
		t.Fatal("a gating profile must still list its sources")
	}
	for _, f := range LintProfile(gated, NodeReality{Reported: true}) {
		if f.Code == FindingHardeningOnly {
			t.Fatal("a profile with a management source is not hardening-only")
		}
	}
}

// sshd takes the FIRST value it reads for a keyword and Include sits near the
// top of sshd_config, so a drop-in that sorts earlier wins outright. At the old
// `60-` name this package lost to `50-cloud-init.conf` (rewritten by cloud-init
// from ssh_pwauth on every re-run) and to `50-redhat.conf`, and on one provider
// image to `00-permit-root-password-auth.conf`, which exists specifically to
// turn root password login back on. Eighteen of thirty-three fleet nodes have
// such a file; they happen to agree today, which is the only reason it was
// invisible.
func TestTheGuardDropInSortsBeforeTheFilesThatWouldOverruleIt(t *testing.T) {
	name := dropInBasename()
	for _, loser := range []string{
		"00-permit-root-password-auth.conf",
		"50-cloud-init.conf",
		"50-redhat.conf",
		"60-lattice-guard.conf",
		"99-template-ipv4-only.conf",
	} {
		if name >= loser {
			t.Fatalf("%q must sort before %q or sshd ignores it", name, loser)
		}
	}
	if LegacyDropInPath == DropInPath {
		t.Fatal("the legacy path must stay distinct so the migration can remove it")
	}
}

// A node hardened under the old name must end up with one file, not two that
// both claim the same keywords, and a revert must put the old one back.
func TestArmMigratesTheLegacyDropInAndTheRevertRestoresIt(t *testing.T) {
	p := Profile{
		NodeID: "n1", KeepLegacyPort: true, Hardening: DefaultHardening(),
		ConfirmWindowSec: 900,
	}
	plan, err := RenderArmPlan(p, "")
	if err != nil {
		t.Fatal(err)
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`LEGACY_DROPIN=` + LegacyDropInPath,
		`if [ -f "$LEGACY_DROPIN" ]; then cp -a "$LEGACY_DROPIN" "$LEGACY_BACKUP"; else : > "$LEGACY_ABSENT"; fi`,
		`rm -f "$LEGACY_DROPIN"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("arm must migrate the legacy drop-in, missing %q", want)
		}
	}
	// Snapshot before removal, or the revert restores nothing.
	snap := strings.Index(script, `cp -a "$LEGACY_DROPIN" "$LEGACY_BACKUP"`)
	del := strings.Index(script, "\nrm -f \"$LEGACY_DROPIN\"\n")
	if snap < 0 || del < 0 || snap > del {
		t.Fatal("the legacy file must be snapshotted before it is removed")
	}
	// And removed only after the replacement is on disk.
	write := strings.Index(script, `chmod 0644 "$DROPIN"`)
	if write < 0 || write > del {
		t.Fatal("the new drop-in must be written before the old one is removed")
	}

	revert := revertScriptHeredoc(false, false)
	for _, want := range []string{
		`cp -a "$STATE/sshd-dropin-legacy.rollback" "$LEGACY_DROPIN"`,
		`rm -f "$LEGACY_DROPIN"`,
	} {
		if !strings.Contains(revert, want) {
			t.Fatalf("revert must restore the legacy drop-in, missing %q", want)
		}
	}
}
