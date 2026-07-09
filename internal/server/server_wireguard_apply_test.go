package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/wireguard"
)

const testWGPlan = "[Interface]\nAddress = 10.66.0.1/32\nPrivateKey = " +
	wireguard.PrivateKeyPlaceholder + "\nListenPort = 51820\n\n[Peer]\nPublicKey = " +
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP=\nAllowedIPs = 10.66.0.2/32\n"

// design-13 W2 / D9: WireGuard apply must carry the same dead-man protection
// the nft paths have. Before this, a bad wg0.conf could strand a node with no
// way back — the interface carrying the agent's own route went down and
// nothing restored it.
func TestWireGuardApplyHasRollbackWatchdogAndSelfcheck(t *testing.T) {
	script := applyScriptForWithServer(
		model.Approval{Plugin: "wireguard", Plan: testWGPlan},
		"https://203.0.113.99",
	)
	for _, want := range []string{
		// validate before the kernel sees it
		`wg-quick strip "$CANDIDATE" > /dev/null`,
		// snapshot the live config
		`cp "$ACTIVE" "$ROLLBACK"`,
		// dead-man switch, armed before the commit
		"start_watchdog",
		"WATCHDOG_FIRED=/tmp/lattice-wireguard-watchdog.$$",
		"trap 'rollback; cleanup_watchdog; rm -f \"$STRIPPED\"' ERR",
		"sleep 60",
		// commit
		"wg-quick up wg0",
		// verify the control plane survived, then disarm
		"--selfcheck-controlplane -server 'https://203.0.113.99'",
		"assert_watchdog_clean",
		"cleanup_watchdog",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("wireguard apply script missing %q:\n%s", want, script)
		}
	}

	// Ordering is the whole point: arm before commit, verify before disarm.
	// Measure only the executable tail — the rollback()/start_watchdog()
	// function bodies defined above it also mention these commands.
	arm := strings.Index(script, "\nstart_watchdog\n")
	if arm < 0 {
		t.Fatalf("watchdog is never armed:\n%s", script)
	}
	tail := script[arm:]
	commit := strings.Index(tail, "wg-quick up wg0")
	verify := strings.Index(tail, "assert_watchdog_clean\n")
	disarm := strings.Index(tail, "\ncleanup_watchdog\n")
	if commit < 0 || verify < 0 || disarm < 0 || !(commit < verify && verify < disarm) {
		t.Fatalf("unsafe ordering after arming: commit=%d verify=%d disarm=%d:\n%s", commit, verify, disarm, tail)
	}

	// The private key placeholder is substituted on-node; the plan the server
	// stores and the operator reviews never carries a secret.
	if !strings.Contains(script, wireguard.PrivateKeyPlaceholder) {
		t.Fatal("script must substitute the private-key placeholder on-node")
	}
	if strings.Contains(script, "PrivateKey = abc") {
		t.Fatal("a real private key must never appear in the apply script")
	}
}

// Peer-only changes reload without dropping established tunnels; interface
// changes still take the full restart path.
func TestWireGuardApplyUsesSyncconfFastPath(t *testing.T) {
	script := applyScriptForWithServer(model.Approval{Plugin: "wireguard", Plan: testWGPlan}, "")
	for _, want := range []string{
		"iface_block()",
		`MODE=syncconf`,
		`wg syncconf wg0 "$STRIPPED"`,
		`MODE=restart`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing syncconf fast path %q:\n%s", want, script)
		}
	}
	// syncconf must only be chosen when the [Interface] block is unchanged.
	if !strings.Contains(script, `[ "$(iface_block "$ACTIVE")" = "$(iface_block "$CANDIDATE")" ]`) {
		t.Fatalf("syncconf must be gated on an unchanged interface block:\n%s", script)
	}
}

// $STRIPPED holds the substituted private key while syncconf runs. It must be
// cleared on the failure path too, not only on success.
func TestWireGuardApplyClearsStrippedKeyOnEveryExitPath(t *testing.T) {
	script := applyScriptForWithServer(model.Approval{Plugin: "wireguard", Plan: testWGPlan}, "")
	if !strings.Contains(script, `trap 'rollback; cleanup_watchdog; rm -f "$STRIPPED"' ERR`) {
		t.Fatalf("the ERR trap must remove the stripped key file:\n%s", script)
	}
	if !strings.Contains(script, "  rm -f \"$STRIPPED\"\n") {
		t.Fatalf("the success path must remove the stripped key file:\n%s", script)
	}
	// umask 077 means anything written under /etc/wireguard is 0600.
	if !strings.Contains(script, "umask 077\n") {
		t.Fatal("key-bearing files must be written with umask 077")
	}
}

func TestWireGuardApplyWithoutPublicURLSkipsSelfcheckLoudly(t *testing.T) {
	script := applyScriptForWithServer(model.Approval{Plugin: "wireguard", Plan: testWGPlan}, "")
	if strings.Contains(script, "--selfcheck-controlplane") {
		t.Fatal("no public url means no selfcheck")
	}
	if !strings.Contains(script, "control-plane selfcheck skipped because public_url is unset") {
		t.Fatalf("the skip must be loud, not silent:\n%s", script)
	}
	// The watchdog is still armed: it is the only remaining net.
	if !strings.Contains(script, "start_watchdog") {
		t.Fatal("watchdog must be armed even when the selfcheck is skipped")
	}
}

// The generated shell must actually parse. `sh -n` catches quoting mistakes in
// the watchdog's nested `sh -c` bodies that a string-contains test cannot.
func TestApplyScriptsAreValidShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	cases := []struct {
		name string
		app  model.Approval
	}{
		{"wireguard", model.Approval{Plugin: "wireguard", Plan: testWGPlan}},
		{"nft", model.Approval{Plugin: "nft", Plan: "table inet lattice_guard {\n}\n"}},
	}
	for _, tc := range cases {
		for _, serverURL := range []string{"", "https://203.0.113.99"} {
			t.Run(tc.name+"/url="+serverURL, func(t *testing.T) {
				script := applyScriptForWithServer(tc.app, serverURL)
				path := filepath.Join(t.TempDir(), "apply.sh")
				if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
					t.Fatal(err)
				}
				out, err := exec.Command(sh, "-n", path).CombinedOutput()
				if err != nil {
					t.Fatalf("generated script is not valid shell: %v\n%s\n--- script ---\n%s", err, out, script)
				}
			})
		}
	}
}

// The watchdog window is one shared constant so the nft and wireguard paths
// cannot drift apart.
func TestWatchdogWindowIsSharedAcrossApplyPaths(t *testing.T) {
	wg := applyScriptForWithServer(model.Approval{Plugin: "wireguard", Plan: testWGPlan}, "")
	nft := applyScriptForWithServer(model.Approval{Plugin: "nft", Plan: "table inet lattice_guard {\n}\n"}, "")
	window := "sleep 60"
	if !strings.Contains(wg, window) || !strings.Contains(nft, window) {
		t.Fatalf("both apply paths must arm the same %q window", window)
	}
	if applyWatchdogWindowSec != 60 {
		t.Fatalf("applyWatchdogWindowSec = %d; update this test deliberately", applyWatchdogWindowSec)
	}
}
