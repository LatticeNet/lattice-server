package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A plan now names the keepalive drop-in and the update guard, and the
// script carries both steps in the order that keeps a restart from ever
// running unguarded: binary in place, drop-in, daemon-reload, guard armed,
// restart scheduled.
func TestAgentUpdateScriptWritesKeepaliveDropInAndArmsGuardBeforeRestart(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	approval := seedAgentUpdateApproved(t, srv, st)
	for _, line := range []string{agentUpdateKeepalivePlanLine, agentUpdateGuardPlanLine} {
		if !strings.Contains(approval.Plan, line) {
			t.Fatalf("plan does not show the operator %q:\n%s", line, approval.Plan)
		}
	}
	script, err := agentUpdateApplyScript(approval, srv.publicURL)
	if err != nil {
		t.Fatal(err)
	}
	order := []string{
		"CANDIDATE_VERSION=$(\"$CANDIDATE\" -version)",
		"CANDIDATE_COMPAT=$(\"$CANDIDATE\" -compat-json 2>/dev/null || true)",
		"BACKUP=\"$TARGET.bak.$(date +%Y%m%d%H%M%S)\"",
		"mv \"$TARGET.new\" \"$TARGET\"",
		"*'\"sd-notify-v1\"'*)",
		"'NotifyAccess=main' \"RuntimeDirectory=$UNIT_NAME\" 'RuntimeDirectoryMode=0700'",
		"mv \"$DROPIN.new\" \"$DROPIN\"",
		"systemctl daemon-reload\ncase",
		"*'\"health-marker-v1\"'*)",
		"if [ \"$KEEPALIVE\" = 1 ] && [ -n \"$BACKUP\" ]; then",
		"--on-active=300s",
		"--setenv=LATTICE_GUARD_MARKER=\"/run/$UNIT_NAME/healthy\"",
		"--setenv=LATTICE_GUARD_SHA=\"$EXPECT_SHA\"",
		"/bin/sh \"$GUARD_FILE\"",
		"systemd-run --unit=\"$RESTART_UNIT\" --on-active=3s /bin/systemctl restart \"$SERVICE\"",
	}
	at := 0
	for _, want := range order {
		i := strings.Index(script[at:], want)
		if i < 0 {
			t.Fatalf("script missing %q after offset %d:\n%s", want, at, script)
		}
		at += i + len(want)
	}
	// Under the drop-in the unit stays Type=simple without WatchdogSec, so an
	// older binary later installed under it is never killed for silence.
	for _, forbidden := range []string{"Type=notify", "WatchdogSec"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script writes %s:\n%s", forbidden, script)
		}
	}
	// A guard that cannot be armed stops the update with the old binary back.
	failArm := strings.Index(script, "could not arm the update guard")
	if failArm < 0 || !strings.Contains(script[:failArm], "mv \"$TARGET.rollback\" \"$TARGET\"") || !strings.Contains(script[failArm:], "exit 1") {
		t.Fatalf("an unarmed guard must restore the backup and fail the task:\n%s", script)
	}
	if out, err := exec.Command("sh", "-n", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("script is not valid shell: %v\n%s", err, out)
	}
}

// An approval planned before the keepalive and guard lines existed runs
// exactly the script it was approved with: no compat probe, no drop-in, no
// guard.
func TestAgentUpdateScriptForAPlanWithoutKeepaliveLinesIsUnchanged(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	approval := seedAgentUpdateApproved(t, srv, st)
	approval.Plan = strings.Replace(approval.Plan, agentUpdateKeepalivePlanLine+"\n", "", 1)
	approval.Plan = strings.Replace(approval.Plan, agentUpdateGuardPlanLine+"\n", "", 1)
	script, err := agentUpdateApplyScript(approval, srv.publicURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"CANDIDATE_COMPAT", "DROPIN", "GUARD", "10-lattice-keepalive.conf"} {
		if strings.Contains(script, absent) {
			t.Fatalf("a pre-keepalive approval got %q:\n%s", absent, script)
		}
	}
	// With only the keepalive line, the drop-in is written and no guard armed.
	approval.Plan = strings.Replace(approval.Plan, "- execution still requires", agentUpdateKeepalivePlanLine+"\n- execution still requires", 1)
	script, err = agentUpdateApplyScript(approval, srv.publicURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "10-lattice-keepalive.conf") || strings.Contains(script, "GUARD") {
		t.Fatalf("keepalive line alone must write the drop-in and arm nothing:\n%s", script)
	}
}

// The guard body itself, run against a scratch install: it keeps a binary
// whose agent wrote its version to the marker, leaves a binary that changed
// since the update, and otherwise restores the backup and restarts the unit.
func TestAgentUpdateGuardScriptKeepsRestoresOrLeaves(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	run := func(t *testing.T, marker string, mutateTarget bool) (target string, restarted string) {
		t.Helper()
		dir := t.TempDir()
		target = filepath.Join(dir, "lattice-agent")
		backup := target + ".bak.1"
		if err := os.WriteFile(target, []byte("new binary\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(backup, []byte("old binary\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte("new binary\n"))
		if mutateTarget {
			if err := os.WriteFile(target, []byte("a later update\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		markerPath := filepath.Join(dir, "healthy")
		if marker != "" {
			if err := os.WriteFile(markerPath, []byte(marker+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		bin := filepath.Join(dir, "bin")
		if err := os.Mkdir(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		restartLog := filepath.Join(dir, "restarts")
		fake := "#!/bin/sh\necho \"$*\" >>" + restartLog + "\n"
		if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(fake), 0o755); err != nil {
			t.Fatal(err)
		}
		guard := filepath.Join(dir, "guard.sh")
		if err := os.WriteFile(guard, []byte(agentUpdateGuardScript), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", guard)
		cmd.Env = append(os.Environ(),
			"PATH="+bin+":"+os.Getenv("PATH"),
			"LATTICE_GUARD_TARGET="+target,
			"LATTICE_GUARD_BACKUP="+backup,
			"LATTICE_GUARD_SERVICE=lattice-agent.service",
			"LATTICE_GUARD_MARKER="+markerPath,
			"LATTICE_GUARD_VERSION=0.3.10-alpha.1",
			"LATTICE_GUARD_SHA="+hex.EncodeToString(sum[:]),
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("guard failed: %v\n%s", err, out)
		}
		if _, err := os.Stat(guard); !os.IsNotExist(err) {
			t.Fatalf("guard did not remove its own file: %v", err)
		}
		data, _ := os.ReadFile(target)
		r, _ := os.ReadFile(restartLog)
		return string(data), string(r)
	}

	if got, restarted := run(t, "0.3.10-alpha.1", false); got != "new binary\n" || restarted != "" {
		t.Fatalf("healthy agent: target=%q restarts=%q", got, restarted)
	}
	if got, restarted := run(t, "0.3.9", false); got != "old binary\n" || restarted != "restart lattice-agent.service\n" {
		t.Fatalf("marker from another version: target=%q restarts=%q", got, restarted)
	}
	if got, restarted := run(t, "", false); got != "old binary\n" || restarted != "restart lattice-agent.service\n" {
		t.Fatalf("no marker: target=%q restarts=%q", got, restarted)
	}
	if got, restarted := run(t, "", true); got != "a later update\n" || restarted != "" {
		t.Fatalf("target changed since the update: target=%q restarts=%q", got, restarted)
	}
}
