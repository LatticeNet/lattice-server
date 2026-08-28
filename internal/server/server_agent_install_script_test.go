package server

import (
	"os/exec"
	"strings"
	"testing"
)

const testSums = `aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111  lattice-agent-linux-amd64
bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222  lattice-agent-darwin-arm64
`

func TestRenderAgentInstallScript(t *testing.T) {
	out, err := renderAgentInstallScript("LatticeNet/lattice-node-agent", "0.3.8", "v0.3.8", testSums)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"VERSION='0.3.8'",
		"https://github.com/LatticeNet/lattice-node-agent/releases/download/v0.3.8",
		"linux/amd64 lattice-agent-linux-amd64 aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
		"darwin/arm64 lattice-agent-darwin-arm64 bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered script missing %q:\n%s", want, out)
		}
	}
	// A platform the release does not publish must not appear at all: a row
	// without a checksum would be a row nobody can verify.
	if strings.Contains(out, "linux/arm64") || strings.Contains(out, "darwin/amd64") {
		t.Fatalf("unpublished platform leaked into the table:\n%s", out)
	}
	// It updates, it does not enrol, and it never stops the service on its own.
	if !strings.Contains(out, "This script updates an enrolled node") {
		t.Fatalf("missing the enrolment refusal")
	}
	if strings.Contains(out, "systemctl stop") {
		t.Fatalf("must never stop the unit separately from restarting it")
	}
}

// The script is what runs on the boxes; a syntax error there is not caught by
// anything else in this repo.
func TestAgentInstallScriptIsValidPOSIXShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	out, err := renderAgentInstallScript("LatticeNet/lattice-node-agent", "0.3.8", "v0.3.8", testSums)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(out)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n rejected the script: %v\n%s", err, combined)
	}
}

func TestRenderAgentInstallScriptRefusesAReleaseWithNoChecksums(t *testing.T) {
	if _, err := renderAgentInstallScript("r", "0.3.8", "v0.3.8", "unrelated content\n"); err == nil {
		t.Fatalf("a release with no usable checksum must be an error, not an unverified script")
	}
}
