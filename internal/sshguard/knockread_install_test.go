package sshguard

import (
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/knocktool"
)

// The console leads with this control plane when the server knows its URL,
// for networks that cannot reach GitHub, and pins the GitHub route to the
// checksum the server carries.
func TestKnockCommandsOfferTheControlPlaneFirst(t *testing.T) {
	seq := KnockSequence{Ports: []int{20001, 20002, 20003}}
	install := seq.KnockCommands("198.51.100.4", 22, "https://lattice.example.com/")[0].Install
	if len(install) < 2 || install[0].Platform != "This control plane" ||
		install[0].Command != "curl -fsSL https://lattice.example.com/tools/knock/install.sh | sh" {
		t.Fatalf("the first install line must be this control plane: %+v", install)
	}
	if install[1].Platform != "GitHub" || install[1].Command != knocktool.GitHubInstallCommand() ||
		!strings.Contains(install[1].Command, "--sha256 "+knocktool.KnockSHA256()) {
		t.Fatalf("the second install line must be GitHub, pinned to the carried checksum: %+v", install[1])
	}
	for _, bad := range []string{"", "http://lattice.example.com", "https://lattice.example.com/$(id)"} {
		for _, in := range seq.KnockCommands("198.51.100.4", 22, bad)[0].Install {
			if in.Platform == "This control plane" {
				t.Fatalf("control plane %q must not produce an install line: %+v", bad, in)
			}
		}
	}
}

// The plan offers the same sources as the console: with the URL the server
// set on the profile it leads with this control plane, and without one it
// starts at GitHub.
func TestArmPlanOffersTheControlPlaneTheServerSet(t *testing.T) {
	p := Profile{
		NodeID: "node-a", SSHPort: 58394, KeepLegacyPort: true,
		Hardening: DefaultHardening(), MgmtSources: []string{"203.0.113.5"},
		ConfirmWindowSec: 900,
		Knock:            &KnockPolicy{Ports: []int{20001, 20002, 20003}, SeqTimeoutSec: 15, OpenFor: "12h"},
	}
	bare, err := RenderArmPlan(p, "Node A")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bare, "This control plane") || !strings.Contains(bare, "- GitHub: `"+knocktool.GitHubInstallCommand()+"`") {
		t.Fatalf("a plan without a URL must start its install list at GitHub:\n%s", bare)
	}

	p.ControlPlane = "https://lattice.example.com"
	plan, err := RenderArmPlan(p, "Node A")
	if err != nil {
		t.Fatal(err)
	}
	lead := "- This control plane: `curl -fsSL https://lattice.example.com/tools/knock/install.sh | sh`\n- GitHub: `"
	if !strings.Contains(plan, lead) {
		t.Fatalf("the plan must lead its install list with this control plane, then GitHub:\n%s", plan)
	}

	p.ControlPlane = "https://lattice.example.com/$(id)"
	unsafe, err := RenderArmPlan(p, "Node A")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unsafe, "This control plane") || strings.Contains(unsafe, "$(id)") {
		t.Fatalf("a URL a shell would interpret must not reach the plan:\n%s", unsafe)
	}
}
