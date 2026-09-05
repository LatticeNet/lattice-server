package server

import (
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The task runner hands scripts PATH=/usr/bin:/bin:/usr/local/bin. On a node
// whose sbin is not merged into /usr/bin, a bare `nft` is exit 127, which on
// legend-sg (nftables 1.0.6) stopped the netguard canary at its first line.
func TestNFTApplyScriptsPutSbinOnPathBeforeTheFirstNFT(t *testing.T) {
	const pathLine = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
	cases := map[string]string{
		"netguard apply":   applyScriptForWithServer(model.Approval{Plugin: "nft", Action: netGuardApprovalAction, Plan: "table inet lattice_guard {}\n"}, "https://lattice.example"),
		"legacy nft apply": applyScriptForWithServer(model.Approval{Plugin: "nft", Action: nftPolicyApplyAction, Plan: "table inet lattice_guard {}\n"}, ""),
		"nftpolicy apply":  nftPolicyApplyScript("table inet lattice_policy {}\n", "", nil),
		"plan check":       applyScriptForWithServer(model.Approval{Plugin: "unknown-plugin", Plan: "table inet x {}\n"}, ""),
	}
	for name, script := range cases {
		at := strings.Index(script, pathLine)
		if at < 0 {
			t.Fatalf("%s: script never widens PATH:\n%s", name, script)
		}
		first := strings.Index(script, "nft ")
		if first < 0 {
			t.Fatalf("%s: script never runs nft:\n%s", name, script)
		}
		if first < at {
			t.Fatalf("%s: nft runs at %d before PATH is set at %d:\n%s", name, first, at, script)
		}
	}
}
