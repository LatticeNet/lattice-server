package server

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Four bugs in one day had the same shape: a plugin was added, the tables that
// dispatch on plugin identity were not all updated, and the missing entry fell
// through to a default that was wrong for it.
//
//   - approvalDecisionExtraScope had no netguard entry, so authoring a firewall
//     change required netguard:admin and dispatching it required only
//     network:apply.
//   - approvalPrimaryScopeAllows had no sshguard entry, so bare network:plan
//     could read a plan carrying the node's knock sequence in plaintext.
//   - approvalApplyTaskTimeoutSec had no sshguard entry, so an apply that may
//     run apt-get got the 30 second default.
//   - duplicate detection had no name signal, which is the same failure in a
//     different table.
//
// None of them were caught by review, because a missing switch case looks like
// nothing. This test makes the tables enumerate themselves: every plugin that
// can produce an approval must have a decided answer in each table, and an
// answer of "the default is correct here" has to be written down as such.
//
// Adding a plugin without deciding these questions fails this test. That is the
// point of it.
var approvalPlugins = []string{
	"nft", "nftpolicy", "wireguard", "cftunnel", "selfdns",
	agentUpdatePlugin, proxyCorePlugin,
	singBoxLineUserPlugin, singBoxLineMetaPlugin, singBoxManagedLinePlugin,
	lineChainPlugin, sshGuardPlugin,
}

func TestEveryApprovalPluginHasADecidedDecisionScope(t *testing.T) {
	// Plugins whose decisions are deliberately gated on network:apply alone.
	// An entry here is a decision, not an omission: it says the plugin has no
	// domain of its own beyond the apply itself.
	intentionallyBare := map[string]string{
		"wireguard":              "mesh config carries no authority the apply scope does not already imply",
		singBoxManagedLinePlugin: "managed lines are gated at authoring; the decision adds nothing",
		lineChainPlugin:          "linechain decisions are gated by the durable-protocol capability check",
	}
	for _, plugin := range approvalPlugins {
		t.Run(plugin, func(t *testing.T) {
			action := ""
			if plugin == "nft" {
				// The one plugin whose two actions have different answers.
				action = netGuardApprovalAction
			}
			got := approvalDecisionExtraScope(model.Approval{Plugin: plugin, Action: action})
			if got == "" {
				if _, ok := intentionallyBare[plugin]; !ok {
					t.Fatalf("%s has no decision scope. Either give it one, or record here why network:apply alone is the right gate for it.", plugin)
				}
			}
		})
	}
}

func TestEveryApprovalPluginHasADecidedApplyTimeout(t *testing.T) {
	// Plugins for which the 30 second default is genuinely right: the apply is
	// a local write and a reload, with no download and no package manager.
	intentionallyDefault := map[string]string{
		"cftunnel":               "writes a config and reloads cloudflared",
		"wireguard":              "writes a config and brings an interface up",
		proxyCorePlugin:          "has its own runtime path and does not use this table",
		singBoxLineUserPlugin:    "edits a user roster in place",
		singBoxLineMetaPlugin:    "writes a metadata sidecar",
		singBoxManagedLinePlugin: "writes a config fragment",
		lineChainPlugin:          "atomic file publish with its own journal",
	}
	for _, plugin := range approvalPlugins {
		t.Run(plugin, func(t *testing.T) {
			got := approvalApplyTaskTimeoutSec(plugin)
			if got == defaultTaskTimeoutSec {
				if _, ok := intentionallyDefault[plugin]; !ok {
					t.Fatalf("%s gets the %ds default. Either give it a timeout that covers what its apply actually does, or record here why the default is right.",
						plugin, defaultTaskTimeoutSec)
				}
			}
			// The agent treats anything over ten minutes as out of range and
			// falls back to 30 seconds rather than clamping, so a generous
			// value here can silently become the least generous one available.
			if got > 600 {
				t.Fatalf("%s asks for %ds; over 600 the agent falls back to 30s, so this asks for less than it looks", plugin, got)
			}
		})
	}
}

// A plan that reaches a host is a plan that must be bound to what was reviewed.
func TestEveryApprovalPluginCarryingAPlanRequiresItsHash(t *testing.T) {
	for _, plugin := range approvalPlugins {
		t.Run(plugin, func(t *testing.T) {
			if !approvalRequiresPlanHash(model.Approval{Plugin: plugin, Plan: "something"}) {
				t.Fatalf("%s can carry a plan that is not bound to the reviewed text", plugin)
			}
		})
	}
}

// A plugin whose decisions are gated on its own domain must stay gated for an
// action nobody has classified yet. The alternative is that adding an action
// and forgetting to register it silently downgrades the gate, which is the
// failure this whole file exists to prevent.
func TestAnUnclassifiedSSHGuardActionStillRequiresTheDomain(t *testing.T) {
	for _, action := range []string{"", "sshguard-something-new:v1", "arbitrary"} {
		if got := approvalDecisionExtraScope(model.Approval{Plugin: sshGuardPlugin, Action: action}); got != "sshguard:admin" {
			t.Fatalf("action %q decided with %q; an unrecognised action must not be cheaper to decide", action, got)
		}
	}
	// netguard is the deliberate exception: plugin "nft" carries a legacy
	// action whose authoring gate really is only network:plan, so widening it
	// to the whole plugin would add a gate that path never had.
	if got := approvalDecisionExtraScope(model.Approval{Plugin: "nft", Action: "apply-ruleset"}); got != "" {
		t.Fatalf("the legacy nft path must keep its own gate, got %q", got)
	}
}
