package server

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-server/internal/sshguard"

	"github.com/LatticeNet/lattice-sdk/model"
)

// approvalDisplayReason returns the human-readable reason shown for an
// approval. Approvals created before reasons existed (and system writers that
// never set one) store an empty Reason. Rather than migrating stored rows, the
// reason is derived at read time from the same plan the reviewer is shown, so
// stored data stays untouched and every reader — old rows included — sees a
// consistent sentence. A non-empty stored Reason always wins.
func approvalDisplayReason(a model.Approval) string {
	if strings.TrimSpace(a.Reason) != "" {
		return a.Reason
	}
	switch {
	case a.Plugin == agentUpdatePlugin && approvalActionIs(a.Action, agentUpdateAction):
		return agentUpdateDisplayReason(a.Plan)
	case a.Plugin == "singbox-linemeta" && approvalActionIs(a.Action, "apply-metadata"):
		return lineMetaDisplayReason(a.Plan)
	case a.Plugin == sshGuardPlugin && a.Action == sshGuardArmAction:
		return sshGuardArmDisplayReason(a.Plan)
	case a.Plugin == sshGuardPlugin && a.Action == sshGuardConfirmAction:
		// The wording matters more here than anywhere else in this list. This
		// approval looks trivial and is the one that makes an SSH change
		// permanent, so the label has to say what approving it asserts.
		return "Confirm SSH Guard: you have opened a NEW connection and gotten a shell"
	case a.Plugin == "nft" && a.Action == netGuardApprovalAction:
		return "Apply NetGuard nftables ruleset"
	case a.Plugin == "nft" && a.Action == "apply-ruleset":
		return "Apply nftables ruleset"
	case a.Plugin == "nftpolicy" && approvalActionIs(a.Action, nftPolicyApplyAction):
		return "Apply network policy ruleset"
	case a.Plugin == "selfdns" && approvalActionIs(a.Action, selfDNSApplyAction):
		return selfDNSDisplayReason(a.Plan)
	case a.Plugin == proxyCorePlugin && approvalActionIs(a.Action, proxyCoreApplyAction):
		return proxyCoreDisplayReason(a.Plan)
	case a.Plugin == "cftunnel" && a.Action == "apply-config":
		return "Apply Cloudflare Tunnel config"
	case a.Plugin == "wireguard" && a.Action == "apply-config":
		return "Apply WireGuard mesh config"
	default:
		return approvalFallbackReason(a)
	}
}

// approvalActionIs matches an approval action against a bare action name or
// its parameterized "<name>:<payload>" form (e.g. "apply-metadata:<sha256>").
func approvalActionIs(action, name string) bool {
	return action == name || strings.HasPrefix(action, name+":")
}

// agentUpdateDisplayReason summarizes the YAML-ish agent update plan header
// (current_version:/target_version:/node_name: lines written by
// renderAgentUpdatePlan).
func agentUpdateDisplayReason(plan string) string {
	current := approvalPlanField(plan, "current_version")
	target := approvalPlanField(plan, "target_version")
	if current == "" || target == "" {
		return "Node agent upgrade"
	}
	if name := approvalPlanField(plan, "node_name"); name != "" {
		return fmt.Sprintf("Node agent upgrade %s -> %s (%s)", current, target, name)
	}
	return fmt.Sprintf("Node agent upgrade %s -> %s", current, target)
}

// lineMetaDisplayReason summarizes a singbox-linemeta plan (JSON, schema
// lattice.singbox-metadata.v2) by counting the inbounds it carries.
func lineMetaDisplayReason(plan string) string {
	var parsed struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(plan), &parsed); err != nil {
		// The reviewer still sees the raw plan; a malformed one just gets the
		// generic sentence instead of an inbound count.
		return "Line identity metadata sync"
	}
	return fmt.Sprintf("Line identity metadata sync (%d inbounds)", len(parsed.Inbounds))
}

// selfDNSDisplayReason names the DNS deployment from the plan header when it
// is present.
func selfDNSDisplayReason(plan string) string {
	if name := approvalPlanField(plan, "name"); name != "" {
		return fmt.Sprintf("Apply self-hosted DNS %q", name)
	}
	return "Apply self-hosted DNS plan"
}

// proxyCoreDisplayReason summarizes the rendered proxycore plan header
// (core:/inbound_count: lines written by renderProxyCoreApprovalPlan).
func proxyCoreDisplayReason(plan string) string {
	core := approvalPlanField(plan, "core")
	if core == "" {
		return "Apply proxy core config"
	}
	if n, err := strconv.Atoi(approvalPlanField(plan, "inbound_count")); err == nil {
		return fmt.Sprintf("Apply %s proxy config (%d inbounds)", core, n)
	}
	return fmt.Sprintf("Apply %s proxy config", core)
}

// approvalPlanField reads "key: value" lines from a human-reviewable plan
// header. Plans are display text, not a schema, so parsing is deliberately
// best-effort: the first matching line wins and anything unexpected yields "".
func approvalPlanField(plan, key string) string {
	for _, line := range strings.Split(plan, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || k != key {
			continue
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// approvalFallbackReason title-cases "<plugin> <action-name>" for plugins that
// have no dedicated sentence yet, so the API still answers something readable
// instead of an empty string.
func approvalFallbackReason(a model.Approval) string {
	action := a.Action
	if i := strings.Index(action, ":"); i >= 0 {
		action = action[:i]
	}
	text := strings.TrimSpace(strings.TrimSpace(a.Plugin) + " " + strings.TrimSpace(action))
	if text == "" {
		return ""
	}
	words := strings.Fields(text)
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

// sshGuardArmDisplayReason summarizes an arm plan in one line for the approvals
// list. It reads the plan text rather than a stored profile so the summary and
// the reviewed document cannot disagree.
func sshGuardArmDisplayReason(plan string) string {
	art, err := sshguard.ParseApprovalPlan(plan)
	if err != nil {
		return "Apply SSH Guard hardening"
	}
	knock := "no knock"
	if art.KnockdConf != "" {
		knock = "port knocking"
	}
	if art.SSHPort == 0 {
		return fmt.Sprintf("Harden sshd and gate %s (%s, auto-revert in %ds)",
			joinPortList(art.GatedPorts), knock, art.ConfirmWindowSec)
	}
	return fmt.Sprintf("Move sshd to tcp/%d and gate %s (%s, auto-revert in %ds)",
		art.SSHPort, joinPortList(art.GatedPorts), knock, art.ConfirmWindowSec)
}

func joinPortList(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("tcp/%d", port))
	}
	return strings.Join(parts, " and ")
}
