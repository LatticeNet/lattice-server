package server

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestApprovalDisplayReason(t *testing.T) {
	agentPlan := "plugin: agentupdate\n" +
		"mode: auto\n" +
		"node_id: node-1\n" +
		"node_name: edge-1\n" +
		"current_version: 0.3.0\n" +
		"target_version: 0.3.3\n" +
		"binary_url: https://example.com/lattice-agent\n" +
		"sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n" +
		"install_path: /opt/lattice/node-agent/lattice-agent\n" +
		"service_name: lattice-agent.service\n" +
		"\nSafety:\n" +
		"- download is HTTPS-only and verified against the pinned SHA-256 digest\n"

	lineMetaPlan := `{"schema":"lattice.singbox-metadata.v2","node_id":"node-1","inbounds":[{"tag":"a"},{"tag":"b"},{"tag":"c"}]}`

	proxyPlan := "# Lattice proxycore review plan\n\n" +
		"node_id: node-1\n" +
		"profile_id: prof-1\n" +
		"core: sing-box\n" +
		"config_path: /etc/sing-box/config.json\n" +
		"artifact_sha256: abc123\n" +
		"inbound_count: 4\n"

	dnsPlan := "# Lattice Self-host DNS plan\n\n" +
		"deployment_id: dep-1\n" +
		"name: Internal DNS\n" +
		"node_id: node-1\n" +
		"engine: coredns\n" +
		"exposure: lan\n"

	tests := []struct {
		name     string
		approval model.Approval
		want     string
	}{
		{
			name:     "stored reason always wins",
			approval: model.Approval{Plugin: "nft", Action: "apply-ruleset", Plan: "x", Reason: "rejected: task failed"},
			want:     "rejected: task failed",
		},
		{
			name:     "agent update with versions and node name",
			approval: model.Approval{Plugin: "agentupdate", Action: "update-agent:eyJub2RlX2lkIjoibm9kZS0xIn0", Plan: agentPlan},
			want:     "Node agent upgrade 0.3.0 -> 0.3.3 (edge-1)",
		},
		{
			name: "agent update without node name",
			approval: model.Approval{Plugin: "agentupdate", Action: "update-agent:abc", Plan: "plugin: agentupdate\n" +
				"node_id: node-1\n" +
				"current_version: 0.3.0\n" +
				"target_version: 0.3.3\n"},
			want: "Node agent upgrade 0.3.0 -> 0.3.3",
		},
		{
			name:     "agent update with unparseable plan falls back to the generic sentence",
			approval: model.Approval{Plugin: "agentupdate", Action: "update-agent:abc", Plan: "not a plan"},
			want:     "Node agent upgrade",
		},
		{
			name:     "linemeta counts inbounds",
			approval: model.Approval{Plugin: "singbox-linemeta", Action: "apply-metadata:0123456789abcdef", Plan: lineMetaPlan},
			want:     "Line identity metadata sync (3 inbounds)",
		},
		{
			name:     "linemeta with malformed JSON must not error, falls back",
			approval: model.Approval{Plugin: "singbox-linemeta", Action: "apply-metadata:abc", Plan: "{not json"},
			want:     "Line identity metadata sync",
		},
		{
			name:     "linemeta with empty inbounds",
			approval: model.Approval{Plugin: "singbox-linemeta", Action: "apply-metadata:abc", Plan: `{"schema":"lattice.singbox-metadata.v2"}`},
			want:     "Line identity metadata sync (0 inbounds)",
		},
		{
			name:     "nft ruleset",
			approval: model.Approval{Plugin: "nft", Action: "apply-ruleset", Plan: "table inet lattice_guard {}"},
			want:     "Apply nftables ruleset",
		},
		{
			name:     "nft ruleset from netguard shares the sentence",
			approval: model.Approval{Plugin: "nft", Action: "apply-ruleset", Plan: "table inet lattice_guard {}", ActorID: "user-1"},
			want:     "Apply nftables ruleset",
		},
		{
			name:     "nftpolicy bare action",
			approval: model.Approval{Plugin: "nftpolicy", Action: "apply-ruleset", Plan: "ruleset"},
			want:     "Apply network policy ruleset",
		},
		{
			name:     "nftpolicy parameterized action",
			approval: model.Approval{Plugin: "nftpolicy", Action: "apply-ruleset:eyJwdWJsaWNfdXJsIjoieCJ9", Plan: "ruleset"},
			want:     "Apply network policy ruleset",
		},
		{
			name:     "selfdns names the deployment",
			approval: model.Approval{Plugin: "selfdns", Action: "apply-config:ZGVwLTE", Plan: dnsPlan},
			want:     `Apply self-hosted DNS "Internal DNS"`,
		},
		{
			name:     "selfdns without a name line",
			approval: model.Approval{Plugin: "selfdns", Action: "apply-config:ZGVwLTE", Plan: "# Lattice Self-host DNS plan\n"},
			want:     "Apply self-hosted DNS plan",
		},
		{
			name:     "proxycore with core and inbound count",
			approval: model.Approval{Plugin: "proxycore", Action: "apply-config:abc123", Plan: proxyPlan},
			want:     "Apply sing-box proxy config (4 inbounds)",
		},
		{
			name:     "proxycore without parseable header",
			approval: model.Approval{Plugin: "proxycore", Action: "apply-config:abc123", Plan: "??"},
			want:     "Apply proxy core config",
		},
		{
			name:     "cftunnel",
			approval: model.Approval{Plugin: "cftunnel", Action: "apply-config", Plan: "tunnel: x"},
			want:     "Apply Cloudflare Tunnel config",
		},
		{
			name:     "wireguard",
			approval: model.Approval{Plugin: "wireguard", Action: "apply-config", Plan: "[Interface]"},
			want:     "Apply WireGuard mesh config",
		},
		{
			name:     "unknown plugin falls back to title-cased plugin and action name",
			approval: model.Approval{Plugin: "acme-dns", Action: "publish-zone:abc", Plan: "x"},
			want:     "Acme-dns Publish-zone",
		},
		{
			name:     "empty writer empty plan still falls back",
			approval: model.Approval{Plugin: "nft", Action: "apply-ruleset"},
			want:     "Apply nftables ruleset",
		},
		{
			name:     "whitespace-only stored reason is treated as empty",
			approval: model.Approval{Plugin: "nft", Action: "apply-ruleset", Reason: "   "},
			want:     "Apply nftables ruleset",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := approvalDisplayReason(tt.approval); got != tt.want {
				t.Fatalf("approvalDisplayReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestToApprovalViewPopulatesReason pins the read-path contract: the API
// reason field is populated for legacy rows whose stored Reason is empty,
// while stored rows themselves are never rewritten.
func TestToApprovalViewPopulatesReason(t *testing.T) {
	a := model.Approval{
		ID:     "ap-1",
		Plugin: "nft",
		Action: "apply-ruleset",
		Plan:   "table inet lattice_guard {}",
		Status: model.ApprovalPending,
	}
	views := toApprovalViews([]model.Approval{a})
	if len(views) != 1 {
		t.Fatalf("expected one view, got %d", len(views))
	}
	if views[0].Reason != "Apply nftables ruleset" {
		t.Fatalf("view reason = %q", views[0].Reason)
	}
	if a.Reason != "" {
		t.Fatalf("derivation must not mutate the stored approval, reason = %q", a.Reason)
	}
}
