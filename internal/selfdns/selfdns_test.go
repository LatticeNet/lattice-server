package selfdns

import (
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

func TestGenerateConfigForwardMesh(t *testing.T) {
	dep := baseDeployment()
	cfg, err := GenerateConfig(dep, RenderOptions{MeshBindIP: "10.66.0.7/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		".:53 {",
		"bind 10.66.0.7",
		"errors",
		"log",
		"loop",
		"cache 30",
		"forward . 1.1.1.1 9.9.9.9:53 tls://1.0.0.1",
	} {
		if !strings.Contains(cfg.Corefile, want) {
			t.Fatalf("corefile missing %q:\n%s", want, cfg.Corefile)
		}
	}
	if len(cfg.ZoneFiles) != 0 {
		t.Fatalf("forward-only deployment should not render zone files: %+v", cfg.ZoneFiles)
	}
}

func TestGenerateConfigStaticZoneFile(t *testing.T) {
	dep := baseDeployment()
	dep.RecordTTL = 120
	dep.Zones = []model.DNSZone{{
		Suffix: "mesh.local.",
		Mode:   model.DNSZoneStatic,
		Records: []model.DNSRecord{
			{Name: "gw.mesh.local.", Type: "A", Value: "10.66.0.1", TTL: 60},
			{Name: "v6.mesh.local.", Type: "AAAA", Value: "2001:db8::1"},
			{Name: "alias.mesh.local.", Type: "CNAME", Value: "gw.mesh.local."},
		},
	}}
	cfg, err := GenerateConfig(dep, RenderOptions{MeshBindIP: "10.66.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.Corefile, "file /etc/lattice/selfdns/zones/01_mesh_local.zone mesh.local.") {
		t.Fatalf("corefile missing file plugin:\n%s", cfg.Corefile)
	}
	if len(cfg.ZoneFiles) != 1 {
		t.Fatalf("expected one zone file, got %+v", cfg.ZoneFiles)
	}
	zone := cfg.ZoneFiles[0].Content
	for _, want := range []string{
		"$ORIGIN mesh.local.",
		"$TTL 120",
		"@ IN SOA ns.mesh.local. hostmaster.mesh.local. 1 3600 600 86400 120",
		"ns IN A 10.66.0.7",
		"gw.mesh.local. 60 IN A 10.66.0.1",
		"v6.mesh.local. 120 IN AAAA 2001:db8::1",
		"alias.mesh.local. 120 IN CNAME gw.mesh.local.",
	} {
		if !strings.Contains(zone, want) {
			t.Fatalf("zone file missing %q:\n%s", want, zone)
		}
	}
}

func TestGenerateConfigRejectsUnsafeInputs(t *testing.T) {
	cases := []model.DNSDeployment{
		func() model.DNSDeployment {
			dep := baseDeployment()
			dep.Zones[0].Suffix = "bad {\nzone"
			return dep
		}(),
		func() model.DNSDeployment {
			dep := baseDeployment()
			dep.Zones[0].Upstreams = []string{"1.1.1.1\nforward . evil"}
			return dep
		}(),
		func() model.DNSDeployment {
			dep := baseDeployment()
			dep.Zones = []model.DNSZone{{Suffix: ".", Mode: model.DNSZoneStatic, Records: []model.DNSRecord{{Name: "x.", Type: "A", Value: "10.0.0.1"}}}}
			return dep
		}(),
	}
	for i, dep := range cases {
		if _, err := GenerateConfig(dep, RenderOptions{MeshBindIP: "10.66.0.7"}); err == nil {
			t.Fatalf("case %d should fail", i)
		}
	}
}

func TestComposeFirewallPlan(t *testing.T) {
	dep := baseDeployment()
	plan, summary, err := ComposeFirewallPlan(dep, network.NFTPlan{WireGuardUDP: []int{51820}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ints(plan.WireGuardUDP), ",") != "53,51820" || strings.Join(ints(plan.WireGuardTCP), ",") != "53" {
		t.Fatalf("mesh ports not composed: %+v summary=%+v", plan, summary)
	}
	if strings.Join(summary, " | ") != "mesh UDP/53 via WireGuard CIDR | mesh TCP/53 via WireGuard CIDR" {
		t.Fatalf("bad summary: %+v", summary)
	}

	dep.Exposure = model.DNSExposurePublic
	plan, summary, err = ComposeFirewallPlan(dep, network.NFTPlan{PublicTCP: []int{443}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ints(plan.PublicUDP), ",") != "53" || strings.Join(ints(plan.PublicTCP), ",") != "53,443" {
		t.Fatalf("public ports not composed: %+v summary=%+v", plan, summary)
	}
}

func TestRenderApprovalPlanIsSecretFree(t *testing.T) {
	dep := baseDeployment()
	dep.Hostname = "n1.dns.example.com"
	dep.CFAPIToken = "super-secret-token"
	dep.RecordTTL = 60
	cfg, err := GenerateConfig(dep, RenderOptions{MeshBindIP: "10.66.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	plan, summary, err := ComposeFirewallPlan(dep, network.NFTPlan{})
	if err != nil {
		t.Fatal(err)
	}
	nft, err := network.GenerateNFTPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	out := RenderApprovalPlan(dep, "tokyo-1", cfg, nft, summary)
	for _, want := range []string{
		"# Lattice Self-host DNS plan",
		"deployment_id: dns1",
		"node_name: tokyo-1",
		"credential=true",
		"## CoreDNS Corefile",
		"## nftables lattice_guard candidate",
		"publish n1.dns.example.com",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("approval plan missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "super-secret-token") || strings.Contains(out, "cf_api_token") {
		t.Fatalf("approval plan leaked secret material:\n%s", out)
	}
}

func TestParseApprovalPlanAndApplyScript(t *testing.T) {
	dep := baseDeployment()
	dep.Zones = []model.DNSZone{{
		Suffix:  "mesh.local.",
		Mode:    model.DNSZoneStatic,
		Records: []model.DNSRecord{{Name: "gw.mesh.local.", Type: "A", Value: "10.66.0.1"}},
	}}
	cfg, err := GenerateConfig(dep, RenderOptions{MeshBindIP: "10.66.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	plan, summary, err := ComposeFirewallPlan(dep, network.NFTPlan{})
	if err != nil {
		t.Fatal(err)
	}
	nft, err := network.GenerateNFTPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	review := RenderApprovalPlan(dep, "tokyo-1", cfg, nft, summary)
	artifacts, err := ParseApprovalPlan(review)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(artifacts.Corefile, "file /etc/lattice/selfdns/zones/01_mesh_local.zone mesh.local.") {
		t.Fatalf("missing corefile artifact:\n%s", artifacts.Corefile)
	}
	if len(artifacts.ZoneFiles) != 1 || !strings.Contains(artifacts.ZoneFiles[0].Content, "gw.mesh.local.") {
		t.Fatalf("bad zone artifacts: %+v", artifacts.ZoneFiles)
	}
	if !strings.Contains(artifacts.NFTRuleset, "table inet lattice_guard") {
		t.Fatalf("missing nft artifact:\n%s", artifacts.NFTRuleset)
	}
	script, err := ApplyScriptFromPlan(review)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"command -v coredns",
		"command -v nft",
		"CONFIG_BACKUP=/etc/lattice/selfdns.rollback.$$",
		"WATCHDOG_FIRED=/tmp/lattice-selfdns-watchdog.$$",
		"setsid sh -c",
		"assert_watchdog_clean",
		"refusing to mark apply verified",
		"trap 'rollback; cleanup_watchdog' ERR INT TERM HUP",
		"nft -c -f \"$NFT_CANDIDATE\"",
		"{ echo 'flush ruleset'; nft list ruleset; } > \"$NFT_ROLLBACK\"",
		"nft -f \"$NFT_CANDIDATE\"",
		"lattice-selfdns.service",
		"systemctl is-active --quiet lattice-selfdns.service",
		"lattice selfdns: applied and verified",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("apply script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "nft list ruleset > \"$NFT_ROLLBACK\"") {
		t.Fatalf("selfdns rollback snapshot must flush before replay:\n%s", script)
	}
}

func TestPinnedCoreDNSBinaryIsPlanBoundAndInstalledByDigest(t *testing.T) {
	dep := baseDeployment()
	cfg, err := GenerateConfig(dep, RenderOptions{MeshBindIP: "10.66.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	plan, summary, err := ComposeFirewallPlan(dep, network.NFTPlan{})
	if err != nil {
		t.Fatal(err)
	}
	nft, err := network.GenerateNFTPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	binary := CoreDNSBinarySource{
		Version: "1.12.4",
		URL:     "https://downloads.example.com/coredns-1.12.4-linux-amd64",
		SHA256:  strings.Repeat("a", 64),
	}
	review, err := RenderApprovalPlanWithOptions(dep, "tokyo-1", cfg, nft, summary, ApprovalPlanOptions{CoreDNSBinary: binary})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"## CoreDNS binary",
		"version: 1.12.4",
		"url: https://downloads.example.com/coredns-1.12.4-linux-amd64",
		"sha256: " + strings.Repeat("a", 64),
		"install_path: /usr/local/bin/coredns",
	} {
		if !strings.Contains(review, want) {
			t.Fatalf("review plan missing %q:\n%s", want, review)
		}
	}
	artifacts, err := ParseApprovalPlan(review)
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.CoreDNSBinary == nil || artifacts.CoreDNSBinary.URL != binary.URL || artifacts.CoreDNSBinary.SHA256 != binary.SHA256 {
		t.Fatalf("binary metadata not parsed: %+v", artifacts.CoreDNSBinary)
	}
	script, err := ApplyScriptFromPlan(review)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"COREDNS_BIN='/usr/local/bin/coredns'",
		"COREDNS_URL='https://downloads.example.com/coredns-1.12.4-linux-amd64'",
		"COREDNS_SHA256='" + strings.Repeat("a", 64) + "'",
		"verify_coredns_sha256",
		"curl -fsSL --proto '=https' --tlsv1.2",
		"wget --https-only -qO \"$tmpbin\" \"$COREDNS_URL\"",
		"install -m 0755 \"$tmpbin\" \"$COREDNS_BIN\"",
		"\"$COREDNS_BIN\" -conf '/etc/lattice/selfdns/Corefile' -plugins",
		"ExecStart=/usr/local/bin/coredns -conf /etc/lattice/selfdns/Corefile",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("pinned install script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "command -v coredns >/dev/null ||") {
		t.Fatalf("pinned install script should not fail just because PATH lacks coredns:\n%s", script)
	}
}

func TestPinnedCoreDNSBinaryRejectsUnsafeMetadata(t *testing.T) {
	cases := []CoreDNSBinarySource{
		{Version: "1.12.4", URL: "http://downloads.example.com/coredns", SHA256: strings.Repeat("a", 64)},
		{Version: "1.12.4", URL: "https://user:pass@downloads.example.com/coredns", SHA256: strings.Repeat("a", 64)},
		{Version: "1.12.4\nbad", URL: "https://downloads.example.com/coredns", SHA256: strings.Repeat("a", 64)},
		{Version: "1.12.4", URL: "https://downloads.example.com/coredns", SHA256: "not-a-sha"},
		{Version: "1.12.4", URL: "", SHA256: strings.Repeat("a", 64)},
	}
	for i, src := range cases {
		if _, err := src.Normalize(); err == nil {
			t.Fatalf("case %d should reject unsafe binary metadata: %+v", i, src)
		}
	}
}

func TestParseApprovalPlanRejectsUnsafeCoreDNSBinarySection(t *testing.T) {
	review := `# Lattice Self-host DNS plan

## CoreDNS binary
` + "```lattice-coredns-binary\nversion: 1.12.4\nurl: http://downloads.example.com/coredns\nsha256: " + strings.Repeat("a", 64) + "\ninstall_path: /usr/local/bin/coredns\n```\n" + `
## CoreDNS Corefile
` + "```coredns\n.:53 {\n  forward . 1.1.1.1\n}\n```\n" + `
## nftables lattice_guard candidate
` + "```nft\ntable inet lattice_guard {\n}\n```\n"
	if _, err := ParseApprovalPlan(review); err == nil {
		t.Fatal("unsafe coredns binary section should be rejected")
	}
}

func TestParseApprovalPlanRejectsUnsafeZonePath(t *testing.T) {
	review := `# Lattice Self-host DNS plan

## CoreDNS Corefile
` + "```coredns\n.:53 {\n  forward . 1.1.1.1\n}\n```\n" + `
## Zone file: /etc/lattice/selfdns/../evil.zone
` + "```dns-zone\n$ORIGIN evil.\n```\n" + `
## nftables lattice_guard candidate
` + "```nft\ntable inet lattice_guard {\n}\n```\n"
	if _, err := ParseApprovalPlan(review); err == nil {
		t.Fatal("unsafe zone path should be rejected")
	}
}

func baseDeployment() model.DNSDeployment {
	return model.DNSDeployment{
		ID:         "dns1",
		Name:       "private dns",
		NodeID:     "n1",
		Engine:     model.DNSEngineCoreDNS,
		ListenPort: 53,
		EnableUDP:  true,
		EnableTCP:  true,
		Exposure:   model.DNSExposureMesh,
		Zones: []model.DNSZone{{
			Suffix:    ".",
			Mode:      model.DNSZoneForward,
			Upstreams: []string{"1.1.1.1", "9.9.9.9:53", "tls://1.0.0.1"},
		}},
	}
}

func ints(values []int) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strconv.Itoa(value))
	}
	return out
}
