package selfdns

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

// publicForwardWithClients is a public forwarding deployment that names its
// clients, the shape design 32 S5b makes possible, with a static zone beside
// the forward one so the ACL has two server blocks to cover.
func publicForwardWithClients() model.DNSDeployment {
	dep := baseDeployment()
	dep.Exposure = model.DNSExposurePublic
	dep.AllowedClients = []string{"203.0.113.0/24", "2001:db8::/32"}
	dep.Zones = append(dep.Zones, model.DNSZone{
		Suffix:  "mesh.local.",
		Mode:    model.DNSZoneStatic,
		Records: []model.DNSRecord{{Name: "gw.mesh.local.", Type: "A", Value: "10.66.0.1"}},
	})
	return dep
}

// serverBlocks splits a rendered Corefile into its server blocks.
func serverBlocks(corefile string) []string {
	var blocks []string
	for _, block := range strings.Split(corefile, "\n}\n") {
		if strings.TrimSpace(block) != "" {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

// The ACL goes in every server block, one allow per network and then a bare
// block, because the plugin's default action is allow: without the block a
// query no rule matches would recurse. It is written before the zone's own
// plugin, so the block reads in the order CoreDNS applies it.
func TestAllowedClientsRenderACLBeforeTheZones(t *testing.T) {
	cfg, err := GenerateConfig(publicForwardWithClients(), RenderOptions{})
	if err != nil {
		t.Fatalf("a public forward deployment that names its clients renders: %v", err)
	}
	acl := "  acl {\n    allow net 203.0.113.0/24\n    allow net 2001:db8::/32\n    block\n  }\n"
	blocks := serverBlocks(cfg.Corefile)
	if len(blocks) != 2 {
		t.Fatalf("want two server blocks, got %d:\n%s", len(blocks), cfg.Corefile)
	}
	for i, block := range blocks {
		at := strings.Index(block, acl)
		if at < 0 {
			t.Fatalf("server block %d has no acl ending in block:\n%s", i+1, block)
		}
		zone := strings.Index(block, "  forward . ")
		if zone < 0 {
			zone = strings.Index(block, "  file ")
		}
		if zone < 0 || at > zone {
			t.Fatalf("server block %d renders its acl after the zone:\n%s", i+1, block)
		}
	}

	// A deployment that names no clients renders no acl at all.
	plain, err := GenerateConfig(baseDeployment(), RenderOptions{MeshBindIP: "10.66.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.Corefile, "acl") {
		t.Fatalf("no allowed clients, no acl:\n%s", plain.Corefile)
	}
}

// The S0 refusal of a public forward deployment stands when it names no
// clients and is lifted when it names some.
func TestAllowedClientsLiftTheOpenResolverRefusal(t *testing.T) {
	dep := publicForwardWithClients()
	if IsOpenResolver(dep) {
		t.Fatal("a public forward deployment that names its clients is not an open resolver")
	}
	if err := RefuseOpenResolver(dep); err != nil {
		t.Fatalf("not refused: %v", err)
	}
	dep.AllowedClients = nil
	if !IsOpenResolver(dep) {
		t.Fatal("without allowed clients it is still an open resolver")
	}
	if _, err := GenerateConfig(dep, RenderOptions{}); !errors.Is(err, ErrOpenResolver) {
		t.Fatalf("without allowed clients the render is refused, got %v", err)
	}
	if !strings.Contains(ErrOpenResolver.Error(), "allowed_clients") {
		t.Fatalf("the refusal names the way out: %v", ErrOpenResolver)
	}
}

func TestNormalizeAllowedClients(t *testing.T) {
	got, err := NormalizeAllowedClients([]string{" 203.0.113.0/24 ", "2001:DB8::/32", "203.0.113.0/24", "198.51.100.7/32"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"203.0.113.0/24", "2001:db8::/32", "198.51.100.7/32"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("canonical, deduplicated, in the order given: got %v want %v", got, want)
	}
	if got, err := NormalizeAllowedClients(nil); err != nil || got != nil {
		t.Fatalf("no list is no list: %v %v", got, err)
	}

	for _, tc := range []struct {
		input []string
		index int
		says  string
	}{
		{[]string{"10.0.0.0/8", "0.0.0.0/0"}, 1, "reopens the resolver"},
		{[]string{"::/0"}, 0, "reopens the resolver"},
		{[]string{"10.0.0.1/8"}, 0, "host bits"},
		{[]string{"2001:db8::1/32"}, 0, "host bits"},
		{[]string{"10.0.0.1"}, 0, "CIDR"},
		{[]string{"lan"}, 0, "CIDR"},
		{[]string{""}, 0, "empty"},
		{[]string{"::ffff:10.0.0.0/104"}, 0, "IPv4"},
		// The renderer writes each entry onto a Corefile line, so nothing
		// that is not a parsed network may reach it.
		{[]string{"10.0.0.0/8\n  forward . 8.8.8.8"}, 0, "CIDR"},
		// Two halves rebuild what /0 covers, overlapping or not.
		{[]string{"0.0.0.0/1", "128.0.0.0/1"}, -1, "every IPv4 address"},
		{[]string{"128.0.0.0/2", "0.0.0.0/1", "64.0.0.0/2", "192.0.0.0/2", "10.0.0.0/8"}, -1, "every IPv4 address"},
		{[]string{"::/1", "8000::/1"}, -1, "every IPv6 address"},
	} {
		_, err := NormalizeAllowedClients(tc.input)
		var refusal *AllowedClientsError
		if !errors.As(err, &refusal) {
			t.Fatalf("%q: want an AllowedClientsError, got %v", tc.input, err)
		}
		if refusal.Index != tc.index || !strings.Contains(err.Error(), tc.says) {
			t.Fatalf("%q: want entry %d refused with %q, got entry %d: %v", tc.input, tc.index, tc.says, refusal.Index, err)
		}
	}

	many := make([]string, 0, model.DNSAllowedClientsMax+1)
	for i := range model.DNSAllowedClientsMax + 1 {
		many = append(many, fmt.Sprintf("10.%d.0.0/16", i))
	}
	// Most of a family is not all of it.
	if _, err := NormalizeAllowedClients([]string{"0.0.0.0/1", "192.0.0.0/2", "::/1"}); err != nil {
		t.Fatalf("a list that leaves addresses out is allowed: %v", err)
	}
	if _, err := NormalizeAllowedClients(many[:model.DNSAllowedClientsMax]); err != nil {
		t.Fatalf("%d networks are allowed: %v", model.DNSAllowedClientsMax, err)
	}
	_, err = NormalizeAllowedClients(many)
	var refusal *AllowedClientsError
	if !errors.As(err, &refusal) || refusal.Index != -1 || !strings.Contains(err.Error(), "at most 64") {
		t.Fatalf("a list over the cap is refused as a whole: %v", err)
	}

	// The renderer does not trust its input either.
	dep := publicForwardWithClients()
	dep.AllowedClients = []string{"10.0.0.0/8 } forward . 8.8.8.8 {"}
	if _, err := GenerateConfig(dep, RenderOptions{}); err == nil {
		t.Fatal("an unparsed network must not reach the Corefile")
	}
}

// The plan says what the ACL does and what it does not: it decides who gets
// answers, not who reaches the port.
func TestAllowedClientsPlanSaysTheACLLimitsAnswersNotReachability(t *testing.T) {
	dep := publicForwardWithClients()
	cfg, err := GenerateConfig(dep, RenderOptions{})
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
	for _, want := range []string{
		"## Allowed clients\n- 203.0.113.0/24\n- 2001:db8::/32\n",
		"refuses every other client",
		"not who can reach the port",
	} {
		if !strings.Contains(review, want) {
			t.Fatalf("plan missing %q:\n%s", want, review)
		}
	}
	// The section sits between the header and the artifacts and changes
	// neither.
	header, err := ParsePlanHeader(review)
	if err != nil || header.Exposure != model.DNSExposurePublic {
		t.Fatalf("header: %+v %v", header, err)
	}
	if _, err := ParseApprovalPlan(review); err != nil {
		t.Fatal(err)
	}

	plain := baseDeployment()
	plainCfg, err := GenerateConfig(plain, RenderOptions{MeshBindIP: "10.66.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(RenderApprovalPlan(plain, "tokyo-1", plainCfg, nft, summary), "## Allowed clients") {
		t.Fatal("a deployment that names no clients has no allowed clients section")
	}
}

// The approval gate judges the plan, not the record: a public forwarding plan
// whose every forwarding block carries the ACL is not an open resolver, and
// one with a forwarding block left unguarded is.
func TestPlanIsOpenResolverReadsTheACL(t *testing.T) {
	dep := publicForwardWithClients()
	cfg, err := GenerateConfig(dep, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := RenderApprovalPlanWithOptions(dep, "tokyo-1", cfg, "", nil, ApprovalPlanOptions{NetGuardOwnsFirewall: true})
	if err != nil {
		t.Fatal(err)
	}
	if open, err := PlanIsOpenResolver(plan); err != nil || open {
		t.Fatalf("a public forwarding plan with the acl is not an open resolver: %v %v", open, err)
	}
	// The forwarding block loses its final block: a query no rule matches
	// would recurse again.
	unblocked := strings.Replace(plan, ".:53 {\n  acl {\n    allow net 203.0.113.0/24\n    allow net 2001:db8::/32\n    block\n", ".:53 {\n  acl {\n    allow net 203.0.113.0/24\n    allow net 2001:db8::/32\n", 1)
	if unblocked == plan {
		t.Fatalf("test edit did not apply:\n%s", plan)
	}
	if open, err := PlanIsOpenResolver(unblocked); err != nil || !open {
		t.Fatalf("an acl without a final block guards nothing: %v %v", open, err)
	}
	// The forwarding block loses its acl altogether; the static block
	// keeping one does not help.
	bare := strings.Replace(plan, ".:53 {\n  acl {\n    allow net 203.0.113.0/24\n    allow net 2001:db8::/32\n    block\n  }\n", ".:53 {\n", 1)
	if bare == plan {
		t.Fatalf("test edit did not apply:\n%s", plan)
	}
	if open, err := PlanIsOpenResolver(bare); err != nil || !open {
		t.Fatalf("a forwarding block without an acl is an open resolver: %v %v", open, err)
	}

	// A shape the renderer never writes is judged open, not guessed at:
	// CRLF line ends must not carry a guarded block's verdict into the next,
	// and a block that never closes is not a guarded one.
	guarded := "a.example:53 {\n  acl {\n    allow net 203.0.113.0/24\n    block\n  }\n  file /z a.example.\n}\n"
	unguarded := ".:53 {\n  forward . 1.1.1.1\n}\n"
	if !corefileRecursesForAnyone(strings.ReplaceAll(guarded+unguarded, "\n", "\r\n")) {
		t.Fatal("CRLF line ends hid an unguarded forwarding block")
	}
	if !corefileRecursesForAnyone(".:53 {\n  acl {\n    allow net 203.0.113.0/24\n    block\n  }\n  forward . 1.1.1.1\n.:54 {\n  forward . 1.1.1.1\n}\n") {
		t.Fatal("a block opened inside another is not judged guarded")
	}
	if corefileRecursesForAnyone(guarded) {
		t.Fatal("a guarded static block is not open")
	}
}

// Whatever binary the node runs, the apply refuses before it writes anything
// when the Corefile uses acl and the binary does not list the plugin; a
// Corefile without acl does not ask.
func TestApplyScriptChecksTheBinaryHasACL(t *testing.T) {
	check := `"$COREDNS_BIN" -plugins | grep -Eq '^[[:space:]]*(dns\.)?acl$'`
	dep := publicForwardWithClients()
	cfg, err := GenerateConfig(dep, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := RenderApprovalPlanWithOptions(dep, "tokyo-1", cfg, "", nil, ApprovalPlanOptions{NetGuardOwnsFirewall: true})
	if err != nil {
		t.Fatal(err)
	}
	script, err := ApplyScriptFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	at := strings.Index(script, check)
	if at < 0 || !strings.Contains(script, "lacks the acl plugin (dns.acl)") {
		t.Fatalf("apply script does not check for the acl plugin by name:\n%s", script)
	}
	if write := strings.Index(script, "mkdir -p \"$SELF_DNS_DIR\""); write < 0 || at > write {
		t.Fatalf("the acl check must run before the apply writes anything:\n%s", script)
	}

	plain := baseDeployment()
	plainCfg, err := GenerateConfig(plain, RenderOptions{MeshBindIP: "10.66.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	plainPlan, err := RenderApprovalPlanWithOptions(plain, "tokyo-1", plainCfg, "", nil, ApprovalPlanOptions{NetGuardOwnsFirewall: true})
	if err != nil {
		t.Fatal(err)
	}
	plainScript, err := ApplyScriptFromPlan(plainPlan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plainScript, "-plugins |") {
		t.Fatalf("a Corefile without acl does not check for it:\n%s", plainScript)
	}
}
