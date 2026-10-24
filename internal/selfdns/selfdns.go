// Package selfdns renders the reviewable artifacts for Lattice-owned DNS
// deployment intent. It is deliberately dependency-free: the server renders
// CoreDNS and nftables text from already-validated model state, then sends the
// resulting plan through the existing approval gate before any host mutation.
package selfdns

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

const (
	CorefilePath = "/etc/lattice/selfdns/Corefile"
	ZoneDir      = "/etc/lattice/selfdns/zones"
	ServiceName  = "lattice-selfdns.service"
	NFTGuardPath = "/etc/lattice/guard.nft"
	CoreDNSPath  = "/usr/local/bin/coredns"
)

var dnsLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var (
	coreDNSVersionRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	sha256HexRe      = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
)

type RenderOptions struct {
	// MeshBindIP is required for mesh exposure. It is normally the node's
	// WireGuard IP with any /32 suffix removed. Binding CoreDNS to the mesh IP is
	// defense in depth on top of the nft rule.
	MeshBindIP string
}

// CoreDNSBinarySource is an optional, operator-provided pinned artifact used by
// the apply script to install CoreDNS when the node does not already have the
// expected executable. The URL must point directly to an executable binary, not
// an archive. The binary is accepted only after SHA-256 verification.
type CoreDNSBinarySource struct {
	Version string
	URL     string
	SHA256  string
}

func (src CoreDNSBinarySource) Enabled() bool {
	return strings.TrimSpace(src.Version) != "" || strings.TrimSpace(src.URL) != "" || strings.TrimSpace(src.SHA256) != ""
}

func (src CoreDNSBinarySource) Normalize() (CoreDNSBinarySource, error) {
	src.Version = strings.TrimSpace(src.Version)
	src.URL = strings.TrimSpace(src.URL)
	src.SHA256 = strings.ToLower(strings.TrimSpace(src.SHA256))
	if !src.Enabled() {
		return CoreDNSBinarySource{}, nil
	}
	if src.Version == "" || src.URL == "" || src.SHA256 == "" {
		return CoreDNSBinarySource{}, errors.New("coredns binary source requires version, url, and sha256")
	}
	if !coreDNSVersionRe.MatchString(src.Version) {
		return CoreDNSBinarySource{}, errors.New("coredns binary version contains unsafe characters")
	}
	if strings.ContainsAny(src.URL, "\x00\r\n\t ") {
		return CoreDNSBinarySource{}, errors.New("coredns binary url contains unsafe characters")
	}
	parsed, err := url.Parse(src.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return CoreDNSBinarySource{}, errors.New("coredns binary url must be https with no userinfo")
	}
	if parsed.Fragment != "" {
		return CoreDNSBinarySource{}, errors.New("coredns binary url must not contain a fragment")
	}
	if len(src.URL) > 2048 {
		return CoreDNSBinarySource{}, errors.New("coredns binary url is too long")
	}
	if !sha256HexRe.MatchString(src.SHA256) {
		return CoreDNSBinarySource{}, errors.New("coredns binary sha256 must be 64 hex characters")
	}
	return src, nil
}

type ApprovalPlanOptions struct {
	CoreDNSBinary CoreDNSBinarySource
	// FirewallSource names who composed the plan's lattice_guard candidate:
	// FirewallSourceNetGuard on a node NetGuard manages, FirewallSourceLegacy
	// otherwise. It is recorded in the plan so the approve can hold a
	// NetGuard-composed plan to NetGuard's gates.
	FirewallSource string
}

const (
	FirewallSourceNetGuard = "netguard"
	FirewallSourceLegacy   = "legacy"
)

// Listener is one socket a CoreDNS deployment's plan opens in lattice_guard.
type Listener struct {
	Exposure string // mesh | public
	Protocol string // udp | tcp
	Port     int
}

// Listeners is the socket set a deployment's plan opens: none for a disabled
// deployment or an engine Lattice does not render, as ComposeFirewallPlan
// treats them.
func Listeners(dep model.DNSDeployment) []Listener {
	if dep.Engine != model.DNSEngineCoreDNS || dep.Disabled {
		return nil
	}
	var out []Listener
	if dep.EnableUDP {
		out = append(out, Listener{Exposure: dep.Exposure, Protocol: "udp", Port: dep.ListenPort})
	}
	if dep.EnableTCP {
		out = append(out, Listener{Exposure: dep.Exposure, Protocol: "tcp", Port: dep.ListenPort})
	}
	return out
}

// PlanFirewall is what an approved DNS plan says about its firewall: who
// composed the lattice_guard candidate and which listeners it opens.
type PlanFirewall struct {
	// Source is FirewallSourceNetGuard or FirewallSourceLegacy, or empty for a
	// plan made before the source was recorded.
	Source    string
	Listeners []Listener
}

const (
	firewallHeading  = "## Firewall source"
	firewallLanguage = "lattice-dns-firewall"
)

// ParsePlanFirewall reads the firewall section of a DNS approval plan. A plan
// made before the section existed falls back to its header's exposure and
// listen lines, which the renderer has always written, and to the disabled
// marker of its firewall delta.
func ParsePlanFirewall(plan string) (PlanFirewall, error) {
	section, ok, err := optionalFencedSection(plan, firewallHeading, firewallLanguage)
	if err != nil {
		return PlanFirewall{}, err
	}
	if !ok {
		return planFirewallFromHeader(plan)
	}
	var out PlanFirewall
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "source: "):
			out.Source = strings.TrimPrefix(line, "source: ")
			if out.Source != FirewallSourceNetGuard && out.Source != FirewallSourceLegacy {
				return PlanFirewall{}, fmt.Errorf("unknown firewall source %q", out.Source)
			}
		case strings.HasPrefix(line, "listen: "):
			l, err := parseListener(strings.Fields(strings.TrimPrefix(line, "listen: ")))
			if err != nil {
				return PlanFirewall{}, err
			}
			out.Listeners = append(out.Listeners, l)
		default:
			return PlanFirewall{}, fmt.Errorf("unexpected firewall line %q", line)
		}
	}
	return out, nil
}

func parseListener(fields []string) (Listener, error) {
	if len(fields) != 3 {
		return Listener{}, fmt.Errorf("listener %q is not exposure protocol port", strings.Join(fields, " "))
	}
	port, err := strconv.Atoi(fields[2])
	if err != nil || port < 1 || port > 65535 {
		return Listener{}, fmt.Errorf("listener port %q out of range", fields[2])
	}
	if fields[0] != model.DNSExposureMesh && fields[0] != model.DNSExposurePublic {
		return Listener{}, fmt.Errorf("listener exposure %q", fields[0])
	}
	if fields[1] != "udp" && fields[1] != "tcp" {
		return Listener{}, fmt.Errorf("listener protocol %q", fields[1])
	}
	return Listener{Exposure: fields[0], Protocol: fields[1], Port: port}, nil
}

// planFirewallFromHeader reads a plan rendered before the firewall section:
// its header (up to the first section) carries "exposure: X" and
// "listen: udp=B tcp=B port=N", and a disabled deployment's firewall delta
// says it added no ports.
func planFirewallFromHeader(plan string) (PlanFirewall, error) {
	header := plan
	if i := strings.Index(plan, "\n## "); i >= 0 {
		header = plan[:i]
	}
	if strings.Contains(plan, "\n- disabled deployment: no DNS listener ports added\n") {
		return PlanFirewall{}, nil
	}
	exposure, listen := "", ""
	for _, line := range strings.Split(header, "\n") {
		if v, ok := strings.CutPrefix(line, "exposure: "); ok {
			exposure = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "listen: "); ok {
			listen = strings.TrimSpace(v)
		}
	}
	var udp, tcp bool
	var port int
	if _, err := fmt.Sscanf(listen, "udp=%t tcp=%t port=%d", &udp, &tcp, &port); err != nil {
		return PlanFirewall{}, fmt.Errorf("plan header has no listen line: %w", err)
	}
	dep := model.DNSDeployment{Engine: model.DNSEngineCoreDNS, Exposure: exposure, EnableUDP: udp, EnableTCP: tcp, ListenPort: port}
	var out PlanFirewall
	for _, l := range Listeners(dep) {
		if _, err := parseListener([]string{l.Exposure, l.Protocol, strconv.Itoa(l.Port)}); err != nil {
			return PlanFirewall{}, err
		}
		out.Listeners = append(out.Listeners, l)
	}
	return out, nil
}

// planField keeps a free-text value on its one header line. Deployment and
// node names are operator text; a line break in one could otherwise plant a
// section heading ahead of the real Corefile or firewall section, which the
// apply script and the approve read by heading.
func planField(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
}

type ZoneFile struct {
	Path    string
	Content string
}

type ConfigBundle struct {
	Corefile  string
	ZoneFiles []ZoneFile
}

type ApplyArtifacts struct {
	Corefile      string
	ZoneFiles     []ZoneFile
	NFTRuleset    string
	CoreDNSBinary *CoreDNSBinarySource
}

// GenerateConfig renders a CoreDNS Corefile plus any static-zone files.
func GenerateConfig(dep model.DNSDeployment, opts RenderOptions) (ConfigBundle, error) {
	if err := validateDeployment(dep, opts); err != nil {
		return ConfigBundle{}, err
	}
	bindIP := ""
	if dep.Exposure == model.DNSExposureMesh {
		parsed, err := normalizeBindIP(opts.MeshBindIP)
		if err != nil {
			return ConfigBundle{}, err
		}
		bindIP = parsed
	}

	clientNets, err := NormalizeClientNetworks(dep.AllowedClientNetworks)
	if err != nil {
		return ConfigBundle{}, err
	}

	var core strings.Builder
	zoneFiles := []ZoneFile{}
	for i, zone := range dep.Zones {
		zoneSuffix, err := normalizeDNSName(zone.Suffix, true, true)
		if err != nil {
			return ConfigBundle{}, fmt.Errorf("zone %d suffix: %w", i+1, err)
		}
		zone.Suffix = zoneSuffix
		zone.Mode = strings.ToLower(strings.TrimSpace(zone.Mode))
		suffix := strings.TrimSuffix(zone.Suffix, ".")
		if zone.Suffix == "." {
			suffix = "."
		}
		fmt.Fprintf(&core, "%s:%d {\n", suffix, dep.ListenPort)
		if bindIP != "" {
			fmt.Fprintf(&core, "  bind %s\n", bindIP)
		}
		// Every server block shares the deployment's listener, so each one
		// carries the acl. block answers REFUSED, which is no larger than the
		// query and so gives a spoofed source nothing to amplify.
		if len(clientNets) > 0 {
			core.WriteString("  acl {\n")
			fmt.Fprintf(&core, "    allow net %s\n", strings.Join(clientNets, " "))
			core.WriteString("    block\n")
			core.WriteString("  }\n")
		}
		core.WriteString("  errors\n")
		core.WriteString("  log\n")
		core.WriteString("  loop\n")
		core.WriteString("  cache 30\n")
		switch zone.Mode {
		case model.DNSZoneForward:
			upstreams := normalizeUpstreams(zone.Upstreams)
			fmt.Fprintf(&core, "  forward . %s\n", strings.Join(upstreams, " "))
		case model.DNSZoneStatic:
			zf, err := renderStaticZoneFile(dep, zone, i, bindIP)
			if err != nil {
				return ConfigBundle{}, err
			}
			zoneFiles = append(zoneFiles, zf)
			fmt.Fprintf(&core, "  file %s %s\n", zf.Path, zone.Suffix)
		case model.DNSZoneBlock:
			core.WriteString("  template IN ANY {\n")
			core.WriteString("    rcode NXDOMAIN\n")
			core.WriteString("  }\n")
		default:
			return ConfigBundle{}, fmt.Errorf("unsupported zone mode %q", zone.Mode)
		}
		core.WriteString("}\n\n")
	}
	sort.Slice(zoneFiles, func(i, j int) bool { return zoneFiles[i].Path < zoneFiles[j].Path })
	return ConfigBundle{Corefile: core.String(), ZoneFiles: zoneFiles}, nil
}

// ComposeFirewallPlan folds the DNS listener ports into the node's single
// lattice_guard input render. It returns the modified plan plus a compact
// operator-facing summary of the widened port set.
func ComposeFirewallPlan(dep model.DNSDeployment, base network.NFTPlan) (network.NFTPlan, []string, error) {
	if dep.ListenPort < 1 || dep.ListenPort > 65535 {
		return network.NFTPlan{}, nil, errors.New("listen_port must be between 1 and 65535")
	}
	if dep.Disabled {
		normalized, err := network.NormalizeNFTPlan(base)
		return normalized, []string{"disabled deployment: no DNS listener ports added"}, err
	}
	summary := []string{}
	switch dep.Exposure {
	case model.DNSExposureMesh:
		if dep.EnableUDP {
			base.WireGuardUDP = appendPort(base.WireGuardUDP, dep.ListenPort)
			summary = append(summary, fmt.Sprintf("mesh UDP/%d via WireGuard CIDR", dep.ListenPort))
		}
		if dep.EnableTCP {
			base.WireGuardTCP = appendPort(base.WireGuardTCP, dep.ListenPort)
			summary = append(summary, fmt.Sprintf("mesh TCP/%d via WireGuard CIDR", dep.ListenPort))
		}
	case model.DNSExposurePublic:
		if dep.EnableUDP {
			base.PublicUDP = appendPort(base.PublicUDP, dep.ListenPort)
			summary = append(summary, fmt.Sprintf("public UDP/%d", dep.ListenPort))
		}
		if dep.EnableTCP {
			base.PublicTCP = appendPort(base.PublicTCP, dep.ListenPort)
			summary = append(summary, fmt.Sprintf("public TCP/%d", dep.ListenPort))
		}
	default:
		return network.NFTPlan{}, nil, fmt.Errorf("unsupported exposure %q", dep.Exposure)
	}
	normalized, err := network.NormalizeNFTPlan(base)
	if err != nil {
		return network.NFTPlan{}, nil, err
	}
	if len(summary) == 0 {
		summary = append(summary, "no DNS listener ports enabled")
	}
	return normalized, summary, nil
}

// RenderApprovalPlan renders the exact text an operator reviews and hashes
// before approval. It must contain no bearer secrets.
func RenderApprovalPlan(dep model.DNSDeployment, nodeName string, cfg ConfigBundle, nftRuleset string, firewallSummary []string) string {
	plan, _ := RenderApprovalPlanWithOptions(dep, nodeName, cfg, nftRuleset, firewallSummary, ApprovalPlanOptions{})
	return plan
}

// RenderApprovalPlanWithOptions is the checked variant used by server paths that
// need to include optional install/provenance metadata in the reviewed plan.
func RenderApprovalPlanWithOptions(dep model.DNSDeployment, nodeName string, cfg ConfigBundle, nftRuleset string, firewallSummary []string, opts ApprovalPlanOptions) (string, error) {
	binary, err := opts.CoreDNSBinary.Normalize()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Lattice Self-host DNS plan\n\n")
	fmt.Fprintf(&b, "deployment_id: %s\n", planField(dep.ID))
	fmt.Fprintf(&b, "name: %s\n", planField(dep.Name))
	fmt.Fprintf(&b, "node_id: %s\n", planField(dep.NodeID))
	if nodeName != "" {
		fmt.Fprintf(&b, "node_name: %s\n", planField(nodeName))
	}
	fmt.Fprintf(&b, "engine: %s\n", dep.Engine)
	fmt.Fprintf(&b, "exposure: %s\n", dep.Exposure)
	fmt.Fprintf(&b, "listen: udp=%t tcp=%t port=%d\n", dep.EnableUDP, dep.EnableTCP, dep.ListenPort)
	if dep.Hostname != "" {
		fmt.Fprintf(&b, "hostname: %s\n", dep.Hostname)
		fmt.Fprintf(&b, "publish: ipv4=%t ipv6=%t ttl=%d credential=%t\n", dep.PublishIPv4, dep.PublishIPv6, dep.RecordTTL, dep.CFAPIToken != "" || dep.DDNSProfileID != "")
	} else {
		b.WriteString("hostname: (none)\n")
	}
	b.WriteString("\n## Firewall delta\n")
	for _, line := range firewallSummary {
		fmt.Fprintf(&b, "- %s\n", planField(line))
	}
	source := opts.FirewallSource
	if source == "" {
		source = FirewallSourceLegacy
	}
	if source != FirewallSourceNetGuard && source != FirewallSourceLegacy {
		return "", fmt.Errorf("unknown firewall source %q", source)
	}
	b.WriteString("\n" + firewallHeading + "\n")
	b.WriteString("```" + firewallLanguage + "\n")
	fmt.Fprintf(&b, "source: %s\n", source)
	for _, l := range Listeners(dep) {
		fmt.Fprintf(&b, "listen: %s %s %d\n", l.Exposure, l.Protocol, l.Port)
	}
	b.WriteString("```\n")
	if binary.Enabled() {
		b.WriteString("\n## CoreDNS binary\n")
		b.WriteString("```lattice-coredns-binary\n")
		fmt.Fprintf(&b, "version: %s\n", binary.Version)
		fmt.Fprintf(&b, "url: %s\n", binary.URL)
		fmt.Fprintf(&b, "sha256: %s\n", binary.SHA256)
		fmt.Fprintf(&b, "install_path: %s\n", CoreDNSPath)
		b.WriteString("```\n")
	}
	b.WriteString("\n## CoreDNS Corefile\n")
	b.WriteString("```coredns\n")
	b.WriteString(cfg.Corefile)
	if !strings.HasSuffix(cfg.Corefile, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("```\n")
	for _, zf := range cfg.ZoneFiles {
		fmt.Fprintf(&b, "\n## Zone file: %s\n", zf.Path)
		b.WriteString("```dns-zone\n")
		b.WriteString(zf.Content)
		if !strings.HasSuffix(zf.Content, "\n") {
			b.WriteByte('\n')
		}
		b.WriteString("```\n")
	}
	b.WriteString("\n## nftables lattice_guard candidate\n")
	b.WriteString("```nft\n")
	b.WriteString(nftRuleset)
	if !strings.HasSuffix(nftRuleset, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("```\n")
	if dep.Hostname != "" {
		b.WriteString("\n## Cloudflare action\n")
		fmt.Fprintf(&b, "- publish %s A=%t AAAA=%t via server-side DDNS/Cloudflare credential; token is not included in this plan\n", dep.Hostname, dep.PublishIPv4, dep.PublishIPv6)
	}
	return b.String(), nil
}

// ParseApprovalPlan extracts the exact artifacts from the reviewed plan text.
// The apply path intentionally uses the reviewed plan as source of truth instead
// of re-rendering current mutable store state.
func ParseApprovalPlan(plan string) (ApplyArtifacts, error) {
	core, err := fencedSection(plan, "## CoreDNS Corefile", "coredns")
	if err != nil {
		return ApplyArtifacts{}, err
	}
	nft, err := fencedSection(plan, "## nftables lattice_guard candidate", "nft")
	if err != nil {
		return ApplyArtifacts{}, err
	}
	zones, err := zoneSections(plan)
	if err != nil {
		return ApplyArtifacts{}, err
	}
	binary, err := coreDNSBinarySection(plan)
	if err != nil {
		return ApplyArtifacts{}, err
	}
	return ApplyArtifacts{Corefile: core, ZoneFiles: zones, NFTRuleset: nft, CoreDNSBinary: binary}, nil
}

// ApplyScriptFromPlan builds a bounded shell script that applies the reviewed
// CoreDNS artifacts and committed lattice_guard ruleset. Cloudflare publication
// remains server-side and is intentionally not part of this script.
func ApplyScriptFromPlan(plan string) (string, error) {
	artifacts, err := ParseApprovalPlan(plan)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("umask 077\n")
	b.WriteString("SELF_DNS_DIR=/etc/lattice/selfdns\n")
	b.WriteString("ZONE_DIR=/etc/lattice/selfdns/zones\n")
	b.WriteString("CORE_CANDIDATE=/etc/lattice/selfdns/Corefile.new\n")
	b.WriteString("NFT_CANDIDATE=/etc/lattice/guard.nft.new\n")
	b.WriteString("NFT_ROLLBACK=/etc/lattice/guard.rollback.nft\n")
	b.WriteString("CONFIG_BACKUP=/etc/lattice/selfdns.rollback.$$\n")
	b.WriteString("WATCHDOG=\n")
	b.WriteString("WATCHDOG_FIRED=/tmp/lattice-selfdns-watchdog.$$\n")
	b.WriteString("UNIT=/etc/systemd/system/lattice-selfdns.service\n")
	writeCoreDNSBootstrap(&b, artifacts.CoreDNSBinary)
	b.WriteString("command -v nft >/dev/null || { echo 'lattice selfdns: nft binary not found in PATH' >&2; exit 1; }\n")
	b.WriteString("command -v systemctl >/dev/null || { echo 'lattice selfdns: systemd is required for this apply slice' >&2; exit 1; }\n")
	b.WriteString("mkdir -p \"$SELF_DNS_DIR\" \"$ZONE_DIR\" /etc/lattice\n")
	b.WriteString("rm -rf \"$CONFIG_BACKUP\"\n")
	b.WriteString("if [ -d \"$SELF_DNS_DIR\" ]; then cp -a \"$SELF_DNS_DIR\" \"$CONFIG_BACKUP\"; else mkdir -p \"$CONFIG_BACKUP\"; fi\n")
	b.WriteString("rollback() {\n")
	b.WriteString("  set +e\n")
	b.WriteString("  echo 'lattice selfdns: rolling back config and firewall' >&2\n")
	b.WriteString("  nft -f \"$NFT_ROLLBACK\" 2>/dev/null || true\n")
	b.WriteString("  if [ -d \"$CONFIG_BACKUP\" ]; then rm -rf \"$SELF_DNS_DIR\"; mv \"$CONFIG_BACKUP\" \"$SELF_DNS_DIR\"; fi\n")
	b.WriteString("  systemctl restart lattice-selfdns.service 2>/dev/null || true\n")
	b.WriteString("}\n")
	b.WriteString("cleanup_watchdog() {\n")
	b.WriteString("  if [ -n \"$WATCHDOG\" ]; then\n")
	b.WriteString("    kill \"$WATCHDOG\" 2>/dev/null || true\n")
	b.WriteString("    wait \"$WATCHDOG\" 2>/dev/null || true\n")
	b.WriteString("  fi\n")
	b.WriteString("  rm -f \"$WATCHDOG_FIRED\"\n")
	b.WriteString("}\n")
	b.WriteString("start_watchdog() {\n")
	b.WriteString("  if command -v setsid >/dev/null 2>&1; then\n")
	b.WriteString("    setsid sh -c 'sleep 60; echo \"lattice selfdns: watchdog rollback fired\" >&2; touch \"$1\" 2>/dev/null || true; echo \"lattice selfdns: rolling back config and firewall\" >&2; nft -f \"$2\" 2>/dev/null || true; if [ -d \"$3\" ]; then rm -rf \"$4\"; mv \"$3\" \"$4\"; fi; systemctl restart lattice-selfdns.service 2>/dev/null || true' sh \"$WATCHDOG_FIRED\" \"$NFT_ROLLBACK\" \"$CONFIG_BACKUP\" \"$SELF_DNS_DIR\" &\n")
	b.WriteString("  else\n")
	b.WriteString("    ( sleep 60; echo 'lattice selfdns: watchdog rollback fired' >&2; touch \"$WATCHDOG_FIRED\" 2>/dev/null || true; rollback ) &\n")
	b.WriteString("  fi\n")
	b.WriteString("  WATCHDOG=$!\n")
	b.WriteString("}\n")
	b.WriteString("assert_watchdog_clean() {\n")
	b.WriteString("  if [ -f \"$WATCHDOG_FIRED\" ]; then\n")
	b.WriteString("    echo 'lattice selfdns: watchdog rollback fired before commit; refusing to mark apply verified' >&2\n")
	b.WriteString("    false\n")
	b.WriteString("  fi\n")
	b.WriteString("}\n")
	b.WriteString("trap 'rollback; cleanup_watchdog' ERR INT TERM HUP\n")
	for _, zf := range artifacts.ZoneFiles {
		b.WriteString(heredocWrite(zf.Path+".new", "LATTICE_SELF_DNS_ZONE_EOF", zf.Content))
		b.WriteString("mv " + shellQuote(zf.Path+".new") + " " + shellQuote(zf.Path) + "\n")
	}
	b.WriteString(heredocWrite(CorefilePath+".new", "LATTICE_SELF_DNS_CORE_EOF", artifacts.Corefile))
	b.WriteString("mv \"$CORE_CANDIDATE\" " + shellQuote(CorefilePath) + "\n")
	b.WriteString("\"$COREDNS_BIN\" -conf " + shellQuote(CorefilePath) + " -plugins >/dev/null\n")
	b.WriteString(heredocWrite(NFTGuardPath+".new", "LATTICE_SELF_DNS_NFT_EOF", artifacts.NFTRuleset))
	b.WriteString("nft -c -f \"$NFT_CANDIDATE\"\n")
	// One table only: a `flush ruleset` snapshot would take Docker's tables,
	// SSH Guard's lattice_knock and every other tenant with it on rollback.
	b.WriteString("{ echo 'add table inet lattice_guard'; echo 'delete table inet lattice_guard'; nft list table inet lattice_guard 2>/dev/null || true; } > \"$NFT_ROLLBACK\"\n")
	b.WriteString("start_watchdog\n")
	b.WriteString("nft -f \"$NFT_CANDIDATE\"\n")
	b.WriteString("mv \"$NFT_CANDIDATE\" " + shellQuote(NFTGuardPath) + "\n")
	serviceExec := "/usr/bin/env coredns"
	if artifacts.CoreDNSBinary != nil && artifacts.CoreDNSBinary.Enabled() {
		serviceExec = CoreDNSPath
	}
	b.WriteString(heredocWrite("/etc/systemd/system/lattice-selfdns.service", "LATTICE_SELF_DNS_UNIT_EOF", serviceUnit(serviceExec)))
	b.WriteString("chmod 0644 \"$UNIT\"\n")
	b.WriteString("systemctl daemon-reload\n")
	b.WriteString("systemctl enable --now lattice-selfdns.service\n")
	b.WriteString("systemctl restart lattice-selfdns.service\n")
	b.WriteString("systemctl is-active --quiet lattice-selfdns.service\n")
	b.WriteString("assert_watchdog_clean\n")
	b.WriteString("trap - ERR INT TERM HUP\n")
	b.WriteString("cleanup_watchdog\n")
	b.WriteString("rm -rf \"$CONFIG_BACKUP\"\n")
	b.WriteString("echo 'lattice selfdns: applied and verified'\n")
	return b.String(), nil
}

func renderStaticZoneFile(dep model.DNSDeployment, zone model.DNSZone, index int, bindIP string) (ZoneFile, error) {
	origin, err := normalizeDNSName(zone.Suffix, true, true)
	if err != nil {
		return ZoneFile{}, err
	}
	if origin == "." {
		return ZoneFile{}, errors.New("static root zone is not supported")
	}
	safe := strings.TrimSuffix(origin, ".")
	safe = strings.ReplaceAll(safe, ".", "_")
	filePath := path.Join(ZoneDir, fmt.Sprintf("%02d_%s.zone", index+1, safe))
	ttl := dep.RecordTTL
	if ttl == 0 {
		ttl = 300
	}
	nsHost := "ns." + origin
	hostmaster := "hostmaster." + origin
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$ORIGIN %s\n", origin)
	fmt.Fprintf(&b, "$TTL %d\n", ttl)
	fmt.Fprintf(&b, "@ IN SOA %s %s 1 3600 600 86400 %d\n", nsHost, hostmaster, ttl)
	fmt.Fprintf(&b, "@ IN NS %s\n", nsHost)
	if addr, _ := netip.ParseAddr(bindIP); addr.Is6() {
		fmt.Fprintf(&b, "ns IN AAAA %s\n", bindIP)
	} else {
		fmt.Fprintf(&b, "ns IN A %s\n", bindIP)
	}
	for _, rec := range zone.Records {
		name, err := normalizeDNSName(rec.Name, true, false)
		if err != nil {
			return ZoneFile{}, err
		}
		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		value := strings.TrimSpace(rec.Value)
		if recType == "CNAME" {
			value, err = normalizeDNSName(value, true, false)
			if err != nil {
				return ZoneFile{}, err
			}
		}
		recTTL := rec.TTL
		if recTTL == 0 {
			recTTL = ttl
		}
		fmt.Fprintf(&b, "%s %d IN %s %s\n", name, recTTL, recType, value)
	}
	return ZoneFile{Path: filePath, Content: b.String()}, nil
}

func fencedSection(plan, heading, language string) (string, error) {
	start := strings.Index(plan, heading)
	if start < 0 {
		return "", fmt.Errorf("missing section %q", heading)
	}
	rest := plan[start+len(heading):]
	fence := "```" + language + "\n"
	fenceStart := strings.Index(rest, fence)
	if fenceStart < 0 {
		return "", fmt.Errorf("section %q missing %s fence", heading, language)
	}
	contentStart := fenceStart + len(fence)
	fenceEnd := strings.Index(rest[contentStart:], "\n```")
	if fenceEnd < 0 {
		return "", fmt.Errorf("section %q missing closing fence", heading)
	}
	content := rest[contentStart : contentStart+fenceEnd]
	if strings.TrimSpace(content) == "" {
		return "", fmt.Errorf("section %q is empty", heading)
	}
	return content + "\n", nil
}

func zoneSections(plan string) ([]ZoneFile, error) {
	zones := []ZoneFile{}
	rest := plan
	for {
		idx := strings.Index(rest, "## Zone file: ")
		if idx < 0 {
			break
		}
		rest = rest[idx+len("## Zone file: "):]
		lineEnd := strings.IndexByte(rest, '\n')
		if lineEnd < 0 {
			return nil, errors.New("zone file heading missing newline")
		}
		zonePath, err := validateZonePath(strings.TrimSpace(rest[:lineEnd]))
		if err != nil {
			return nil, err
		}
		content, err := zoneFence(rest[lineEnd:])
		if err != nil {
			return nil, err
		}
		zones = append(zones, ZoneFile{Path: zonePath, Content: content})
		rest = rest[lineEnd:]
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Path < zones[j].Path })
	return zones, nil
}

func coreDNSBinarySection(plan string) (*CoreDNSBinarySource, error) {
	content, ok, err := optionalFencedSection(plan, "## CoreDNS binary", "lattice-coredns-binary")
	if err != nil || !ok {
		return nil, err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid coredns binary metadata line %q", line)
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if fields["install_path"] != CoreDNSPath {
		return nil, fmt.Errorf("coredns binary install_path must be %s", CoreDNSPath)
	}
	src, err := (CoreDNSBinarySource{
		Version: fields["version"],
		URL:     fields["url"],
		SHA256:  fields["sha256"],
	}).Normalize()
	if err != nil {
		return nil, err
	}
	return &src, nil
}

func optionalFencedSection(plan, heading, language string) (string, bool, error) {
	start := strings.Index(plan, heading)
	if start < 0 {
		return "", false, nil
	}
	section, err := fencedSection(plan, heading, language)
	if err != nil {
		return "", true, err
	}
	return section, true, nil
}

func zoneFence(input string) (string, error) {
	fence := "```dns-zone\n"
	start := strings.Index(input, fence)
	if start < 0 {
		return "", errors.New("zone file section missing dns-zone fence")
	}
	contentStart := start + len(fence)
	end := strings.Index(input[contentStart:], "\n```")
	if end < 0 {
		return "", errors.New("zone file section missing closing fence")
	}
	content := input[contentStart : contentStart+end]
	if strings.TrimSpace(content) == "" {
		return "", errors.New("zone file section is empty")
	}
	return content + "\n", nil
}

func validateZonePath(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("invalid zone file path")
	}
	clean := filepath.Clean(value)
	if !strings.HasPrefix(clean, ZoneDir+"/") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("zone file path %q must stay under %s", value, ZoneDir)
	}
	if strings.HasSuffix(clean, "/") || !strings.HasSuffix(clean, ".zone") {
		return "", fmt.Errorf("zone file path %q must be a .zone file", value)
	}
	return clean, nil
}

func heredocWrite(target, marker, content string) string {
	delimiter := marker
	for strings.Contains(content, delimiter) {
		delimiter += "_X"
	}
	return "cat > " + shellQuote(target) + " <<'" + delimiter + "'\n" + content + "\n" + delimiter + "\n"
}

func writeCoreDNSBootstrap(b *strings.Builder, binary *CoreDNSBinarySource) {
	if binary == nil || !binary.Enabled() {
		b.WriteString("command -v coredns >/dev/null || { echo 'lattice selfdns: coredns binary not found in PATH' >&2; exit 1; }\n")
		b.WriteString("COREDNS_BIN=$(command -v coredns)\n")
		return
	}
	b.WriteString("COREDNS_BIN=" + shellQuote(CoreDNSPath) + "\n")
	b.WriteString("COREDNS_URL=" + shellQuote(binary.URL) + "\n")
	b.WriteString("COREDNS_SHA256=" + shellQuote(binary.SHA256) + "\n")
	b.WriteString("verify_coredns_sha256() {\n")
	b.WriteString("  if command -v sha256sum >/dev/null; then printf '%s  %s\\n' \"$COREDNS_SHA256\" \"$1\" | sha256sum -c - >/dev/null; return $?; fi\n")
	b.WriteString("  if command -v shasum >/dev/null; then printf '%s  %s\\n' \"$COREDNS_SHA256\" \"$1\" | shasum -a 256 -c - >/dev/null; return $?; fi\n")
	b.WriteString("  echo 'lattice selfdns: sha256sum or shasum is required for pinned CoreDNS install' >&2\n")
	b.WriteString("  return 127\n")
	b.WriteString("}\n")
	b.WriteString("install_pinned_coredns() {\n")
	b.WriteString("  command -v install >/dev/null || { echo 'lattice selfdns: install command not found' >&2; return 1; }\n")
	b.WriteString("  tmpdir=$(mktemp -d /tmp/lattice-coredns.XXXXXX)\n")
	b.WriteString("  tmpbin=\"$tmpdir/coredns\"\n")
	b.WriteString("  if command -v curl >/dev/null; then curl -fsSL --proto '=https' --tlsv1.2 \"$COREDNS_URL\" -o \"$tmpbin\"; elif command -v wget >/dev/null; then wget --https-only -qO \"$tmpbin\" \"$COREDNS_URL\"; else echo 'lattice selfdns: curl or wget is required for pinned CoreDNS install' >&2; return 1; fi\n")
	b.WriteString("  verify_coredns_sha256 \"$tmpbin\"\n")
	b.WriteString("  install -m 0755 \"$tmpbin\" \"$COREDNS_BIN\"\n")
	b.WriteString("  rm -rf \"$tmpdir\"\n")
	b.WriteString("}\n")
	b.WriteString("if [ -x \"$COREDNS_BIN\" ] && verify_coredns_sha256 \"$COREDNS_BIN\"; then echo 'lattice selfdns: pinned CoreDNS already installed'; else install_pinned_coredns; fi\n")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func serviceUnit(execStart string) string {
	return `[Unit]
Description=Lattice Self-host DNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + execStart + ` -conf /etc/lattice/selfdns/Corefile
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`
}

func validateDeployment(dep model.DNSDeployment, opts RenderOptions) error {
	if dep.Engine != model.DNSEngineCoreDNS {
		return fmt.Errorf("unsupported dns engine %q", dep.Engine)
	}
	if dep.ListenPort < 1 || dep.ListenPort > 65535 {
		return errors.New("listen_port must be between 1 and 65535")
	}
	if !dep.EnableUDP && !dep.EnableTCP {
		return errors.New("at least one listener protocol must be enabled")
	}
	switch dep.Exposure {
	case model.DNSExposureMesh:
		if _, err := normalizeBindIP(opts.MeshBindIP); err != nil {
			return fmt.Errorf("mesh exposure requires node wireguard_ip: %w", err)
		}
	case model.DNSExposurePublic:
	default:
		return fmt.Errorf("unsupported exposure %q", dep.Exposure)
	}
	if len(dep.Zones) == 0 {
		return errors.New("at least one dns zone is required")
	}
	for i, zone := range dep.Zones {
		if _, err := normalizeDNSName(zone.Suffix, true, true); err != nil {
			return fmt.Errorf("zone %d suffix: %w", i+1, err)
		}
		switch zone.Mode {
		case model.DNSZoneForward:
			if len(zone.Upstreams) == 0 {
				return fmt.Errorf("zone %d forward mode requires upstreams", i+1)
			}
			for _, upstream := range zone.Upstreams {
				if err := validateUpstream(upstream); err != nil {
					return fmt.Errorf("zone %d upstream %q: %w", i+1, upstream, err)
				}
			}
		case model.DNSZoneStatic:
			if len(zone.Records) == 0 {
				return fmt.Errorf("zone %d static mode requires records", i+1)
			}
			for j, rec := range zone.Records {
				if _, err := normalizeDNSName(rec.Name, true, false); err != nil {
					return fmt.Errorf("zone %d record %d name: %w", i+1, j+1, err)
				}
				if rec.TTL < 0 || rec.TTL > 86400 {
					return fmt.Errorf("zone %d record %d ttl must be between 1 and 86400", i+1, j+1)
				}
				if err := validateRecordValue(rec); err != nil {
					return fmt.Errorf("zone %d record %d: %w", i+1, j+1, err)
				}
			}
		case model.DNSZoneBlock:
		default:
			return fmt.Errorf("zone %d unsupported mode %q", i+1, zone.Mode)
		}
	}
	if _, err := NormalizeClientNetworks(dep.AllowedClientNetworks); err != nil {
		return err
	}
	return RefuseOpenResolver(dep)
}

// RefuseOpenResolver refuses a public deployment with a forward zone that
// names no allowed client networks: it would recurse for anyone who reaches
// the listener, which makes the node an open resolver and a reflection source.
func RefuseOpenResolver(dep model.DNSDeployment) error {
	if dep.Exposure != model.DNSExposurePublic || len(dep.AllowedClientNetworks) > 0 {
		return nil
	}
	for _, zone := range dep.Zones {
		if strings.ToLower(strings.TrimSpace(zone.Mode)) == model.DNSZoneForward {
			return errors.New("public exposure with a forward zone answers recursive queries from anyone, which makes the node an open resolver; set allowed_client_networks to the networks that should use it")
		}
	}
	return nil
}

// MaxAllowedClientNetworks bounds the acl so the reviewed Corefile stays
// readable.
const MaxAllowedClientNetworks = 64

// NormalizeClientNetworks canonicalizes a deployment's allowed client
// networks in the order given: a bare address becomes its host prefix and
// duplicates collapse. A prefix with host bits set is refused rather than
// silently widened, and so is a /0, which would allow every client and turn
// the acl back into an open resolver.
func NormalizeClientNetworks(input []string) ([]string, error) {
	if len(input) > MaxAllowedClientNetworks {
		return nil, fmt.Errorf("at most %d allowed client networks", MaxAllowedClientNetworks)
	}
	seen := map[netip.Prefix]bool{}
	out := make([]string, 0, len(input))
	for _, raw := range input {
		value := strings.TrimSpace(raw)
		prefix, err := parseClientNetwork(value)
		if err != nil {
			return nil, fmt.Errorf("allowed client network %q: %w", value, err)
		}
		if seen[prefix] {
			continue
		}
		seen[prefix] = true
		out = append(out, prefix.String())
	}
	if family := coveredFamily(seen); family != "" {
		return nil, fmt.Errorf("allowed client networks together cover all of %s, which allows every client; name the networks that should use this resolver", family)
	}
	return out, nil
}

// coveredFamily names the address family a prefix set covers whole, such as
// 0.0.0.0/1 plus 128.0.0.0/1, or "" when it covers neither.
func coveredFamily(prefixes map[netip.Prefix]bool) string {
	for _, family := range []struct {
		name  string
		first netip.Addr
		last  netip.Addr
		is4   bool
	}{
		{"IPv4", netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255}), true},
		{"IPv6", netip.IPv6Unspecified(), netip.AddrFrom16([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}), false},
	} {
		var ranges [][2]netip.Addr
		for prefix := range prefixes {
			if prefix.Addr().Is4() == family.is4 {
				ranges = append(ranges, [2]netip.Addr{prefix.Masked().Addr(), lastAddr(prefix)})
			}
		}
		sort.Slice(ranges, func(i, j int) bool { return ranges[i][0].Less(ranges[j][0]) })
		next := family.first
		covered := false
		for _, r := range ranges {
			if next.Less(r[0]) {
				break
			}
			if !r[1].Less(next) {
				if r[1] == family.last {
					covered = true
					break
				}
				next = r[1].Next()
			}
		}
		if covered {
			return family.name
		}
	}
	return ""
}

// lastAddr is the highest address in a prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	b := addr.AsSlice()
	for bit := prefix.Bits(); bit < len(b)*8; bit++ {
		b[bit/8] |= 0x80 >> (bit % 8)
	}
	last, _ := netip.AddrFromSlice(b)
	return last
}

func parseClientNetwork(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, errors.New("not a CIDR prefix or an IP address")
		}
		if prefix != prefix.Masked() {
			return netip.Prefix{}, fmt.Errorf("has host bits set; the network is %s", prefix.Masked())
		}
		// An IPv4-mapped prefix is an IPv4 network in IPv6 spelling, and
		// net.ParseCIDR reads ::ffff:0:0/96 as 0.0.0.0/0, so judge it as the
		// IPv4 prefix it is.
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return netip.Prefix{}, errors.New("mixes IPv4-mapped and IPv6 space; name the IPv4 network instead")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		if prefix.Bits() == 0 {
			return netip.Prefix{}, errors.New("allows every client; name the networks that should use this resolver")
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, errors.New("not a CIDR prefix or an IP address")
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func validateRecordValue(rec model.DNSRecord) error {
	switch strings.ToUpper(rec.Type) {
	case "A":
		addr, err := netip.ParseAddr(rec.Value)
		if err != nil || !addr.Is4() || addr.IsUnspecified() {
			return errors.New("A value must be a concrete IPv4 address")
		}
	case "AAAA":
		addr, err := netip.ParseAddr(rec.Value)
		if err != nil || !addr.Is6() || addr.IsUnspecified() {
			return errors.New("AAAA value must be a concrete IPv6 address")
		}
	case "CNAME":
		if _, err := normalizeDNSName(rec.Value, true, false); err != nil {
			return fmt.Errorf("CNAME value: %w", err)
		}
	default:
		return fmt.Errorf("unsupported type %q", rec.Type)
	}
	return nil
}

func validateUpstream(value string) error {
	if value == "" || strings.ContainsAny(value, "\r\n{};") {
		return errors.New("contains unsafe characters")
	}
	addr := strings.TrimPrefix(value, "tls://")
	if parsed, err := netip.ParseAddr(addr); err == nil {
		if parsed.IsUnspecified() {
			return errors.New("upstream cannot be unspecified")
		}
		return nil
	}
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		if ap.Addr().IsUnspecified() || ap.Port() == 0 {
			return errors.New("upstream address or port is invalid")
		}
		return nil
	}
	return errors.New("must be an IP, IP:port, or tls://IP[:port]")
}

func normalizeUpstreams(input []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(input))
	for _, raw := range input {
		value := strings.TrimSpace(raw)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func normalizeBindIP(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty bind ip")
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		addr := prefix.Addr()
		if addr.IsUnspecified() {
			return "", errors.New("bind ip cannot be unspecified")
		}
		return addr.String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", err
	}
	if addr.IsUnspecified() {
		return "", errors.New("bind ip cannot be unspecified")
	}
	return addr.String(), nil
}

func normalizeDNSName(value string, trailingDot bool, allowRoot bool) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if strings.ContainsAny(v, "\r\n\t {};/\\") {
		return "", errors.New("contains unsafe characters")
	}
	if allowRoot && v == "." {
		return ".", nil
	}
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return "", errors.New("empty name")
	}
	if len(v) > 253 {
		return "", errors.New("name is too long")
	}
	for _, label := range strings.Split(v, ".") {
		if !dnsLabelRe.MatchString(label) {
			return "", fmt.Errorf("invalid label %q", label)
		}
	}
	if trailingDot {
		return v + ".", nil
	}
	return v, nil
}

func appendPort(ports []int, port int) []int {
	for _, existing := range ports {
		if existing == port {
			return ports
		}
	}
	return append(ports, port)
}
