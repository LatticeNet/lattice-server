// Package selfdns renders the reviewable artifacts for Lattice-owned DNS
// deployment intent. It is deliberately dependency-free: the server renders
// CoreDNS and nftables text from already-validated model state, then sends the
// resulting plan through the existing approval gate before any host mutation.
package selfdns

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/network"
)

const (
	CorefilePath = "/etc/lattice/selfdns/Corefile"
	ZoneDir      = "/etc/lattice/selfdns/zones"
	ServiceName  = "lattice-selfdns.service"
	NFTGuardPath = "/etc/lattice/guard.nft"
)

var dnsLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type RenderOptions struct {
	// MeshBindIP is required for mesh exposure. It is normally the node's
	// WireGuard IP with any /32 suffix removed. Binding CoreDNS to the mesh IP is
	// defense in depth on top of the nft rule.
	MeshBindIP string
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
	Corefile   string
	ZoneFiles  []ZoneFile
	NFTRuleset string
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
	var b strings.Builder
	b.WriteString("# Lattice Self-host DNS plan\n\n")
	fmt.Fprintf(&b, "deployment_id: %s\n", dep.ID)
	fmt.Fprintf(&b, "name: %s\n", dep.Name)
	fmt.Fprintf(&b, "node_id: %s\n", dep.NodeID)
	if nodeName != "" {
		fmt.Fprintf(&b, "node_name: %s\n", nodeName)
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
		fmt.Fprintf(&b, "- %s\n", line)
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
	return b.String()
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
	return ApplyArtifacts{Corefile: core, ZoneFiles: zones, NFTRuleset: nft}, nil
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
	b.WriteString("UNIT=/etc/systemd/system/lattice-selfdns.service\n")
	b.WriteString("command -v coredns >/dev/null || { echo 'lattice selfdns: coredns binary not found in PATH' >&2; exit 1; }\n")
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
	b.WriteString("trap rollback ERR INT TERM HUP\n")
	for _, zf := range artifacts.ZoneFiles {
		b.WriteString(heredocWrite(zf.Path+".new", "LATTICE_SELF_DNS_ZONE_EOF", zf.Content))
		b.WriteString("mv " + shellQuote(zf.Path+".new") + " " + shellQuote(zf.Path) + "\n")
	}
	b.WriteString(heredocWrite(CorefilePath+".new", "LATTICE_SELF_DNS_CORE_EOF", artifacts.Corefile))
	b.WriteString("mv \"$CORE_CANDIDATE\" " + shellQuote(CorefilePath) + "\n")
	b.WriteString("coredns -conf " + shellQuote(CorefilePath) + " -plugins >/dev/null\n")
	b.WriteString(heredocWrite(NFTGuardPath+".new", "LATTICE_SELF_DNS_NFT_EOF", artifacts.NFTRuleset))
	b.WriteString("nft -c -f \"$NFT_CANDIDATE\"\n")
	b.WriteString("nft list ruleset > \"$NFT_ROLLBACK\"\n")
	b.WriteString("( sleep 60; echo 'lattice selfdns: watchdog rollback fired' >&2; rollback ) &\n")
	b.WriteString("WATCHDOG=$!\n")
	b.WriteString("nft -f \"$NFT_CANDIDATE\"\n")
	b.WriteString("mv \"$NFT_CANDIDATE\" " + shellQuote(NFTGuardPath) + "\n")
	b.WriteString(heredocWrite("/etc/systemd/system/lattice-selfdns.service", "LATTICE_SELF_DNS_UNIT_EOF", serviceUnit()))
	b.WriteString("chmod 0644 \"$UNIT\"\n")
	b.WriteString("systemctl daemon-reload\n")
	b.WriteString("systemctl enable --now lattice-selfdns.service\n")
	b.WriteString("systemctl restart lattice-selfdns.service\n")
	b.WriteString("systemctl is-active --quiet lattice-selfdns.service\n")
	b.WriteString("kill \"$WATCHDOG\" 2>/dev/null || true\n")
	b.WriteString("wait \"$WATCHDOG\" 2>/dev/null || true\n")
	b.WriteString("trap - ERR INT TERM HUP\n")
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

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func serviceUnit() string {
	return `[Unit]
Description=Lattice Self-host DNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env coredns -conf /etc/lattice/selfdns/Corefile
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
	return nil
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
