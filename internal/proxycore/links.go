package proxycore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	SubscriptionFormatBase64    = "base64"
	SubscriptionFormatPlain     = "plain"
	SubscriptionFormatSingBox   = "sing-box"
	SubscriptionFormatClash     = "clash"
	SubscriptionFormatClashMeta = "clash-meta"
)

// SubscriptionProfile is the small server-provided view needed to render links.
// It intentionally carries display-only node metadata, not Node secrets.
type SubscriptionProfile struct {
	Profile  model.ProxyNodeProfile
	NodeName string
}

type SubscriptionOptions struct {
	Now time.Time
}

// VLESSRealityEndpoint is a validated, secret-free client subscription endpoint
// for the currently supported VLESS+REALITY+TCP shape.
type VLESSRealityEndpoint struct {
	Label       string
	Tag         string
	NodeID      string
	InboundID   string
	Server      string
	ServerPort  int
	UUID        string
	Flow        string
	Network     string
	SNI         string
	Fingerprint string
	ALPN        []string
	PublicKey   string
	ShortID     string
}

// VLESSRealityLinks renders MVP VLESS+REALITY links for one subscriber across
// applied node profiles. It returns an empty slice for inactive users instead
// of an error so the public subscription endpoint can stay token-stable while
// enforcing expiry/quota server-side.
func VLESSRealityLinks(user model.ProxyUser, profiles []SubscriptionProfile, inbounds []model.ProxyInbound, opts SubscriptionOptions) ([]string, []string, error) {
	endpoints, warnings, err := VLESSRealityEndpoints(user, profiles, inbounds, opts)
	if err != nil {
		return nil, nil, err
	}
	links := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		links = append(links, endpoint.Link())
	}
	sort.Strings(links)
	return links, warnings, nil
}

// VLESSRealityEndpoints renders structured subscription endpoints for the
// currently supported VLESS+REALITY+TCP shape. All public subscription formats
// are derived from these endpoints so validation and secret stripping stay in
// one place.
func VLESSRealityEndpoints(user model.ProxyUser, profiles []SubscriptionProfile, inbounds []model.ProxyInbound, opts SubscriptionOptions) ([]VLESSRealityEndpoint, []string, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if reason := skipProxyUserReason(user, now); reason != "" {
		return []VLESSRealityEndpoint{}, []string{"user " + user.ID + " has no active subscription links: " + reason}, nil
	}
	if !safeTagRe.MatchString(user.ID) {
		return nil, nil, fmt.Errorf("invalid proxy user id %q", user.ID)
	}
	if !uuidRe.MatchString(user.UUID) {
		return nil, nil, fmt.Errorf("proxy user %s has invalid uuid", user.ID)
	}

	byID, err := inboundMap(inbounds)
	if err != nil {
		return nil, nil, err
	}
	sortedProfiles := append([]SubscriptionProfile(nil), profiles...)
	sort.Slice(sortedProfiles, func(i, j int) bool {
		return sortedProfiles[i].Profile.NodeID < sortedProfiles[j].Profile.NodeID
	})

	endpoints := []VLESSRealityEndpoint{}
	warnings := []string{}
	for _, sp := range sortedProfiles {
		profile := sp.Profile
		if profile.Core != model.ProxyCoreSingbox {
			warnings = append(warnings, fmt.Sprintf("profile %s omitted: unsupported core %s", profile.NodeID, profile.Core))
			continue
		}
		if profile.AppliedSHA256 == "" {
			warnings = append(warnings, fmt.Sprintf("profile %s omitted: no applied config", profile.NodeID))
			continue
		}
		if profile.LastError != "" {
			warnings = append(warnings, fmt.Sprintf("profile %s omitted: last apply error is not clear", profile.NodeID))
			continue
		}
		host := strings.TrimSpace(profile.Hostname)
		if host == "" {
			warnings = append(warnings, fmt.Sprintf("profile %s omitted: hostname is required for subscriptions", profile.NodeID))
			continue
		}
		if err := validateSubscriptionHost(host); err != nil {
			return nil, nil, fmt.Errorf("profile %s hostname: %w", profile.NodeID, err)
		}
		for _, inboundID := range profile.InboundIDs {
			inbound, ok := byID[inboundID]
			if !ok {
				return nil, nil, fmt.Errorf("profile %s references missing inbound %q", profile.NodeID, inboundID)
			}
			if !userAppliesToInbound(user, inboundID) {
				continue
			}
			endpoint, err := vlessRealityEndpointFor(user, sp, inbound, host)
			if err != nil {
				return nil, nil, err
			}
			endpoints = append(endpoints, endpoint)
		}
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Label == endpoints[j].Label {
			if endpoints[i].NodeID == endpoints[j].NodeID {
				return endpoints[i].InboundID < endpoints[j].InboundID
			}
			return endpoints[i].NodeID < endpoints[j].NodeID
		}
		return endpoints[i].Label < endpoints[j].Label
	})
	assignUniqueEndpointTags(endpoints)
	return endpoints, warnings, nil
}

func vlessRealityEndpointFor(user model.ProxyUser, sp SubscriptionProfile, inbound model.ProxyInbound, host string) (VLESSRealityEndpoint, error) {
	if err := validateVLESSRealityInbound(inbound); err != nil {
		return VLESSRealityEndpoint{}, err
	}
	if inbound.RealityPublicKey == "" || !realityKeyRe.MatchString(inbound.RealityPublicKey) {
		return VLESSRealityEndpoint{}, fmt.Errorf("inbound %s has invalid reality public key", inbound.ID)
	}
	if len(inbound.RealityShortIDs) == 0 {
		return VLESSRealityEndpoint{}, fmt.Errorf("inbound %s requires at least one reality short id", inbound.ID)
	}
	shortID := strings.ToLower(strings.TrimSpace(inbound.RealityShortIDs[0]))
	if shortID == "" || !realityShortIDRe.MatchString(shortID) || len(shortID)%2 != 0 {
		return VLESSRealityEndpoint{}, fmt.Errorf("inbound %s has invalid reality short id %q", inbound.ID, inbound.RealityShortIDs[0])
	}
	sni := strings.TrimSpace(inbound.SNI)
	if inbound.SNI != "" {
		if err := validateHostToken(sni); err != nil {
			return VLESSRealityEndpoint{}, fmt.Errorf("inbound %s sni: %w", inbound.ID, err)
		}
	}
	fingerprint := strings.TrimSpace(inbound.Fingerprint)
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	if strings.ContainsFunc(fingerprint, isUnsafeControl) {
		return VLESSRealityEndpoint{}, fmt.Errorf("inbound %s fingerprint contains control characters", inbound.ID)
	}
	label := subscriptionLabel(sp, inbound)
	return VLESSRealityEndpoint{
		Label:       label,
		Tag:         label,
		NodeID:      strings.TrimSpace(sp.Profile.NodeID),
		InboundID:   inbound.ID,
		Server:      host,
		ServerPort:  inbound.Port,
		UUID:        strings.ToLower(user.UUID),
		Flow:        "xtls-rprx-vision",
		Network:     model.ProxyTransportTCP,
		SNI:         sni,
		Fingerprint: fingerprint,
		ALPN:        cleanStringList(inbound.ALPN),
		PublicKey:   inbound.RealityPublicKey,
		ShortID:     shortID,
	}, nil
}

func (e VLESSRealityEndpoint) Link() string {
	values := url.Values{}
	values.Set("type", e.Network)
	values.Set("encryption", "none")
	values.Set("security", model.ProxySecurityReality)
	values.Set("flow", e.Flow)
	values.Set("pbk", e.PublicKey)
	values.Set("sid", e.ShortID)
	if e.SNI != "" {
		values.Set("sni", e.SNI)
	}
	if e.Fingerprint != "" {
		values.Set("fp", e.Fingerprint)
	}
	if len(e.ALPN) > 0 {
		values.Set("alpn", strings.Join(e.ALPN, ","))
	}
	return "vless://" + e.UUID + "@" + net.JoinHostPort(e.Server, strconv.Itoa(e.ServerPort)) + "?" + values.Encode() + "#" + url.PathEscape(e.Label)
}

func assignUniqueEndpointTags(endpoints []VLESSRealityEndpoint) {
	counts := map[string]int{}
	for _, endpoint := range endpoints {
		counts[endpoint.Label]++
	}
	seen := map[string]int{}
	for i := range endpoints {
		label := endpoints[i].Label
		if counts[label] == 1 {
			endpoints[i].Tag = label
			continue
		}
		seen[label]++
		suffix := strings.Trim(endpoints[i].NodeID+" "+endpoints[i].InboundID, " ")
		if suffix == "" {
			suffix = strconv.Itoa(seen[label])
		}
		endpoints[i].Tag = label + " (" + suffix + ")"
	}
}

func subscriptionLabel(sp SubscriptionProfile, inbound model.ProxyInbound) string {
	node := strings.TrimSpace(sp.NodeName)
	if node == "" {
		node = strings.TrimSpace(sp.Profile.NodeID)
	}
	name := strings.TrimSpace(inbound.Name)
	if name == "" || name == inbound.ID {
		return node
	}
	return node + " - " + name
}

func validateSubscriptionHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if strings.ContainsFunc(host, isUnsafeControl) {
		return fmt.Errorf("host contains control characters")
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.IsValid() {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("host is too long")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("host has an empty label")
	}
	if strings.ContainsAny(host, "/\\\"'`$;&|<>(){}[]@?#%:, ") {
		return fmt.Errorf("host contains unsafe characters: %q", host)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("host has an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("host label is too long")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("host label has invalid hyphen placement")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("host contains unsupported character %q", r)
		}
	}
	return nil
}

func PlainSubscription(links []string) []byte {
	if len(links) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(links, "\n") + "\n")
}

func Base64Subscription(links []string) []byte {
	plain := PlainSubscription(links)
	if len(plain) == 0 {
		return []byte{}
	}
	return []byte(base64.StdEncoding.EncodeToString(plain))
}

type singBoxClientConfig struct {
	Outbounds []singBoxClientVLESSOutbound `json:"outbounds"`
}

type singBoxClientVLESSOutbound struct {
	Type       string           `json:"type"`
	Tag        string           `json:"tag"`
	Server     string           `json:"server"`
	ServerPort int              `json:"server_port"`
	UUID       string           `json:"uuid"`
	Flow       string           `json:"flow,omitempty"`
	Network    string           `json:"network,omitempty"`
	TLS        singBoxClientTLS `json:"tls"`
}

type singBoxClientTLS struct {
	Enabled    bool                 `json:"enabled"`
	ServerName string               `json:"server_name,omitempty"`
	ALPN       []string             `json:"alpn,omitempty"`
	UTLS       *singBoxClientUTLS   `json:"utls,omitempty"`
	Reality    singBoxClientReality `json:"reality"`
}

type singBoxClientUTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type singBoxClientReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

// SingBoxClientSubscription renders a minimal sing-box client outbound config
// for the supported VLESS+REALITY+TCP endpoints.
func SingBoxClientSubscription(endpoints []VLESSRealityEndpoint) ([]byte, error) {
	cfg := singBoxClientConfig{Outbounds: make([]singBoxClientVLESSOutbound, 0, len(endpoints))}
	for _, endpoint := range endpoints {
		tls := singBoxClientTLS{
			Enabled:    true,
			ServerName: endpoint.SNI,
			ALPN:       append([]string(nil), endpoint.ALPN...),
			Reality: singBoxClientReality{
				Enabled:   true,
				PublicKey: endpoint.PublicKey,
				ShortID:   endpoint.ShortID,
			},
		}
		if endpoint.Fingerprint != "" {
			tls.UTLS = &singBoxClientUTLS{Enabled: true, Fingerprint: endpoint.Fingerprint}
		}
		cfg.Outbounds = append(cfg.Outbounds, singBoxClientVLESSOutbound{
			Type:       model.ProxyProtocolVLESS,
			Tag:        endpoint.Tag,
			Server:     endpoint.Server,
			ServerPort: endpoint.ServerPort,
			UUID:       endpoint.UUID,
			Flow:       endpoint.Flow,
			Network:    endpoint.Network,
			TLS:        tls,
		})
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal sing-box subscription: %w", err)
	}
	return append(data, '\n'), nil
}

// ClashMetaSubscription renders a dependency-free Clash.Meta-compatible YAML
// proxy list for the supported VLESS+REALITY+TCP endpoints.
func ClashMetaSubscription(endpoints []VLESSRealityEndpoint) []byte {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, endpoint := range endpoints {
		b.WriteString("  - name: ")
		b.WriteString(yamlQuote(endpoint.Tag))
		b.WriteString("\n")
		b.WriteString("    type: vless\n")
		b.WriteString("    server: ")
		b.WriteString(yamlQuote(endpoint.Server))
		b.WriteString("\n")
		b.WriteString("    port: ")
		b.WriteString(strconv.Itoa(endpoint.ServerPort))
		b.WriteString("\n")
		b.WriteString("    uuid: ")
		b.WriteString(yamlQuote(endpoint.UUID))
		b.WriteString("\n")
		b.WriteString("    network: tcp\n")
		b.WriteString("    tls: true\n")
		b.WriteString("    udp: true\n")
		b.WriteString("    flow: ")
		b.WriteString(yamlQuote(endpoint.Flow))
		b.WriteString("\n")
		b.WriteString("    packet-encoding: xudp\n")
		b.WriteString("    encryption: \"\"\n")
		if endpoint.SNI != "" {
			b.WriteString("    servername: ")
			b.WriteString(yamlQuote(endpoint.SNI))
			b.WriteString("\n")
		}
		if endpoint.Fingerprint != "" {
			b.WriteString("    client-fingerprint: ")
			b.WriteString(yamlQuote(endpoint.Fingerprint))
			b.WriteString("\n")
		}
		if len(endpoint.ALPN) > 0 {
			b.WriteString("    alpn:\n")
			for _, alpn := range endpoint.ALPN {
				b.WriteString("      - ")
				b.WriteString(yamlQuote(alpn))
				b.WriteString("\n")
			}
		}
		b.WriteString("    reality-opts:\n")
		b.WriteString("      public-key: ")
		b.WriteString(yamlQuote(endpoint.PublicKey))
		b.WriteString("\n")
		b.WriteString("      short-id: ")
		b.WriteString(yamlQuote(endpoint.ShortID))
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func yamlQuote(value string) string {
	return strconv.Quote(value)
}

func SubscriptionUserinfo(user model.ProxyUser) string {
	expire := int64(0)
	if !user.ExpiresAt.IsZero() {
		expire = user.ExpiresAt.Unix()
	}
	total := user.TrafficLimitBytes
	if total < 0 {
		total = 0
	}
	download := user.UsedBytes
	if download < 0 {
		download = 0
	}
	return fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", download, total, expire)
}
