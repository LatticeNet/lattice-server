// Package proxycore renders reviewed proxy-core artifacts from server-owned
// intent models. It is deliberately narrow at first: the MVP supports only
// sing-box VLESS over TCP with REALITY, and rejects every other combination.
package proxycore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	DefaultSingBoxConfigPath = "/etc/sing-box/config.json"
	DefaultXrayConfigPath    = "/usr/local/etc/xray/config.json"
	DefaultListenAddress     = "::"
	defaultOutboundTag       = "direct"
)

var (
	safeTagRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	uuidRe           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	realityKeyRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	realityShortIDRe = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)
)

// RenderOptions controls deterministic render behavior. Now is used to filter
// expired users; zero means time.Now().UTC().
type RenderOptions struct {
	Now time.Time
}

// Artifact is the canonical renderer output for the plan/apply path. ConfigJSON
// contains user UUIDs and REALITY private keys and must be treated as a
// node-scoped secret-bearing artifact.
type Artifact struct {
	Core         string
	ConfigJSON   string
	ConfigSHA256 string
	ConfigPath   string
	Warnings     []string
}

// SingBoxArtifact is kept as a compatibility alias for older call sites while
// xray support shares the same secret-bearing artifact contract.
type SingBoxArtifact = Artifact

type singBoxConfig struct {
	Log          singBoxLog           `json:"log"`
	Inbounds     []singBoxInbound     `json:"inbounds"`
	Outbounds    []singBoxOutbound    `json:"outbounds"`
	Route        singBoxRoute         `json:"route"`
	Experimental *singBoxExperimental `json:"experimental,omitempty"`
}

type singBoxLog struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type singBoxExperimental struct {
	ClashAPI *singBoxClashAPI `json:"clash_api,omitempty"`
	V2RayAPI *singBoxV2RayAPI `json:"v2ray_api,omitempty"`
}

// singBoxV2RayAPI is the loopback stats endpoint the usage collector reads.
// Like the Clash API it must never bind a routable address: it reports the
// traffic of every user on the node.
type singBoxV2RayAPI struct {
	Listen string            `json:"listen"`
	Stats  singBoxV2RayStats `json:"stats"`
}

// singBoxV2RayStats is the counter allowlist, and it is not optional
// decoration. sing-box builds its inbound, outbound and user match sets from
// these three lists when the service starts, and returns a connection matching
// none of them uncounted. Enabled with empty lists is a stats API that reports
// zero for everything, which reads as "usage collection is on" while nothing
// is measured, so the renderer always fills them from what it just rendered.
type singBoxV2RayStats struct {
	Enabled   bool     `json:"enabled"`
	Inbounds  []string `json:"inbounds"`
	Outbounds []string `json:"outbounds"`
	Users     []string `json:"users"`
}

// singBoxClashAPI is the loopback control endpoint the trace collector reads.
// It is what makes per-node log verbosity changeable without restarting the
// core, because sing-box delivers to Clash API subscribers without applying
// log.level. Restarting is what drops every live connection, so the whole
// feature depends on this block being present.
type singBoxClashAPI struct {
	ExternalController string `json:"external_controller"`
	Secret             string `json:"secret,omitempty"`
}

// defaultSingBoxLogLevel is what a managed node gets when its profile does not
// say. It is "info" rather than "warn" because the connection lifecycle lines
// that a trace record is assembled from are logged at info; at warn a node is
// silent about every connection it serves.
const defaultSingBoxLogLevel = "info"

// allowedSingBoxLogLevels are the levels a profile may ask for. Anything else
// is rejected rather than silently corrected, because a typo that quietly
// downgrades a node to "no connection logging" is exactly the kind of silent
// failure this subsystem exists to remove.
var allowedSingBoxLogLevels = map[string]bool{
	"trace": true, "debug": true, "info": true,
	"warn": true, "error": true, "fatal": true, "panic": true,
}

// renderLogAndExperimental builds the log block and, when the profile asks for
// them, the Clash API and stats API blocks. Both addresses must be loopback:
// one serves live connection metadata and log lines, the other every user's
// traffic totals, so binding either anywhere reachable would hand that to the
// network.
//
// inbounds and outbounds are the tags this render produced and users the names
// it wrote, which is what the stats allowlist has to name for the counters to
// exist. Passing them in rather than deriving them later is what keeps the
// allowlist from drifting away from the config it describes.
func renderLogAndExperimental(profile model.ProxyNodeProfile, inbounds, outbounds, users []string) (singBoxLog, *singBoxExperimental, error) {
	level := strings.TrimSpace(profile.LogLevel)
	if level == "" {
		level = defaultSingBoxLogLevel
	}
	if !allowedSingBoxLogLevels[level] {
		return singBoxLog{}, nil, fmt.Errorf("log_level %q is not a valid sing-box level", profile.LogLevel)
	}
	log := singBoxLog{Level: level, Timestamp: true}

	experimental := &singBoxExperimental{}
	if addr := strings.TrimSpace(profile.ClashAPI); addr != "" {
		if err := validateLoopbackAddr(addr); err != nil {
			return singBoxLog{}, nil, fmt.Errorf("clash_api: %w", err)
		}
		experimental.ClashAPI = &singBoxClashAPI{
			ExternalController: addr,
			Secret:             strings.TrimSpace(profile.ClashAPISecret),
		}
	}
	if addr := strings.TrimSpace(profile.StatsAPI); addr != "" {
		if err := validateLoopbackAddr(addr); err != nil {
			return singBoxLog{}, nil, fmt.Errorf("stats_api: %w", err)
		}
		experimental.V2RayAPI = &singBoxV2RayAPI{
			Listen: addr,
			Stats: singBoxV2RayStats{
				Enabled:   true,
				Inbounds:  sortedUnique(inbounds),
				Outbounds: sortedUnique(outbounds),
				Users:     sortedUnique(users),
			},
		}
	}
	if experimental.ClashAPI == nil && experimental.V2RayAPI == nil {
		return log, nil, nil
	}
	return log, experimental, nil
}

// sortedUnique returns the non-empty values of in, deduplicated and ordered, so
// two renders of the same intent produce byte-identical allowlists. The result
// is never nil: an empty JSON list is a meaningful value here, and omitting the
// key would leave sing-box matching on nothing.
func sortedUnique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// validateLoopbackAddr accepts only host:port where host is a loopback literal
// or "localhost". A hostname that merely resolves to loopback today is refused,
// because resolution is not a property the renderer can pin.
func validateLoopbackAddr(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q must be host:port", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port %q is out of range", portStr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host %q must be a loopback literal or localhost", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("host %q is not a loopback address", host)
	}
	return nil
}

type singBoxInbound struct {
	Type       string             `json:"type"`
	Tag        string             `json:"tag"`
	Listen     string             `json:"listen"`
	ListenPort int                `json:"listen_port"`
	Users      []singBoxVLESSUser `json:"users"`
	TLS        singBoxTLS         `json:"tls"`
}

type singBoxVLESSUser struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"-"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

type singBoxTLS struct {
	Enabled    bool           `json:"enabled"`
	ServerName string         `json:"server_name,omitempty"`
	ALPN       []string       `json:"alpn,omitempty"`
	Reality    singBoxReality `json:"reality"`
}

type singBoxReality struct {
	Enabled           bool                 `json:"enabled"`
	Handshake         singBoxRealityTarget `json:"handshake"`
	PrivateKey        string               `json:"private_key"`
	ShortID           []string             `json:"short_id"`
	MaxTimeDifference string               `json:"max_time_difference,omitempty"`
}

type singBoxRealityTarget struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

type singBoxOutbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type singBoxRoute struct {
	Final string `json:"final"`
}

// RenderSingBoxConfigJSON renders a canonical sing-box config for one node
// profile. The output is valid JSON with a trailing newline and includes the
// direct outbound that server-side proxy deployments need by default.
func RenderSingBoxConfigJSON(profile model.ProxyNodeProfile, inbounds []model.ProxyInbound, users []model.ProxyUser, opts RenderOptions) (SingBoxArtifact, error) {
	cfg, warnings, err := RenderSingBoxConfig(profile, inbounds, users, opts)
	if err != nil {
		return SingBoxArtifact{}, err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return SingBoxArtifact{}, fmt.Errorf("marshal sing-box config: %w", err)
	}
	data = append(data, '\n')
	sum := sha256.Sum256(data)
	path := strings.TrimSpace(profile.ConfigPath)
	if path == "" {
		path = DefaultSingBoxConfigPath
	}
	return SingBoxArtifact{
		Core:         model.ProxyCoreSingbox,
		ConfigJSON:   string(data),
		ConfigSHA256: hex.EncodeToString(sum[:]),
		ConfigPath:   path,
		Warnings:     warnings,
	}, nil
}

// RenderSingBoxConfig builds the in-memory sing-box config. It returns structs
// rather than string templates so operator-controlled labels cannot break JSON
// syntax.
func RenderSingBoxConfig(profile model.ProxyNodeProfile, inbounds []model.ProxyInbound, users []model.ProxyUser, opts RenderOptions) (singBoxConfig, []string, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateProfileForCore(profile, model.ProxyCoreSingbox); err != nil {
		return singBoxConfig{}, nil, err
	}
	byID, err := inboundMap(inbounds)
	if err != nil {
		return singBoxConfig{}, nil, err
	}
	selected, err := selectedInbounds(profile.InboundIDs, byID)
	if err != nil {
		return singBoxConfig{}, nil, err
	}

	rendered := make([]singBoxInbound, 0, len(selected))
	warnings := []string{}
	usedPorts := map[string]string{}
	for _, inbound := range selected {
		listen := strings.TrimSpace(profile.ListenIP)
		if listen == "" {
			listen = strings.TrimSpace(inbound.Listen)
		}
		if listen == "" {
			listen = DefaultListenAddress
		}
		if err := validateListenAddress(listen); err != nil {
			return singBoxConfig{}, nil, fmt.Errorf("inbound %s: %w", inbound.ID, err)
		}
		portKey := listen + ":" + strconv.Itoa(inbound.Port)
		if previous := usedPorts[portKey]; previous != "" {
			return singBoxConfig{}, nil, fmt.Errorf("inbound %s conflicts with %s on %s", inbound.ID, previous, portKey)
		}
		usedPorts[portKey] = inbound.ID

		sbInbound, skipped, err := renderVLESSRealityInbound(inbound, listen, users, now)
		if err != nil {
			return singBoxConfig{}, nil, err
		}
		warnings = append(warnings, skipped...)
		rendered = append(rendered, sbInbound)
	}
	outbounds := []singBoxOutbound{{Type: "direct", Tag: defaultOutboundTag}}
	// The names the stats allowlist has to carry, taken from what was just
	// rendered rather than from the intent, so a user dropped as expired or an
	// inbound skipped as invalid is not claimed to be counted.
	inboundTags := make([]string, 0, len(rendered))
	userNames := []string{}
	for _, in := range rendered {
		inboundTags = append(inboundTags, in.Tag)
		for _, u := range in.Users {
			// Only a named user can be counted individually: the allowlist
			// matches on name, so an unnamed one stays in the inbound total.
			if u.Name != "" {
				userNames = append(userNames, u.Name)
			}
		}
	}
	outboundTags := make([]string, 0, len(outbounds))
	for _, out := range outbounds {
		outboundTags = append(outboundTags, out.Tag)
	}
	logBlock, experimental, err := renderLogAndExperimental(profile, inboundTags, outboundTags, userNames)
	if err != nil {
		return singBoxConfig{}, nil, err
	}
	return singBoxConfig{
		Log:          logBlock,
		Inbounds:     rendered,
		Outbounds:    outbounds,
		Route:        singBoxRoute{Final: defaultOutboundTag},
		Experimental: experimental,
	}, warnings, nil
}

func validateProfileForCore(profile model.ProxyNodeProfile, core string) error {
	if strings.TrimSpace(profile.NodeID) == "" {
		return errors.New("proxy node profile requires node_id")
	}
	if profile.Core != core {
		return fmt.Errorf("proxy profile uses core %q, renderer requires %s", profile.Core, core)
	}
	if len(profile.InboundIDs) == 0 {
		return errors.New("proxy node profile requires at least one inbound")
	}
	seen := map[string]bool{}
	for _, id := range profile.InboundIDs {
		if !safeTagRe.MatchString(id) {
			return fmt.Errorf("invalid inbound id %q", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate inbound id %q", id)
		}
		seen[id] = true
	}
	if profile.ConfigPath != "" {
		if err := validateConfigPath(profile.ConfigPath); err != nil {
			return err
		}
	}
	return nil
}

func inboundMap(inbounds []model.ProxyInbound) (map[string]model.ProxyInbound, error) {
	out := make(map[string]model.ProxyInbound, len(inbounds))
	for _, inbound := range inbounds {
		if !safeTagRe.MatchString(inbound.ID) {
			return nil, fmt.Errorf("invalid inbound id %q", inbound.ID)
		}
		if _, exists := out[inbound.ID]; exists {
			return nil, fmt.Errorf("duplicate inbound id %q", inbound.ID)
		}
		out[inbound.ID] = inbound
	}
	return out, nil
}

func selectedInbounds(ids []string, byID map[string]model.ProxyInbound) ([]model.ProxyInbound, error) {
	out := make([]model.ProxyInbound, 0, len(ids))
	for _, id := range ids {
		inbound, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("profile references missing inbound %q", id)
		}
		if !inbound.Enabled {
			return nil, fmt.Errorf("profile references disabled inbound %q", id)
		}
		out = append(out, inbound)
	}
	return out, nil
}

func renderVLESSRealityInbound(inbound model.ProxyInbound, listen string, users []model.ProxyUser, now time.Time) (singBoxInbound, []string, error) {
	if err := validateVLESSRealityInboundForCore(inbound, model.ProxyCoreSingbox); err != nil {
		return singBoxInbound{}, nil, err
	}
	eligible, warnings, err := eligibleVLESSUsers(inbound.ID, users, now)
	if err != nil {
		return singBoxInbound{}, nil, err
	}
	if len(eligible) == 0 {
		return singBoxInbound{}, nil, fmt.Errorf("inbound %s has no eligible VLESS users", inbound.ID)
	}
	target, err := parseRealityDest(inbound.RealityDest)
	if err != nil {
		return singBoxInbound{}, nil, fmt.Errorf("inbound %s reality_dest: %w", inbound.ID, err)
	}
	tls := singBoxTLS{
		Enabled: true,
		ALPN:    cleanStringList(inbound.ALPN),
		Reality: singBoxReality{
			Enabled:           true,
			Handshake:         target,
			PrivateKey:        inbound.RealityPrivateKey,
			ShortID:           cleanStringList(inbound.RealityShortIDs),
			MaxTimeDifference: "1m",
		},
	}
	if inbound.SNI != "" {
		if err := validateHostToken(inbound.SNI); err != nil {
			return singBoxInbound{}, nil, fmt.Errorf("inbound %s sni: %w", inbound.ID, err)
		}
		tls.ServerName = inbound.SNI
	}
	return singBoxInbound{
		Type:       model.ProxyProtocolVLESS,
		Tag:        inbound.ID,
		Listen:     listen,
		ListenPort: inbound.Port,
		Users:      eligible,
		TLS:        tls,
	}, warnings, nil
}

func validateVLESSRealityInbound(inbound model.ProxyInbound) error {
	if inbound.Core != model.ProxyCoreSingbox && inbound.Core != model.ProxyCoreXray {
		return fmt.Errorf("inbound %s uses unsupported core %q", inbound.ID, inbound.Core)
	}
	return validateVLESSRealityInboundShape(inbound)
}

func validateVLESSRealityInboundForCore(inbound model.ProxyInbound, core string) error {
	if inbound.Core != core {
		return fmt.Errorf("inbound %s uses core %q, renderer requires %s", inbound.ID, inbound.Core, core)
	}
	return validateVLESSRealityInboundShape(inbound)
}

func validateVLESSRealityInboundShape(inbound model.ProxyInbound) error {
	if inbound.Protocol != model.ProxyProtocolVLESS {
		return fmt.Errorf("inbound %s uses unsupported protocol %q", inbound.ID, inbound.Protocol)
	}
	if inbound.Transport != "" && inbound.Transport != model.ProxyTransportTCP {
		return fmt.Errorf("inbound %s uses unsupported transport %q", inbound.ID, inbound.Transport)
	}
	if inbound.Path != "" || inbound.Host != "" {
		return fmt.Errorf("inbound %s cannot set path/host for the TCP REALITY MVP renderer", inbound.ID)
	}
	if inbound.Security != model.ProxySecurityReality {
		return fmt.Errorf("inbound %s uses unsupported security %q", inbound.ID, inbound.Security)
	}
	if inbound.Port < 1 || inbound.Port > 65535 {
		return fmt.Errorf("inbound %s has invalid port %d", inbound.ID, inbound.Port)
	}
	if !realityKeyRe.MatchString(inbound.RealityPrivateKey) {
		return fmt.Errorf("inbound %s has invalid reality private key", inbound.ID)
	}
	if len(inbound.RealityShortIDs) == 0 {
		return fmt.Errorf("inbound %s requires at least one reality short id", inbound.ID)
	}
	for _, shortID := range inbound.RealityShortIDs {
		if strings.TrimSpace(shortID) == "" {
			return fmt.Errorf("inbound %s has empty reality short id", inbound.ID)
		}
		if !realityShortIDRe.MatchString(shortID) || len(shortID)%2 != 0 {
			return fmt.Errorf("inbound %s has invalid reality short id %q", inbound.ID, shortID)
		}
	}
	for _, alpn := range inbound.ALPN {
		if strings.ContainsFunc(alpn, isUnsafeControl) {
			return fmt.Errorf("inbound %s has unsafe alpn value", inbound.ID)
		}
	}
	if inbound.CertPath != "" || inbound.KeyPath != "" {
		return fmt.Errorf("inbound %s cannot combine certificate paths with reality in the MVP renderer", inbound.ID)
	}
	if inbound.SSMethod != "" {
		return fmt.Errorf("inbound %s shadowsocks method is not valid for VLESS", inbound.ID)
	}
	return nil
}

func eligibleVLESSUsers(inboundID string, users []model.ProxyUser, now time.Time) ([]singBoxVLESSUser, []string, error) {
	out := []singBoxVLESSUser{}
	warnings := []string{}
	seenUUID := map[string]string{}
	sorted := append([]model.ProxyUser(nil), users...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})
	for _, user := range sorted {
		if !userAppliesToInbound(user, inboundID) {
			continue
		}
		reason := skipProxyUserReason(user, now)
		if reason != "" {
			warnings = append(warnings, fmt.Sprintf("user %s omitted from inbound %s: %s", user.ID, inboundID, reason))
			continue
		}
		if !safeTagRe.MatchString(user.ID) {
			return nil, nil, fmt.Errorf("invalid proxy user id %q", user.ID)
		}
		if strings.ContainsFunc(user.Name, isUnsafeControl) {
			return nil, nil, fmt.Errorf("proxy user %s has unsafe name", user.ID)
		}
		if !uuidRe.MatchString(user.UUID) {
			return nil, nil, fmt.Errorf("proxy user %s has invalid uuid", user.ID)
		}
		if previous := seenUUID[strings.ToLower(user.UUID)]; previous != "" {
			return nil, nil, fmt.Errorf("proxy user %s duplicates uuid with %s", user.ID, previous)
		}
		seenUUID[strings.ToLower(user.UUID)] = user.ID
		out = append(out, singBoxVLESSUser{ID: user.ID, Name: user.Name, UUID: strings.ToLower(user.UUID), Flow: "xtls-rprx-vision"})
	}
	return out, warnings, nil
}

func userAppliesToInbound(user model.ProxyUser, inboundID string) bool {
	if len(user.InboundIDs) == 0 {
		return true
	}
	for _, id := range user.InboundIDs {
		if id == inboundID {
			return true
		}
	}
	return false
}

func skipProxyUserReason(user model.ProxyUser, now time.Time) string {
	if !user.Enabled {
		return "disabled"
	}
	switch user.Status {
	case "", model.ProxyUserStatusActive:
	case model.ProxyUserStatusDisabled, model.ProxyUserStatusExpired, model.ProxyUserStatusOverQuota:
		return user.Status
	default:
		return "unknown status " + user.Status
	}
	if !user.ExpiresAt.IsZero() && !user.ExpiresAt.After(now) {
		return "expired"
	}
	if user.TrafficLimitBytes > 0 && user.UsedBytes >= user.TrafficLimitBytes {
		return "over_quota"
	}
	return ""
}

func validateListenAddress(value string) error {
	if strings.ContainsFunc(value, isUnsafeControl) {
		return fmt.Errorf("listen address contains control characters")
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return fmt.Errorf("listen address must be an IP address: %q", value)
	}
	return nil
}

func validateConfigPath(value string) error {
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("config_path has leading or trailing whitespace: %q", value)
	}
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("config_path must be absolute: %q", value)
	}
	if strings.ContainsFunc(value, isUnsafeControl) {
		return fmt.Errorf("config_path contains control characters")
	}
	if strings.ContainsAny(value, "\"'`$;&|<>") {
		return fmt.Errorf("config_path contains unsafe shell characters: %q", value)
	}
	return nil
}

func parseRealityDest(value string) (singBoxRealityTarget, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return singBoxRealityTarget{}, errors.New("required")
	}
	if strings.ContainsFunc(value, isUnsafeControl) {
		return singBoxRealityTarget{}, errors.New("contains control characters")
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return singBoxRealityTarget{}, err
	}
	if err := validateHostToken(host); err != nil {
		return singBoxRealityTarget{}, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return singBoxRealityTarget{}, fmt.Errorf("invalid port %q", portText)
	}
	return singBoxRealityTarget{Server: host, ServerPort: port}, nil
}

func validateHostToken(host string) error {
	if strings.TrimSpace(host) == "" {
		return errors.New("host is required")
	}
	if strings.ContainsFunc(host, isUnsafeControl) {
		return errors.New("host contains control characters")
	}
	if strings.ContainsAny(host, "/\\\"'`$;&|<>(){}[]") {
		return fmt.Errorf("host contains unsafe characters: %q", host)
	}
	return nil
}

func cleanStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func isUnsafeControl(r rune) bool {
	return unicode.IsControl(r) || r == '\u007f'
}
