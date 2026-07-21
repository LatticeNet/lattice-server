package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// NodeProfileRuntime is the vpn-core per-node runtime view (design-12 S4): the
// operator-facing "is this node under vpn-core management, what core/version is on
// it, is the config applied, is the collector healthy, what was last probed" page.
// It is a DERIVED read-model unioning the Lattice ProxyNodeProfile (managed config
// + apply/collector status) with the live discovered SingBoxInventory (core version
// + discovered node count + discovery status). A node appears if it has either.
type NodeProfileRuntime struct {
	NodeID          string                 `json:"node_id"`
	NodeName        string                 `json:"node_name,omitempty"`
	Managed         bool                   `json:"managed"` // a Lattice ProxyNodeProfile exists
	Core            string                 `json:"core,omitempty"`
	CoreVersion     string                 `json:"core_version,omitempty"`
	ConfigPath      string                 `json:"config_path,omitempty"`
	StatsAPI        string                 `json:"stats_api,omitempty"`
	Applied         bool                   `json:"applied"`
	LastApplyAt     string                 `json:"last_apply_at,omitempty"`
	LastError       string                 `json:"last_error,omitempty"`
	InboundCount    int                    `json:"inbound_count"`
	DiscoveredCount int                    `json:"discovered_count"`
	DiscoveryStatus string                 `json:"discovery_status,omitempty"`
	DiscoveryError  string                 `json:"discovery_error,omitempty"`
	DiscoveredAt    string                 `json:"discovered_at,omitempty"`
	Collector       *UsageCollectorRuntime `json:"collector,omitempty"`
	Capabilities    []string               `json:"capabilities"`
}

type UsageCollectorRuntime struct {
	Source    string `json:"source,omitempty"`
	Status    string `json:"status,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
	LastOKAt  string `json:"last_ok_at,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

const rtTimeFmt = "2006-01-02T15:04:05Z07:00"

// buildNodeProfileRuntimes unions managed profiles + discovered inventories per node.
func (s *Server) buildNodeProfileRuntimes() []NodeProfileRuntime {
	byNode := map[string]*NodeProfileRuntime{}
	get := func(nodeID string) *NodeProfileRuntime {
		rt, ok := byNode[nodeID]
		if !ok {
			rt = &NodeProfileRuntime{NodeID: nodeID, NodeName: s.nodeDisplayName(nodeID)}
			byNode[nodeID] = rt
		}
		return rt
	}

	for _, prof := range s.store.ProxyNodeProfiles() {
		rt := get(prof.NodeID)
		rt.Managed = true
		rt.Core = prof.Core
		rt.ConfigPath = prof.ConfigPath
		rt.StatsAPI = prof.StatsAPI
		rt.InboundCount = len(prof.InboundIDs)
		rt.Applied = prof.AppliedSHA256 != ""
		rt.LastError = prof.LastError
		if !prof.LastApplyAt.IsZero() {
			rt.LastApplyAt = prof.LastApplyAt.UTC().Format(rtTimeFmt)
		}
		if prof.UsageCollectorSource != "" || prof.UsageCollectorStatus != "" || prof.UsageCollectorLastError != "" {
			c := &UsageCollectorRuntime{Source: prof.UsageCollectorSource, Status: prof.UsageCollectorStatus, LastError: prof.UsageCollectorLastError}
			if !prof.UsageCollectorCheckedAt.IsZero() {
				c.CheckedAt = prof.UsageCollectorCheckedAt.UTC().Format(rtTimeFmt)
			}
			if !prof.UsageCollectorLastOKAt.IsZero() {
				c.LastOKAt = prof.UsageCollectorLastOKAt.UTC().Format(rtTimeFmt)
			}
			rt.Collector = c
		}
	}

	for _, inv := range s.liveSingBoxInventories(s.now()) {
		rt := get(inv.NodeID)
		if rt.Core == "" {
			rt.Core = "sing-box"
		}
		if inv.CoreVersion != "" {
			rt.CoreVersion = inv.CoreVersion
		}
		rt.DiscoveredCount = len(inv.Nodes)
		rt.DiscoveryStatus = inv.Status
		rt.DiscoveryError = inv.Error
		if !inv.At.IsZero() {
			rt.DiscoveredAt = inv.At.UTC().Format(rtTimeFmt)
		}
	}

	out := make([]NodeProfileRuntime, 0, len(byNode))
	for _, rt := range byNode {
		rt.Capabilities = runtimeCapabilities(rt)
		out = append(out, *rt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// runtimeCapabilities reports what the node-level vpn-core runtime can do TODAY.
// Conservative and honest: only capabilities backed by a shipped code path are
// listed. inspect/stats/add_user are reserved for S1b/S3b and intentionally absent.
func runtimeCapabilities(rt *NodeProfileRuntime) []string {
	caps := []string{"probe"} // node-driven `sb --json list/provision` probe is shipped
	if rt.Managed {
		caps = append(caps, "apply") // plan->approve->apply pipeline exists for managed profiles
	}
	if rt.DiscoveredCount > 0 || rt.DiscoveryStatus != "" {
		caps = append(caps, "discover")
	}
	return caps
}

// vpnCoreProfilesRPC serves latticenet.vpn-core/profiles (design-12 S4), proxy:read.
//
//	query -> {profiles: [...], count}
type vpnCoreProfilePluginConfig struct {
	SingBoxDiscover       bool   `json:"singbox_discover"`
	SingBoxBin            string `json:"singbox_bin,omitempty"`
	ProxyUsageFile        string `json:"proxy_usage_file,omitempty"`
	ProxyUsageURL         string `json:"proxy_usage_url,omitempty"`
	ProxyUsageXrayAPI     string `json:"proxy_usage_xray_api,omitempty"`
	ProxyUsageXrayBin     string `json:"proxy_usage_xray_bin,omitempty"`
	ProxyUsageXrayPattern string `json:"proxy_usage_xray_pattern,omitempty"`
	SingBoxStatsAPI       string `json:"singbox_stats_api,omitempty"`
}

type vpnCoreProfileSettingsRequest struct {
	NodeID string `json:"node_id"`
}

type vpnCoreProfileConfigureRequest struct {
	NodeID string `json:"node_id"`
	vpnCoreProfilePluginConfig
}

type vpnCoreProfilePrerequisites struct {
	AllowExec             bool `json:"allow_exec"`
	AllowRootExec         bool `json:"allow_root_exec"`
	NoExec                bool `json:"no_exec"`
	ReportedAllowExec     bool `json:"reported_allow_exec"`
	ReportedAllowRootExec bool `json:"reported_allow_root_exec"`
	ReportedNoExec        bool `json:"reported_no_exec"`
}

type vpnCoreProfileSettings struct {
	NodeID              string                      `json:"node_id"`
	NodeName            string                      `json:"node_name,omitempty"`
	Prerequisites       vpnCoreProfilePrerequisites `json:"prerequisites"`
	Saved               vpnCoreProfilePluginConfig  `json:"saved"`
	Reported            *vpnCoreProfilePluginConfig `json:"reported,omitempty"`
	ReconfigureRequired bool                        `json:"reconfigure_required"`
}

const (
	vpnCoreProfilePathMax    = 2048
	vpnCoreProfileURLMax     = 4096
	vpnCoreProfilePatternMax = 1024
)

// vpnCoreProfilesRPC serves the plugin-owned profiles control surface. Query is
// fleet-wide and already scope-gated by the plugin gateway. Node settings and
// configuration additionally bind authorization to the exact node here so a
// restricted principal cannot cross its server allowlist through an RPC call.
func (s *Server) vpnCoreProfilesRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "query":
		profiles := s.buildNodeProfileRuntimes()
		if profiles == nil {
			profiles = []NodeProfileRuntime{}
		}
		return json.Marshal(struct {
			Profiles []NodeProfileRuntime `json:"profiles"`
			Count    int                  `json:"count"`
		}{Profiles: profiles, Count: len(profiles)})
	case "settings":
		var req vpnCoreProfileSettingsRequest
		if err := decodeVPNCoreProfileRequest(request, &req); err != nil {
			return nil, err
		}
		nodeID := strings.TrimSpace(req.NodeID)
		if nodeID == "" {
			return nil, errors.New("vpn-core/profiles settings: node_id is required")
		}
		if _, err := s.requireVPNCoreProfileNodeScope(ctx, "node:read", nodeID, "vpn-core.profile.settings"); err != nil {
			return nil, err
		}
		settings, err := s.vpnCoreProfileSettings(nodeID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(settings)
	case "configure":
		var req vpnCoreProfileConfigureRequest
		if err := decodeVPNCoreProfileRequest(request, &req); err != nil {
			return nil, err
		}
		req.NodeID = strings.TrimSpace(req.NodeID)
		if req.NodeID == "" {
			return nil, errors.New("vpn-core/profiles configure: node_id is required")
		}
		p, err := s.requireVPNCoreProfileNodeScope(ctx, "node:admin", req.NodeID, "vpn-core.profile.configure")
		if err != nil {
			return nil, err
		}
		if !rbac.Allows(p.Principal, "task:run", req.NodeID) {
			s.recordPrincipalAudit(p, model.AuditEvent{
				ID: id.New("audit"), NodeID: req.NodeID, Action: "vpn-core.profile.configure",
				Scope: "task:run", Decision: "deny", Reason: "missing exact-node task:run permission",
			})
			return nil, errors.New("vpn-core/profiles configure: task:run denied for node")
		}
		config, err := normalizeVPNCoreProfilePluginConfig(req.vpnCoreProfilePluginConfig)
		if err != nil {
			s.recordPrincipalAudit(p, model.AuditEvent{
				ID: id.New("audit"), NodeID: req.NodeID, Action: "vpn-core.profile.configure",
				Scope: "node:admin", Decision: "deny", Reason: err.Error(),
			})
			return nil, err
		}
		node, ok := s.store.Node(req.NodeID)
		if !ok {
			return nil, errors.New("vpn-core/profiles configure: node not found")
		}
		launch := model.AgentLaunchConfig{}
		if node.AgentLaunch != nil {
			launch = *node.AgentLaunch
		}
		applyVPNCoreProfilePluginConfig(&launch, config)
		launch = normalizeAgentLaunchConfig(launch)
		launch.UpdatedAt = s.now().UTC()
		node.AgentLaunch = &launch
		if err := s.store.UpsertNode(node); err != nil {
			return nil, err
		}
		settings, err := s.vpnCoreProfileSettings(req.NodeID)
		if err != nil {
			return nil, err
		}
		commands := s.agentReconfigureCommands(s.agentEnrollServerURL(), req.NodeID, launch)
		manualCommand := commands["manual"]
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID: id.New("audit"), NodeID: req.NodeID, Action: "vpn-core.profile.configure",
			Scope: "node:admin", Decision: "allow",
			Metadata: map[string]string{"execution": "not_queued", "requires_reconfigure": "true"},
		})
		return json.Marshal(map[string]any{
			"node_id": req.NodeID, "command": manualCommand,
			"commands": map[string]string{"manual": manualCommand},
			"settings": settings, "reconfigure_required": true,
		})
	default:
		return nil, fmt.Errorf("vpn-core/profiles: unknown method %q", method)
	}
}

func decodeVPNCoreProfileRequest(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("vpn-core/profiles: invalid request: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("vpn-core/profiles: invalid trailing request data")
	}
	return nil
}

func (s *Server) requireVPNCoreProfileNodeScope(ctx context.Context, scope, nodeID, action string) (principal, error) {
	p, err := pluginOperatorPrincipal(ctx)
	if err != nil {
		return principal{}, err
	}
	if rbac.Allows(p.Principal, scope, nodeID) {
		return p, nil
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: nodeID, Action: action, Scope: scope,
		Decision: "deny", Reason: "missing scope or server allowlist denied",
	})
	return principal{}, fmt.Errorf("%s denied for node", scope)
}

func (s *Server) vpnCoreProfileSettings(nodeID string) (vpnCoreProfileSettings, error) {
	node, ok := s.store.Node(nodeID)
	if !ok {
		return vpnCoreProfileSettings{}, errors.New("vpn-core/profiles: node not found")
	}
	launch := model.AgentLaunchConfig{}
	if node.AgentLaunch != nil {
		launch = *node.AgentLaunch
	}
	settings := vpnCoreProfileSettings{
		NodeID: node.ID, NodeName: node.Name,
		Prerequisites: vpnCoreProfilePrerequisites{
			AllowExec: launch.AllowExec, AllowRootExec: launch.AllowRootExec, NoExec: launch.NoExec,
		},
		Saved: vpnCoreProfilePluginConfigFromLaunch(launch),
	}
	if runtime := s.agentRuntimeSnapshot(nodeID); runtime != nil {
		reported := vpnCoreProfilePluginConfig{
			SingBoxDiscover: runtime.SingBoxDiscover, SingBoxBin: runtime.SingBoxBin,
			ProxyUsageFile: runtime.ProxyUsageFile, ProxyUsageURL: runtime.ProxyUsageURL,
			ProxyUsageXrayAPI: runtime.ProxyUsageXrayAPI, ProxyUsageXrayBin: runtime.ProxyUsageXrayBin,
			ProxyUsageXrayPattern: runtime.ProxyUsageXrayPattern, SingBoxStatsAPI: runtime.SingBoxStatsAPI,
		}
		settings.Reported = &reported
		settings.Prerequisites.ReportedAllowExec = runtime.AllowExec
		settings.Prerequisites.ReportedAllowRootExec = runtime.AllowRootExec
		settings.Prerequisites.ReportedNoExec = runtime.NoExec
		settings.ReconfigureRequired = settings.Saved != reported
	} else {
		settings.ReconfigureRequired = settings.Saved != (vpnCoreProfilePluginConfig{})
	}
	return settings, nil
}

func vpnCoreProfilePluginConfigFromLaunch(launch model.AgentLaunchConfig) vpnCoreProfilePluginConfig {
	return vpnCoreProfilePluginConfig{
		SingBoxDiscover: launch.SingBoxDiscover, SingBoxBin: launch.SingBoxBin,
		ProxyUsageFile: launch.ProxyUsageFile, ProxyUsageURL: launch.ProxyUsageURL,
		ProxyUsageXrayAPI: launch.ProxyUsageXrayAPI, ProxyUsageXrayBin: launch.ProxyUsageXrayBin,
		ProxyUsageXrayPattern: launch.ProxyUsageXrayPattern, SingBoxStatsAPI: launch.SingBoxStatsAPI,
	}
}

func applyVPNCoreProfilePluginConfig(launch *model.AgentLaunchConfig, config vpnCoreProfilePluginConfig) {
	launch.SingBoxDiscover = config.SingBoxDiscover
	launch.SingBoxBin = config.SingBoxBin
	launch.ProxyUsageFile = config.ProxyUsageFile
	launch.ProxyUsageURL = config.ProxyUsageURL
	launch.ProxyUsageXrayAPI = config.ProxyUsageXrayAPI
	launch.ProxyUsageXrayBin = config.ProxyUsageXrayBin
	launch.ProxyUsageXrayPattern = config.ProxyUsageXrayPattern
	launch.SingBoxStatsAPI = config.SingBoxStatsAPI
}

func normalizeVPNCoreProfilePluginConfig(in vpnCoreProfilePluginConfig) (vpnCoreProfilePluginConfig, error) {
	out := in
	var err error
	for field, value := range map[string]*string{
		"singbox_bin": &out.SingBoxBin, "proxy_usage_file": &out.ProxyUsageFile,
		"proxy_usage_xray_bin": &out.ProxyUsageXrayBin,
	} {
		*value = strings.TrimSpace(*value)
		if len(*value) > vpnCoreProfilePathMax {
			return vpnCoreProfilePluginConfig{}, fmt.Errorf("%s is too long", field)
		}
		if *value != "" {
			if err = validateProxyConfigPath(*value); err != nil {
				return vpnCoreProfilePluginConfig{}, fmt.Errorf("%s is unsafe: %w", field, err)
			}
		}
	}
	out.ProxyUsageURL = strings.TrimSpace(out.ProxyUsageURL)
	if len(out.ProxyUsageURL) > vpnCoreProfileURLMax {
		return vpnCoreProfilePluginConfig{}, errors.New("proxy_usage_url is too long")
	}
	if out.ProxyUsageURL != "" {
		u, parseErr := url.ParseRequestURI(out.ProxyUsageURL)
		if parseErr != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return vpnCoreProfilePluginConfig{}, errors.New("proxy_usage_url must be an absolute http or https URL")
		}
		if u.User != nil || u.Fragment != "" {
			return vpnCoreProfilePluginConfig{}, errors.New("proxy_usage_url must not contain userinfo or a fragment")
		}
	}
	out.ProxyUsageXrayAPI = strings.TrimSpace(out.ProxyUsageXrayAPI)
	if out.ProxyUsageXrayAPI != "" {
		if err := validateProxyHostPort(out.ProxyUsageXrayAPI, "proxy_usage_xray_api"); err != nil {
			return vpnCoreProfilePluginConfig{}, err
		}
	}
	out.SingBoxStatsAPI = strings.TrimSpace(out.SingBoxStatsAPI)
	if out.SingBoxStatsAPI != "" {
		if err := validateProxyHostPort(out.SingBoxStatsAPI, "singbox_stats_api"); err != nil {
			return vpnCoreProfilePluginConfig{}, err
		}
	}
	out.ProxyUsageXrayPattern = strings.TrimSpace(out.ProxyUsageXrayPattern)
	if len(out.ProxyUsageXrayPattern) > vpnCoreProfilePatternMax || strings.ContainsFunc(out.ProxyUsageXrayPattern, proxyUnsafeControl) {
		return vpnCoreProfilePluginConfig{}, errors.New("proxy_usage_xray_pattern must be printable and at most 1024 bytes")
	}
	return out, nil
}
