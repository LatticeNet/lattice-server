package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
)

const (
	// vpnCorePluginID is the first-party proxy/"vpn-core" provider identity. Its
	// rendering engine stays in core (ADR D5/D6); it exposes node connection info
	// to other plugins through the inter-plugin RPC bus (design-09 §F).
	vpnCorePluginID = "latticenet.vpn-core"
	// vpnCoreNodesService is the inter-plugin service id other plugins call to
	// import live node data through a signed, active manifest dependency.
	vpnCoreNodesService = "latticenet.vpn-core/nodes"
	// vpnCoreLinesService is the read-model the dashboard calls (via the design-10
	// gateway) to render the unified, node-grouped Lines view (design-12 S1).
	vpnCoreLinesService = "latticenet.vpn-core/lines"
	// vpnCoreUsersService is the read side of the identity model (design-12 S2),
	// scoped proxy:read; vpnCoreUsersAdminService carries the mutations at
	// proxy:admin so reads and writes are gated independently by the gateway.
	vpnCoreUsersService      = "latticenet.vpn-core/users"
	vpnCoreUsersAdminService = "latticenet.vpn-core/users-admin"
	// vpnCoreUsageService is the 3-D usage read-model (design-12 S3), proxy:read.
	vpnCoreUsageService = "latticenet.vpn-core/usage"
	// vpnCoreProfilesService is the per-node runtime read-model (design-12 S4), proxy:read.
	vpnCoreProfilesService = "latticenet.vpn-core/profiles"
)

// registerVPNCoreRPC registers the in-core vpn-core services on the server's RPC
// bus. Called once from New after s.pluginRPC is created. Registration failure is
// logged, not fatal: a missing inter-plugin service degrades that integration
// without taking down the server.
func (s *Server) registerVPNCoreRPC() {
	if s.pluginRPC == nil {
		return
	}
	if err := s.pluginRPC.Register(vpnCorePluginID, vpnCoreNodesService, "v1", []string{"export", "list"}, s.vpnCoreNodesRPC); err != nil {
		s.logger.Printf("vpn-core: register %s failed: %v", vpnCoreNodesService, err)
	}
	if err := s.pluginRPC.Register(vpnCorePluginID, vpnCoreLinesService, "v1", []string{"list", "get", "sync_metadata"}, s.vpnCoreLinesRPC); err != nil {
		s.logger.Printf("vpn-core: register %s failed: %v", vpnCoreLinesService, err)
	}
	if err := s.pluginRPC.Register(vpnCorePluginID, vpnCoreUsersService, "v1", []string{"list", "get"}, s.vpnCoreUsersRPC); err != nil {
		s.logger.Printf("vpn-core: register %s failed: %v", vpnCoreUsersService, err)
	}
	if err := s.pluginRPC.Register(vpnCorePluginID, vpnCoreUsersAdminService, "v1", []string{"create", "update", "delete", "bind", "unbind"}, s.vpnCoreUsersAdminRPC); err != nil {
		s.logger.Printf("vpn-core: register %s failed: %v", vpnCoreUsersAdminService, err)
	}
	if err := s.pluginRPC.Register(vpnCorePluginID, vpnCoreUsageService, "v1", []string{"query"}, s.vpnCoreUsageRPC); err != nil {
		s.logger.Printf("vpn-core: register %s failed: %v", vpnCoreUsageService, err)
	}
	if err := s.pluginRPC.Register(vpnCorePluginID, vpnCoreProfilesService, "v1", []string{"query", "settings", "configure"}, s.vpnCoreProfilesRPC); err != nil {
		s.logger.Printf("vpn-core: register %s failed: %v", vpnCoreProfilesService, err)
	}
}

// vpnCoreLinesRPC serves the vpn-core/lines read-model — the unified, node-grouped
// view of managed + discovered proxy lines the dashboard renders (design-12 S1).
//
//	list             -> {"groups":[{node_id,node_name,lines:[...]}], "count":N}
//	get {line_hash_id} -> {"line": {...}}
func (s *Server) vpnCoreLinesRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "list":
		groups := s.buildLineGroups()
		count := 0
		for _, g := range groups {
			count += len(g.Lines)
		}
		return json.Marshal(struct {
			Groups []LineGroup `json:"groups"`
			Count  int         `json:"count"`
		}{Groups: groups, Count: count})
	case "sync_metadata":
		p, err := pluginOperatorPrincipal(ctx)
		if err != nil {
			return nil, err
		}
		return s.vpnCoreLinesSyncMetadata(p, request)
	case "get":
		var req struct {
			LineHashID string `json:"line_hash_id"`
		}
		if len(bytes.TrimSpace(request)) > 0 {
			if err := json.Unmarshal(request, &req); err != nil {
				return nil, fmt.Errorf("vpn-core/lines get: invalid request: %w", err)
			}
		}
		if strings.TrimSpace(req.LineHashID) == "" {
			return nil, fmt.Errorf("vpn-core/lines get: line_hash_id required")
		}
		for _, g := range s.buildLineGroups() {
			for _, ln := range g.Lines {
				if ln.LineHashID == req.LineHashID {
					return json.Marshal(struct {
						Line Line `json:"line"`
					}{Line: ln})
				}
			}
		}
		return nil, fmt.Errorf("vpn-core/lines get: line %q not found", req.LineHashID)
	default:
		return nil, fmt.Errorf("vpn-core/lines: unknown method %q", method)
	}
}

// vpnCoreNodesRPC serves the vpn-core/nodes inter-plugin service — the seam the
// Optional plugins can use to import live node connection info after the host
// grants their signed manifest dependency.
//
//	export {"user_id"?: string} -> {"links":[vless://...], "count":N, "warnings":[...]}
//
// With user_id it returns that subscriber's per-node links; without it, every
// subscriber's. Only APPLIED profiles and renderable inbounds contribute (others
// surface as warnings), exactly like the public /sub/{token} path.
func (s *Server) vpnCoreNodesRPC(_ context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "export":
		return s.vpnCoreExportNodes(request)
	case "list":
		return s.vpnCoreListNodes()
	default:
		return nil, fmt.Errorf("vpn-core/nodes: unknown method %q", method)
	}
}

// vpnCoreListNodes returns the discovered on-box nodes flattened across all live
// machines — the data source for the plugin-contributed "vpn-core Nodes" table.
func (s *Server) vpnCoreListNodes() ([]byte, error) {
	type row struct {
		NodeID   string `json:"node_id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol,omitempty"`
		Network  string `json:"network,omitempty"`
		Port     string `json:"port,omitempty"`
		Address  string `json:"address,omitempty"`
		ShareURL string `json:"share_url,omitempty"`
	}
	out := struct {
		Rows  []row `json:"rows"`
		Count int   `json:"count"`
	}{Rows: []row{}}
	for _, inv := range s.liveSingBoxInventories(s.now()) {
		for _, n := range inv.Nodes {
			out.Rows = append(out.Rows, row{
				NodeID: inv.NodeID, Name: n.Name, Protocol: n.Protocol, Network: n.Network,
				Port: n.Port, Address: n.Address, ShareURL: n.ShareURL,
			})
		}
	}
	out.Count = len(out.Rows)
	return json.Marshal(out)
}

func (s *Server) vpnCoreExportNodes(request []byte) ([]byte, error) {
	// IncludeDiscovered defaults to true (via a *bool so an omitted field still
	// means "include"): an adoption-bridge consumer wants the on-box (233boy)
	// nodes by default, not only Lattice-rendered ones.
	var req struct {
		UserID            string `json:"user_id"`
		IncludeDiscovered *bool  `json:"include_discovered"`
		IncludeManaged    *bool  `json:"include_managed"`
	}
	if len(bytes.TrimSpace(request)) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, fmt.Errorf("vpn-core export: invalid request: %w", err)
		}
	}
	includeDiscovered := req.IncludeDiscovered == nil || *req.IncludeDiscovered
	includeManaged := req.IncludeManaged == nil || *req.IncludeManaged

	out := struct {
		Links    []string `json:"links"`
		Count    int      `json:"count"`
		Warnings []string `json:"warnings,omitempty"`
	}{Links: []string{}}
	seen := map[string]bool{}
	appendLink := func(link string) {
		if link == "" || seen[link] {
			return
		}
		seen[link] = true
		out.Links = append(out.Links, link)
	}

	// (1) Lattice-managed proxy users rendered through the proxy store (Model-A).
	if includeManaged {
		var users []model.ProxyUser
		if req.UserID != "" {
			u, ok := s.store.ProxyUser(req.UserID)
			if !ok {
				return nil, fmt.Errorf("vpn-core export: proxy user %q not found", req.UserID)
			}
			users = []model.ProxyUser{u}
		} else {
			users = s.store.ProxyUsers()
		}
		profiles := s.proxySubscriptionProfiles()
		inbounds := s.store.ProxyInbounds()
		opts := proxycore.SubscriptionOptions{Now: s.now()}
		for _, u := range users {
			links, warnings, err := proxycore.VLESSRealityLinks(u, profiles, inbounds, opts)
			if err != nil {
				return nil, fmt.Errorf("vpn-core export: render user %s: %w", u.ID, err)
			}
			for _, l := range links {
				appendLink(l)
			}
			out.Warnings = append(out.Warnings, warnings...)
		}
	}

	// (2) On-box discovered nodes (adoption bridge): the share_url each agent
	// reported via read-only `sb --json list`. user_id does not apply (these are
	// machine-owned, not Lattice subscribers), so they are included whole when
	// no specific user filter is requested, giving an authorized publisher plugin the
	// full picture of adopted machines.
	if includeDiscovered && req.UserID == "" {
		for _, inv := range s.liveSingBoxInventories(s.now()) {
			if inv.Status != "" && inv.Status != "ok" {
				out.Warnings = append(out.Warnings, fmt.Sprintf("node %s discovery status %q: %s", inv.NodeID, inv.Status, inv.Error))
				continue
			}
			for _, n := range inv.Nodes {
				appendLink(n.ShareURL)
			}
		}
	}

	out.Count = len(out.Links)
	return json.Marshal(out)
}
