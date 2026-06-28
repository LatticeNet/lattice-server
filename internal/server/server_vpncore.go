package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
)

const (
	// vpnCorePluginID is the first-party proxy/"vpn-core" provider identity. Its
	// rendering engine stays in core (ADR D5/D6); it exposes node connection info
	// to other plugins through the inter-plugin RPC bus (design-09 §F).
	vpnCorePluginID = "latticenet.vpn-core"
	// vpnCoreNodesService is the inter-plugin service id other plugins call to
	// import live node data (e.g. the Sub-Store companion).
	vpnCoreNodesService = "latticenet.vpn-core/nodes"
)

// registerVPNCoreRPC registers the in-core vpn-core services on the server's RPC
// bus. Called once from New after s.pluginRPC is created. Registration failure is
// logged, not fatal: a missing inter-plugin service degrades that integration
// without taking down the server.
func (s *Server) registerVPNCoreRPC() {
	if s.pluginRPC == nil {
		return
	}
	if err := s.pluginRPC.Register(vpnCorePluginID, vpnCoreNodesService, "v1", []string{"export"}, s.vpnCoreNodesRPC); err != nil {
		s.logger.Printf("vpn-core: register %s failed: %v", vpnCoreNodesService, err)
	}
	// Grant the first-party Sub-Store companion the directed edge to import nodes.
	s.pluginRPC.Allow(subStorePluginID, vpnCoreNodesService)
}

// vpnCoreNodesRPC serves the vpn-core/nodes inter-plugin service — the seam the
// Sub-Store companion uses to import live node connection info.
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
	default:
		return nil, fmt.Errorf("vpn-core/nodes: unknown method %q", method)
	}
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
	// no specific user filter is requested, giving the Sub-Store companion the
	// full picture of adopted machines.
	if includeDiscovered && req.UserID == "" {
		s.singboxInvMu.RLock()
		for _, inv := range s.singboxInv {
			if inv.Status != "" && inv.Status != "ok" {
				out.Warnings = append(out.Warnings, fmt.Sprintf("node %s discovery status %q: %s", inv.NodeID, inv.Status, inv.Error))
				continue
			}
			for _, n := range inv.Nodes {
				appendLink(n.ShareURL)
			}
		}
		s.singboxInvMu.RUnlock()
	}

	out.Count = len(out.Links)
	return json.Marshal(out)
}
