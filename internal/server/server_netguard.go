package server

import (
	"errors"
	"net/http"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/netguard"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// design-13 G1: read-only netguard views. Stored security groups, zones, and
// bindings are served as-is; nodes that only have a legacy NFTInputs baseline
// are served as an on-the-fly converted view marked source:"legacy". Nothing
// here mutates the store or touches any apply path.

const (
	netGuardSourceStored = "stored"
	netGuardSourceLegacy = "legacy"
)

type securityGroupView struct {
	model.SecurityGroup
	Source string `json:"source"`
	NodeID string `json:"node_id,omitempty"` // set for node-private legacy groups
}

type nodeGuardView struct {
	NodeID   string                 `json:"node_id"`
	NodeName string                 `json:"node_name,omitempty"`
	Source   string                 `json:"source"`
	Binding  model.NodeGuardBinding `json:"binding"`
	Groups   []securityGroupView    `json:"groups"`
	Zones    []model.GuardZone      `json:"zones"`
}

func (s *Server) handleNetGuardGroups(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	views := make([]securityGroupView, 0)
	for _, group := range s.store.SecurityGroups() {
		views = append(views, securityGroupView{SecurityGroup: group, Source: netGuardSourceStored})
	}
	for _, inputs := range s.store.AllNFTInputs() {
		if !rbac.Allows(p.Principal, "netguard:read", inputs.NodeID) {
			continue
		}
		if _, ok := s.store.SecurityGroup(netguard.LegacyGroupPrefix + inputs.NodeID); ok {
			continue // an adopted stored group supersedes the legacy view
		}
		converted := netguard.LegacyBaseline(inputs)
		views = append(views, securityGroupView{
			SecurityGroup: converted.Group,
			Source:        netGuardSourceLegacy,
			NodeID:        inputs.NodeID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": views})
}

func (s *Server) handleNetGuardZones(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	builtin := []model.GuardZone{
		{ID: model.GuardZonePublic, Name: "public", Builtin: true},
		{ID: model.GuardZoneLoopback, Name: "loopback", Builtin: true, Interfaces: []string{"lo"}},
		{ID: model.GuardZoneWireGuard, Name: "wireguard", Builtin: true},
		{ID: model.GuardZoneTailscale, Name: "tailscale", Builtin: true},
	}
	zones := make([]model.GuardZone, 0, len(builtin))
	seen := map[string]bool{}
	for _, zone := range s.store.GuardZones() {
		zones = append(zones, zone)
		seen[zone.ID] = true
	}
	for _, zone := range builtin {
		if !seen[zone.ID] {
			zones = append(zones, zone)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones})
}

func (s *Server) handleNetGuardNodes(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	views := make([]nodeGuardView, 0)
	covered := map[string]bool{}
	for _, binding := range s.store.NodeGuardBindings() {
		if !rbac.Allows(p.Principal, "netguard:read", binding.NodeID) {
			continue
		}
		covered[binding.NodeID] = true
		views = append(views, s.storedNodeGuardView(binding))
	}
	for _, inputs := range s.store.AllNFTInputs() {
		if covered[inputs.NodeID] {
			continue
		}
		if !rbac.Allows(p.Principal, "netguard:read", inputs.NodeID) {
			continue
		}
		converted := netguard.LegacyBaseline(inputs)
		views = append(views, nodeGuardView{
			NodeID:   inputs.NodeID,
			NodeName: s.nodeName(inputs.NodeID),
			Source:   netGuardSourceLegacy,
			Binding:  converted.Binding,
			Groups: []securityGroupView{{
				SecurityGroup: converted.Group,
				Source:        netGuardSourceLegacy,
				NodeID:        inputs.NodeID,
			}},
			Zones: converted.Zones,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": views})
}

func (s *Server) storedNodeGuardView(binding model.NodeGuardBinding) nodeGuardView {
	groups := make([]securityGroupView, 0, len(binding.GroupIDs))
	for _, groupID := range binding.GroupIDs {
		if group, ok := s.store.SecurityGroup(groupID); ok {
			groups = append(groups, securityGroupView{SecurityGroup: group, Source: netGuardSourceStored})
		}
	}
	zones := make([]model.GuardZone, 0, len(binding.ZoneIDs))
	for _, zoneID := range binding.ZoneIDs {
		if zone, ok := s.store.GuardZone(zoneID); ok {
			zones = append(zones, zone)
		}
	}
	return nodeGuardView{
		NodeID:   binding.NodeID,
		NodeName: s.nodeName(binding.NodeID),
		Source:   netGuardSourceStored,
		Binding:  binding,
		Groups:   groups,
		Zones:    zones,
	}
}

func (s *Server) nodeName(nodeID string) string {
	if node, ok := s.store.Node(nodeID); ok {
		return node.Name
	}
	return ""
}
