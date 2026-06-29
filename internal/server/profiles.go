package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
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
func (s *Server) vpnCoreProfilesRPC(_ context.Context, method string, _ []byte) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("vpn-core/profiles: unknown method %q", method)
	}
}
