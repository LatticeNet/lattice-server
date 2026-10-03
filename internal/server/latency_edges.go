package server

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Provider edge names for the latency probes.
//
// A node behind a provider's NAT declares the host name the provider forwards
// into it from, and a probe of that node has to dial the edge. The name comes
// from the node, so the control plane never hands it to the source as a name:
// the source would resolve it on its own network, where a name a node chose
// can point at the source's loopback or LAN, and the probe's loss and latency
// would read as a blind port scan of it. The control plane resolves each edge
// name at every sweep instead, and the probe dials the address it got, only
// when every address the name has is public. A name with one internal address
// is refused whole.
//
// Planning reads the cache and never resolves, because the plan is also built
// on every console read. A name the last sweep could not resolve keeps its
// last good answer for latencyEdgeStale, so a DNS hiccup does not pause and
// resume a probe (two monitor writes and two audit rows); a name that
// resolved to an internal address is refused at once.

const (
	latencyEdgeLookupTimeout = 3 * time.Second
	latencyEdgeStale         = 30 * time.Minute
)

// latencyEdgeCache maps each edge name the last sweep asked about to the
// public IPv4 addresses it accepted for it.
type latencyEdgeCache struct {
	mu      sync.Mutex
	entries map[string]latencyEdgeEntry
	// lookup resolves one name; nil uses net.DefaultResolver. Tests set it.
	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
}

type latencyEdgeEntry struct {
	addrs    []string // public IPv4, sorted; nil when refused
	resolved time.Time
}

func latencyEdgeKey(host string) string { return strings.ToLower(strings.TrimSpace(host)) }

// latencyEdgeNames lists the edge names the live inventories declare.
func latencyEdgeNames(inventories []model.SingBoxInventory) []string {
	var hosts []string
	for _, inv := range inventories {
		if inv.Status != "" && inv.Status != "ok" {
			continue
		}
		if edge := strings.TrimSpace(inv.ProviderEdge); latencyHostname(edge) {
			hosts = append(hosts, edge)
		}
	}
	return hosts
}

// latencyPublicIPv6 reports whether ip is a global IPv6 address. Edge names
// are only dialled over IPv4, but an internal AAAA record still refuses the
// name.
func latencyPublicIPv6(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified()
}

// latencyEdgePublicAddrs returns a name's public IPv4 addresses, sorted, or
// nil when any address it has is not public.
func latencyEdgePublicAddrs(ips []net.IPAddr) []string {
	var out []string
	for _, a := range ips {
		if v4 := a.IP.To4(); v4 != nil {
			ip, ok := latencyPublicIPv4(v4.String())
			if !ok {
				return nil
			}
			out = append(out, ip)
			continue
		}
		if !latencyPublicIPv6(a.IP) {
			return nil
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// refresh resolves every name in hosts at once, within one timeout, and
// replaces the cache with the answers; a name no longer asked about is
// dropped. syncLatencyProbes calls it under latencySync, so two refreshes
// never overlap.
func (c *latencyEdgeCache) refresh(hosts []string, now time.Time) {
	keys := map[string]bool{}
	for _, host := range hosts {
		keys[latencyEdgeKey(host)] = true
	}
	c.mu.Lock()
	prior, lookup := c.entries, c.lookup
	c.mu.Unlock()
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	ctx, cancel := context.WithTimeout(context.Background(), latencyEdgeLookupTimeout)
	defer cancel()
	type answer struct {
		key   string
		entry latencyEdgeEntry
		keep  bool
	}
	answers := make(chan answer, len(keys))
	for key := range keys {
		go func() {
			ips, err := lookup(ctx, key)
			if err == nil {
				answers <- answer{key: key, entry: latencyEdgeEntry{addrs: latencyEdgePublicAddrs(ips), resolved: now}, keep: true}
				return
			}
			old, ok := prior[key]
			answers <- answer{key: key, entry: old, keep: ok && old.addrs != nil && now.Sub(old.resolved) < latencyEdgeStale}
		}()
	}
	next := make(map[string]latencyEdgeEntry, len(keys))
	for range keys {
		if a := <-answers; a.keep {
			next[a.key] = a.entry
		}
	}
	c.mu.Lock()
	c.entries = next
	c.mu.Unlock()
}

// snapshot returns each cached name's accepted addresses. The slices are
// shared and never written after a refresh publishes them.
func (c *latencyEdgeCache) snapshot() map[string][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string][]string, len(c.entries))
	for key, entry := range c.entries {
		if entry.addrs != nil {
			out[key] = entry.addrs
		}
	}
	return out
}
