package server

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// Names the line catalogue resolves (design 28).
//
// A catalogue row lists the addresses its line's host names resolved to at
// the last template sync, and marks each DDNS name of the node verified when
// it resolved to the node's current public address. Core uses both when it
// validates a plan: a plan node's server may be one of the line's addresses
// (so Resolve Domain still works), and only a verified DDNS name may stand in
// for a line's dial address. Both are therefore resolved by the control plane
// on the template sync's clock and read from this cache, never resolved on a
// catalogue read, which is on the serving path.
//
// A name answers only with public addresses. A name with one internal
// address is refused whole, as a latency edge name is: a node's script or a
// provider chooses these names, and an internal address in the allowed set
// would let a plan point a client at its own network. A name the last sync
// could not resolve keeps its last good answer for lineCatalogueNameStale.

const (
	lineCatalogueNameLookupTimeout = 3 * time.Second
	lineCatalogueNameStale         = 30 * time.Minute
	// maxLineCatalogueNames bounds the names one sync resolves, and
	// lineCatalogueNameLookups how many it resolves at once.
	maxLineCatalogueNames    = 4096
	lineCatalogueNameLookups = 32
)

// lineCatalogueNames maps each name the last sync asked about to the public
// addresses it accepted for it.
type lineCatalogueNames struct {
	mu      sync.Mutex
	entries map[string]lineCatalogueNameEntry
	// lookup resolves one name; nil uses net.DefaultResolver. Tests set it.
	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
	// refreshMu keeps two refreshes from overlapping.
	refreshMu sync.Mutex
}

type lineCatalogueNameEntry struct {
	addrs    []string // canonical, sorted; nil when refused
	resolved time.Time
}

func lineCatalogueNameKey(host string) string { return strings.ToLower(strings.TrimSpace(host)) }

// lineCataloguePublicAddrs returns a name's addresses in canonical form,
// sorted, or nil when any of them is not public.
func lineCataloguePublicAddrs(ips []net.IPAddr) []string {
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
		if !latencyPublicIPv6(a.IP) || lineCatalogueSpecialIPv6(a.IP) {
			return nil
		}
		out = append(out, a.IP.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// lineCatalogueSpecialIPv6 are global-unicast ranges that are not anyone's
// public address: documentation space, and the NAT64 prefixes, which embed an
// IPv4 address the egress policy judges on its own.
var lineCatalogueSpecialIPv6 = func() func(net.IP) bool {
	var nets []*net.IPNet
	for _, cidr := range []string{"2001:db8::/32", "64:ff9b::/96", "64:ff9b:1::/48"} {
		_, n, _ := net.ParseCIDR(cidr)
		nets = append(nets, n)
	}
	return func(ip net.IP) bool {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
}()

// refresh resolves every name at once, inside one timeout, and replaces the
// cache with the answers. A name no longer asked about is dropped.
func (c *lineCatalogueNames) refresh(names []string, now time.Time) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	keys := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		key := lineCatalogueNameKey(name)
		if !latencyHostname(key) || seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
		if len(keys) == maxLineCatalogueNames {
			break
		}
	}
	c.mu.Lock()
	prior, lookup := c.entries, c.lookup
	c.mu.Unlock()
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	ctx, cancel := context.WithTimeout(context.Background(), lineCatalogueNameLookupTimeout)
	defer cancel()
	type answer struct {
		key   string
		entry lineCatalogueNameEntry
		keep  bool
	}
	answers := make(chan answer, len(keys))
	slots := make(chan struct{}, lineCatalogueNameLookups)
	for _, key := range keys {
		go func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			ips, err := lookup(ctx, key)
			if err == nil {
				answers <- answer{key: key, entry: lineCatalogueNameEntry{addrs: lineCataloguePublicAddrs(ips), resolved: now}, keep: true}
				return
			}
			old, ok := prior[key]
			answers <- answer{key: key, entry: old, keep: ok && old.addrs != nil && now.Sub(old.resolved) < lineCatalogueNameStale}
		}()
	}
	next := make(map[string]lineCatalogueNameEntry, len(keys))
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
func (c *lineCatalogueNames) snapshot() map[string][]string {
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

// refreshLineCatalogueNames resolves every host name a catalogue row names:
// each line's template host, public host and provider edge, and every DDNS
// name of every node. The template sync calls it after each sync.
func (s *Server) refreshLineCatalogueNames(now time.Time) {
	var names []string
	groups, _ := s.lineReadModel()
	for _, g := range groups {
		for _, ln := range g.Lines {
			names = append(names, ln.PublicHost, ln.ProviderEdge)
		}
	}
	for _, t := range s.store.LineClientTemplates() {
		names = append(names, t.Host)
	}
	for _, profile := range s.store.DDNSProfiles() {
		names = append(names, profile.Domains...)
	}
	s.substoreCatalogue.names.refresh(names, now)
}
