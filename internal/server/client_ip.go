package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// defaultTrustedProxies is the set of immediate peers whose forwarding headers
// are believed when TrustProxy is on and the operator named no proxies.
//
// Loopback alone is not enough for the deployment this repository documents:
// the server runs in a Docker bridge network and the port is published on the
// host's loopback, so a reverse proxy on the same host reaches the server
// through docker-proxy and the server sees the bridge gateway (a 172.16/12
// address by default, 172.18.0.1 on hkg), not 127.0.0.1. A loopback-only
// default would collapse every client into that one gateway address, and with
// it every per-address limiter and every audit source address: the agent
// limiter alone (10 rps, burst 40) would throttle a fleet of a few dozen agents
// into looking offline.
//
// So the default is loopback plus the private-use and unique-local ranges,
// the same shape as Express's "loopback, uniquelocal" preset. It still refuses
// the case that matters most: a public peer that reaches the server directly
// can no longer choose its own address with a header. LATTICE_TRUSTED_PROXIES
// replaces this whole set, loopback included, so the logged set is exactly the
// set the resolver checks; an operator whose proxy connects over loopback
// lists 127.0.0.1 or ::1 there.
var defaultTrustedProxies = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// parseTrustedProxies turns operator-supplied CIDRs or bare addresses into
// prefixes. An empty list yields the default set; a non-empty list is the
// whole set. A malformed entry is an error: guessing at a trust boundary is
// worse than refusing to start.
func parseTrustedProxies(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range entries {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if strings.Contains(v, "/") {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy %q: %w", v, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", v, err)
		}
		a = a.Unmap().WithZone("")
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	if len(out) == 0 {
		return append([]netip.Prefix(nil), defaultTrustedProxies...), nil
	}
	return out, nil
}

// EffectiveTrustedProxies returns the set of peers whose forwarding headers
// TrustProxy believes for the given LATTICE_TRUSTED_PROXIES entries: the
// default set when the entries are empty, otherwise exactly the entries. The
// server checks the same set, so the startup log can print it verbatim.
func EffectiveTrustedProxies(entries []string) ([]netip.Prefix, error) {
	return parseTrustedProxies(entries)
}

// SplitTrustedProxies splits the LATTICE_TRUSTED_PROXIES value, which may be
// separated by commas or whitespace.
func SplitTrustedProxies(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
}

func isTrustedProxy(a netip.Addr, trusted []netip.Prefix) bool {
	a = a.Unmap().WithZone("")
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseForwardedAddr reads one address out of a forwarding header entry. It
// accepts a bare address and the host:port and [v6]:port forms some proxies
// write.
func parseForwardedAddr(v string) (netip.Addr, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

// resolveClientIP derives the client address used for rate limits, audit
// attribution, challenge binding and agent source allowlists.
//
// Forwarding headers are read only when trustProxy is on AND the immediate
// peer is a trusted proxy. CF-Connecting-IP is a single value a trusted proxy
// overwrites, so it wins when present and valid. X-Forwarded-For is read from
// the right: a proxy appends the address it saw, so the rightmost entries are
// the ones our own proxies wrote and the leftmost are whatever the client
// sent. The walk skips trusted hops and returns the first address that is not
// one of ours. If every entry is trusted, the leftmost trusted entry is the
// best attribution; a malformed entry stops the walk, since nothing to its
// left can be vouched for.
func resolveClientIP(remoteAddr string, h http.Header, trustProxy bool, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if !trustProxy {
		return host
	}
	peer, ok := parseForwardedAddr(host)
	if !ok || !isTrustedProxy(peer, trusted) {
		return host
	}
	if cf, ok := parseForwardedAddr(h.Get("CF-Connecting-IP")); ok {
		return cf.String()
	}
	candidate := peer.String()
	var hops []string
	for _, line := range h.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(line, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if strings.TrimSpace(hops[i]) == "" {
			continue
		}
		a, ok := parseForwardedAddr(hops[i])
		if !ok {
			break
		}
		candidate = a.String()
		if !isTrustedProxy(a, trusted) {
			return candidate
		}
	}
	return candidate
}
