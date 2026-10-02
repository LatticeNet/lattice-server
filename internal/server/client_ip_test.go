package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestResolveClientIP(t *testing.T) {
	defaults, err := parseTrustedProxies(nil)
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := parseTrustedProxies([]string{"172.18.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		remote  string
		trust   bool
		trusted []netip.Prefix
		cf      string
		xff     []string
		want    string
	}{
		// Trust off: headers never matter, whoever sends them.
		{name: "trust off ignores CF", remote: "127.0.0.1:5000", cf: "198.51.100.7", want: "127.0.0.1"},
		{name: "trust off ignores XFF", remote: "203.0.113.20:5000", xff: []string{"198.51.100.10"}, want: "203.0.113.20"},

		// Untrusted (public) peer under trust-proxy: every header is a spoof.
		{name: "public peer CF spoof", remote: "203.0.113.20:5000", trust: true, cf: "198.51.100.7", want: "203.0.113.20"},
		{name: "public peer XFF spoof", remote: "203.0.113.20:5000", trust: true, xff: []string{"198.51.100.10"}, want: "203.0.113.20"},
		{name: "public peer both spoofed", remote: "[2001:db8::5]:443", trust: true, cf: "198.51.100.7", xff: []string{"198.51.100.10, 10.0.0.1"}, want: "2001:db8::5"},

		// hkg: nginx on the host, server in a Docker bridge. nginx sets
		// CF-Connecting-IP to $remote_addr and appends to X-Forwarded-For; the
		// server's peer is the bridge gateway.
		{name: "hkg bridge CF", remote: "172.18.0.1:40000", trust: true, cf: "198.51.100.10", xff: []string{"198.51.100.10"}, want: "198.51.100.10"},
		{name: "hkg bridge CF beats forged XFF", remote: "172.18.0.1:40000", trust: true, cf: "198.51.100.10", xff: []string{"6.6.6.6, 198.51.100.10"}, want: "198.51.100.10"},
		{name: "hkg bridge client-sent CF is overwritten by nginx", remote: "172.18.0.1:40000", trust: true, cf: "198.51.100.10", xff: []string{"6.6.6.6, 198.51.100.10"}, want: "198.51.100.10"},
		// The same proxy reached over loopback (host networking).
		{name: "loopback nginx CF", remote: "127.0.0.1:40000", trust: true, cf: "198.51.100.10", want: "198.51.100.10"},
		{name: "loopback v6 nginx CF", remote: "[::1]:40000", trust: true, cf: "198.51.100.10", want: "198.51.100.10"},
		{name: "mapped loopback peer", remote: "[::ffff:127.0.0.1]:40000", trust: true, cf: "198.51.100.10", want: "198.51.100.10"},

		// A trusted proxy that only appends X-Forwarded-For (the docker
		// tutorial's nginx block): read from the right.
		{name: "XFF single hop", remote: "127.0.0.1:1", trust: true, xff: []string{"198.51.100.10"}, want: "198.51.100.10"},
		{name: "XFF forged leftmost", remote: "127.0.0.1:1", trust: true, xff: []string{"6.6.6.6, 198.51.100.10"}, want: "198.51.100.10"},
		{name: "XFF forged many", remote: "127.0.0.1:1", trust: true, xff: []string{"1.1.1.1, 2.2.2.2,3.3.3.3 , 198.51.100.10"}, want: "198.51.100.10"},
		{name: "XFF skips trusted hops", remote: "127.0.0.1:1", trust: true, xff: []string{"6.6.6.6, 198.51.100.10, 10.1.2.3, 172.18.0.1"}, want: "198.51.100.10"},
		{name: "XFF across repeated headers", remote: "127.0.0.1:1", trust: true, xff: []string{"6.6.6.6", "198.51.100.10, 10.1.2.3"}, want: "198.51.100.10"},
		{name: "XFF all trusted gives leftmost trusted", remote: "127.0.0.1:1", trust: true, xff: []string{"10.0.0.5, 172.18.0.1"}, want: "10.0.0.5"},
		{name: "XFF garbage stops walk", remote: "127.0.0.1:1", trust: true, xff: []string{"6.6.6.6, not-an-ip, 10.0.0.5"}, want: "10.0.0.5"},
		{name: "XFF garbage at right falls back to peer", remote: "127.0.0.1:1", trust: true, xff: []string{"6.6.6.6, not-an-ip"}, want: "127.0.0.1"},
		{name: "XFF trailing comma tolerated", remote: "127.0.0.1:1", trust: true, xff: []string{"198.51.100.10, "}, want: "198.51.100.10"},
		{name: "XFF host:port entry", remote: "127.0.0.1:1", trust: true, xff: []string{"198.51.100.10:5555"}, want: "198.51.100.10"},
		{name: "XFF bracketed v6 entry", remote: "127.0.0.1:1", trust: true, xff: []string{"[2001:db8::9]:443"}, want: "2001:db8::9"},
		{name: "invalid CF falls through to XFF", remote: "127.0.0.1:1", trust: true, cf: "garbage", xff: []string{"198.51.100.10"}, want: "198.51.100.10"},
		{name: "trusted peer no headers", remote: "172.18.0.1:9", trust: true, want: "172.18.0.1"},

		// An explicit list replaces the private ranges; loopback stays.
		{name: "narrow list trusts named gateway", remote: "172.18.0.1:9", trust: true, trusted: narrow, cf: "198.51.100.10", want: "198.51.100.10"},
		{name: "narrow list refuses other private peer", remote: "10.9.9.9:9", trust: true, trusted: narrow, cf: "198.51.100.10", want: "10.9.9.9"},
		{name: "narrow list keeps loopback", remote: "127.0.0.1:9", trust: true, trusted: narrow, cf: "198.51.100.10", want: "198.51.100.10"},
		{name: "narrow list XFF private client not skipped", remote: "127.0.0.1:9", trust: true, trusted: narrow, xff: []string{"6.6.6.6, 10.0.0.5, 172.18.0.1"}, want: "10.0.0.5"},

		// Malformed RemoteAddr keeps today's raw fallback and trusts nothing.
		{name: "remote without port", remote: "203.0.113.20", trust: true, cf: "198.51.100.7", want: "203.0.113.20"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.cf != "" {
				h.Set("CF-Connecting-IP", tc.cf)
			}
			for _, v := range tc.xff {
				h.Add("X-Forwarded-For", v)
			}
			trusted := tc.trusted
			if trusted == nil {
				trusted = defaults
			}
			if got := resolveClientIP(tc.remote, h, tc.trust, trusted); got != tc.want {
				t.Fatalf("resolveClientIP(%q, cf=%q, xff=%q) = %q, want %q", tc.remote, tc.cf, tc.xff, got, tc.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := parseTrustedProxies(SplitTrustedProxies(" 172.18.0.0/16, 10.0.0.7 fd00::/8\n::ffff:192.0.2.1 "))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"172.18.0.0/16", "10.0.0.7/32", "fd00::/8", "192.0.2.1/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("entry %d = %s, want %s", i, got[i], want[i])
		}
	}
	for _, bad := range []string{"not-an-ip", "10.0.0.0/33", "https://proxy"} {
		if _, err := parseTrustedProxies([]string{bad}); err == nil {
			t.Fatalf("malformed trusted proxy %q accepted", bad)
		}
	}
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Store: st, AdminPassword: testAdminPass, TrustProxy: true, TrustedProxies: []string{"nope"}}); err == nil || !strings.Contains(err.Error(), "trusted proxy") {
		t.Fatalf("New must refuse a malformed trusted proxy, got %v", err)
	}
}

// TestClientIPSpoofedHeadersDoNotWidenSubLimiter drives the real middleware:
// a public client that rotates a forged leftmost X-Forwarded-For entry
// through a trusted proxy still lands in its own limiter bucket. Before the
// right-to-left read every forged entry was a fresh bucket.
func TestClientIPSpoofedHeadersDoNotWidenSubLimiter(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, TrustProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	passed := 0
	h := srv.withSubscriptionLimit(func(w http.ResponseWriter, r *http.Request) { passed++ })
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodGet, "/sub/demo/"+strings.Repeat("a", 40), nil)
		req.RemoteAddr = "172.18.0.1:40000"
		req.Header.Set("X-Forwarded-For", "203.0."+strconv.Itoa(i)+".1, 198.51.100.10")
		h(httptest.NewRecorder(), req)
	}
	// Burst 20 plus at most a couple of refills while the loop runs.
	if passed > 25 {
		t.Fatalf("%d of 60 requests passed the share limiter; forged entries widened the budget", passed)
	}
}
