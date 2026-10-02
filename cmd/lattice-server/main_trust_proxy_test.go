package main

import (
	"strings"
	"testing"
)

func TestDescribeClientIPTrustLogsTheEffectiveSet(t *testing.T) {
	cases := []struct {
		name       string
		trustProxy bool
		raw        string
		want       string
	}{
		{
			name:       "default set",
			trustProxy: true,
			want:       "trust-proxy: forwarding headers believed only from peers in 127.0.0.0/8, ::1/128, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 (default)",
		},
		{
			name:       "list replaces the default entirely",
			trustProxy: true,
			raw:        "172.18.0.1, fd00::/8",
			want:       "trust-proxy: forwarding headers believed only from peers in 172.18.0.1/32, fd00::/8 (LATTICE_TRUSTED_PROXIES)",
		},
		{
			name:       "blank list keeps the default",
			trustProxy: true,
			raw:        " , ",
			want:       "trust-proxy: forwarding headers believed only from peers in 127.0.0.0/8, ::1/128, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 (default)",
		},
		{
			name: "trust off",
			want: "trust-proxy: off; the socket peer address is the client address",
		},
		{
			name: "list without trust-proxy",
			raw:  "172.18.0.1",
			want: "WARNING: LATTICE_TRUSTED_PROXIES is ignored without LATTICE_TRUST_PROXY=1; the socket peer address is the client address",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := describeClientIPTrust(tc.trustProxy, tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
	if _, err := describeClientIPTrust(true, "172.18.0.1, nope"); err == nil || !strings.Contains(err.Error(), "trusted proxy") {
		t.Fatalf("a malformed LATTICE_TRUSTED_PROXIES must fail startup, got %v", err)
	}
}
