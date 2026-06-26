package server

import (
	"net"
	"testing"
)

// TestPickPublicIP locks in the IP-pollution guard: a non-routable observed
// source (e.g. the Docker bridge gateway 172.18.0.1 seen when the server runs
// containerized behind nginx) must never be persisted as a node's public IP,
// and a previously-poisoned stored value must self-heal to "".
func TestPickPublicIP(t *testing.T) {
	s := &Server{} // logger nil; pickPublicIP guards on it

	cases := []struct {
		name     string
		observed string // raw observed source address ("" => none)
		reported string
		current  string
		wantV4   bool
		want     string
	}{
		{"reported wins over observed", "8.8.8.8", "1.1.1.1", "", true, "1.1.1.1"},
		{"bridge observed rejected, no fallback", "172.18.0.1", "", "", true, ""},
		{"private observed rejected", "10.0.0.5", "", "", true, ""},
		{"loopback observed rejected", "127.0.0.1", "", "", true, ""},
		{"public observed adopted", "8.8.8.8", "", "", true, "8.8.8.8"},
		{"bridge observed, poisoned current self-heals", "172.18.0.1", "", "172.18.0.1", true, ""},
		{"bridge observed, routable current preserved", "172.18.0.1", "", "1.1.1.1", true, "1.1.1.1"},
		{"no observation, routable current preserved", "", "", "9.9.9.9", true, "9.9.9.9"},
		{"no observation, private current dropped", "", "", "192.168.1.1", true, ""},
		{"v4 observed ignored for v6 family", "8.8.8.8", "", "", false, ""},
		{"v6 public observed adopted", "2606:4700:4700::1111", "", "", false, "2606:4700:4700::1111"},
		{"reported trimmed", "", "  1.1.1.1  ", "", true, "1.1.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var observed net.IP
			if tc.observed != "" {
				observed = net.ParseIP(tc.observed)
			}
			got := s.pickPublicIP(observed, tc.reported, tc.current, tc.wantV4)
			if got != tc.want {
				t.Fatalf("pickPublicIP(observed=%q reported=%q current=%q v4=%v) = %q, want %q",
					tc.observed, tc.reported, tc.current, tc.wantV4, got, tc.want)
			}
		})
	}
}
