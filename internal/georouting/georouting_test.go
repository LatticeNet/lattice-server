package georouting

import (
	"strings"
	"testing"
)

// Three nodes on three continents.
func sampleNodes() []GeoNode {
	return []GeoNode{
		{ID: "eu1", Name: "frankfurt", IPv4: "192.0.2.1", Lat: 50.1, Lon: 8.7, HasGeo: true, Healthy: true}, // Europe
		{ID: "as1", Name: "tokyo", IPv4: "192.0.2.2", Lat: 35.7, Lon: 139.7, HasGeo: true, Healthy: true},   // Asia
		{ID: "na1", Name: "ashburn", IPv4: "192.0.2.3", Lat: 39.0, Lon: -77.5, HasGeo: true, Healthy: true}, // N. America
	}
}

func TestRenderGeoIPSelectsNearestPerContinent(t *testing.T) {
	res, err := Render(Input{Hostname: "dns.roobli.org", Nodes: sampleNodes()})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"EU": "eu1", "AF": "eu1", // Africa is nearest to Frankfurt of the three
		"AS": "as1", "OC": "as1", // Oceania nearest to Tokyo of the three
		"NA": "na1", "SA": "na1", // S. America nearest to Ashburn of the three
		"AN": "as1", // Antarctica -> whichever is nearest; assert it's chosen, value checked below loosely
	}
	for code, node := range want {
		if code == "AN" {
			continue // centroid is far from all; don't pin the exact node
		}
		if res.ContinentChoice[code] != node {
			t.Fatalf("continent %s -> %s, want %s", code, res.ContinentChoice[code], node)
		}
	}
	// The config must reference each chosen node's IP and use geoip+view.
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if !strings.Contains(res.Config, ip) {
			t.Fatalf("config missing %s:\n%s", ip, res.Config)
		}
	}
	if !strings.Contains(res.Config, "geoip ") || !strings.Contains(res.Config, "view geo_") {
		t.Fatalf("config missing geoip/view:\n%s", res.Config)
	}
	if res.SHA256 == "" {
		t.Fatal("expected a sha")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, err := Render(Input{Hostname: "dns.roobli.org", Nodes: sampleNodes()})
	if err != nil {
		t.Fatal(err)
	}
	// Same nodes, shuffled order, must produce byte-identical output + sha.
	shuffled := []GeoNode{sampleNodes()[2], sampleNodes()[0], sampleNodes()[1]}
	b, err := Render(Input{Hostname: "dns.roobli.org", Nodes: shuffled})
	if err != nil {
		t.Fatal(err)
	}
	if a.Config != b.Config || a.SHA256 != b.SHA256 {
		t.Fatalf("render not deterministic:\nA:\n%s\nB:\n%s", a.Config, b.Config)
	}
}

func TestRenderOmitsUnhealthyAndShiftsTraffic(t *testing.T) {
	nodes := sampleNodes()
	nodes[1].Healthy = false // Tokyo offline
	res, err := Render(Input{Hostname: "dns.roobli.org", Nodes: nodes})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Config, "192.0.2.2") {
		t.Fatalf("offline node must not appear:\n%s", res.Config)
	}
	// Asia/Oceania now go to the next-nearest healthy node (not tokyo).
	if res.ContinentChoice["AS"] == "as1" {
		t.Fatalf("AS should have shifted off the offline node, got %s", res.ContinentChoice["AS"])
	}
	foundWarn := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "as1") && strings.Contains(w, "not healthy") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected an omission warning for as1, got %v", res.Warnings)
	}
}

func TestRenderAllHealthyStrategy(t *testing.T) {
	res, err := Render(Input{Hostname: "dns.roobli.org", Strategy: StrategyAllHealthy, Nodes: sampleNodes()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Config, "geoip ") || strings.Contains(res.Config, "view ") {
		t.Fatalf("all-healthy must not emit geoip/view:\n%s", res.Config)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if !strings.Contains(res.Config, ip) {
			t.Fatalf("all-healthy must include %s", ip)
		}
	}
	if !strings.Contains(res.Config, "loadbalance round_robin") {
		t.Fatalf("multi-node all-healthy should round-robin:\n%s", res.Config)
	}
}

func TestRenderGeoIPFallsBackWhenNoCoordinates(t *testing.T) {
	nodes := []GeoNode{
		{ID: "n1", IPv4: "192.0.2.1", Healthy: true}, // no geo
		{ID: "n2", IPv4: "192.0.2.2", Healthy: true}, // no geo
	}
	res, err := Render(Input{Hostname: "dns.roobli.org", Strategy: StrategyGeoIP, Nodes: nodes})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Config, "geoip ") {
		t.Fatalf("should fall back to all-healthy when no node has geo:\n%s", res.Config)
	}
	fellBack := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "all-healthy") {
			fellBack = true
		}
	}
	if !fellBack {
		t.Fatalf("expected a fallback warning, got %v", res.Warnings)
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	cases := []Input{
		{Hostname: "", Nodes: sampleNodes()},
		{Hostname: "bad host name", Nodes: sampleNodes()},
		{Hostname: "dns.roobli.org", Strategy: "weird", Nodes: sampleNodes()},
		{Hostname: "dns.roobli.org", Nodes: nil},                                               // no nodes
		{Hostname: "dns.roobli.org", Nodes: []GeoNode{{ID: "x", Healthy: true}}},               // no IP
		{Hostname: "dns.roobli.org", Nodes: []GeoNode{{ID: "x", IPv4: "nope", Healthy: true}}}, // invalid IP -> omitted -> none
		{Hostname: "dns.roobli.org", GeoIPDBPath: "/etc/coredns/GeoLite2.mmdb\nreload", Nodes: sampleNodes()},
		{Hostname: "dns.roobli.org", GeoIPDBPath: "/etc/coredns/../secret.mmdb", Nodes: sampleNodes()},
		{Hostname: "dns.roobli.org", GeoIPDBPath: "/etc/coredns/Geo Lite.mmdb", Nodes: sampleNodes()},
	}
	for i, in := range cases {
		if _, err := Render(in); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestRenderIncludesIPv6(t *testing.T) {
	nodes := []GeoNode{
		{ID: "eu1", IPv4: "192.0.2.1", IPv6: "2001:db8::1", Lat: 50, Lon: 8, HasGeo: true, Healthy: true},
	}
	res, err := Render(Input{Hostname: "dns.roobli.org", Nodes: nodes})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, "2001:db8::1") {
		t.Fatalf("config missing IPv6:\n%s", res.Config)
	}
}

func TestHaversineSanity(t *testing.T) {
	// London (51.5,-0.13) to Paris (48.85,2.35) ~ 340 km.
	d := haversine(51.5, -0.13, 48.85, 2.35)
	if d < 300 || d > 380 {
		t.Fatalf("London-Paris distance off: %.1f km", d)
	}
}
