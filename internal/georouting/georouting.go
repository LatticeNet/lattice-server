// Package georouting renders a geo-aware CoreDNS zone that answers one apex
// hostname with the nearest healthy node by client location. It is the pure-Go,
// deterministic core of Design 06 (Lattice-native GeoDNS): no network, no new
// dependency. The server feeds it participating nodes (with operator-owned
// NodeGeo coordinates + health) and ships the rendered config to the Design 02
// CoreDNS node via the existing reviewed apply path. CoreDNS does the actual
// client geolocation at query time via its stock geoip+view plugins.
package georouting

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
)

const (
	// StrategyGeoIP routes by client continent (CoreDNS geoip+view; needs a
	// GeoLite2 DB on the node). StrategyAllHealthy is a zero-dependency degrade:
	// round-robin all healthy nodes (failover, but no geo).
	StrategyGeoIP      = "geoip"
	StrategyAllHealthy = "all-healthy"

	DefaultTTL         = 60
	defaultGeoIPDBPath = "/etc/coredns/GeoLite2-City.mmdb"
)

// continentCentroids are coarse representative coordinates per MaxMind continent
// code. They only bucket the client; the trustworthy signal is each node's
// operator-set NodeGeo. Order is fixed for deterministic rendering.
var continentOrder = []string{"AF", "AN", "AS", "EU", "NA", "OC", "SA"}

var continentCentroids = map[string][2]float64{
	"AF": {0, 20},    // Africa
	"AN": {-75, 0},   // Antarctica
	"AS": {34, 100},  // Asia
	"EU": {54, 15},   // Europe
	"NA": {40, -100}, // North America
	"OC": {-22, 140}, // Oceania
	"SA": {-15, -60}, // South America
}

// GeoNode is one participating target as the renderer needs it.
type GeoNode struct {
	ID      string
	Name    string
	IPv4    string
	IPv6    string
	Lat     float64
	Lon     float64
	HasGeo  bool
	Healthy bool
}

// Input is the render request.
type Input struct {
	Hostname    string
	TTL         int
	Strategy    string
	GeoIPDBPath string // path to the GeoLite2 DB on the node (geoip strategy)
	Nodes       []GeoNode
}

// Result is the rendered CoreDNS config plus diagnostics.
type Result struct {
	Config   string
	SHA256   string
	Warnings []string
	// Continent -> selected node ID (geoip strategy), for plan display/tests.
	ContinentChoice map[string]string
}

// Render produces a deterministic CoreDNS server-block set for the apex.
func Render(in Input) (Result, error) {
	host := strings.TrimSpace(strings.ToLower(in.Hostname))
	if host == "" {
		return Result{}, fmt.Errorf("georouting: hostname is required")
	}
	if err := validateHostname(host); err != nil {
		return Result{}, err
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	strategy := strings.TrimSpace(in.Strategy)
	if strategy == "" {
		strategy = StrategyGeoIP
	}
	if strategy != StrategyGeoIP && strategy != StrategyAllHealthy {
		return Result{}, fmt.Errorf("georouting: unknown strategy %q", strategy)
	}

	eligible, warnings := eligibleNodes(in.Nodes)
	if len(eligible) == 0 {
		return Result{}, fmt.Errorf("georouting: no healthy node with an IP is available")
	}

	var b strings.Builder
	result := Result{Warnings: warnings, ContinentChoice: map[string]string{}}

	if strategy == StrategyAllHealthy {
		writeDefaultBlock(&b, host, ttl, eligible)
	} else {
		geoEligible := geoNodes(eligible)
		if len(geoEligible) == 0 {
			// geoip requested but no node has coordinates: degrade to all-healthy
			// rather than emit an empty geo zone, and say so loudly.
			warnings = append(warnings, "no participating node has NodeGeo coordinates; falling back to all-healthy round-robin")
			result.Warnings = warnings
			writeDefaultBlock(&b, host, ttl, eligible)
		} else {
			dbPath := strings.TrimSpace(in.GeoIPDBPath)
			if dbPath == "" {
				dbPath = defaultGeoIPDBPath
			}
			// Per continent, pick the nearest geo-capable healthy node.
			byNode := map[string][]string{} // nodeID -> continents
			for _, code := range continentOrder {
				nearest := nearestNode(continentCentroids[code], geoEligible)
				byNode[nearest.ID] = append(byNode[nearest.ID], code)
				result.ContinentChoice[code] = nearest.ID
			}
			// One view block per distinct selected node, deterministic order.
			groups := make([]nodeGroup, 0, len(byNode))
			nodesByID := indexByID(geoEligible)
			for nodeID, conts := range byNode {
				sort.Strings(conts)
				groups = append(groups, nodeGroup{node: nodesByID[nodeID], continents: conts})
			}
			sort.Slice(groups, func(i, j int) bool {
				return strings.Join(groups[i].continents, ",") < strings.Join(groups[j].continents, ",")
			})
			for _, g := range groups {
				writeViewBlock(&b, host, ttl, dbPath, g)
			}
			// Default block for unknown/unmatched clients: all healthy round-robin.
			writeDefaultBlock(&b, host, ttl, eligible)
		}
	}

	cfg := b.String()
	sum := sha256.Sum256([]byte(cfg))
	result.Config = cfg
	result.SHA256 = hex.EncodeToString(sum[:])
	return result, nil
}

type nodeGroup struct {
	node       GeoNode
	continents []string
}

func eligibleNodes(nodes []GeoNode) ([]GeoNode, []string) {
	out := []GeoNode{}
	warnings := []string{}
	seen := map[string]bool{}
	// Deterministic: sort by ID first.
	sorted := append([]GeoNode(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, n := range sorted {
		if seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		if !n.Healthy {
			warnings = append(warnings, fmt.Sprintf("node %s omitted: not healthy", n.ID))
			continue
		}
		if strings.TrimSpace(n.IPv4) == "" && strings.TrimSpace(n.IPv6) == "" {
			warnings = append(warnings, fmt.Sprintf("node %s omitted: no public IP", n.ID))
			continue
		}
		if v4 := strings.TrimSpace(n.IPv4); v4 != "" && net.ParseIP(v4) == nil {
			warnings = append(warnings, fmt.Sprintf("node %s omitted: invalid IPv4 %q", n.ID, v4))
			continue
		}
		if v6 := strings.TrimSpace(n.IPv6); v6 != "" && net.ParseIP(v6) == nil {
			warnings = append(warnings, fmt.Sprintf("node %s omitted: invalid IPv6 %q", n.ID, v6))
			continue
		}
		out = append(out, n)
	}
	return out, warnings
}

func geoNodes(nodes []GeoNode) []GeoNode {
	out := []GeoNode{}
	for _, n := range nodes {
		if n.HasGeo {
			out = append(out, n)
		}
	}
	return out
}

func nearestNode(centroid [2]float64, nodes []GeoNode) GeoNode {
	best := nodes[0]
	bestDist := haversine(centroid[0], centroid[1], best.Lat, best.Lon)
	for _, n := range nodes[1:] {
		d := haversine(centroid[0], centroid[1], n.Lat, n.Lon)
		// Tie-break by ID for determinism.
		if d < bestDist || (d == bestDist && n.ID < best.ID) {
			best = n
			bestDist = d
		}
	}
	return best
}

// haversine returns the great-circle distance in kilometers.
func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0 // km
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Min(1, math.Sqrt(a)))
}

func indexByID(nodes []GeoNode) map[string]GeoNode {
	m := make(map[string]GeoNode, len(nodes))
	for _, n := range nodes {
		m[n.ID] = n
	}
	return m
}

func writeViewBlock(b *strings.Builder, host string, ttl int, dbPath string, g nodeGroup) {
	exprs := make([]string, 0, len(g.continents))
	for _, code := range g.continents {
		exprs = append(exprs, fmt.Sprintf("metadata('geoip/continent/code') == '%s'", code))
	}
	viewName := "geo_" + strings.ToLower(strings.Join(g.continents, "_"))
	fmt.Fprintf(b, "%s {\n", host)
	fmt.Fprintf(b, "    geoip %s\n", dbPath)
	fmt.Fprintf(b, "    metadata\n")
	fmt.Fprintf(b, "    view %s {\n", viewName)
	fmt.Fprintf(b, "        expr %s\n", strings.Join(exprs, " || "))
	fmt.Fprintf(b, "    }\n")
	writeHosts(b, host, ttl, []GeoNode{g.node})
	fmt.Fprintf(b, "}\n")
}

func writeDefaultBlock(b *strings.Builder, host string, ttl int, nodes []GeoNode) {
	fmt.Fprintf(b, "%s {\n", host)
	writeHosts(b, host, ttl, nodes)
	if len(nodes) > 1 {
		fmt.Fprintf(b, "    loadbalance round_robin\n")
	}
	fmt.Fprintf(b, "}\n")
}

func writeHosts(b *strings.Builder, host string, ttl int, nodes []GeoNode) {
	fmt.Fprintf(b, "    hosts {\n")
	fmt.Fprintf(b, "        ttl %d\n", ttl)
	for _, n := range nodes {
		if v4 := strings.TrimSpace(n.IPv4); v4 != "" {
			fmt.Fprintf(b, "        %s %s\n", v4, host)
		}
		if v6 := strings.TrimSpace(n.IPv6); v6 != "" {
			fmt.Fprintf(b, "        %s %s\n", v6, host)
		}
	}
	fmt.Fprintf(b, "        no_reverse\n")
	fmt.Fprintf(b, "        fallthrough\n")
	fmt.Fprintf(b, "    }\n")
}

func validateHostname(host string) error {
	if len(host) > 253 {
		return fmt.Errorf("georouting: hostname too long")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("georouting: hostname has an empty label")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("georouting: invalid hostname label")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return fmt.Errorf("georouting: hostname contains an unsupported character %q", r)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("georouting: hostname label has invalid hyphen placement")
		}
	}
	return nil
}
