// Package groups resolves fleet group membership. Membership is computed from a
// group's explicit Members list (the canonical, policy-relevant source of
// truth) unioned with the nodes matched by its optional display-only Selector.
//
// This package is intentionally pure and side-effect free so it can be table
// tested without a store or server: every function is a deterministic
// transformation over in-memory model values. The selector semantics here agree
// with the dashboard's lib/fleet.ts bucketing (tags / role / country / region)
// so the server-computed Node.GroupIDs and the client's grouping never diverge.
package groups

import (
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// ResolveMembers returns the resolved node IDs for a single group: the explicit
// g.Members (canonical authored membership) unioned with every node matched by
// g.Selector (display-only smart filter). The result is deduplicated and stably
// sorted by node ID. When Selector is nil, the result is just the deduped,
// sorted explicit Members.
//
// Explicit Members are returned verbatim (deduped) even if a listed node no
// longer exists in allNodes — the authored list is canonical and stale-entry
// cleanup is a separate Phase-1 concern. Only selector matches are drawn from
// allNodes.
//
// Membership is flat, so no cycle guard is needed here. Parent-cycle and
// nesting-depth validation over Group.ParentID is enforced by the group CRUD
// layer; this resolver never walks ParentID.
func ResolveMembers(g model.Group, allNodes []model.Node) []string {
	set := make(map[string]struct{}, len(g.Members))
	for _, id := range g.Members {
		if id != "" {
			set[id] = struct{}{}
		}
	}
	if g.Selector != nil {
		for i := range allNodes {
			if selectorMatches(g.Selector, allNodes[i]) {
				set[allNodes[i].ID] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ResolveAll resolves every group against the same node set, returning a map of
// group ID to its resolved (deduped, sorted) node IDs.
func ResolveAll(groups []model.Group, nodes []model.Node) map[string][]string {
	out := make(map[string][]string, len(groups))
	for _, g := range groups {
		out[g.ID] = ResolveMembers(g, nodes)
	}
	return out
}

// GroupIDsForNode is the reverse lookup over a ResolveAll result: it returns the
// sorted IDs of every group whose resolved membership contains nodeID. This is
// what populates the read-only Node.GroupIDs convenience field.
func GroupIDsForNode(nodeID string, resolved map[string][]string) []string {
	var out []string
	for gid, members := range resolved {
		for _, m := range members {
			if m == nodeID {
				out = append(out, gid)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// selectorMatches reports whether a node satisfies a display-only group
// selector. Each populated criterion is an OR-set (the node need only match one
// value within it), and the populated criteria are AND-ed together (the node
// must satisfy every criterion that is set) — the conventional "smart filter"
// narrowing semantic, consistent with Kubernetes-style label selectors.
//
// A selector with no populated criteria matches NO nodes: a group must never be
// silently widened to the whole fleet by an empty filter. (Migration seeds
// single-criterion selectors, so this AND-vs-OR distinction does not affect the
// Phase-0 backfill; it only governs hand-authored multi-criterion selectors.)
func selectorMatches(sel *model.GroupSelector, n model.Node) bool {
	if sel == nil {
		return false
	}
	populated := false

	if len(sel.MatchTagsAny) > 0 {
		populated = true
		if !anyTagMatches(n.Tags, sel.MatchTagsAny) {
			return false
		}
	}
	if len(sel.MatchRoles) > 0 {
		populated = true
		if !containsExact(sel.MatchRoles, strings.TrimSpace(n.Role)) {
			return false
		}
	}
	if len(sel.MatchCountry) > 0 {
		populated = true
		if !containsFold(sel.MatchCountry, nodeCountry(n)) {
			return false
		}
	}
	if len(sel.MatchContinent) > 0 {
		populated = true
		if !containsFold(sel.MatchContinent, continentOf(nodeCountry(n))) {
			return false
		}
	}
	return populated
}

// nodeCountry returns the node's ISO-3166 alpha-2 country code, or "" when no
// geo is set.
func nodeCountry(n model.Node) string {
	if n.Geo == nil {
		return ""
	}
	return n.Geo.Country
}

// anyTagMatches reports whether the node carries any of the wanted tags (exact,
// case-sensitive match — tags are free-text labels where case is significant).
func anyTagMatches(nodeTags, wanted []string) bool {
	for _, w := range wanted {
		for _, t := range nodeTags {
			if t == w {
				return true
			}
		}
	}
	return false
}

// containsExact reports whether want is present in set (exact, case-sensitive).
func containsExact(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

// containsFold reports whether want is present in set, comparing
// case-insensitively. Used for ISO country/continent codes, which the dashboard
// also compares uppercased.
func containsFold(set []string, want string) bool {
	if want == "" {
		return false
	}
	for _, s := range set {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// continentOf returns the coarse continent bucket ("AS", "EU", "NA", "SA",
// "AF", "OC", "AN") for an ISO-3166 alpha-2 country code, or "??" when the code
// is unknown or not two letters. The table is ported verbatim from the
// dashboard's lib/fleet.ts COUNTRY_CONTINENT map so server-side group
// resolution and the client's region bucketing agree exactly.
func continentOf(code string) string {
	if len(code) != 2 {
		return "??"
	}
	if c, ok := countryContinent[strings.ToUpper(code)]; ok {
		return c
	}
	return "??"
}

// countryContinent maps ISO-3166 alpha-2 codes to a coarse continent bucket.
// Ported verbatim from lattice-dashboard/src/lib/fleet.ts so the two agree.
// Note the two intentional quirks carried over from fleet.ts: the country code
// "AS" (American Samoa) maps to Oceania, and "NA" (Namibia) maps to Africa —
// neither collides with the continent enum values "AS"/"NA", which are only ever
// produced by looking up other country codes.
var countryContinent = map[string]string{
	// Asia
	"AE": "AS", "AF": "AS", "AM": "AS", "AZ": "AS", "BD": "AS", "BH": "AS", "BN": "AS", "BT": "AS",
	"CN": "AS", "CY": "AS", "GE": "AS", "HK": "AS", "ID": "AS", "IL": "AS", "IN": "AS", "IQ": "AS",
	"IR": "AS", "JO": "AS", "JP": "AS", "KG": "AS", "KH": "AS", "KP": "AS", "KR": "AS", "KW": "AS",
	"KZ": "AS", "LA": "AS", "LB": "AS", "LK": "AS", "MM": "AS", "MN": "AS", "MO": "AS", "MV": "AS",
	"MY": "AS", "NP": "AS", "OM": "AS", "PH": "AS", "PK": "AS", "PS": "AS", "QA": "AS", "SA": "AS",
	"SG": "AS", "SY": "AS", "TH": "AS", "TJ": "AS", "TL": "AS", "TM": "AS", "TR": "AS", "TW": "AS",
	"UZ": "AS", "VN": "AS", "YE": "AS",
	// Europe
	"AD": "EU", "AL": "EU", "AT": "EU", "BA": "EU", "BE": "EU", "BG": "EU", "BY": "EU", "CH": "EU",
	"CZ": "EU", "DE": "EU", "DK": "EU", "EE": "EU", "ES": "EU", "FI": "EU", "FO": "EU", "FR": "EU",
	"GB": "EU", "GG": "EU", "GI": "EU", "GR": "EU", "HR": "EU", "HU": "EU", "IE": "EU", "IM": "EU",
	"IS": "EU", "IT": "EU", "JE": "EU", "LI": "EU", "LT": "EU", "LU": "EU", "LV": "EU", "MC": "EU",
	"MD": "EU", "ME": "EU", "MK": "EU", "MT": "EU", "NL": "EU", "NO": "EU", "PL": "EU", "PT": "EU",
	"RO": "EU", "RS": "EU", "RU": "EU", "SE": "EU", "SI": "EU", "SK": "EU", "SM": "EU", "UA": "EU",
	"VA": "EU", "XK": "EU",
	// North America
	"AG": "NA", "AI": "NA", "AW": "NA", "BB": "NA", "BL": "NA", "BM": "NA", "BS": "NA", "BZ": "NA",
	"CA": "NA", "CR": "NA", "CU": "NA", "CW": "NA", "DM": "NA", "DO": "NA", "GD": "NA", "GL": "NA",
	"GP": "NA", "GT": "NA", "HN": "NA", "HT": "NA", "JM": "NA", "KN": "NA", "KY": "NA", "LC": "NA",
	"MF": "NA", "MQ": "NA", "MS": "NA", "MX": "NA", "NI": "NA", "PA": "NA", "PM": "NA", "PR": "NA",
	"SV": "NA", "SX": "NA", "TC": "NA", "TT": "NA", "US": "NA", "VC": "NA", "VG": "NA", "VI": "NA",
	// South America
	"AR": "SA", "BO": "SA", "BR": "SA", "CL": "SA", "CO": "SA", "EC": "SA", "FK": "SA", "GF": "SA",
	"GY": "SA", "PE": "SA", "PY": "SA", "SR": "SA", "UY": "SA", "VE": "SA",
	// Africa
	"AO": "AF", "BF": "AF", "BI": "AF", "BJ": "AF", "BW": "AF", "CD": "AF", "CF": "AF", "CG": "AF",
	"CI": "AF", "CM": "AF", "CV": "AF", "DJ": "AF", "DZ": "AF", "EG": "AF", "EH": "AF", "ER": "AF",
	"ET": "AF", "GA": "AF", "GH": "AF", "GM": "AF", "GN": "AF", "GQ": "AF", "GW": "AF", "KE": "AF",
	"KM": "AF", "LR": "AF", "LS": "AF", "LY": "AF", "MA": "AF", "MG": "AF", "ML": "AF", "MR": "AF",
	"MU": "AF", "MW": "AF", "MZ": "AF", "NA": "AF", "NE": "AF", "NG": "AF", "RE": "AF", "RW": "AF",
	"SC": "AF", "SD": "AF", "SL": "AF", "SN": "AF", "SO": "AF", "SS": "AF", "ST": "AF", "SZ": "AF",
	"TD": "AF", "TG": "AF", "TN": "AF", "TZ": "AF", "UG": "AF", "YT": "AF", "ZA": "AF", "ZM": "AF",
	"ZW": "AF",
	// Oceania
	"AS": "OC", "AU": "OC", "CK": "OC", "FJ": "OC", "FM": "OC", "GU": "OC", "KI": "OC", "MH": "OC",
	"MP": "OC", "NC": "OC", "NF": "OC", "NR": "OC", "NU": "OC", "NZ": "OC", "PF": "OC", "PG": "OC",
	"PW": "OC", "SB": "OC", "TK": "OC", "TO": "OC", "TV": "OC", "VU": "OC", "WF": "OC", "WS": "OC",
	// Antarctica
	"AQ": "AN",
}
