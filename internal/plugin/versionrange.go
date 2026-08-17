package plugin

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// design-18 D3/E1: dependency version ranges. The comparator language is a
// comma- or space-separated set of comparators (">=0.8.0-alpha.5, <0.9"),
// each of >=, <=, >, <, = (== and a bare version both mean exact). Empty means
// "any installed version". This is deliberately the small language the
// manifests actually need — not full semver-range syntax (no wildcards, no
// || unions, no caret/tilde): every comparator set is an AND, so a review can
// evaluate one by eye.

var versionComparatorRe = regexp.MustCompile(`^(>=|<=|==|!=|=|>|<)?\s*([0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z.-]+)?)$`)

// compareVersions orders release-ish versions: numeric core first, then the
// semver prerelease rule (a release outranks its prereleases; prerelease
// segments compare numerically when both numeric, lexically otherwise, and
// numeric segments rank below alphanumeric ones). Returns -1/0/1.
func compareVersions(a, b string) int {
	ca, pa := splitVersion(a)
	cb, pb := splitVersion(b)
	for i := 0; i < len(ca) || i < len(cb); i++ {
		var x, y int
		if i < len(ca) {
			x = ca[i]
		}
		if i < len(cb) {
			y = cb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	if pa == "" && pb == "" {
		return 0
	}
	if pa == "" {
		return 1 // release outranks prerelease
	}
	if pb == "" {
		return -1
	}
	sa := strings.Split(pa, ".")
	sb := strings.Split(pb, ".")
	for i := 0; i < len(sa) || i < len(sb); i++ {
		if i >= len(sa) {
			return -1 // fewer segments ranks lower when all shared ones match
		}
		if i >= len(sb) {
			return 1
		}
		if sa[i] == sb[i] {
			continue
		}
		na, erra := strconv.Atoi(sa[i])
		nb, errb := strconv.Atoi(sb[i])
		switch {
		case erra == nil && errb == nil:
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		case erra == nil:
			return -1 // numeric ranks below alphanumeric
		case errb == nil:
			return 1
		default:
			if c := strings.Compare(sa[i], sb[i]); c != 0 {
				return c
			}
		}
	}
	return 0
}

func splitVersion(v string) (core []int, prerelease string) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if i := strings.IndexByte(v, '-'); i >= 0 {
		prerelease = v[i+1:]
		v = v[:i]
	}
	for _, part := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(part)
		core = append(core, n)
	}
	return core, prerelease
}

// VersionInRange reports whether version satisfies the comparator set —
// exported for the server-side activation gate (plugin load uses the same
// evaluator internally).
func VersionInRange(version, rangeExpr string) bool {
	return versionInRange(version, rangeExpr)
}

// versionInRange reports whether version satisfies the comparator set.
func versionInRange(version, rangeExpr string) bool {
	rangeExpr = strings.TrimSpace(rangeExpr)
	if rangeExpr == "" || rangeExpr == "*" {
		return true
	}
	for _, term := range strings.FieldsFunc(rangeExpr, func(r rune) bool { return r == ',' || r == ' ' }) {
		m := versionComparatorRe.FindStringSubmatch(term)
		if m == nil {
			return false
		}
		op, want := m[1], m[2]
		cmp := compareVersions(version, want)
		switch op {
		case "", "=", "==":
			if cmp != 0 {
				return false
			}
		case "!=":
			if cmp == 0 {
				return false
			}
		case ">=":
			if cmp < 0 {
				return false
			}
		case "<=":
			if cmp > 0 {
				return false
			}
		case ">":
			if cmp <= 0 {
				return false
			}
		case "<":
			if cmp >= 0 {
				return false
			}
		}
	}
	return true
}

// validVersionRange reports whether every term parses — garbage ranges are a
// load-time validation error, not a runtime surprise.
func validVersionRange(rangeExpr string) error {
	rangeExpr = strings.TrimSpace(rangeExpr)
	if rangeExpr == "" || rangeExpr == "*" {
		return nil
	}
	for _, term := range strings.FieldsFunc(rangeExpr, func(r rune) bool { return r == ',' || r == ' ' }) {
		if versionComparatorRe.FindStringSubmatch(term) == nil {
			return fmt.Errorf("invalid version comparator %q", term)
		}
	}
	return nil
}
