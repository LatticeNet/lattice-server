package plugin

import (
	"fmt"
	"regexp"
	"strings"
)

// A manifest names the oldest server it runs on in compatibility.server (and,
// for older manifests, min_server). Floors are written in semver against the
// server's train: ">=0.2.2-alpha.147" for the image tagged alpha-0.2.2a147.

var serverTagRe = regexp.MustCompile(`^(?:v?([0-9]+\.[0-9]+\.[0-9]+)|alpha-([0-9]+\.[0-9]+\.[0-9]+)a([0-9]+)|beta-([0-9]+\.[0-9]+\.[0-9]+)b([0-9]+))$`)

// ServerSemver turns the server's release tag into the version a manifest's
// server floor is written against: alpha-0.2.2a147 is 0.2.2-alpha.147,
// beta-0.2.2b3 is 0.2.2-beta.3, v0.2.3 is 0.2.3. ok is false for a
// development build ("dev") or any tag it does not recognise, and floors are
// then not enforced, so a local build still loads every plugin.
func ServerSemver(tag string) (string, bool) {
	m := serverTagRe.FindStringSubmatch(strings.TrimSpace(tag))
	switch {
	case m == nil:
		return "", false
	case m[1] != "":
		return m[1], true
	case m[2] != "":
		return m[2] + "-alpha." + m[3], true
	default:
		return m[4] + "-beta." + m[5], true
	}
}

// checkServerFloor refuses a manifest whose server floor the running server
// does not meet. serverVersion comes from ServerSemver; empty enforces nothing.
// A floor written as a bare version means "at least" that version. A floor
// that does not parse as a version range is not enforced, so a manifest that
// loaded before floors were read keeps loading.
func checkServerFloor(m Manifest, serverVersion string) error {
	if serverVersion == "" {
		return nil
	}
	var floors []string
	if m.Compatibility != nil {
		floors = append(floors, m.Compatibility.Server)
	}
	floors = append(floors, m.MinServer)
	for _, floor := range floors {
		floor = strings.TrimSpace(floor)
		if floor == "" || floor == "*" {
			continue
		}
		rangeExpr := floor
		if floor[0] >= '0' && floor[0] <= '9' {
			rangeExpr = ">=" + floor
		}
		if validVersionRange(rangeExpr) != nil {
			continue
		}
		if !versionInRange(serverVersion, rangeExpr) {
			return fmt.Errorf("needs a server %s, and this server is %s; upgrade the server before installing this plugin", rangeExpr, serverVersion)
		}
	}
	return nil
}
