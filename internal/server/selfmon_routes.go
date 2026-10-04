package server

import (
	"net/http"
	"strings"
)

// routeGroupUnmatched is the group for an /api path no registered route
// owns. Grouping it apart keeps a scanner's guesses out of the real groups
// and out of the metrics store's series.
const routeGroupUnmatched = "/api (unmatched)"

// routeGroupMux is the server's ServeMux, noting the route group of every
// pattern registered on it, so the self-monitor groups requests by what the
// server actually routes.
type routeGroupMux struct {
	*http.ServeMux
	groups routeGroups
}

func newRouteGroupMux() *routeGroupMux {
	return &routeGroupMux{ServeMux: http.NewServeMux(), groups: routeGroups{}}
}

func (m *routeGroupMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.groups[routeGroupOf(pattern)] = true
	m.ServeMux.HandleFunc(pattern, handler)
}

func (m *routeGroupMux) Handle(pattern string, handler http.Handler) {
	m.groups[routeGroupOf(pattern)] = true
	m.ServeMux.Handle(pattern, handler)
}

// routeGroups is the set of groups the registered patterns make. It is
// written only while Handler builds the mux and read-only after.
type routeGroups map[string]bool

// routeGroupOf names the group a path belongs to: "/api/<area>" for the
// console's API, "/api/agent/<endpoint>" for the agent's (a heartbeat and a
// task poll are different work), and the first segment for everything else.
func routeGroupOf(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return "/"
	}
	segs := strings.SplitN(trimmed, "/", 4)
	if segs[0] == "api" {
		switch {
		case len(segs) >= 3 && segs[1] == "agent":
			return "/api/agent/" + segs[2]
		case len(segs) >= 2:
			return "/api/" + segs[1]
		}
		return "/api"
	}
	return "/" + segs[0]
}

// group returns the route group of a request path already made safe by
// telemetry.RequestPathForObservability. A path outside every registered
// group is the console's static handler (registered at "/") unless it is
// under /api, where it is unmatched.
func (g routeGroups) group(path string) string {
	name := routeGroupOf(path)
	if g[name] {
		return name
	}
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		return routeGroupUnmatched
	}
	return "/"
}
