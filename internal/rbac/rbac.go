package rbac

import "strings"

type Principal struct {
	ActorID         string
	TokenID         string
	Scopes          []string
	ServerAllowlist []string
}

func Allows(p Principal, scope string, nodeID string) bool {
	if !scopeAllowed(p.Scopes, scope) {
		return false
	}
	if len(p.ServerAllowlist) == 0 || nodeID == "" {
		return true
	}
	for _, allowed := range p.ServerAllowlist {
		if allowed == "*" || allowed == nodeID {
			return true
		}
	}
	return false
}

func scopeAllowed(scopes []string, required string) bool {
	if directlyAllows(scopes, required) {
		return true
	}
	for _, compatible := range compatibleScopes(required) {
		if directlyAllows(scopes, compatible) {
			return true
		}
	}
	return false
}

func directlyAllows(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == "*" || scope == required {
			return true
		}
		if strings.HasSuffix(scope, ":*") {
			prefix := strings.TrimSuffix(scope, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}
	return false
}

// compatibleScopes keeps existing proxy grants working while the first-party
// vpn-core and sub-store manifests move to narrower domain scopes. vpn-core
// also fronts the existing native proxy APIs, so its scopes bridge those legacy
// checks. Sub-store scopes deliberately do not grant proxy or vpn-core access.
func compatibleScopes(required string) []string {
	switch required {
	case "proxy:read":
		return []string{"vpncore:read"}
	case "proxy:admin":
		return []string{"vpncore:admin"}
	case "vpncore:read", "substore:read":
		return []string{"proxy:read"}
	case "vpncore:admin", "substore:admin":
		return []string{"proxy:admin"}
	default:
		return nil
	}
}

// KnownScopes is the catalog of grantable RBAC scope strings. It is the
// authoritative allowlist the user-management API validates assignments against
// so an operator cannot be saddled with a typo'd or made-up scope that silently
// grants nothing (or, worse, a future-meaningful string). Keep it in sync with
// the scopes actually checked by withAuth(...)/requireScope across the server.
var KnownScopes = map[string]struct{}{
	"audit:read":      {},
	"ddns:admin":      {},
	"dns:admin":       {},
	"geo:admin":       {},
	"geo:read":        {},
	"group:admin":     {},
	"group:read":      {},
	"inventory:admin": {},
	"inventory:read":  {},
	"kv:admin":        {},
	"kv:read":         {},
	"kv:write":        {},
	"log:admin":       {},
	"log:read":        {},
	"log:write":       {},
	"monitor:admin":   {},
	"monitor:read":    {},
	"netguard:admin":  {},
	"netguard:read":   {},
	"netpolicy:admin": {},
	"netpolicy:read":  {},
	"network:apply":   {},
	"network:plan":    {},
	"node:admin":      {},
	"node:read":       {},
	"notify:send":     {},
	"oidc:admin":      {},
	"plugin:admin":    {},
	"plugin:verify":   {},
	"proxy:admin":     {},
	"proxy:read":      {},
	"substore:admin":  {},
	"substore:read":   {},
	"static:admin":    {},
	"static:read":     {},
	"static:write":    {},
	"task:read":       {},
	"task:run":        {},
	"terminal:open":   {},
	"token:admin":     {},
	"tunnel:admin":    {},
	"user:admin":      {},
	"vpncore:admin":   {},
	"vpncore:read":    {},
	"worker:deploy":   {},
}

// ValidScope reports whether s is a grantable scope: the global superuser "*", a
// known catalog member, or a domain wildcard ("node:*") whose prefix matches a
// known scope's domain.
func ValidScope(s string) bool {
	if s == "*" {
		return true
	}
	if _, ok := KnownScopes[s]; ok {
		return true
	}
	if strings.HasSuffix(s, ":*") {
		prefix := strings.TrimSuffix(s, "*")
		for k := range KnownScopes {
			if strings.HasPrefix(k, prefix) {
				return true
			}
		}
	}
	return false
}
