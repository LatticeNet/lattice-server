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

// SecretRevealScope lets an API token read secret material: identity
// credentials, subscription links and their tokens, a line's share URL, a
// knock sequence. It is the one scope no other grant implies. Not "*", not an
// admin scope and not a domain wildcard satisfies it, so a token minted before
// it existed, however broad, reveals nothing. An interactive session never
// needs it: a person reveals through a fresh second-factor step-up instead.
//
// Never test it with Allows, which reads "*" as covering every scope. The
// server's reveal gate tests it with HoldsExplicitScope.
const SecretRevealScope = "secrets:reveal"

// explicitOnlyScopes are scopes a principal holds only by naming them.
var explicitOnlyScopes = map[string]bool{SecretRevealScope: true}

// ExplicitOnly reports whether scope is held only by naming it. The server
// grants such a scope through its own door (a token minted by a full
// administrator's session after step-up), never through the ordinary
// delegation rule, and never to a user account.
func ExplicitOnly(scope string) bool { return explicitOnlyScopes[scope] }

// HoldsExplicitScope reports whether scopes names scope itself. Wildcards do
// not count, which is the whole point for an explicit-only scope.
func HoldsExplicitScope(scopes []string, scope string) bool {
	for _, held := range scopes {
		if held == scope {
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
	if explicitOnlyScopes[required] {
		return HoldsExplicitScope(scopes, required)
	}
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
	case "sshguard:read":
		// Administering the domain implies reading it. Without this a holder of
		// sshguard:admin could author and decide an SSH Guard plan and not be
		// able to list the approval they just created.
		return []string{"sshguard:admin"}
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

// CanDelegateScope reports whether p may assign delegated to another user or
// token. Unlike Allows, delegation is intentionally not symmetric across the
// runtime compatibility aliases: vpn-core and sub-store grants stay confined
// to their own domains. Legacy proxy grants may delegate equal-strength scopes
// into either replacement domain during the migration window.
func CanDelegateScope(p Principal, delegated string) bool {
	if !ValidScope(delegated) {
		return false
	}
	if directlyAllows(p.Scopes, delegated) {
		return true
	}
	switch delegated {
	case "vpncore:read", "substore:read":
		return directlyAllows(p.Scopes, "proxy:read")
	case "vpncore:admin", "substore:admin":
		return directlyAllows(p.Scopes, "proxy:admin")
	case "vpncore:*", "substore:*":
		return directlyAllows(p.Scopes, "proxy:*")
	default:
		return false
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
	// notify split (2026-09): notify:send authorizes dispatch only (the
	// test-send endpoint and the plugin notify capability); notify:admin
	// governs the routing fabric, channels, rules and inbound webhooks.
	// One flat notify:send let a dispatch-only token re-route fleet-wide
	// security telemetry. Compat: a token holding only notify:send keeps
	// dispatch and loses management; "*" and "notify:*" grants (the
	// bootstrap admin holds "*") satisfy both sides of the split.
	"notify:admin":    {},
	"notify:send":     {},
	"oidc:admin":      {},
	"plugin:admin":    {},
	"plugin:verify":   {},
	"proxy:admin":     {},
	"proxy:read":      {},
	"secrets:reveal":  {}, // explicit-only: see SecretRevealScope
	"sshguard:admin":  {},
	"sshguard:read":   {},
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
	"wireguard:admin": {},
	"wireguard:read":  {},
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
			if strings.HasPrefix(k, prefix) && !explicitOnlyScopes[k] {
				return true
			}
		}
	}
	return false
}
