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
