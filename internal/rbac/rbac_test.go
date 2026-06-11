package rbac

import "testing"

func TestAllowsScopeAndServerAllowlist(t *testing.T) {
	p := Principal{
		ActorID:         "admin",
		Scopes:          []string{"node:read", "task:*"},
		ServerAllowlist: []string{"node-a"},
	}
	if !Allows(p, "task:run", "node-a") {
		t.Fatal("expected wildcard task scope on allowed node")
	}
	if Allows(p, "task:run", "node-b") {
		t.Fatal("expected server allowlist denial")
	}
	if Allows(p, "network:apply", "node-a") {
		t.Fatal("expected missing scope denial")
	}
}
