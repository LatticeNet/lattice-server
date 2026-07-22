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

func TestScopeMigrationCompatibility(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required string
		want     bool
	}{
		{name: "legacy read reaches vpn-core", granted: "proxy:read", required: "vpncore:read", want: true},
		{name: "legacy admin reaches vpn-core", granted: "proxy:admin", required: "vpncore:admin", want: true},
		{name: "legacy read reaches sub-store", granted: "proxy:read", required: "substore:read", want: true},
		{name: "legacy admin reaches sub-store", granted: "proxy:admin", required: "substore:admin", want: true},
		{name: "vpn-core read reaches native proxy", granted: "vpncore:read", required: "proxy:read", want: true},
		{name: "vpn-core admin reaches native proxy", granted: "vpncore:admin", required: "proxy:admin", want: true},
		{name: "vpn-core wildcard reaches native proxy", granted: "vpncore:*", required: "proxy:admin", want: true},
		{name: "legacy wildcard reaches sub-store", granted: "proxy:*", required: "substore:admin", want: true},
		{name: "sub-store cannot reach native proxy", granted: "substore:read", required: "proxy:read", want: false},
		{name: "sub-store cannot reach vpn-core", granted: "substore:admin", required: "vpncore:admin", want: false},
		{name: "vpn-core cannot reach sub-store", granted: "vpncore:read", required: "substore:read", want: false},
		{name: "read does not imply admin", granted: "proxy:read", required: "vpncore:admin", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Allows(Principal{Scopes: []string{tt.granted}}, tt.required, "")
			if got != tt.want {
				t.Fatalf("Allows(%q, %q) = %v, want %v", tt.granted, tt.required, got, tt.want)
			}
		})
	}
}

func TestCanonicalPluginScopesAreGrantable(t *testing.T) {
	for _, scope := range []string{
		"vpncore:read", "vpncore:admin", "vpncore:*",
		"substore:read", "substore:admin", "substore:*",
	} {
		if !ValidScope(scope) {
			t.Errorf("ValidScope(%q) = false", scope)
		}
	}
}

func TestCanDelegateScopeUsesDirectedMigrationRules(t *testing.T) {
	tests := []struct {
		name      string
		principal []string
		delegated string
		want      bool
	}{
		{name: "global wildcard delegates any valid scope", principal: []string{"*"}, delegated: "substore:admin", want: true},
		{name: "legacy read delegates vpn-core read", principal: []string{"proxy:read"}, delegated: "vpncore:read", want: true},
		{name: "legacy admin delegates sub-store admin", principal: []string{"proxy:admin"}, delegated: "substore:admin", want: true},
		{name: "legacy wildcard delegates vpn-core wildcard", principal: []string{"proxy:*"}, delegated: "vpncore:*", want: true},
		{name: "legacy wildcard delegates sub-store wildcard", principal: []string{"proxy:*"}, delegated: "substore:*", want: true},
		{name: "legacy read cannot delegate admin", principal: []string{"proxy:read"}, delegated: "vpncore:admin", want: false},
		{name: "legacy read cannot delegate wildcard", principal: []string{"proxy:read"}, delegated: "vpncore:*", want: false},
		{name: "vpn-core wildcard delegates own read", principal: []string{"vpncore:*"}, delegated: "vpncore:read", want: true},
		{name: "vpn-core cannot delegate legacy proxy", principal: []string{"vpncore:*"}, delegated: "proxy:read", want: false},
		{name: "vpn-core cannot delegate sub-store", principal: []string{"vpncore:*"}, delegated: "substore:read", want: false},
		{name: "sub-store wildcard delegates own admin", principal: []string{"substore:*"}, delegated: "substore:admin", want: true},
		{name: "sub-store cannot delegate legacy proxy", principal: []string{"substore:*"}, delegated: "proxy:admin", want: false},
		{name: "sub-store cannot delegate vpn-core", principal: []string{"substore:*"}, delegated: "vpncore:read", want: false},
		{name: "unknown future scope is never delegable", principal: []string{"*"}, delegated: "future:admin", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanDelegateScope(Principal{Scopes: tt.principal}, tt.delegated)
			if got != tt.want {
				t.Fatalf("CanDelegateScope(%v, %q) = %v, want %v", tt.principal, tt.delegated, got, tt.want)
			}
		})
	}
}
