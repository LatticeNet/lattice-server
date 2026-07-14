package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// A plugin secret is readable by the plugin BACKEND and by nothing else.
//
// The plugin KV store shows how easily that is lost: it is reachable over GET /api/kv
// by any principal holding the kv:read RBAC scope, so `plugin:<id>`'s whole bucket is
// browser-readable. Plugin capabilities and operator RBAC scopes are separate
// namespaces that happen to share spellings, and the moment "secret:read" appears in
// KnownScopes it becomes grantable to a token and, from there, reachable from a page.
//
// There is no HTTP handler for the secret collection, and there must never be one.
func TestSecretCapabilitiesAreNotOperatorRBACScopes(t *testing.T) {
	for _, capability := range []string{"secret:read", "secret:write"} {
		if _, ok := rbac.KnownScopes[capability]; ok {
			t.Fatalf("%q is an operator RBAC scope: a token could be granted it, making the "+
				"plugin vault reachable from the browser", capability)
		}
	}
}

// Defense in depth, in the crudest and most durable form: no source file outside the
// host adapter may reach the secret store. A future handler added by reflex would trip
// this before it could ship.
func TestNoHTTPHandlerReachesThePluginSecretStore(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == "plugin_host.go" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"PluginSecret(", "PutPluginSecret(", "DeletePluginSecret("} {
			if strings.Contains(string(body), forbidden) {
				t.Errorf("%s reaches the plugin secret store via %s; only the broker's host "+
					"adapter (plugin_host.go) may touch it", name, forbidden)
			}
		}
	}
}
