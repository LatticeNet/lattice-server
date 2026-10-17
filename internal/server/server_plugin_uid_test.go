package server

import (
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Per-plugin uids apply only to the system runner, so a uid range without a
// runtime dir is refused instead of leaving the operator to believe plugins
// are isolated (design 30).
func TestNewRefusesPluginUIDsWithoutARuntimeDir(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginUIDs: &plugin.PluginUIDRange{Base: 300000, Size: 8},
	})
	if err == nil || srv != nil || !strings.Contains(err.Error(), "LATTICE_PLUGIN_RUNTIME_DIR is not") {
		t.Fatalf("New with a uid range and no runtime dir: got a server=%t, err=%v; want a refusal", srv != nil, err)
	}
}
