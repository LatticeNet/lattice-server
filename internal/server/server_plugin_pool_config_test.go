package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestNewRejectsInvalidPluginRuntimePoolBeforePluginArtifacts(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pluginDir := t.TempDir()
	bundleDir := filepath.Join(pluginDir, "would.load")
	if err := os.Mkdir(bundleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "manifest.json"), []byte(`{"id":"would.load"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := t.TempDir()
	runtimeDir := filepath.Join(t.TempDir(), "runtime-not-created")
	bad := &plugin.SystemPoolConfig{Size: 0, MaxOverflow: 0, StartTimeout: time.Second, MaxUses: 1, MaxAge: time.Minute}
	srv, err := New(Options{
		Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true,
		PluginDir: pluginDir, PluginBundleCacheDir: cacheDir, PluginRuntimeDir: runtimeDir, PluginRuntimePool: bad,
	})
	if err == nil || srv != nil || !strings.Contains(err.Error(), "pool size") {
		t.Fatalf("server=%v err=%v", srv, err)
	}
	if _, err := os.Stat(runtimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid config touched runtime dir: %v", err)
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid config created plugin cache artifacts: %v", entries)
	}
}
