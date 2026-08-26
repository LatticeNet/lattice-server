package proxycore

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A managed node renders at info, not warn.
//
// This is pinned because it is load bearing and was previously unpinned: the
// connection lifecycle lines a trace record is assembled from are logged at
// info, so a node rendered at warn is silent about every connection it serves,
// and nothing in the suite would have noticed.
func TestRenderDefaultsToInfoLevel(t *testing.T) {
	cfg, _, err := RenderSingBoxConfig(baseProfile(), []model.ProxyInbound{baseInbound()}, []model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", time.Now())}, RenderOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("log level = %q, want info", cfg.Log.Level)
	}
	if !cfg.Log.Timestamp {
		t.Fatal("timestamp should stay on")
	}
	if cfg.Experimental != nil {
		t.Fatalf("no clash api was asked for, got %+v", cfg.Experimental)
	}
}

func TestRenderHonorsProfileLogLevel(t *testing.T) {
	for _, level := range []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"} {
		p := baseProfile()
		p.LogLevel = level
		cfg, _, err := RenderSingBoxConfig(p, []model.ProxyInbound{baseInbound()}, []model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", time.Now())}, RenderOptions{})
		if err != nil {
			t.Fatalf("level %s: %v", level, err)
		}
		if cfg.Log.Level != level {
			t.Fatalf("level %s rendered as %q", level, cfg.Log.Level)
		}
	}
}

// An unknown level is refused rather than quietly corrected. A typo that
// downgrades a node to "no connection logging" is the silent failure this
// subsystem exists to remove, so it must be loud at render time.
func TestRenderRejectsUnknownLogLevel(t *testing.T) {
	p := baseProfile()
	p.LogLevel = "verbose"
	if _, _, err := RenderSingBoxConfig(p, []model.ProxyInbound{baseInbound()}, []model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", time.Now())}, RenderOptions{}); err == nil {
		t.Fatal("expected an error for an unknown log level")
	}
}

func TestRenderClashAPIBlock(t *testing.T) {
	p := baseProfile()
	p.ClashAPI = "127.0.0.1:9090"
	p.ClashAPISecret = "s3cret"
	art, err := RenderSingBoxConfigJSON(p, []model.ProxyInbound{baseInbound()}, []model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", time.Now())}, RenderOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got struct {
		Experimental struct {
			ClashAPI struct {
				ExternalController string `json:"external_controller"`
				Secret             string `json:"secret"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal([]byte(art.ConfigJSON), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Experimental.ClashAPI.ExternalController != "127.0.0.1:9090" {
		t.Fatalf("external_controller = %q", got.Experimental.ClashAPI.ExternalController)
	}
	if got.Experimental.ClashAPI.Secret != "s3cret" {
		t.Fatalf("secret = %q", got.Experimental.ClashAPI.Secret)
	}
}

// The Clash API serves live connection metadata and log lines. Binding it off
// loopback would hand that to the network, so the renderer refuses rather than
// leaving it to node-side configuration to get right.
func TestRenderRejectsNonLoopbackClashAPI(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:9090",
		"1.2.3.4:9090",
		"[::]:9090",
		"example.com:9090",
		"127.0.0.1:0",
		"127.0.0.1:70000",
		"127.0.0.1",
		"",
	} {
		p := baseProfile()
		p.ClashAPI = addr
		_, _, err := RenderSingBoxConfig(p, []model.ProxyInbound{baseInbound()}, []model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", time.Now())}, RenderOptions{})
		if addr == "" {
			// Empty means "do not render the block", which is not an error.
			if err != nil {
				t.Fatalf("empty clash api should not error: %v", err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("address %q was accepted and should not have been", addr)
		}
	}
}

func TestRenderAcceptsLoopbackForms(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:9090", "localhost:9090", "[::1]:9090", "127.9.9.9:1"} {
		p := baseProfile()
		p.ClashAPI = addr
		if _, _, err := RenderSingBoxConfig(p, []model.ProxyInbound{baseInbound()}, []model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", time.Now())}, RenderOptions{}); err != nil {
			t.Fatalf("address %q rejected: %v", addr, err)
		}
	}
}

// The rendered config is a node-scoped secret-bearing artifact and the Clash
// API secret rides in it. This asserts the secret is not emitted when no API is
// configured, so a profile carrying a stale secret cannot leak it into a config
// that has nothing to authenticate.
func TestRenderOmitsSecretWithoutClashAPI(t *testing.T) {
	p := baseProfile()
	p.ClashAPISecret = "leftover-secret"
	art, err := RenderSingBoxConfigJSON(p, []model.ProxyInbound{baseInbound()}, []model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", time.Now())}, RenderOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(art.ConfigJSON, "leftover-secret") {
		t.Fatal("secret was rendered with no clash_api block present")
	}
	if strings.Contains(art.ConfigJSON, "experimental") {
		t.Fatal("experimental block should be omitted entirely")
	}
}
