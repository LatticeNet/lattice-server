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

// A managed node that declares a stats API gets a v2ray_api block whose
// allowlist names every tag and user the render just produced.
//
// This is pinned because the failure is silent in the worst way: sing-box
// builds its match sets from these lists at startup and returns anything
// matching none of them uncounted, so an omitted or empty allowlist produces a
// stats API that answers every query with zero. The node reports "usage
// collection ok" and every counter reads nothing.
func TestRenderStatsAPIAllowlistNamesWhatItRendered(t *testing.T) {
	p := baseProfile()
	p.StatsAPI = "127.0.0.1:8080"
	now := time.Now()
	// The fixture has to contain a user the renderer will drop, or the test
	// cannot tell "the allowlist names what was rendered" from "the allowlist
	// names what it was asked to render". With only eligible users both
	// derivations produce the same list and a regression to the intent source
	// ships undetected, which is the node-side bug this whole change exists to
	// stop: a name in the allowlist that no longer matches a user in the config
	// reads as healthy collection while under-counting.
	expired := baseUser("carol", "u_c3d4e5f607182930", "33333333-3333-3333-3333-333333333333", now)
	expired.ExpiresAt = now.Add(-time.Hour)
	overQuota := baseUser("dave", "u_d4e5f60718293041", "44444444-4444-4444-4444-444444444444", now)
	overQuota.TrafficLimitBytes = 1024
	overQuota.UsedBytes = 4096
	disabled := baseUser("erin", "u_e5f6071829304152", "55555555-5555-5555-5555-555555555555", now)
	disabled.Enabled = false
	users := []model.ProxyUser{
		baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", now),
		baseUser("bob", "u_b2c3d4e5f6071829", "22222222-2222-2222-2222-222222222222", now),
		expired, overQuota, disabled,
	}
	cfg, _, err := RenderSingBoxConfig(p, []model.ProxyInbound{baseInbound()}, users, RenderOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if cfg.Experimental == nil || cfg.Experimental.V2RayAPI == nil {
		t.Fatalf("stats api was asked for but not rendered: %+v", cfg.Experimental)
	}
	api := cfg.Experimental.V2RayAPI
	if api.Listen != "127.0.0.1:8080" {
		t.Fatalf("listen = %q", api.Listen)
	}
	if !api.Stats.Enabled {
		t.Fatal("stats must be enabled when the block is rendered")
	}
	wantInbounds := []string{}
	for _, in := range cfg.Inbounds {
		wantInbounds = append(wantInbounds, in.Tag)
	}
	if len(api.Stats.Inbounds) != len(wantInbounds) || len(wantInbounds) == 0 {
		t.Fatalf("inbound allowlist = %v, rendered inbounds %v", api.Stats.Inbounds, wantInbounds)
	}
	for _, tag := range wantInbounds {
		if !containsString(api.Stats.Inbounds, tag) {
			t.Fatalf("inbound %q is rendered but not counted: %v", tag, api.Stats.Inbounds)
		}
	}
	for _, out := range cfg.Outbounds {
		if !containsString(api.Stats.Outbounds, out.Tag) {
			t.Fatalf("outbound %q is rendered but not counted: %v", out.Tag, api.Stats.Outbounds)
		}
	}
	for _, in := range cfg.Inbounds {
		for _, u := range in.Users {
			if u.Name == "" {
				continue
			}
			if !containsString(api.Stats.Users, u.Name) {
				t.Fatalf("user %q is rendered but not counted: %v", u.Name, api.Stats.Users)
			}
		}
	}
	if len(api.Stats.Users) != 2 {
		t.Fatalf("users = %v, want exactly the two the renderer kept", api.Stats.Users)
	}
	// The three ineligible users must not appear. Naming one would mean the
	// allowlist was derived from the intent rather than from the output.
	for _, name := range []string{"u_c3d4e5f607182930", "u_d4e5f60718293041", "u_e5f6071829304152"} {
		if containsString(api.Stats.Users, name) {
			t.Fatalf("user %q was dropped from the config but is still counted: %v", name, api.Stats.Users)
		}
	}
	// And the ones it did drop really were dropped, so the assertion above is
	// about the allowlist rather than about a fixture that renders everything.
	rendered := map[string]bool{}
	for _, in := range cfg.Inbounds {
		for _, u := range in.Users {
			rendered[u.Name] = true
		}
	}
	if len(rendered) != 2 {
		t.Fatalf("the fixture rendered %d users; it must drop three for this test to mean anything", len(rendered))
	}
}

// The allowlist is serialised as three lists, never omitted. An absent key
// leaves sing-box matching on nothing, which is the same silent zero as an
// empty one but harder to see in a diff.
func TestRenderStatsAPIAllowlistIsAlwaysSerialised(t *testing.T) {
	p := baseProfile()
	p.StatsAPI = "127.0.0.1:8080"
	_, _, artifact, err := renderArtifactForTest(p)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got struct {
		Experimental struct {
			V2RayAPI struct {
				Listen string `json:"listen"`
				Stats  struct {
					Enabled   bool      `json:"enabled"`
					Inbounds  *[]string `json:"inbounds"`
					Outbounds *[]string `json:"outbounds"`
					Users     *[]string `json:"users"`
				} `json:"stats"`
			} `json:"v2ray_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal([]byte(artifact.ConfigJSON), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Experimental.V2RayAPI.Stats.Inbounds == nil ||
		got.Experimental.V2RayAPI.Stats.Outbounds == nil ||
		got.Experimental.V2RayAPI.Stats.Users == nil {
		t.Fatalf("an allowlist key was omitted from the rendered JSON: %s", artifact.ConfigJSON)
	}
}

// A profile with no stats API renders no v2ray_api block, and asking for a
// routable one is refused rather than quietly bound: this endpoint reports
// every user's traffic.
func TestRenderStatsAPIAbsentAndNonLoopbackRefused(t *testing.T) {
	now := time.Now()
	users := []model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", now)}
	cfg, _, err := RenderSingBoxConfig(baseProfile(), []model.ProxyInbound{baseInbound()}, users, RenderOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if cfg.Experimental != nil {
		t.Fatalf("no stats api was asked for, got %+v", cfg.Experimental)
	}
	for _, addr := range []string{"0.0.0.0:8080", "[::]:8080", "10.0.0.1:8080", "example.com:8080", "127.0.0.1"} {
		p := baseProfile()
		p.StatsAPI = addr
		if _, _, err := RenderSingBoxConfig(p, []model.ProxyInbound{baseInbound()}, users, RenderOptions{}); err == nil {
			t.Fatalf("stats_api %q should be refused", addr)
		}
	}
}

// Both loopback endpoints coexist: enabling stats must not drop the Clash API
// the trace collector depends on, and vice versa.
func TestRenderStatsAPIAndClashAPICoexist(t *testing.T) {
	p := baseProfile()
	p.ClashAPI = "127.0.0.1:9090"
	p.StatsAPI = "127.0.0.1:8080"
	cfg, _, err := RenderSingBoxConfig(p, []model.ProxyInbound{baseInbound()},
		[]model.ProxyUser{baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", time.Now())}, RenderOptions{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if cfg.Experimental == nil || cfg.Experimental.ClashAPI == nil || cfg.Experimental.V2RayAPI == nil {
		t.Fatalf("both endpoints should render: %+v", cfg.Experimental)
	}
	if cfg.Experimental.ClashAPI.ExternalController != "127.0.0.1:9090" {
		t.Fatalf("clash api = %q", cfg.Experimental.ClashAPI.ExternalController)
	}
	if cfg.Experimental.V2RayAPI.Listen != "127.0.0.1:8080" {
		t.Fatalf("stats api = %q", cfg.Experimental.V2RayAPI.Listen)
	}
}

// The same intent renders byte-identical allowlists, so an apply is not
// triggered by list ordering alone.
func TestRenderStatsAPIAllowlistIsDeterministic(t *testing.T) {
	p := baseProfile()
	p.StatsAPI = "127.0.0.1:8080"
	first, second := "", ""
	for i := 0; i < 2; i++ {
		_, _, artifact, err := renderArtifactForTest(p)
		if err != nil {
			t.Fatalf("render %d: %v", i, err)
		}
		if i == 0 {
			first = artifact.ConfigSHA256
		} else {
			second = artifact.ConfigSHA256
		}
	}
	if first != second {
		t.Fatalf("render is not deterministic: %s vs %s", first, second)
	}
}

func renderArtifactForTest(p model.ProxyNodeProfile) (model.ProxyNodeProfile, []string, Artifact, error) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	users := []model.ProxyUser{
		baseUser("bob", "u_b2c3d4e5f6071829", "22222222-2222-2222-2222-222222222222", now),
		baseUser("alice", "u_a1b2c3d4e5f60718", "11111111-1111-1111-1111-111111111111", now),
	}
	artifact, err := RenderSingBoxConfigJSON(p, []model.ProxyInbound{baseInbound()}, users, RenderOptions{Now: now})
	return p, nil, artifact, err
}

func containsString(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}
