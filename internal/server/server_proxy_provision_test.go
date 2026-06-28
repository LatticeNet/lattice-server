package server

import (
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
)

func TestProxyCoreApplyScriptSingBoxAutoProvisions(t *testing.T) {
	script := proxyCoreApplyScript(proxycore.Artifact{
		Core:       model.ProxyCoreSingbox,
		ConfigPath: "/etc/sing-box/config.json",
		ConfigJSON: "{}",
	})
	for _, needle := range []string{
		"https://github.com/SagerNet/sing-box/releases/latest", // resolve latest version
		"sing-box-${SB_VER}-linux-${SB_ARCH}",                  // arch + version artifact name
		"install -m 0755",                                      // binary install
		"/etc/systemd/system/sing-box.service",                 // unit path
		"ExecStart=$SB_RUN run -c $SB_CFG",                     // unit points at the config we apply
		"systemctl daemon-reload",
		"sing-box check -c",                  // existing config validation preserved
		"systemctl reload sing-box",          // existing reload preserved
		"/opt/lattice/.archive_backup",       // auto-backup before apply
		"sing-box-$(date -u +%Y%m%d-%H%M%S)", // timestamped per-node archive
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("sing-box apply script missing %q:\n%s", needle, script)
		}
	}
	// Install must be skipped when the binary is already present (idempotent).
	if !strings.Contains(script, `if ! command -v sing-box >/dev/null 2>&1 && [ ! -x "$SB_BIN" ]; then`) {
		t.Fatalf("install must be guarded by a presence check:\n%s", script)
	}
	// Unit creation must be skipped when a unit already exists (don't clobber a
	// hand-managed or 233boy-managed sing-box service).
	if !strings.Contains(script, "! systemctl cat sing-box >/dev/null 2>&1") {
		t.Fatalf("unit creation must be skipped when a unit already exists:\n%s", script)
	}
	// sing-box must no longer hard-fail when absent.
	if strings.Contains(script, "sing-box binary not found on node") {
		t.Fatalf("sing-box apply script should auto-provision, not hard-fail:\n%s", script)
	}
}

func TestProxyCoreApplyScriptXrayStillHardFails(t *testing.T) {
	script := proxyCoreApplyScript(proxycore.Artifact{
		Core:       model.ProxyCoreXray,
		ConfigPath: "/usr/local/etc/xray/config.json",
		ConfigJSON: "{}",
	})
	if !strings.Contains(script, "xray binary not found on node") {
		t.Fatalf("xray apply script must keep fail-closed behavior:\n%s", script)
	}
	if strings.Contains(script, "releases/latest") {
		t.Fatalf("xray apply script must not auto-provision sing-box:\n%s", script)
	}
}
