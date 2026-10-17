//go:build linux

package plugin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// requireRoot skips a test whose setup only root can make (a chown, a file
// capability). Under LATTICE_TEST_REQUIRE_UID_DROP=1 it fails instead, unless
// LATTICE_TEST_ALLOW_NO_CHOWN=1 says the run holds only the server's three
// capabilities and the root run covers these tests.
func requireRoot(t *testing.T, why string) {
	t.Helper()
	if os.Geteuid() == 0 {
		return
	}
	if os.Getenv("LATTICE_TEST_REQUIRE_UID_DROP") == "1" && os.Getenv("LATTICE_TEST_ALLOW_NO_CHOWN") != "1" {
		t.Fatal(why)
	}
	t.Skip(why)
}

// setFileCapabilities gives path cap_setuid,cap_setgid,cap_kill+ep, as the
// image's setcap does: a revision 2 security.capability value with the
// effective flag and the three in the permitted set.
func setFileCapabilities(t *testing.T, path string) {
	t.Helper()
	value := make([]byte, 20)
	binary.LittleEndian.PutUint32(value[0:], 0x02000000|0x1)
	binary.LittleEndian.PutUint32(value[4:], 1<<capSetuid|1<<capSetgid|1<<capKill)
	if err := syscall.Setxattr(path, "security.capability", value, 0); err != nil {
		t.Fatalf("set file capabilities on %s: %v", path, err)
	}
}

// writeBinary writes a stand-in server binary with mode and owner, then the
// three file capabilities when capped is set. chown clears file
// capabilities, so they are set last.
func writeBinary(t *testing.T, path string, mode os.FileMode, uid, gid int, capped bool) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if capped {
		setFileCapabilities(t, path)
	}
}

// File capabilities land on whoever execs the file, so a capped server binary
// a plugin uid can exec hands that plugin CAP_SETUID back. The check refuses
// exactly the binaries a plugin identity (its uid as its gid, no
// supplementary groups) could exec while they carry capabilities.
func TestPluginUIDRefusesACappedServerBinaryPluginsCanExec(t *testing.T) {
	requireRoot(t, "setting a file capability needs root")
	rng := PluginUIDRange{Base: 200000, Size: 64}
	inRange := int(rng.Base) + 5
	bin := filepath.Join(t.TempDir(), "lattice-server")
	for _, tc := range []struct {
		name     string
		mode     os.FileMode
		uid, gid int
		capped   bool
		refused  bool
	}{
		{"0755 without capabilities", 0o755, 0, 0, false, false},
		{"0755 with the three capabilities, the image before the review", 0o755, 0, 0, true, true},
		{"0751 with capabilities", 0o751, 0, 0, true, true},
		{"0750 root and the server's group, as the image installs it", 0o750, 0, 101, true, false},
		{"0750 with a group inside the range", 0o750, 0, inRange, true, true},
		{"0700 with a group inside the range", 0o700, 0, inRange, true, false},
		{"0700 owned by a uid inside the range", 0o700, inRange, 0, true, true},
	} {
		writeBinary(t, bin, tc.mode, tc.uid, tc.gid, tc.capped)
		err := checkCappedBinary(bin, rng)
		if tc.refused && (err == nil || !strings.Contains(err.Error(), "file capabilities")) {
			t.Fatalf("%s: got %v, want a refusal", tc.name, err)
		}
		if !tc.refused && err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
}

// The runner checks its own binary before it arms the drop, and only then.
func TestPluginUIDRunnerWillNotArmOverACappedBinaryPluginsCanExec(t *testing.T) {
	requireRoot(t, "setting a file capability needs root")
	bin := filepath.Join(t.TempDir(), "lattice-server")
	orig := serverExecutable
	serverExecutable = func() (string, error) { return bin, nil }
	t.Cleanup(func() { serverExecutable = orig })
	rng := &PluginUIDRange{Base: 200000, Size: 64}

	writeBinary(t, bin, 0o755, 0, 0, true)
	if _, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), PluginUIDs: rng}); err == nil || !strings.Contains(err.Error(), "regain CAP_SETUID") {
		t.Fatalf("arming over a 0755 capped binary: got %v, want a refusal", err)
	}
	if _, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir()}); err != nil {
		t.Fatalf("with the drop off the binary is not checked: %v", err)
	}
	writeBinary(t, bin, 0o750, 0, 101, true)
	if _, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), PluginUIDs: rng}); err != nil {
		t.Fatalf("arming over the image's 0750 root:lattice binary: %v", err)
	}
}

// A data file or master key owned by a uid or group in the range would belong
// to the plugin assigned it, so the drop is not armed over one.
func TestPluginUIDOwnershipRefusesAFileARangeIDOwns(t *testing.T) {
	requireRoot(t, "changing an owner needs root")
	rng := PluginUIDRange{Base: 200000, Size: 64}
	inRange := int(rng.Base) + 9
	data := t.TempDir()
	sub := filepath.Join(data, "plugin-bundles")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(data, "state.json")
	wal := filepath.Join(sub, "bundle.json")
	key := filepath.Join(t.TempDir(), "master.key")
	for _, f := range []string{state, wal, key} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := rng.CheckOwnership(data, key); err != nil {
		t.Fatalf("a tree the server owns: %v", err)
	}
	for _, path := range []string{data, sub, state, wal, key} {
		for _, owner := range [][2]int{{inRange, 0}, {0, inRange}} {
			if err := os.Lchown(path, owner[0], owner[1]); err != nil {
				t.Fatal(err)
			}
			if err := rng.CheckOwnership(data, key); err == nil || !strings.Contains(err.Error(), path+" is owned by") {
				t.Fatalf("%s owned by %d:%d: got %v, want a refusal naming it", path, owner[0], owner[1], err)
			}
			if err := os.Lchown(path, 0, 0); err != nil {
				t.Fatal(err)
			}
		}
	}
	// An owner outside the range is not this check's concern.
	if err := os.Lchown(state, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if err := rng.CheckOwnership(data, key); err != nil {
		t.Fatalf("an owner outside the range: %v", err)
	}

	// The walk resolves a symlinked path once and follows no symlink below it.
	elsewhere := t.TempDir()
	planted := filepath.Join(elsewhere, "planted")
	if err := os.WriteFile(planted, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(planted, inRange, inRange); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(data, "link")); err != nil {
		t.Fatal(err)
	}
	if err := rng.CheckOwnership(data); err != nil {
		t.Fatalf("a symlink below the data directory must not be followed: %v", err)
	}
	rootLink := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(elsewhere, rootLink); err != nil {
		t.Fatal(err)
	}
	if err := rng.CheckOwnership(rootLink); err == nil || !strings.Contains(err.Error(), "planted is owned by") {
		t.Fatalf("a symlinked data directory must be resolved: got %v", err)
	}
	if err := rng.CheckOwnership("", filepath.Join(data, "missing")); err != nil {
		t.Fatalf("empty and missing paths are skipped: %v", err)
	}
}
