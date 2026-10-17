package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePluginUIDRange(t *testing.T) {
	for name, tc := range map[string]struct {
		base, size string
		want       *PluginUIDRange
		refusal    string
	}{
		"unset is off":                 {"", "", nil, ""},
		"blank is off":                 {"  ", "", nil, ""},
		"base alone takes the default": {"200000", "", &PluginUIDRange{Base: 200000, Size: DefaultPluginUIDRange}, ""},
		"base and range":               {" 200000 ", " 64 ", &PluginUIDRange{Base: 200000, Size: 64}, ""},
		"the lowest base":              {"1000", "1", &PluginUIDRange{Base: 1000, Size: 1}, ""},
		"the last valid uid":           {"4294967294", "1", &PluginUIDRange{Base: 4294967294, Size: 1}, ""},
		"range without a base":         {"", "32", nil, "LATTICE_PLUGIN_UID_BASE is not"},
		"base below 1000":              {"999", "", nil, "below 1000"},
		"base zero":                    {"0", "", nil, "below 1000"},
		"base not a number":            {"lattice", "", nil, "invalid LATTICE_PLUGIN_UID_BASE"},
		"negative base":                {"-1", "", nil, "invalid LATTICE_PLUGIN_UID_BASE"},
		"base past 32 bits":            {"4294967296", "", nil, "invalid LATTICE_PLUGIN_UID_BASE"},
		"empty range":                  {"200000", "0", nil, "invalid LATTICE_PLUGIN_UID_RANGE"},
		"range not a number":           {"200000", "many", nil, "invalid LATTICE_PLUGIN_UID_RANGE"},
		"range reaching (uid_t)-1":     {"4294967294", "2", nil, "past the largest valid uid"},
		"range past 32 bits":           {"4294967000", "1000", nil, "past the largest valid uid"},
	} {
		got, err := ParsePluginUIDRange(tc.base, tc.size)
		if tc.refusal != "" {
			if err == nil || !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("%s: got %v, %v; want a refusal mentioning %q", name, got, err, tc.refusal)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Fatalf("%s: got %+v, want %+v", name, got, tc.want)
		}
	}
}

// The range is refused when any server identity number, or the probe's
// 65532, falls inside it, at either edge.
func TestPluginUIDRangeRefusesTheServerIdentity(t *testing.T) {
	server := processIdentity{UIDs: []uint32{100, 100}, GIDs: []uint32{101, 101}, Groups: []uint32{101, 65532}}
	for name, tc := range map[string]struct {
		rng     PluginUIDRange
		refusal string
	}{
		"clear of everything":          {PluginUIDRange{Base: 200000, Size: 1024}, ""},
		"ends just below 65532":        {PluginUIDRange{Base: 65000, Size: 532}, ""},
		"starts just above 65532":      {PluginUIDRange{Base: 65533, Size: 10}, ""},
		"contains 65532":               {PluginUIDRange{Base: 65000, Size: 533}, "65532"},
		"starts at 65532":              {PluginUIDRange{Base: 65532, Size: 1}, "65532"},
		"below 1000":                   {PluginUIDRange{Base: 100, Size: 10}, "below 1000"},
		"server uid at the first slot": {PluginUIDRange{Base: 1000, Size: 10}, ""},
	} {
		err := tc.rng.validate(server)
		if tc.refusal == "" {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.refusal) {
			t.Fatalf("%s: got %v, want a refusal mentioning %q", name, err, tc.refusal)
		}
	}

	// A server running on a high uid: each identity field is checked.
	high := func(mut func(*processIdentity)) processIdentity {
		id := processIdentity{UIDs: []uint32{1500, 1500}, GIDs: []uint32{1600, 1600}, Groups: []uint32{1600}}
		mut(&id)
		return id
	}
	rng := PluginUIDRange{Base: 200000, Size: 1024}
	for name, tc := range map[string]struct {
		id      processIdentity
		refusal string
	}{
		"real uid at the first uid":          {high(func(id *processIdentity) { id.UIDs[0] = 200000 }), "server's own uid 200000"},
		"effective uid at the last uid":      {high(func(id *processIdentity) { id.UIDs[1] = 201023 }), "server's own uid 201023"},
		"real gid inside":                    {high(func(id *processIdentity) { id.GIDs[0] = 200500 }), "server's gid 200500"},
		"effective gid inside":               {high(func(id *processIdentity) { id.GIDs[1] = 200501 }), "server's gid 200501"},
		"a supplementary group inside":       {high(func(id *processIdentity) { id.Groups = append(id.Groups, 200777) }), "supplementary group 200777"},
		"a uid one past the end is fine":     {high(func(id *processIdentity) { id.UIDs[0] = 201024 }), ""},
		"a group one before the start is ok": {high(func(id *processIdentity) { id.Groups = append(id.Groups, 199999) }), ""},
	} {
		err := rng.validate(tc.id)
		if tc.refusal == "" {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.refusal) {
			t.Fatalf("%s: got %v, want a refusal mentioning %q", name, err, tc.refusal)
		}
	}
}

// NewSystemRunner checks the range against the process it runs in.
func TestNewSystemRunnerRefusesARangeHoldingItsOwnIdentity(t *testing.T) {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())
	for name, rng := range map[string]PluginUIDRange{
		"own uid": {Base: max(uid, MinPluginUIDBase), Size: 1},
		"own gid": {Base: max(gid, MinPluginUIDBase), Size: 1},
	} {
		if (name == "own uid" && uid < MinPluginUIDBase) || (name == "own gid" && gid < MinPluginUIDBase) {
			// The identity itself is below the floor, so the floor refuses
			// it first; the overlap is covered by the identity table above.
			continue
		}
		if _, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), PluginUIDs: &rng}); err == nil {
			t.Fatalf("%s: a range holding the server's %s was accepted", name, name)
		}
	}
	if _, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), PluginUIDs: &PluginUIDRange{Base: 10, Size: 5}}); err == nil || !strings.Contains(err.Error(), "below 1000") {
		t.Fatalf("a base below 1000 must be refused at construction, got %v", err)
	}
	if _, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), PluginUIDs: &PluginUIDRange{Base: 65500, Size: 100}}); err == nil || !strings.Contains(err.Error(), "65532") {
		t.Fatalf("a range holding 65532 must be refused at construction, got %v", err)
	}
	r, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), PluginUIDs: &PluginUIDRange{Base: 3000000, Size: 32}})
	if err != nil {
		t.Fatalf("a clear range: %v", err)
	}
	if r.uids == nil {
		t.Fatal("a configured range must arm the uid map")
	}
	off, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir()})
	if err != nil || off.uids != nil {
		t.Fatalf("an unset range must leave the drop off: uids=%v err=%v", off.uids, err)
	}
}

func TestPluginUIDMapIsDeterministicAndCollisionFree(t *testing.T) {
	rng := PluginUIDRange{Base: 200000, Size: 32}
	ids := []string{"latticenet.vpn-core", "latticenet.sub-store", "latticenet.netguard", "latticenet.wireguard"}

	first := newPluginUIDMap(rng)
	got := map[string]uint32{}
	for _, id := range ids {
		uid, assigned, err := first.assign(id)
		if err != nil || !assigned {
			t.Fatalf("assign %s: uid=%d assigned=%t err=%v", id, uid, assigned, err)
		}
		if uid < rng.Base || uid > rng.Last() {
			t.Fatalf("%s got uid %d outside %s", id, uid, rng)
		}
		got[id] = uid
	}
	// Asking again returns the same uid without a new assignment.
	for _, id := range ids {
		uid, assigned, err := first.assign(id)
		if err != nil || assigned || uid != got[id] {
			t.Fatalf("reassign %s: uid=%d assigned=%t err=%v want %d", id, uid, assigned, err, got[id])
		}
	}
	// A fresh map (a restart) that sees the same plugins in another order
	// gives each the same uid, as long as no two hash to one slot.
	collided := map[uint32]bool{}
	for _, id := range ids {
		slot := homeSlot(id, rng.Size)
		if collided[slot] {
			t.Skipf("two production ids share a home slot in a range of %d; order independence does not hold for them", rng.Size)
		}
		collided[slot] = true
	}
	second := newPluginUIDMap(rng)
	for i := len(ids) - 1; i >= 0; i-- {
		uid, _, err := second.assign(ids[i])
		if err != nil || uid != got[ids[i]] {
			t.Fatalf("after a restart %s got uid %d, want %d (err=%v)", ids[i], uid, got[ids[i]], err)
		}
	}
}

func homeSlot(id string, size uint32) uint32 {
	m := newPluginUIDMap(PluginUIDRange{Base: MinPluginUIDBase, Size: size})
	uid, _, _ := m.assign(id)
	return uid - MinPluginUIDBase
}

// A full range is filled exactly once, every plugin on its own uid, and the
// next plugin is refused rather than given a shared uid.
func TestPluginUIDMapFillsTheRangeThenRefuses(t *testing.T) {
	rng := PluginUIDRange{Base: 300000, Size: 8}
	m := newPluginUIDMap(rng)
	seen := map[uint32]string{}
	for i := range int(rng.Size) {
		id := fmt.Sprintf("p.%d", i)
		uid, _, err := m.assign(id)
		if err != nil {
			t.Fatalf("assign %s: %v", id, err)
		}
		if other, ok := seen[uid]; ok {
			t.Fatalf("%s and %s share uid %d", id, other, uid)
		}
		if uid < rng.Base || uid > rng.Last() {
			t.Fatalf("%s got uid %d outside %s", id, uid, rng)
		}
		seen[uid] = id
	}
	if _, _, err := m.assign("p.one-too-many"); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("a full range must refuse the next plugin, got %v", err)
	}
	// Plugins already holding a uid keep it.
	if uid, _, err := m.assign("p.3"); err != nil || seen[uid] != "p.3" {
		t.Fatalf("p.3 lost its uid: uid=%d err=%v", uid, err)
	}
}

func TestPluginCredentialClearsSupplementaryGroups(t *testing.T) {
	cred := pluginCredential(200123)
	if cred.Uid != 200123 || cred.Gid != 200123 || cred.Groups == nil || len(cred.Groups) != 0 || cred.NoSetGroups {
		t.Fatalf("credential=%+v; want uid=gid=200123, an empty non-nil group list and setgroups on", cred)
	}
	attr := childSysProcAttr(cred)
	if !attr.Setpgid || attr.Credential != cred {
		t.Fatalf("attributes=%+v; want Setpgid and the credential", attr)
	}
	if off := childSysProcAttr(nil); !off.Setpgid || off.Credential != nil {
		t.Fatalf("attributes with the drop off=%+v; want Setpgid alone, as before design 30", off)
	}
}

// With the drop on, Prepare assigns the plugin's uid before staging and the
// state carries it to every later exec; the v1 and v2 generations of one
// plugin share it, and a range with no room refuses Prepare before anything
// is staged.
func TestSystemRunnerAssignsTheCredentialAtPrepare(t *testing.T) {
	runtimeDir := t.TempDir()
	r := newRunner(t, SystemRunnerOptions{RuntimeDir: runtimeDir, PluginUIDs: &PluginUIDRange{Base: 400000, Size: 1}})
	loaded := makeBundle(t, "p.cred", "#!/bin/sh\nexit 0\n", "")
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	cred := r.st[loaded.Manifest.ID][1].credential
	r.mu.Unlock()
	if cred == nil || cred.Uid != 400000 || cred.Gid != 400000 || len(cred.Groups) != 0 {
		t.Fatalf("staged credential=%+v; want uid=gid=400000 with no groups", cred)
	}
	other := makeBundle(t, "p.no-room", "#!/bin/sh\nexit 0\n", "")
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: other.Manifest.ID, Generation: 1, Loaded: other}); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("a second plugin in a one-uid range must be refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, other.Manifest.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused plugin must stage nothing: %v", err)
	}

	off := newRunner(t, SystemRunnerOptions{})
	if _, err := off.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	off.mu.Lock()
	offCred := off.st[loaded.Manifest.ID][1].credential
	off.mu.Unlock()
	if offCred != nil {
		t.Fatalf("with the drop off the state must carry no credential, got %+v", offCred)
	}
}

// With the drop on, the staged chain is 0711 from the runtime root down and
// the artifact 0555, all owned by the server, whatever modes the root had
// before. The check runs before every exec; the Linux tests exec for real.
func TestSystemRunnerStagesTheRelaxedChain(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "plugin-runtime")
	// A runtime root made before design 30.
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	r := newRunner(t, SystemRunnerOptions{RuntimeDir: runtimeDir, PluginUIDs: &PluginUIDRange{Base: 400000, Size: 8}})
	loaded := makeBundle(t, "p.chain", "#!/bin/sh\nread line\necho '{\"ok\":true}'\n", "")
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 3, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	st := r.st[loaded.Manifest.ID][3]
	r.mu.Unlock()
	owner := uint32(os.Geteuid())
	pluginDir := filepath.Join(runtimeDir, loaded.Manifest.ID)
	genDir := filepath.Join(pluginDir, "generation-3")
	artifact := filepath.Join(genDir, "artifact")
	if st.execPath != artifact {
		t.Fatalf("staged at %s, want %s", st.execPath, artifact)
	}
	for path, want := range map[string]os.FileMode{runtimeDir: stagedDirMode, pluginDir: stagedDirMode, genDir: stagedDirMode, artifact: stagedArtifactMode} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want || info.Mode()&os.ModeType&^os.ModeDir != 0 {
			t.Fatalf("%s is %s, want %04o", path, info.Mode(), want)
		}
		if uid, ok := fileOwner(info); !ok || uid != owner {
			t.Fatalf("%s is owned by %d, want the server's %d", path, uid, owner)
		}
	}
	check := func() error { return r.checkStagedArtifact(loaded.Manifest.ID, 3, st.execPath, st.execSHA256) }
	if err := check(); err != nil {
		t.Fatalf("the staged chain as written: %v", err)
	}

	// Every mode mutation of every element is refused before exec, and
	// restoring the mode restores service.
	for _, path := range []string{runtimeDir, pluginDir, genDir} {
		for _, mode := range []os.FileMode{0o700, 0o755, 0o731, 0o713, 0o777, os.ModeSticky | 0o711} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if err := check(); !errors.Is(err, errStagedArtifactChanged) {
				t.Fatalf("%s at %s: got %v, want a refusal", path, mode, err)
			}
			if err := os.Chmod(path, stagedDirMode); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, mode := range []os.FileMode{0o700, 0o755, 0o775, 0o557, 0o511, os.ModeSetuid | 0o555} {
		if err := os.Chmod(artifact, mode); err != nil {
			t.Fatal(err)
		}
		if err := check(); !errors.Is(err, errStagedArtifactChanged) {
			t.Fatalf("artifact at %s: got %v, want a refusal", mode, err)
		}
		if err := os.Chmod(artifact, stagedArtifactMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := check(); err != nil {
		t.Fatalf("the restored chain: %v", err)
	}

	// An owner other than the server's uid is refused for the chain and the
	// artifact alike. Changing the owner needs root, so the runner is told
	// to expect another uid instead; the Linux root test chowns for real.
	r.layout.owner = owner + 1
	if err := check(); !errors.Is(err, errStagedArtifactChanged) || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("a chain owned by another uid: got %v, want a refusal", err)
	}
	r.layout.owner = owner

	// A symlink in place of the plugin directory is refused even when it
	// points at an identical chain.
	twin := filepath.Join(t.TempDir(), "twin")
	if err := os.Rename(pluginDir, twin); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(twin, pluginDir); err != nil {
		t.Fatal(err)
	}
	if err := stagedChainMatches(runtimeDir, genDir, owner); !errors.Is(err, errStagedArtifactChanged) {
		t.Fatalf("a symlinked plugin directory: got %v, want a refusal", err)
	}
}

// With the drop off, the runner stages and checks exactly as before design
// 30: a 0700 working directory and a 0700 artifact, the operator's runtime
// root left at the mode it has, and nothing above the artifact checked.
func TestSystemRunnerUnsetKeepsThePrivateLayout(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "plugin-runtime")
	if err := os.Mkdir(runtimeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	r := newRunner(t, SystemRunnerOptions{RuntimeDir: runtimeDir, CrashThreshold: 1000})
	loaded := makeBundle(t, "p.private", "#!/bin/sh\nread line\necho '{\"ok\":true}'\n", "")
	if _, err := r.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 2, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	if err := r.ActivateGeneration(loaded.Manifest.ID, 2); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(runtimeDir, loaded.Manifest.ID)
	genDir := filepath.Join(pluginDir, "generation-2")
	artifact := filepath.Join(genDir, "artifact")
	for path, want := range map[string]os.FileMode{runtimeDir: 0o750, pluginDir: 0o700, genDir: 0o700, artifact: 0o700} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s is %s, want %04o as before design 30", path, info.Mode(), want)
		}
	}
	invoke := func() error {
		_, err := r.Invoke(t.Context(), InvokeRequest{PluginID: loaded.Manifest.ID, Generation: 2, Action: "plan"})
		return err
	}
	if err := invoke(); err != nil {
		t.Fatalf("the private layout as written: %v", err)
	}
	// The root and the plugin directory are not checked, as before.
	for _, path := range []string{runtimeDir, pluginDir} {
		if err := os.Chmod(path, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := invoke(); err != nil {
		t.Fatalf("an operator's root at 0777 with the drop off: %v", err)
	}
	// The artifact keeps the exact 0700 rule; the isolated 0555 is refused.
	if err := os.Chmod(artifact, stagedArtifactMode); err != nil {
		t.Fatal(err)
	}
	if err := invoke(); !errors.Is(err, errStagedArtifactChanged) {
		t.Fatalf("a 0555 artifact with the drop off: got %v, want a refusal", err)
	}
}

// The runtime root itself may be a symlink the operator configured.
func TestStagedChainFollowsAConfiguredRootSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "runtime")
	if err := os.Symlink(real, root); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "p.x", "generation-1")
	if err := os.MkdirAll(dir, stagedDirMode); err != nil {
		t.Fatal(err)
	}
	if err := setStagedChainMode(root, dir); err != nil {
		t.Fatal(err)
	}
	if err := stagedChainMatches(root, dir, uint32(os.Geteuid())); err != nil {
		t.Fatalf("a symlinked root: %v", err)
	}
	if _, err := stagedChain(root, filepath.Join(base, "elsewhere")); err == nil {
		t.Fatal("a staging directory outside the root must be refused")
	}
}
