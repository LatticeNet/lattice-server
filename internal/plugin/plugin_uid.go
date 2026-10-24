package plugin

import (
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Design 30: a plugin child runs as its own unprivileged uid instead of the
// server's, so the kernel's access control keeps it away from master.key, the
// state files, the audit WAL and the probe socket, and from signalling or
// tracing the server or a sibling plugin. The server needs CAP_SETUID,
// CAP_SETGID and CAP_KILL for this, carried as file capabilities on its
// binary (see the Dockerfile); without them a child that cannot drop fails
// to start, which is fail-closed.

const (
	// MinPluginUIDBase keeps plugin uids clear of the system accounts an
	// image defines below 1000.
	MinPluginUIDBase = 1000
	// DefaultPluginUIDRange is the number of uids reserved when only the base
	// is configured. The range sizes plugins, not workers: every pooled
	// worker of one plugin (at most 32) shares that plugin's uid, because
	// they are one principal with one capability scope. A range far larger
	// than the plugin count keeps the hashed assignment below mostly free of
	// collisions, so a plugin keeps the same uid across restarts.
	DefaultPluginUIDRange = 1024
	// probeGroupID is lattice-probe's uid and gid (design 27). Its socket is
	// 0660 65532:65532, so a plugin uid or gid equal to it would reach the
	// socket the boundary exists to close.
	probeGroupID = 65532
	// maxValidUID is the largest uid the kernel accepts; (uid_t)-1 means
	// "leave unchanged" to setresuid.
	maxValidUID = 1<<32 - 2
)

// PluginUIDRange is the block of uids plugin children run as, Base through
// Base+Size-1. Each plugin's gid equals its uid and needs no /etc/passwd
// entry.
type PluginUIDRange struct {
	Base uint32
	Size uint32
}

// Last is the highest uid in the range.
func (r PluginUIDRange) Last() uint32 { return r.Base + r.Size - 1 }

func (r PluginUIDRange) String() string { return fmt.Sprintf("%d-%d", r.Base, r.Last()) }

// contains reports whether v, as a uid or a gid, falls in the range.
func (r PluginUIDRange) contains(v uint32) bool { return v >= r.Base && v <= r.Last() }

// ParsePluginUIDRange reads the LATTICE_PLUGIN_UID_BASE and
// LATTICE_PLUGIN_UID_RANGE settings. An empty base turns the drop off and
// returns nil; a range without a base is refused rather than ignored, since
// it means the operator meant to turn isolation on. The range must also pass
// the identity check NewSystemRunner makes against the running server.
func ParsePluginUIDRange(base, size string) (*PluginUIDRange, error) {
	base, size = strings.TrimSpace(base), strings.TrimSpace(size)
	if base == "" {
		if size != "" {
			return nil, errors.New("LATTICE_PLUGIN_UID_RANGE is set but LATTICE_PLUGIN_UID_BASE is not; set both, or neither to keep plugins on the server's uid")
		}
		return nil, nil
	}
	b, err := strconv.ParseUint(base, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid LATTICE_PLUGIN_UID_BASE %q: want a uid of at least %d: %w", base, MinPluginUIDBase, err)
	}
	rng := PluginUIDRange{Base: uint32(b), Size: DefaultPluginUIDRange}
	if size != "" {
		n, err := strconv.ParseUint(size, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid LATTICE_PLUGIN_UID_RANGE %q: want a positive number of uids: %w", size, err)
		}
		if n == 0 {
			return nil, fmt.Errorf("invalid LATTICE_PLUGIN_UID_RANGE %q: want a positive number of uids", size)
		}
		rng.Size = uint32(n)
	}
	if err := rng.validateBounds(); err != nil {
		return nil, err
	}
	return &rng, nil
}

func (r PluginUIDRange) validateBounds() error {
	if r.Base < MinPluginUIDBase {
		return fmt.Errorf("plugin uid base %d is below %d: plugin uids must stay clear of system accounts", r.Base, MinPluginUIDBase)
	}
	if r.Size == 0 {
		return errors.New("plugin uid range is empty")
	}
	if uint64(r.Base)+uint64(r.Size)-1 > maxValidUID {
		return fmt.Errorf("plugin uid range starting at %d with %d uids runs past the largest valid uid %d", r.Base, r.Size, uint64(maxValidUID))
	}
	return nil
}

// processIdentity is what the server runs as. No plugin uid or gid may equal
// any of it: a plugin sharing the server's uid would own its files, and one
// sharing a group would keep that group's access (65532 is how the server
// opens the probe socket).
type processIdentity struct {
	UIDs   []uint32
	GIDs   []uint32
	Groups []uint32
}

func currentProcessIdentity() (processIdentity, error) {
	groups, err := os.Getgroups()
	if err != nil {
		return processIdentity{}, fmt.Errorf("read the server's supplementary groups: %w", err)
	}
	id := processIdentity{
		UIDs: []uint32{uint32(os.Getuid()), uint32(os.Geteuid())}, // #nosec G115 -- POSIX uids and gids are 32-bit kernel ids
		GIDs: []uint32{uint32(os.Getgid()), uint32(os.Getegid())}, // #nosec G115 -- POSIX uids and gids are 32-bit kernel ids
	}
	for _, g := range groups {
		id.Groups = append(id.Groups, uint32(g)) // #nosec G115 -- POSIX uids and gids are 32-bit kernel ids
	}
	return id, nil
}

// validate refuses a range that starts below MinPluginUIDBase, runs past the
// largest valid uid, or contains the server's uid, one of its groups, or the
// probe's 65532. The range is used for gids too, so every number is checked
// against the whole range.
func (r PluginUIDRange) validate(id processIdentity) error {
	if err := r.validateBounds(); err != nil {
		return err
	}
	inRange := r.contains
	for _, uid := range id.UIDs {
		if inRange(uid) {
			return fmt.Errorf("plugin uid range %s contains the server's own uid %d; a plugin on that uid would own the server's files", r, uid)
		}
	}
	for _, gid := range id.GIDs {
		if inRange(gid) {
			return fmt.Errorf("plugin uid range %s contains the server's gid %d; plugin gids equal their uids and must not share a server group", r, gid)
		}
	}
	for _, gid := range id.Groups {
		if inRange(gid) {
			return fmt.Errorf("plugin uid range %s contains the server's supplementary group %d; plugin gids equal their uids and must not share a server group", r, gid)
		}
	}
	if inRange(probeGroupID) {
		return fmt.Errorf("plugin uid range %s contains %d, lattice-probe's uid and gid; a plugin on it could open the probe socket", r, probeGroupID)
	}
	return nil
}

// CheckOwnership refuses to arm the drop while any of paths, or anything
// under one of them, is owned by a uid or a group inside the range: a plugin
// assigned that uid would own the server's file. The data directory and the
// master key are the paths that matter; a restore, copy or extract run as a
// host user whose uid falls in the range leaves exactly this behind, and the
// container entrypoint is not the only way to start the server. Each path is
// resolved once and the walk below it follows no symlink. A directory the
// server cannot read is skipped after its own owner is checked: the server's
// data is readable to the server. An empty or missing path is skipped.
func (r PluginUIDRange) CheckOwnership(paths ...string) error {
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		root, err := filepath.EvalSymlinks(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("check the ownership of %s before dropping plugin uids: %w", p, err)
		}
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if errors.Is(walkErr, fs.ErrPermission) && d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return walkErr
			}
			info, err := d.Info()
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			if r.contains(st.Uid) || r.contains(st.Gid) {
				return fmt.Errorf("%s is owned by %d:%d, inside the plugin uid range %s, so the plugin assigned that uid would own it; chown it to the server before setting LATTICE_PLUGIN_UID_BASE", path, st.Uid, st.Gid, r)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// pluginUIDMap gives each plugin id its own uid in the range. A plugin's home
// slot is the FNV-1a hash of its id modulo the range size, so the same id
// lands on the same uid on every boot unless another id already took that
// slot, in which case it takes the next free one. An assignment is never
// released while the process lives, so a uid never passes from one plugin to
// another (a file a removed plugin left in /tmp stays its own), and a range
// with no free slot refuses the plugin instead of sharing a uid.
type pluginUIDMap struct {
	rng   PluginUIDRange
	mu    sync.Mutex
	byID  map[string]uint32
	taken map[uint32]string
}

func newPluginUIDMap(rng PluginUIDRange) *pluginUIDMap {
	return &pluginUIDMap{rng: rng, byID: map[string]uint32{}, taken: map[uint32]string{}}
}

// assign returns pluginID's uid and whether this call made the assignment.
func (m *pluginUIDMap) assign(pluginID string) (uint32, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if uid, ok := m.byID[pluginID]; ok {
		return uid, false, nil
	}
	if uint64(len(m.taken)) >= uint64(m.rng.Size) {
		return 0, false, fmt.Errorf("plugin uid range %s is exhausted: %d plugins already hold a uid; widen LATTICE_PLUGIN_UID_RANGE", m.rng, len(m.taken))
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(pluginID))
	slot := h.Sum32() % m.rng.Size
	for {
		uid := m.rng.Base + slot
		if _, used := m.taken[uid]; !used {
			m.byID[pluginID] = uid
			m.taken[uid] = pluginID
			return uid, true, nil
		}
		slot = (slot + 1) % m.rng.Size
	}
}

// pluginCredential is the identity a dropped child starts with: its uid as
// both user and group, and an empty supplementary group list. Empty Groups
// with NoSetGroups false makes the runtime call setgroups(0, NULL), which is
// what removes the inherited 65532.
func pluginCredential(uid uint32) *syscall.Credential {
	return &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}
}

// childSysProcAttr is the attribute set every plugin child starts with: its
// own process group, so teardown reaches its descendants, and the plugin's
// credential when the runner drops plugins to their own uid. A nil cred
// keeps the child on the server's identity, exactly as before design 30.
func childSysProcAttr(cred *syscall.Credential) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Credential: cred}
}
