//go:build linux

package plugin

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// serverExecutable names the running server's binary. Tests point it at a
// stand-in.
var serverExecutable = os.Executable

// checkServerBinary refuses to arm the uid drop while a plugin identity can
// exec the server's own binary and that binary carries file capabilities.
// File capabilities land on whoever execs the file, whatever their uid, so a
// plugin that could run the server binary would get CAP_SETUID, CAP_SETGID
// and CAP_KILL back and could start code under a sibling plugin's uid. The
// image installs the binary 0750, owned by root and the server's group, which
// a plugin (its own uid as its gid, no supplementary groups) cannot exec;
// this check fails closed if a build or a manual install loses that.
func checkServerBinary(rng PluginUIDRange) error {
	path, err := serverExecutable()
	if err != nil {
		return fmt.Errorf("locate the server binary to check its file capabilities: %w", err)
	}
	return checkCappedBinary(path, rng)
}

// checkCappedBinary refuses path when it carries file capabilities and a uid
// or gid in rng may execute it: through the "other" bits, or through the
// owner or group bits when the owner or group falls in the range. A binary
// without file capabilities gives a plugin nothing it does not already hold.
func checkCappedBinary(path string, rng PluginUIDRange) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect the server binary %s: %w", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect the server binary %s: no owner information", path)
	}
	perm := info.Mode().Perm()
	reachable := perm&0o001 != 0 || (perm&0o010 != 0 && rng.contains(st.Gid)) || (perm&0o100 != 0 && rng.contains(st.Uid))
	if !reachable {
		return nil
	}
	_, err = syscall.Getxattr(path, "security.capability", nil)
	switch {
	case errors.Is(err, syscall.ENODATA), errors.Is(err, syscall.ENOTSUP):
		return nil
	case err != nil:
		return fmt.Errorf("read the file capabilities of the server binary %s: %w", path, err)
	}
	return fmt.Errorf("the server binary %s carries file capabilities and plugin uids in %s can execute it (mode %04o, owner %d:%d): a plugin could exec it and regain CAP_SETUID; install it 0750, owned by root and the server's group, before setting LATTICE_PLUGIN_UID_BASE", path, rng, perm, st.Uid, st.Gid)
}
