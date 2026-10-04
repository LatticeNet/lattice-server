//go:build linux || darwin

package server

import (
	"os"
	"syscall"
)

// processCPUSeconds is the user plus system CPU time this process has used.
func processCPUSeconds() (float64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	user := float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
	sys := float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
	return user + sys, true
}

// openFDs counts this process's open file descriptors.
func openFDs() (int, bool) {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err == nil {
			// Reading the directory holds one descriptor of its own.
			return max(len(entries)-1, 0), true
		}
	}
	return 0, false
}

// volumeBytes reports the filesystem holding path: its size, the space an
// unprivileged writer may still use, and the space in use.
func volumeBytes(path string) (total, free, used uint64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, false
	}
	bsize := uint64(st.Bsize)
	total = uint64(st.Blocks) * bsize
	free = uint64(st.Bavail) * bsize
	used = (uint64(st.Blocks) - uint64(st.Bfree)) * bsize
	return total, free, used, true
}
