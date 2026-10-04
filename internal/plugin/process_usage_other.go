//go:build !linux

package plugin

import "syscall"

// rusageMaxRSSBytes returns ru_maxrss, which macOS reports in bytes.
func rusageMaxRSSBytes(ru *syscall.Rusage) int64 { return int64(ru.Maxrss) }
