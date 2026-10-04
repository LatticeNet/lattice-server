//go:build linux

package plugin

import "syscall"

// rusageMaxRSSBytes converts ru_maxrss, which Linux reports in kilobytes.
func rusageMaxRSSBytes(ru *syscall.Rusage) int64 { return ru.Maxrss * 1024 }
