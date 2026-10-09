//go:build !linux

package plugin

import "syscall"

// processPeakFromProc is false off Linux: there is no /proc high-water mark,
// so the exit rusage is used.
const processPeakFromProc = false

// rusageMaxRSSBytes returns ru_maxrss, which macOS reports in bytes.
func rusageMaxRSSBytes(ru *syscall.Rusage) int64 { return int64(ru.Maxrss) }

func readVmHWMBytes(int) int64 { return 0 }
