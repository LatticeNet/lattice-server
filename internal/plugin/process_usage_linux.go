//go:build linux

package plugin

import (
	"bytes"
	"os"
	"strconv"
	"syscall"
)

// processPeakFromProc says a plugin process's own peak resident set comes
// from /proc/<pid>/status, not from the exit rusage.
const processPeakFromProc = true

// rusageMaxRSSBytes converts ru_maxrss, which Linux reports in kilobytes.
func rusageMaxRSSBytes(ru *syscall.Rusage) int64 { return ru.Maxrss * 1024 }

// readVmHWMBytes returns the VmHWM line of /proc/<pid>/status in bytes, or 0
// when the process is gone or has no address space (a zombie).
func readVmHWMBytes(pid int) int64 {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	return parseVmHWM(raw)
}

// parseVmHWM reads "VmHWM:\t  150600 kB" out of a status file.
func parseVmHWM(status []byte) int64 {
	for len(status) > 0 {
		line := status
		if i := bytes.IndexByte(status, '\n'); i >= 0 {
			line, status = status[:i], status[i+1:]
		} else {
			status = nil
		}
		rest, ok := bytes.CutPrefix(line, []byte("VmHWM:"))
		if !ok {
			continue
		}
		fields := bytes.Fields(rest)
		if len(fields) != 2 || string(fields[1]) != "kB" {
			return 0
		}
		kb, err := strconv.ParseInt(string(fields[0]), 10, 64)
		if err != nil || kb < 0 {
			return 0
		}
		return kb * 1024
	}
	return 0
}
