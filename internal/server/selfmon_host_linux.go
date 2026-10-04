//go:build linux

package server

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
)

// processRSS reads the resident set from /proc/self/statm (pages).
func processRSS() (uint64, bool) {
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}

// hostLoad reads the 1, 5 and 15 minute load averages. Inside a container
// they are the host kernel's, which is what is wanted: the control plane
// shares the machine's CPUs with everything else on it.
func hostLoad() (float64, float64, float64, bool) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	var out [3]float64
	for i := range out {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return 0, 0, 0, false
		}
		out[i] = v
	}
	return out[0], out[1], out[2], true
}

// hostMemory reads MemTotal and MemAvailable from /proc/meminfo, in bytes.
// A container sees the host's figures here, not its cgroup limit.
func hostMemory() (total, available uint64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	var haveTotal, haveAvail bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		var dst *uint64
		var have *bool
		switch {
		case bytes.HasPrefix(line, []byte("MemTotal:")):
			dst, have = &total, &haveTotal
		case bytes.HasPrefix(line, []byte("MemAvailable:")):
			dst, have = &available, &haveAvail
		default:
			continue
		}
		fields := strings.Fields(string(line))
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		*dst, *have = kb*1024, true
		if haveTotal && haveAvail {
			break
		}
	}
	return total, available, haveTotal && haveAvail
}
