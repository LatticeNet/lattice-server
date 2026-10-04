//go:build !linux

package server

// Outside Linux (a developer's machine) the process and host readings that
// come from /proc are reported as unavailable rather than guessed.

func processRSS() (uint64, bool) { return 0, false }

func hostLoad() (float64, float64, float64, bool) { return 0, 0, 0, false }

func hostMemory() (total, available uint64, ok bool) { return 0, 0, false }
