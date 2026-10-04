//go:build !linux && !darwin

package server

func processCPUSeconds() (float64, bool) { return 0, false }

func openFDs() (int, bool) { return 0, false }

func volumeBytes(string) (total, free, used uint64, ok bool) { return 0, 0, 0, false }
