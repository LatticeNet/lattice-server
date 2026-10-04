package plugin

import (
	"os"
	"syscall"
)

// processExitFor returns the hook that reports a plugin process's resources
// to the runner's ProcessObserver, or nil when there is none.
func (r *SystemRunner) processExitFor(pluginID string) func(*os.ProcessState) {
	obs := r.opts.ProcessObserver
	if obs == nil {
		return nil
	}
	return func(state *os.ProcessState) {
		if state == nil {
			return
		}
		var rss int64
		if ru, ok := state.SysUsage().(*syscall.Rusage); ok && ru != nil {
			rss = rusageMaxRSSBytes(ru)
		}
		obs(pluginID, state.UserTime()+state.SystemTime(), rss)
	}
}
