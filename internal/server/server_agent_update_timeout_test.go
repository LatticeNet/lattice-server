package server

import (
	"strconv"
	"strings"
	"testing"
)

// The download must be allowed to use the budget the task actually has.
//
// This is pinned because the failure is invisible from the control plane: the
// task reports a curl exit 28 and the node stays on its old agent, while the
// task itself had minutes of unused deadline. xuezhang-jp fetches at about
// 34 KiB/s and needs roughly 385 s for a 13 MiB agent; with the fetch capped at
// 300 s it died having pulled 10 MiB, from the control-plane source as well as
// the upstream one, and could never be updated by any number of retries.
func TestAgentFetchTimeoutFitsInsideTheApplyTaskBudget(t *testing.T) {
	const marker = "--max-time "
	idx := strings.Index(agentFetchCurlTimeouts, marker)
	if idx < 0 {
		t.Fatalf("no --max-time in %q", agentFetchCurlTimeouts)
	}
	field := strings.Fields(agentFetchCurlTimeouts[idx+len(marker):])
	if len(field) == 0 {
		t.Fatalf("no value after --max-time in %q", agentFetchCurlTimeouts)
	}
	maxTime, err := strconv.Atoi(field[0])
	if err != nil {
		t.Fatalf("--max-time %q is not a number: %v", field[0], err)
	}
	budget := approvalApplyTaskTimeoutSec(agentUpdatePlugin)
	if maxTime >= budget {
		t.Fatalf("fetch may run %ds but the task is killed at %ds; a hung source would hit the lease, not the script", maxTime, budget)
	}
	// The steps after the download are a digest check, an install, a restart
	// and a short health wait. Leaving less than a minute for them turns a slow
	// but successful download into a killed task.
	if budget-maxTime < 60 {
		t.Fatalf("only %ds left after a full-length fetch for verify, install and restart", budget-maxTime)
	}
	// A 13 MiB agent over the slowest uplink measured on this fleet, 34 KiB/s,
	// needs about 385s. Anything under that cannot update those nodes at all.
	const slowestObservedBytesPerSec = 34 * 1024
	const agentSizeBytes = 13 * 1024 * 1024
	if need := agentSizeBytes / slowestObservedBytesPerSec; maxTime < need {
		t.Fatalf("fetch capped at %ds but the slowest node on the fleet needs %ds for the binary", maxTime, need)
	}
}

// Both sources carry the timeouts. The control-plane form is a separate command
// string and has regressed independently before.
func TestAgentUpdateDownloadStepCarriesTimeoutsOnBothSources(t *testing.T) {
	for _, source := range []string{agentBinarySourceControlPlane, "upstream"} {
		step := agentUpdateDownloadStep(source)
		if !strings.Contains(step, agentFetchCurlTimeouts) {
			t.Fatalf("source %s: curl timeouts missing from %q", source, step)
		}
		if !strings.Contains(step, agentFetchWgetTimeouts) {
			t.Fatalf("source %s: wget timeouts missing from %q", source, step)
		}
	}
}
