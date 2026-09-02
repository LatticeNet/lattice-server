package store

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TaskTargetState is what the control plane remembers about one target's
// lease history that the SDK's TaskLease cannot carry: how many times the
// task was handed to this node, and whether the store has given up on it.
//
// It lives beside the task rather than on model.TaskLease because model is
// the SDK, pinned by sdk.ref and consumed by plugins; adding a field there is
// a coordinated two-repo release. Keyed by taskResultReceiptKey(task, node),
// persisted in the JSON state like TaskResultReceipts, and pruned with the
// task.
type TaskTargetState struct {
	TaskID string `json:"task_id"`
	NodeID string `json:"node_id"`
	// Attempts counts leases issued to this node for this task, the first
	// one included. A task leased before this record existed has one lease
	// and no record; the re-lease path treats that as one attempt already.
	Attempts int `json:"attempts"`
	// StalledReason is set when the store refuses to lease this target again.
	// Once set it is final: nothing clears it short of deleting the task.
	StalledReason string    `json:"stalled_reason,omitempty"`
	StalledAt     time.Time `json:"stalled_at,omitempty"`
}

// MaxTaskLeaseAttempts is how many times a target may be handed a task whose
// lease keeps dying without a result. Three is enough to absorb one restart
// and one lost poll; past that the loop is the script, not the network.
const MaxTaskLeaseAttempts = 3

// TaskStalledAgentLostReason is the stall reason for a target whose agent
// disappeared mid-run MaxTaskLeaseAttempts times. The wording names the
// mechanism the operator has to look for: the script kills the agent.
const TaskStalledAgentLostReason = "agent lost during run three times"

// Agent update approvals are recognised here because the re-lease decision
// is taken under the store lock, and a downgrade must be stopped at that
// moment rather than reported afterwards. The constants mirror the server's
// agentupdate plugin; the server references these so the two cannot drift.
const (
	AgentUpdatePlugin       = "agentupdate"
	AgentUpdateActionPrefix = "update-agent:"
)

// TaskTargetProgress is one target's share of a leased task, as the console
// needs to read it: what attempt this is, how long the current lease has been
// held, and why the store stopped re-leasing it, if it did.
type TaskTargetProgress struct {
	Status          string
	Attempts        int
	LeaseAge        time.Duration
	LeaseLive       bool
	StalledReason   string
	Answered        bool
	AnsweredFailure bool
}

// TaskProgress is the per-target progress of a leased task plus the derived
// whole-task answer to "is anything still running this".
type TaskProgress struct {
	Stalled bool
	Targets map[string]TaskTargetProgress
}

// TaskProgress reports, for a leased task, what each target is doing and
// whether the task as a whole has stopped making progress (see TaskStalled).
//
// A lease whose StartedAt is zero counts as not live here: for re-execution
// safety taskLeaseExpired treats it as never expiring, but as evidence of
// progress it proves nothing, and this method answers the honesty question,
// not the redelivery one. The second return is false for a missing task or
// one that is not leased, for which no progress view exists.
func (s *Store) TaskProgress(id string, now time.Time) (TaskProgress, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.state.Tasks[id]
	if !ok || t.Status != model.TaskLeased {
		return TaskProgress{}, false
	}
	answered := map[string]model.TaskResult{}
	for _, r := range s.state.Results {
		if r.TaskID != t.ID {
			continue
		}
		prev, seen := answered[r.NodeID]
		if !seen || r.FinishedAt.After(prev.FinishedAt) {
			answered[r.NodeID] = r
		}
	}
	progress := TaskProgress{Targets: make(map[string]TaskTargetProgress, len(t.Targets))}
	owing := false
	for _, target := range uniqueStrings(t.Targets) {
		record := s.state.TaskTargetStates[taskResultReceiptKey(t.ID, target)]
		entry := TaskTargetProgress{Attempts: record.Attempts, StalledReason: record.StalledReason}
		startedAt, hasLease := taskTargetLeaseStart(t, target)
		if hasLease {
			entry.LeaseAge = now.Sub(startedAt)
			entry.LeaseLive = !startedAt.IsZero() && !taskLeaseExpiredAt(startedAt, t.TimeoutSec, now)
			// A lease issued before the attempt record existed is still an
			// attempt; showing zero would say the node was never handed it.
			if entry.Attempts == 0 {
				entry.Attempts = 1
			}
		}
		// A target the store gave up on still never answered: for the
		// whole-task question it owes a result exactly like a dead lease
		// does, it just will not be handed the task again.
		switch {
		case answeredResult(answered, target, &entry):
		case entry.StalledReason != "":
			entry.Status = TaskStalled
			owing = true
		case entry.LeaseLive:
			entry.Status = model.TaskLeased
			owing = true
		case hasLease:
			entry.Status = TaskStalled
			owing = true
		default:
			entry.Status = model.TaskQueued
			owing = true
		}
		progress.Targets[target] = entry
	}
	// Stalled is "something still owes and nothing live is working on it":
	// one live lease anywhere means the task is running, whatever its
	// siblings did.
	progress.Stalled = owing
	for _, entry := range progress.Targets {
		if entry.Status == model.TaskLeased {
			progress.Stalled = false
			break
		}
	}
	return progress, true
}

func answeredResult(answered map[string]model.TaskResult, target string, entry *TaskTargetProgress) bool {
	r, ok := answered[target]
	if !ok {
		return false
	}
	entry.Answered = true
	entry.AnsweredFailure = r.Error != "" || r.ExitCode != 0
	if entry.AnsweredFailure {
		entry.Status = model.TaskFailed
	} else {
		entry.Status = model.TaskFinished
	}
	return true
}

// taskTargetLeaseStart returns when this node's current lease started, or
// false when the node has never been handed the task. It reads the per-target
// lease first and falls back to the single-lease fields of tasks created
// before TargetLeases existed, exactly as the re-lease gate does.
func taskTargetLeaseStart(t model.Task, nodeID string) (time.Time, bool) {
	if lease, ok := t.TargetLeases[nodeID]; ok && lease.LeaseID != "" {
		return lease.StartedAt, true
	}
	if t.LeasedBy == nodeID && t.LeaseID != "" {
		return t.StartedAt, true
	}
	return time.Time{}, false
}

// taskTargetStalled reports whether the store has given up re-leasing this
// target. Both lease gates consult it, so a stalled target is neither freshly
// leased nor redelivered, whichever path the poll takes.
func taskTargetStalled(states map[string]TaskTargetState, taskID, nodeID string) bool {
	return states[taskResultReceiptKey(taskID, nodeID)].StalledReason != ""
}

// agentUpdateSuperseded decides whether re-leasing this task would install an
// agent older than what the node already runs. It is only meaningful for
// tasks filed by an agentupdate approval; anything else is never superseded.
//
// Two sources can outrank the task's target: the version the node reports in
// its heartbeat, and the version a later update policy recorded as applied
// (the node may not have reported since). The newest of the two is named in
// the reason so the operator can see what won.
func agentUpdateSuperseded(st State, t model.Task, nodeID string) (string, bool) {
	if t.ApprovalID == "" {
		return "", false
	}
	approval, ok := st.Approvals[t.ApprovalID]
	if !ok || approval.Plugin != AgentUpdatePlugin {
		return "", false
	}
	target, ok := agentUpdateTargetVersion(approval)
	if !ok {
		return "", false
	}
	newest := ""
	for _, candidate := range []string{st.Nodes[nodeID].AgentVersion, st.AgentUpdates[nodeID].LastAppliedVersion} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if cmp, comparable := CompareAgentVersions(target, candidate); !comparable || cmp >= 0 {
			continue
		}
		if newest == "" {
			newest = candidate
			continue
		}
		if cmp, comparable := CompareAgentVersions(candidate, newest); comparable && cmp > 0 {
			newest = candidate
		}
	}
	if newest == "" {
		return "", false
	}
	return "superseded by " + newest, true
}

// agentUpdateTargetVersion decodes the version an agentupdate approval was
// bound to. The approval action carries the whole payload as base64url JSON
// (see the server's agentUpdateApprovalAction); only target_version is read.
func agentUpdateTargetVersion(approval model.Approval) (string, bool) {
	if !strings.HasPrefix(approval.Action, AgentUpdateActionPrefix) {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(approval.Action, AgentUpdateActionPrefix))
	if err != nil {
		return "", false
	}
	var payload struct {
		TargetVersion string `json:"target_version"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", false
	}
	version := strings.TrimSpace(payload.TargetVersion)
	return version, version != ""
}

var agentVersionPattern = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-(alpha|beta|rc)\.([0-9]+))?$`)

// CompareAgentVersions orders two agent release strings: negative when a is
// older than b, positive when newer, zero when equal. The second return is
// false when either side is not a release the fleet can be compared on (a
// custom build tag, say), in which case no ordering claim is made.
func CompareAgentVersions(a, b string) (int, bool) {
	left, okLeft := parseAgentVersionParts(a)
	right, okRight := parseAgentVersionParts(b)
	if !okLeft || !okRight {
		return 0, false
	}
	for i := range left {
		if left[i] > right[i] {
			return 1, true
		}
		if left[i] < right[i] {
			return -1, true
		}
	}
	return 0, true
}

// parseAgentVersionParts splits a version into major, minor, patch, a
// pre-release rank (alpha < beta < rc < release) and the pre-release number,
// so that a plain lexical compare of the slice orders releases correctly.
// Whitespace is not forgiven: a padded string is not a release, and callers
// that mean to compare a trimmed value trim it themselves.
func parseAgentVersionParts(raw string) ([5]int, bool) {
	match := agentVersionPattern.FindStringSubmatch(raw)
	if match == nil {
		return [5]int{}, false
	}
	var out [5]int
	for i := 1; i <= 3; i++ {
		value, err := strconv.Atoi(match[i])
		if err != nil {
			return [5]int{}, false
		}
		out[i-1] = value
	}
	ranks := map[string]int{"alpha": 0, "beta": 1, "rc": 2, "": 3}
	out[3] = ranks[match[4]]
	if match[5] != "" {
		value, err := strconv.Atoi(match[5])
		if err != nil {
			return [5]int{}, false
		}
		out[4] = value
	}
	return out, true
}

func cloneTaskTargetStates(in map[string]TaskTargetState) map[string]TaskTargetState {
	out := make(map[string]TaskTargetState, len(in)+1)
	maps.Copy(out, in)
	return out
}
