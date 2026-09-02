package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Typed notification kinds for service liveness (design-19), declared beside
// their emitter per the convention: new callers say what the event is, so a
// reworded title can never silently change who receives it.
const (
	EventServiceDown      = "service.down"
	EventServiceRecovered = "service.recovered"
)

// Service states derived from a liveness probe. These are wire values on the
// line read model; the vpn-core UI renders them verbatim.
const (
	serviceStateRunning    = "running"
	serviceStateDown       = "down"
	serviceStateRestarting = "restarting"
	serviceStateUnknown    = "unknown"
)

// serviceDownHold is how long a problem must persist before the down
// notification fires: one notification per incident, not one per probe. The
// 90s value mirrors nodeOfflineThreshold, the existing "stop believing"
// window for agents themselves.
const serviceDownHold = 90 * time.Second

// deriveSingBoxServiceState turns one probe into a state. The process table
// outranks systemd: a trusted process is running whatever the unit claims,
// and an active unit with no trusted process is a contradiction reported as
// unknown rather than resolved by guessing.
func deriveSingBoxServiceState(rt *model.SingBoxRuntime, prevRestarts int, hadPrev bool) string {
	if rt == nil || rt.ProbedAt.IsZero() {
		return serviceStateUnknown
	}
	if rt.Running {
		// A rising restart counter between two probes is a crash loop even
		// when every probe happens to land while the process is briefly up.
		if hadPrev && rt.RestartCount > prevRestarts {
			return serviceStateRestarting
		}
		if rt.ActiveState == "activating" || rt.SubState == "auto-restart" {
			return serviceStateRestarting
		}
		return serviceStateRunning
	}
	if rt.ActiveState == "activating" || rt.SubState == "auto-restart" {
		return serviceStateRestarting
	}
	if rt.ActiveState == "active" {
		// Unit says active, trusted process scan says nothing. Either the
		// binary lives outside the trusted directories or the unit name does
		// not match the process; both mean "we cannot prove it", not "down".
		return serviceStateUnknown
	}
	return serviceStateDown
}

// noteSingBoxLiveness ingests one probe: derives the state, persists the
// record, and handles the transition side effects (audit trail, debounced
// notifications). Called from the inventory ingest path with the
// authenticated node id.
func (s *Server) noteSingBoxLiveness(nodeID string, rt *model.SingBoxRuntime) {
	if rt == nil {
		// An agent without the probe reports nothing; recording an unknown
		// would overwrite a real incident record with absence of evidence.
		return
	}
	now := s.now().UTC()
	boundSingBoxRuntime(rt)

	prev, hadPrev := s.store.SingBoxLivenessRecord(nodeID)
	state := deriveSingBoxServiceState(rt, prev.Runtime.RestartCount, hadPrev)

	rec := store.SingBoxLiveness{
		NodeID:         nodeID,
		Runtime:        *rt,
		State:          state,
		StateSince:     prev.StateSince,
		ProblemSince:   prev.ProblemSince,
		NotifiedDownAt: prev.NotifiedDownAt,
		ReceivedAt:     now,
	}
	if !hadPrev || prev.State != state {
		rec.StateSince = now
	}
	problem := state == serviceStateDown || state == serviceStateRestarting
	if problem && rec.ProblemSince.IsZero() {
		rec.ProblemSince = now
	}
	if state == serviceStateRunning {
		rec.ProblemSince = time.Time{}
	}

	notifyDown := problem && rec.NotifiedDownAt.IsZero() && !rec.ProblemSince.IsZero() &&
		now.Sub(rec.ProblemSince) >= serviceDownHold
	notifyRecovered := state == serviceStateRunning && !prev.NotifiedDownAt.IsZero()
	if notifyDown {
		rec.NotifiedDownAt = now
	}
	if state == serviceStateRunning {
		rec.NotifiedDownAt = time.Time{}
	}

	if _, _, err := s.store.UpsertSingBoxLiveness(rec); err != nil {
		s.logger.Printf("singbox liveness persist failed: node_id=%s: %v", nodeID, err)
	}

	if hadPrev && prev.State != state {
		s.recordAudit(model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   nodeID,
			Action:   "singbox.service.state",
			Decision: "observe",
			Reason:   fmt.Sprintf("%s -> %s", prev.State, state),
			Metadata: map[string]string{
				"state":         state,
				"previous":      prev.State,
				"restart_count": fmt.Sprintf("%d", rt.RestartCount),
				"active_state":  rt.ActiveState,
				"sub_state":     rt.SubState,
			},
		})
	}

	name := s.nodeDisplayName(nodeID)
	if notifyDown {
		s.notifyEventTyped(EventServiceDown,
			fmt.Sprintf("sing-box %s on %s", state, name),
			fmt.Sprintf("node %s: sing-box has been %s since %s (unit %s/%s, restarts %d). Config state is reported separately; this is the service.",
				nodeID, state, rec.ProblemSince.Format(time.RFC3339), rt.ActiveState, rt.SubState, rt.RestartCount))
	}
	if notifyRecovered {
		s.notifyEventTyped(EventServiceRecovered,
			fmt.Sprintf("sing-box recovered on %s", name),
			fmt.Sprintf("node %s: sing-box is running again (pid %d).", nodeID, rt.PID))
	}
}

// boundSingBoxRuntime normalizes agent-reported fields exactly like guard
// reality ingest does: lengths bounded, counters non-negative.
func boundSingBoxRuntime(rt *model.SingBoxRuntime) {
	trim := func(v string, max int) string {
		v = strings.TrimSpace(v)
		if len(v) > max {
			return v[:max]
		}
		return v
	}
	rt.ActiveState = trim(rt.ActiveState, 64)
	rt.SubState = trim(rt.SubState, 64)
	rt.ProbeError = trim(rt.ProbeError, 512)
	if rt.RestartCount < 0 {
		rt.RestartCount = 0
	}
	if rt.PID < 0 {
		rt.PID = 0
	}
	rt.ProbedAt = rt.ProbedAt.UTC()
	if !rt.StartedAt.IsZero() {
		rt.StartedAt = rt.StartedAt.UTC()
	}
}

// singBoxServiceState answers for the line read model: the node's derived
// state, when it was last checked, and the probe's note when the state is
// anything but running. Unknown with no note when no record exists.
func (s *Server) singBoxServiceState(nodeID string) (string, time.Time, string) {
	rec, ok := s.store.SingBoxLivenessRecord(nodeID)
	if !ok || rec.State == "" {
		return serviceStateUnknown, time.Time{}, ""
	}
	return rec.State, rec.Runtime.ProbedAt, serviceNoteFor(rec.State, rec.Runtime.ProbeError)
}

// serviceNoteFor keeps the probe error only where it explains something. A
// running service with a failed `ss` still runs; the note would be noise
// beside a green state. Unknown, down and restarting are the states the
// operator has to act on, and the probe's account is the first clue.
func serviceNoteFor(state, probeError string) string {
	if state == serviceStateRunning {
		return ""
	}
	return strings.TrimSpace(probeError)
}

// refineLineServiceState folds a line's own port evidence into the node
// state: a running service that does not hold this line's port is down for
// this line. Unknown port evidence never downgrades.
func refineLineServiceState(nodeState string, portBound *bool) string {
	if nodeState == serviceStateRunning && portBound != nil && !*portBound {
		return serviceStateDown
	}
	return nodeState
}

// singBoxDownNodes is the subscription filter's input: only nodes whose
// service is positively down. Unknown and restarting are deliberately absent
// (fail open; flapping must not churn rendered subscriptions).
func (s *Server) singBoxDownNodes() map[string]string {
	out := map[string]string{}
	for nodeID, rec := range s.store.SingBoxLivenessAll() {
		if rec.State == serviceStateDown {
			out[nodeID] = rec.State
		}
	}
	return out
}
