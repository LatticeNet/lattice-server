package server

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Agent loop health (keepalive K2).
//
// node-agent 0.3.10 beats on its own goroutine and carries its work loop's
// account of itself as "loop_health" on every metrics POST. A node whose loop
// is stuck therefore keeps beating, and before this file the control plane
// read it as healthy. The record is kept in memory beside agentRuntime and
// replaced on every beat: it is a fact about now, and persisting it per beat
// would be the per-event write the a101 storm came from. A restart forgets
// it until the next beat, ten seconds later.
//
// Every instant in the payload is the agent's clock. The server never
// compares them with its own clock: it reads them against the beat's
// metrics.collected_at (the agent's clock at the beat) and carries the
// result forward by how long ago the beat arrived here. A node whose clock is
// an hour off still reads correctly.
//
// What is derived, and what each derivation is allowed to do:
//
//	stalled            the loop has not completed a cycle for 90 s (node
//	                   status) or 5 min (agent.stalled incident); the step it
//	                   is stuck in is named when the agent reports one.
//	linechain blocked  durable task recovery refuses to proceed, so the agent
//	                   skips every cycle and withholds its durable task
//	                   capability; 60 s for status, 5 min for the incident.
//	core step stale    config, tasks, monitors or inventory has failed three
//	                   times in a row and last succeeded 15 min ago or never;
//	                   status and incident. Other steps (usage, logs, trace,
//	                   guard reality, ...) are shown but derive nothing: each
//	                   has its own freshness rule or may fail by design on a
//	                   node without the feature.
//	results dropped    the agent counted monitor results the server never
//	                   stored within the last 15 min; status only, and named
//	                   in an open incident's detail. A refusal of a result for
//	                   a deleted monitor also counts there, so it never pages
//	                   on its own.
const (
	agentLoopLateAfter       = 90 * time.Second
	agentLoopStallAfter      = 5 * time.Minute
	agentBlockedStatusAfter  = time.Minute
	agentBlockedIncidentHold = 5 * time.Minute
	agentStepStaleAfter      = 15 * time.Minute
	agentStepStaleErrors     = 3
	agentDropsRecentWithin   = 15 * time.Minute

	maxAgentHealthSteps  = 32
	maxAgentHealthText   = 256
	maxAgentHealthStepID = 64
)

// agentCoreSteps are the loop steps whose failure means the node is not doing
// what the control plane asks of it.
var agentCoreSteps = map[string]bool{
	model.AgentStepConfig:    true,
	model.AgentStepTasks:     true,
	model.AgentStepMonitors:  true,
	model.AgentStepInventory: true,
}

// agentHealthRecord is the last loop health a node sent.
type agentHealthRecord struct {
	health model.AgentHealth
	// collectedAt is the agent's clock at the beat; receivedAt this server's.
	collectedAt time.Time
	receivedAt  time.Time
	// droppedRoseAt is when this server saw MonitorResultsDropped go up; it
	// is carried across beats while the count stays the same.
	droppedRoseAt time.Time
}

// agentHealthBook holds the records. Guarded by its own mutex, never taken
// while holding a store lock.
type agentHealthBook struct {
	mu      sync.RWMutex
	records map[string]agentHealthRecord
}

// noteAgentHealth records a node's loop health from one metrics beat.
func (s *Server) noteAgentHealth(nodeID string, h *model.AgentHealth, collectedAt time.Time) {
	if h == nil {
		return
	}
	bounded := boundAgentHealth(*h)
	now := s.now()
	if collectedAt.IsZero() {
		collectedAt = now
	}
	b := &s.agentHealth
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.records == nil {
		b.records = map[string]agentHealthRecord{}
	}
	rec := agentHealthRecord{health: bounded, collectedAt: collectedAt, receivedAt: now}
	if prev, ok := b.records[nodeID]; ok {
		rec.droppedRoseAt = prev.droppedRoseAt
		sameProcess := prev.health.StartedAt.Equal(bounded.StartedAt)
		if bounded.MonitorResultsDropped > 0 && (!sameProcess || bounded.MonitorResultsDropped > prev.health.MonitorResultsDropped) {
			rec.droppedRoseAt = now
		}
		if !sameProcess && bounded.MonitorResultsDropped == 0 {
			rec.droppedRoseAt = time.Time{}
		}
	} else if bounded.MonitorResultsDropped > 0 {
		rec.droppedRoseAt = now
	}
	b.records[nodeID] = rec
}

// forgetAgentHealth drops a deleted node's record.
func (s *Server) forgetAgentHealth(nodeID string) {
	b := &s.agentHealth
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.records, nodeID)
}

func (s *Server) agentHealthRecord(nodeID string) (agentHealthRecord, bool) {
	b := &s.agentHealth
	b.mu.RLock()
	defer b.mu.RUnlock()
	rec, ok := b.records[nodeID]
	return rec, ok
}

func boundAgentHealth(h model.AgentHealth) model.AgentHealth {
	trim := func(v string, max int) string {
		v = strings.TrimSpace(v)
		if len(v) > max {
			v, _ = store.TruncateUTF8(v, max)
		}
		return v
	}
	h.Step = trim(h.Step, maxAgentHealthStepID)
	h.LinechainBlocked = trim(h.LinechainBlocked, maxAgentHealthText)
	if h.CycleDurationMs < 0 {
		h.CycleDurationMs = 0
	}
	if h.MonitorResultsQueued < 0 {
		h.MonitorResultsQueued = 0
	}
	if len(h.Steps) > 0 {
		names := make([]string, 0, len(h.Steps))
		for name := range h.Steps {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > maxAgentHealthSteps {
			names = names[:maxAgentHealthSteps]
		}
		steps := make(map[string]model.AgentLoopStep, len(names))
		for _, name := range names {
			step := h.Steps[name]
			key := trim(name, maxAgentHealthStepID)
			if key == "" {
				continue
			}
			step.LastError = trim(step.LastError, maxAgentHealthText)
			if step.ConsecutiveErrors < 0 {
				step.ConsecutiveErrors = 0
			}
			steps[key] = step
		}
		h.Steps = steps
	}
	return h
}

// agentClock converts agent instants to this server's clock.
type agentClock struct {
	collectedAt, receivedAt time.Time
}

func (c agentClock) toServer(t time.Time) time.Time {
	return c.receivedAt.Add(t.Sub(c.collectedAt))
}

// age is how long before serverNow the agent instant t was.
func (c agentClock) age(t time.Time, serverNow time.Time) time.Duration {
	return serverNow.Sub(c.toServer(t))
}

// agentLoopProblem is one derived problem. since is in the server's clock.
type agentLoopProblem struct {
	kind   string // stalled, linechain_blocked, step_stale, results_dropped
	step   string
	since  time.Time
	reason string
	// status is set when the problem degrades the node; incident when it
	// opens agent.stalled, with opensAt when it would (pending until then).
	status   bool
	incident bool
	opensAt  time.Time
}

const (
	agentProblemStalled          = "stalled"
	agentProblemLinechainBlocked = "linechain_blocked"
	agentProblemStepStale        = "step_stale"
	agentProblemResultsDropped   = "results_dropped"
)

// agentLoopProblems derives what rec proves at serverNow, earliest first.
// It returns problems that are pending (too young to degrade or open) as
// well, so the console can show them; status and incident say which apply.
func agentLoopProblems(rec agentHealthRecord, serverNow time.Time) []agentLoopProblem {
	h := rec.health
	clock := agentClock{collectedAt: rec.collectedAt, receivedAt: rec.receivedAt}
	var out []agentLoopProblem
	blocked := h.LinechainBlocked != ""
	if blocked {
		since := h.LinechainBlockedSince
		if since.IsZero() {
			since = rec.collectedAt
		}
		age := clock.age(since, serverNow)
		out = append(out, agentLoopProblem{
			kind:     agentProblemLinechainBlocked,
			since:    clock.toServer(since),
			reason:   fmt.Sprintf("durable task recovery has been blocked for %s (%s), so the agent skips every cycle", livenessSpan(age), h.LinechainBlocked),
			status:   age >= agentBlockedStatusAfter,
			incident: age >= agentBlockedIncidentHold,
			opensAt:  clock.toServer(since).Add(agentBlockedIncidentHold),
		})
	}
	if !blocked {
		last := h.CycleCompletedAt
		if last.IsZero() {
			last = h.StartedAt
		}
		if !last.IsZero() {
			age := clock.age(last, serverNow)
			if age >= agentLoopLateAfter {
				reason := fmt.Sprintf("the work loop has not completed a cycle for %s", livenessSpan(age))
				if h.Step != "" && !h.StepSince.IsZero() {
					reason = fmt.Sprintf("the work loop has been in step %s for %s and has not completed a cycle for %s", h.Step, livenessSpan(clock.age(h.StepSince, serverNow)), livenessSpan(age))
				}
				out = append(out, agentLoopProblem{
					kind:     agentProblemStalled,
					step:     h.Step,
					since:    clock.toServer(last),
					reason:   reason,
					status:   true,
					incident: age >= agentLoopStallAfter,
					opensAt:  clock.toServer(last).Add(agentLoopStallAfter),
				})
			}
		}
	}
	names := make([]string, 0, len(h.Steps))
	for name := range h.Steps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !agentCoreSteps[name] {
			continue
		}
		step := h.Steps[name]
		if step.ConsecutiveErrors < agentStepStaleErrors {
			continue
		}
		since := step.LastOKAt
		if since.IsZero() {
			since = h.StartedAt
		}
		if since.IsZero() {
			continue
		}
		age := clock.age(since, serverNow)
		if age < agentStepStaleAfter {
			continue
		}
		reason := fmt.Sprintf("step %s has failed %d times in a row and last succeeded %s ago", name, step.ConsecutiveErrors, livenessSpan(age))
		if step.LastOKAt.IsZero() {
			reason = fmt.Sprintf("step %s has failed %d times in a row and has not succeeded since the agent started", name, step.ConsecutiveErrors)
		}
		if step.LastError != "" {
			reason += " (" + step.LastError + ")"
		}
		out = append(out, agentLoopProblem{
			kind: agentProblemStepStale, step: name, since: clock.toServer(since), reason: reason,
			status: true, incident: true, opensAt: clock.toServer(since).Add(agentStepStaleAfter),
		})
	}
	if h.MonitorResultsDropped > 0 && !rec.droppedRoseAt.IsZero() && serverNow.Sub(rec.droppedRoseAt) < agentDropsRecentWithin {
		out = append(out, agentLoopProblem{
			kind:   agentProblemResultsDropped,
			since:  rec.droppedRoseAt,
			reason: fmt.Sprintf("the agent dropped %d monitor results since it started (latest at %s)", h.MonitorResultsDropped, stamp(rec.droppedRoseAt)),
			status: true,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].since.Before(out[j].since) })
	return out
}

// freshAgentHealth returns a node's record when it is as fresh as the node's
// own last beat. A record the agent stopped refreshing says nothing about now,
// and a node that never sent one (an agent before 0.3.10) has none.
func (s *Server) freshAgentHealth(n model.Node) (agentHealthRecord, bool) {
	rec, ok := s.agentHealthRecord(n.ID)
	if !ok {
		return agentHealthRecord{}, false
	}
	if n.LastSeen.Sub(rec.receivedAt) > nodeStatusEvidenceStaleAfter {
		return agentHealthRecord{}, false
	}
	return rec, true
}

// agentHealthDegradations are the loop problems that degrade node status.
func (s *Server) agentHealthDegradations(n model.Node, now time.Time) []degradation {
	rec, ok := s.freshAgentHealth(n)
	if !ok {
		return nil
	}
	var out []degradation
	for _, p := range agentLoopProblems(rec, now) {
		if p.status {
			out = append(out, degradation{since: p.since, reason: p.reason})
		}
	}
	return out
}

// agentLoopHealthView is loop health on the node view: the agent's payload as
// sent, the two clocks needed to age its instants, and what was derived.
// A console computes the age of an instant t as
// (collected_at - t) + (its now - received_at).
type agentLoopHealthView struct {
	model.AgentHealth
	CollectedAt time.Time              `json:"collected_at"`
	ReceivedAt  time.Time              `json:"received_at"`
	Problems    []agentLoopProblemView `json:"problems,omitempty"`
}

type agentLoopProblemView struct {
	Kind     string    `json:"kind"`
	Step     string    `json:"step,omitempty"`
	Since    time.Time `json:"since"`
	Reason   string    `json:"reason"`
	Degrades bool      `json:"degrades,omitempty"`
	Pages    bool      `json:"pages,omitempty"`
}

func (s *Server) agentLoopHealthViewFor(nodeID string, now time.Time) *agentLoopHealthView {
	rec, ok := s.agentHealthRecord(nodeID)
	if !ok {
		return nil
	}
	view := &agentLoopHealthView{AgentHealth: rec.health, CollectedAt: rec.collectedAt, ReceivedAt: rec.receivedAt}
	if len(rec.health.Steps) > 0 {
		steps := make(map[string]model.AgentLoopStep, len(rec.health.Steps))
		for k, v := range rec.health.Steps {
			steps[k] = v
		}
		view.Steps = steps
	}
	for _, p := range agentLoopProblems(rec, now) {
		view.Problems = append(view.Problems, agentLoopProblemView{Kind: p.kind, Step: p.step, Since: p.since, Reason: p.reason, Degrades: p.status, Pages: p.incident})
	}
	return view
}

// evaluateAgentHealthIncidents opens agent.stalled for nodes whose loop
// proves a paging problem and resolves it once the loop is moving again. A
// node whose evidence is stale (offline, or an agent that stopped sending
// loop health) is left as it is: absence of evidence is not health.
func (s *Server) evaluateAgentHealthIncidents(now time.Time) {
	for _, n := range s.store.Nodes() {
		if n.Disabled {
			continue
		}
		if !n.Online || now.Sub(n.LastSeen) > nodeOfflineThreshold {
			continue
		}
		rec, ok := s.freshAgentHealth(n)
		if !ok {
			continue
		}
		problems := agentLoopProblems(rec, now)
		var paging, evidence []agentLoopProblem
		for _, p := range problems {
			if p.incident {
				paging = append(paging, p)
			}
			if p.status {
				evidence = append(evidence, p)
			}
		}
		key := incidentKey(EventAgentStalled, n.ID, "")
		name := nodeLabel(n)
		if len(paging) == 0 {
			s.resolveIncident(key, now, incidentMessage{
				title:  "Lattice agent recovered on " + name,
				detail: fmt.Sprintf("%s (%s): the agent's work loop is completing cycles again.", name, n.ID),
				line:   name + ": work loop moving again",
			})
			continue
		}
		reasons := make([]string, 0, len(evidence))
		for _, p := range evidence {
			reasons = append(reasons, p.reason)
		}
		s.openIncident(incidentSignal{
			kind: EventAgentStalled, nodeID: n.ID, subject: name, since: paging[0].since,
			sortKey: name + "\x00" + n.ID,
			msg: incidentMessage{
				title:  "Lattice agent stalled on " + name,
				detail: fmt.Sprintf("%s (%s) is reporting, but %s.", name, n.ID, strings.Join(reasons, "; and ")),
				line:   fmt.Sprintf("%s: %s", name, paging[0].reason),
			},
		}, now)
	}
}
