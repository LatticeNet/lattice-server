package server

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Trace collector readiness (design 26, slice R1).
//
// node-agent 0.3.10-alpha.4 and later carry their trace collector's account
// of itself as "trace_collector" on every metrics beat, and beat at once when
// the state changes. The beat rather than the trace batch is the carrier
// because a node in no_clash_api or secret_unreadable never starts the
// pipeline that ships batches, and because the beat refills this book within
// ten seconds of a server restart.
//
// The record is kept in memory and replaced per beat, for the reason
// agent_health.go gives: it is a fact about now, and persisting it per beat
// is the write storm a101 came from.
//
// Agents older than traceCollectorStatusMinAgent send nothing, so the server
// infers what it can from the agent version and the policy. One inference is
// certain: those agents read the Clash API address only from the policy and
// stop when it is empty, so a policy without an address is no_clash_api on
// them whatever the node's sing-box config says.

// traceCollectorStatusMinAgent is the first node-agent version that reports
// collector status. Older agents get a server-inferred state. It must equal
// the version the agent release that adds trace_collector carries.
const traceCollectorStatusMinAgent = "0.3.10-alpha.4"

// maxTraceCollectorAddr bounds the Clash API address an agent reports. A
// loopback host:port is at most an IPv6 literal in brackets and a port.
const maxTraceCollectorAddr = 64

// Who decided a collector view's state.
const (
	traceCollectorByAgent  = "agent"
	traceCollectorByServer = "server"
)

// traceCollectorRecord is the last collector status a node's beat carried.
type traceCollectorRecord struct {
	status      model.CollectorStatus
	collectedAt time.Time // agent clock at the beat (metrics.collected_at)
	receivedAt  time.Time // this server's clock
}

// traceCollectorBook holds the records. Guarded by its own mutex, never taken
// while holding a store lock.
type traceCollectorBook struct {
	mu      sync.RWMutex
	records map[string]traceCollectorRecord
}

// noteTraceCollector records a node's collector status from one metrics beat.
// A nil status (an older agent, or a beat sent before the collector exists)
// leaves the previous record alone, and so does a status naming a state the
// agent may not send.
func (s *Server) noteTraceCollector(nodeID string, st *model.CollectorStatus, collectedAt time.Time) {
	if st == nil {
		return
	}
	now := s.now()
	bounded, ok := boundTraceCollector(*st, now)
	if !ok {
		return
	}
	if collectedAt.IsZero() {
		collectedAt = now
	}
	b := &s.traceCollectors
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.records == nil {
		b.records = map[string]traceCollectorRecord{}
	}
	b.records[nodeID] = traceCollectorRecord{status: bounded, collectedAt: collectedAt, receivedAt: now}
}

// forgetTraceCollector drops a deleted node's record.
func (s *Server) forgetTraceCollector(nodeID string) {
	b := &s.traceCollectors
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.records, nodeID)
}

func (s *Server) traceCollectorRecord(nodeID string) (traceCollectorRecord, bool) {
	b := &s.traceCollectors
	b.mu.RLock()
	defer b.mu.RUnlock()
	rec, ok := b.records[nodeID]
	return rec, ok
}

// boundTraceCollector makes an agent's status safe to keep and to show. It
// refuses agent_too_old, which only this server infers, and any state the
// contract does not name. Everything else is trimmed rather than refused:
// the status is low-trust telemetry for display, never for authorization.
// Control characters are stripped so no text an agent sends can break a log
// line or a terminal, and the agent's timestamps are clamped to receivedAt
// (this server's clock) so none reads as a moment that has not happened yet.
func boundTraceCollector(st model.CollectorStatus, receivedAt time.Time) (model.CollectorStatus, bool) {
	if !model.ValidAgentCollectorState(st.State) {
		return model.CollectorStatus{}, false
	}
	st.Detail = stripControlChars(model.BoundCollectorDetail(strings.TrimSpace(st.Detail)))
	st.ClashAPIAddr = strings.TrimSpace(st.ClashAPIAddr)
	if len(st.ClashAPIAddr) > maxTraceCollectorAddr {
		st.ClashAPIAddr, _ = store.TruncateUTF8(st.ClashAPIAddr, maxTraceCollectorAddr)
	}
	st.ClashAPIAddr = stripControlChars(st.ClashAPIAddr)
	if st.Since.After(receivedAt) {
		st.Since = receivedAt
	}
	if st.CountersSince.After(receivedAt) {
		st.CountersSince = receivedAt
	}
	switch st.AddrSource {
	case "", model.ClashAddrFromPolicy, model.ClashAddrFromConfig:
	default:
		st.AddrSource = ""
	}
	if st.Level != "" && !model.ValidTraceLevel(st.Level) {
		st.Level = ""
	}
	if st.LinesPerSec < 0 {
		st.LinesPerSec = 0
	}
	if st.BudgetLinesPerSec < 0 {
		st.BudgetLinesPerSec = 0
	}
	return st, true
}

// stripControlChars drops C0 control characters and DEL. Removing bytes
// only shortens the string, so a bound applied before still holds.
func stripControlChars(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// traceCaptureCoverage says whether running captures switch a node's
// collector on, and when the latest of them started (this server's clock).
type traceCaptureCoverage struct {
	covered   bool
	startedAt time.Time
}

// traceCaptureCoverageFor applies the rule traceAgentConfig uses to hand a
// capture to a node, so readiness and the agent never disagree about whether
// a capture covers it.
func (s *Server) traceCaptureCoverageFor(nodeID string, active []model.TraceSession) traceCaptureCoverage {
	var out traceCaptureCoverage
	for _, sess := range active {
		if _, ok := s.traceAgentSessionFor(nodeID, sess); !ok {
			continue
		}
		out.covered = true
		if sess.StartedAt.After(out.startedAt) {
			out.startedAt = sess.StartedAt
		}
	}
	return out
}

// traceCollectorView is a node's collector readiness as the console reads it.
type traceCollectorView struct {
	model.CollectorStatus
	// ReportedBy is traceCollectorByAgent or traceCollectorByServer.
	ReportedBy string `json:"reported_by"`
	// CollectedAt is the agent's clock at the beat and ReceivedAt this
	// server's; both are set only on agent reports.
	CollectedAt time.Time `json:"collected_at,omitzero"`
	ReceivedAt  time.Time `json:"received_at,omitzero"`
	// Stale is set when the node is offline or no status arrived for
	// agentLoopLateAfter: the state is the last one heard, not a fact about
	// now. An inferred state is stale while the node is offline, because the
	// agent version it rests on is the last one heard.
	Stale bool `json:"stale,omitempty"`
	// Pending is set when the policy changed, or a capture covering the node
	// started, after the last report: the agent has not answered the change.
	// It clears on the first report received after the change, which may be
	// a beat the agent sent before it applied the new config; that leaves a
	// window of at most one work-loop cycle (10 s by default), after which
	// the next report carries the applied state.
	Pending bool `json:"pending,omitempty"`
}

// traceCollectorViewFor decides a node's readiness once, so every reader of
// it shows the same thing. nil means nothing can be said yet: an agent new
// enough to report that has not beaten, or a version this server cannot
// order (a development build), where inferring would risk a wrong state.
func (s *Server) traceCollectorViewFor(n model.Node, cover traceCaptureCoverage, now time.Time) *traceCollectorView {
	version := strings.TrimSpace(n.AgentVersion)
	cmp, ordered := store.CompareAgentVersions(version, traceCollectorStatusMinAgent)
	olderAgent := ordered && cmp < 0
	// A record left by a newer agent says nothing about an older one that
	// replaced it, which never reports, so an older agent is always inferred.
	if rec, ok := s.traceCollectorRecord(n.ID); ok && !olderAgent {
		v := &traceCollectorView{
			CollectorStatus: rec.status,
			ReportedBy:      traceCollectorByAgent,
			CollectedAt:     rec.collectedAt,
			ReceivedAt:      rec.receivedAt,
		}
		v.Stale = !n.Online || now.Sub(rec.receivedAt) > agentLoopLateAfter
		v.Pending = n.Trace.UpdatedAt.After(rec.receivedAt) || cover.startedAt.After(rec.receivedAt)
		return v
	}
	if !olderAgent {
		return nil
	}
	v := &traceCollectorView{ReportedBy: traceCollectorByServer, Stale: !n.Online}
	addr := strings.TrimSpace(n.Trace.ClashAPIAddr)
	switch {
	case !n.Trace.Enabled && !cover.covered:
		v.State = model.CollectorOff
	case addr == "":
		v.State = model.CollectorNoClashAPI
		v.Detail = model.BoundCollectorDetail(fmt.Sprintf(
			"node-agent %s reads the Clash API address only from the policy, and the policy names none; set clash_api_addr or update the agent to %s or later",
			version, traceCollectorStatusMinAgent))
	default:
		v.State = model.CollectorAgentTooOld
		v.ClashAPIAddr = addr
		v.AddrSource = model.ClashAddrFromPolicy
		v.Detail = model.BoundCollectorDetail(fmt.Sprintf(
			"node-agent %s does not report collector readiness; %s and later do",
			version, traceCollectorStatusMinAgent))
	}
	return v
}
