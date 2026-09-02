package server

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Node status is the one word the console renders for a node. It is derived
// here, at view time, so the nodes list, node detail, the overview KPIs, the
// map and the terminal picker all read the same rule at the same instant; the
// same machine used to read offline on one page and degraded on another
// because each page derived its own word from Online, LastSeen and metrics.
//
// Online and Reachability stay on the wire for consumers that have not moved.
// All three come from the same fields, so they cannot contradict Status about
// whether the node is in contact; they only say less.
//
// Precedence, first match wins:
//
//	disabled        Disabled is set. An operator switched the node off, and
//	                that outranks whatever the agent is or is not doing.
//	never_reported  LastSeen is zero. The record has existed since enrollment
//	                and no report has ever arrived. Since is CreatedAt.
//	offline         Online is false, or the last report is older than
//	                nodeOfflineThreshold. The second clause covers the window
//	                between a beat going stale and the liveness sweep flipping
//	                the flag. Since is LastSeen, the last contact.
//	degraded        In contact, but a probe the control plane holds fresh
//	                evidence for says something on the node is broken; see
//	                nodeDegradations for the inputs. Since is the earliest
//	                problem's start.
//	online          In contact within the threshold and nothing proven broken.
//	                Since is OnlineSince, omitted for records written before
//	                that field existed.
const (
	NodeStatusNeverReported = "never_reported"
	NodeStatusOnline        = "online"
	NodeStatusDegraded      = "degraded"
	NodeStatusOffline       = "offline"
	NodeStatusDisabled      = "disabled"
)

// nodeStatusEvidenceStaleAfter bounds how far a probe record may lag the
// node's own last beat before it stops counting. The agent sends the sing-box
// liveness probe with every inventory report, every interval (10 s by
// default), so a record ten minutes older than the last beat means the probe
// stopped, not that the service is still down. Absence of evidence never
// degrades; only a proven, current problem does.
const nodeStatusEvidenceStaleAfter = 10 * time.Minute

// nodeStatus is the derived triple the node views carry.
type nodeStatus struct {
	Status string
	Since  time.Time
	Reason string
}

// degradation is one proven problem on a node that is otherwise in contact.
type degradation struct {
	since  time.Time
	reason string
}

func (s *Server) nodeStatusFor(n model.Node, now time.Time) nodeStatus {
	return deriveNodeStatus(n, now, s.nodeDegradations(n, now))
}

// deriveNodeStatus applies the precedence above. Pure, so every boundary is a
// table test; the store lookups live in nodeDegradations.
func deriveNodeStatus(n model.Node, now time.Time, problems []degradation) nodeStatus {
	switch {
	case n.Disabled:
		reason := "Disabled by an operator; the agent token is refused until the node is enabled again."
		if !n.DisabledAt.IsZero() {
			reason = fmt.Sprintf("Disabled by an operator at %s; the agent token is refused until the node is enabled again.", stamp(n.DisabledAt))
		}
		return nodeStatus{Status: NodeStatusDisabled, Since: n.DisabledAt, Reason: reason}
	case n.LastSeen.IsZero():
		reason := "No report has ever arrived from this node."
		if !n.CreatedAt.IsZero() {
			reason = fmt.Sprintf("No report has arrived since enrollment at %s.", stamp(n.CreatedAt))
		}
		return nodeStatus{Status: NodeStatusNeverReported, Since: n.CreatedAt, Reason: reason}
	case !n.Online || now.Sub(n.LastSeen) > nodeOfflineThreshold:
		return nodeStatus{
			Status: NodeStatusOffline,
			Since:  n.LastSeen,
			Reason: fmt.Sprintf("No report since %s; the control plane stops trusting a node after %s of silence.", stamp(n.LastSeen), nodeOfflineThreshold),
		}
	}
	if len(problems) > 0 {
		reasons := make([]string, 0, len(problems))
		for _, p := range problems {
			reasons = append(reasons, p.reason)
		}
		return nodeStatus{
			Status: NodeStatusDegraded,
			Since:  problems[0].since,
			Reason: "Reporting, but " + strings.Join(reasons, "; and ") + ".",
		}
	}
	return nodeStatus{
		Status: NodeStatusOnline,
		Since:  n.OnlineSince,
		Reason: fmt.Sprintf("Reporting; last report at %s.", stamp(n.LastSeen)),
	}
}

// nodeDegradations collects the problems the control plane can prove today
// for a node that is in contact, earliest first. Two inputs exist:
//
//   - the sing-box service liveness record (design-19): the service is down or
//     restarting, and the record is as fresh as the node's own beat;
//   - the NetGuard guard-reality snapshot: one exists and is older than
//     guardRealityStaleAfter while the agent keeps reporting, which means the
//     reality the SSH Guard page shows for this node is no longer true.
//
// Resource saturation is deliberately not here. High CPU or a full disk is
// load the metric bars already show, not a failed probe, and calling it
// degraded is what made one page disagree with another. No per-node agent
// runtime error is stored today; when one is, it belongs in this list.
func (s *Server) nodeDegradations(n model.Node, now time.Time) []degradation {
	var out []degradation
	if rec, ok := s.store.SingBoxLivenessRecord(n.ID); ok {
		if d, ok := singBoxDegradation(rec, n); ok {
			out = append(out, d)
		}
	}
	if snap, ok := s.store.GuardRealitySnapshot(n.ID); ok {
		if d, ok := guardRealityDegradation(snap, now); ok {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].since.Before(out[j].since) })
	return out
}

func singBoxDegradation(rec store.SingBoxLiveness, n model.Node) (degradation, bool) {
	if rec.State != serviceStateDown && rec.State != serviceStateRestarting {
		return degradation{}, false
	}
	// A record the agent stopped refreshing says nothing about now.
	if n.LastSeen.Sub(rec.ReceivedAt) > nodeStatusEvidenceStaleAfter {
		return degradation{}, false
	}
	since := rec.ProblemSince
	if since.IsZero() {
		since = rec.StateSince
	}
	return degradation{
		since: since,
		reason: fmt.Sprintf("sing-box has been %s since %s (unit %s/%s, %d restarts)",
			rec.State, stamp(since), rec.Runtime.ActiveState, rec.Runtime.SubState, rec.Runtime.RestartCount),
	}, true
}

func guardRealityDegradation(snap store.GuardRealitySnapshot, now time.Time) (degradation, bool) {
	status, staleAfter := guardRealityFreshness(snap, now)
	if status != "stale" {
		return degradation{}, false
	}
	return degradation{
		since: staleAfter,
		reason: fmt.Sprintf("the guard reality snapshot was collected at %s and is older than %s while the agent keeps reporting",
			stamp(snap.Reality.CollectedAt), guardRealityStaleAfter),
	}, true
}

// stamp prints an instant the way the audit trail does, so a reason sentence
// and the event it refers to read the same.
func stamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
