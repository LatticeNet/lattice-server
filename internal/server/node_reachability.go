package server

import (
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Reachability is what the control plane actually knows about a node's contact
// history. model.Node.Online is a bool, so it collapses two situations an
// operator has to tell apart: a node that has been reporting and stopped, and a
// node that has never reported at all.
//
// The second is not a corner case. handleEnrollNode writes the node record with
// neither LastSeen nor Online set, so every node is in it from enrollment until
// its first beat. Rendering that as "offline" tells the operator something
// broke, when what actually happened is that the agent was never installed or
// has never reached the control plane. Those have different fixes.
//
// This is derived at view time rather than stored. The inputs already exist and
// already move together on the heartbeat path; a stored copy would be a second
// source of truth with nothing keeping it in step.
const (
	// ReachabilityOnline means the node is beating within the stale threshold.
	ReachabilityOnline = "online"
	// ReachabilityOffline means the node has reported before and has since gone
	// quiet. LastSeen says when it was last heard from.
	ReachabilityOffline = "offline"
	// ReachabilityNever means the node has never reported. CreatedAt says how
	// long it has been waiting, which is the number worth showing.
	ReachabilityNever = "never"
)

func nodeReachability(n model.Node) string {
	if n.LastSeen.IsZero() {
		// Online without a LastSeen is not a state any writer produces, but if
		// a record ever reaches it, "never reported" is still the honest read:
		// there is no contact time to point at.
		return ReachabilityNever
	}
	if n.Online {
		return ReachabilityOnline
	}
	return ReachabilityOffline
}

// nodeSilence reports how long a node has been out of contact, and from which
// instant that is measured. For a node that has reported it runs from LastSeen;
// for one that never has it runs from enrollment, which is the only instant
// available and the one an operator wants when asking why a node never came up.
func nodeSilence(n model.Node, now time.Time) (time.Duration, bool) {
	since := n.LastSeen
	if since.IsZero() {
		since = n.CreatedAt
	}
	if since.IsZero() || !now.After(since) {
		return 0, false
	}
	return now.Sub(since), true
}
