package server

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// SSH authentication pressure: what the fleet reports, and the one thing worth
// waking someone for.
//
// Alerting on "you are being brute-forced" is the wrong design. Every public
// node in this fleet is being brute-forced, one of them 8449 times in a day, so
// that alert fires constantly, gets muted, and is muted on the day it matters.
//
// The signal that earns an alert is a SUCCESS from a source that had been
// failing. That is a possible compromise and it needs a person now. The volume
// itself is posture: it belongs in an audit trail and a report, where it informs
// a decision made at leisure.
//
// So this file records every window and notifies for almost none of them.
const (
	// EventSSHCompromiseSuspected fires on a successful login from a source
	// that failed first. It is the only pressure-derived event that notifies.
	EventSSHCompromiseSuspected = "ssh.compromise_suspected"
	// EventSSHPressureWindow is recorded, never notified.
	EventSSHPressureWindow = "ssh.pressure_window"
)

// Server-side clamps. The agent already bounds what it sends, and that is not
// a reason to trust it: this feature exists to notice a host being taken over,
// and a taken-over host is exactly the one whose agent might send a million
// entries. Bounds are re-applied on receipt.
const (
	maxPressureTopSources = 10
	maxPressureSuspects   = 16
	maxPressureFieldLen   = 96
)

type sshSourcePressure struct {
	Address     string `json:"address"`
	Failures    int    `json:"failures"`
	InvalidUser int    `json:"invalid_user"`
}

type sshSuspectSuccess struct {
	Address       string    `json:"address"`
	User          string    `json:"user"`
	Method        string    `json:"method"`
	PriorFailures int       `json:"prior_failures"`
	Successes     int       `json:"successes"`
	At            time.Time `json:"at"`
}

type sshPressurePayload struct {
	Start          time.Time           `json:"start"`
	End            time.Time           `json:"end"`
	Failures       int                 `json:"failures"`
	InvalidUser    int                 `json:"invalid_user"`
	Sources        int                 `json:"sources"`
	SourcesDropped int                 `json:"sources_dropped"`
	TopSources     []sshSourcePressure `json:"top_sources"`
	SuspectSuccess []sshSuspectSuccess `json:"suspect_success"`
}

// clamp trims a report to the shape the server is willing to store, and reports
// whether anything had to be cut so that a node sending oversized payloads is
// itself visible rather than silently truncated.
func (p *sshPressurePayload) clamp() (trimmed bool) {
	sort.SliceStable(p.TopSources, func(i, j int) bool { return p.TopSources[i].Failures > p.TopSources[j].Failures })
	if len(p.TopSources) > maxPressureTopSources {
		p.TopSources = p.TopSources[:maxPressureTopSources]
		trimmed = true
	}
	if len(p.SuspectSuccess) > maxPressureSuspects {
		p.SuspectSuccess = p.SuspectSuccess[:maxPressureSuspects]
		trimmed = true
	}
	// Assign unconditionally. clipField both sanitizes and truncates, and
	// writing back only when it truncated would throw the sanitized value away
	// for every field that happened to be short enough, which is most of them.
	for i := range p.TopSources {
		clipped, cut := clipField(p.TopSources[i].Address)
		p.TopSources[i].Address = clipped
		trimmed = trimmed || cut
	}
	for i := range p.SuspectSuccess {
		s := &p.SuspectSuccess[i]
		for _, f := range []*string{&s.Address, &s.User, &s.Method} {
			clipped, cut := clipField(*f)
			*f = clipped
			trimmed = trimmed || cut
		}
	}
	for _, n := range []*int{&p.Failures, &p.InvalidUser, &p.Sources, &p.SourcesDropped} {
		if *n < 0 {
			*n = 0
			trimmed = true
		}
	}
	return trimmed
}

// clipField sanitizes and, separately, reports whether it had to truncate. The
// caller must write the returned value back regardless of the bool: the two
// jobs are independent and only one of them is conditional.
func clipField(v string) (string, bool) {
	v = strings.Map(func(r rune) rune {
		// A username reaches this field from an unauthenticated peer, and it
		// lands in audit metadata and in a notification body. Anything that can
		// add a line to either is dropped rather than escaped.
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		// A double quote is structure in the rendered message, where these
		// fields are quoted so they read as data. Removing it here is what
		// stops a peer-chosen username from closing the quotes and continuing
		// as prose.
		if r == '"' {
			return -1
		}
		return r
	}, v)
	if len(v) > maxPressureFieldLen {
		return v[:maxPressureFieldLen], true
	}
	return v, false
}

// handleSSHPressure records one window and notifies only for a suspected
// compromise.
func (s *Server) handleSSHPressure(nodeID string, payload *sshPressurePayload) {
	if payload == nil {
		return
	}
	trimmed := payload.clamp()

	metadata := map[string]string{
		"failures":     fmt.Sprintf("%d", payload.Failures),
		"invalid_user": fmt.Sprintf("%d", payload.InvalidUser),
		"sources":      fmt.Sprintf("%d", payload.Sources),
		"window":       payload.Start.UTC().Format(time.RFC3339) + "/" + payload.End.UTC().Format(time.RFC3339),
	}
	if payload.SourcesDropped > 0 {
		// Say it out loud. Without this the top-sources list reads as complete
		// when a distributed scan pushed most of the sources out of it.
		metadata["sources_dropped"] = fmt.Sprintf("%d", payload.SourcesDropped)
	}
	if trimmed {
		metadata["payload_trimmed"] = "true"
	}
	if len(payload.TopSources) > 0 {
		metadata["top_source"] = payload.TopSources[0].Address
		metadata["top_source_failures"] = fmt.Sprintf("%d", payload.TopSources[0].Failures)
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), NodeID: nodeID, Action: EventSSHPressureWindow,
		Decision: "observe", Metadata: metadata,
	})

	// One notification per suspect source, not one per window. An operator
	// deciding whether a host was taken over needs the address and the account,
	// and a window summary carrying five of them buries all five.
	for _, suspect := range payload.SuspectSuccess {
		s.recordAudit(model.AuditEvent{
			ID: id.New("audit"), NodeID: nodeID, Action: EventSSHCompromiseSuspected,
			Decision: "observe",
			Metadata: map[string]string{
				"address": suspect.Address, "user": suspect.User, "method": suspect.Method,
				"prior_failures": fmt.Sprintf("%d", suspect.PriorFailures),
				"successes":      fmt.Sprintf("%d", suspect.Successes),
			},
		})
		// The username and the method are chosen by an unauthenticated peer, so
		// they are quoted rather than dropped into the sentence. Unquoted, a
		// username like `root node other-host: everything is fine` reads as a
		// second statement about a different machine to anyone skimming.
		s.emitNotifyTyped(EventSSHCompromiseSuspected,
			"SSH login after repeated failures",
			fmt.Sprintf("node %s: user %q logged in from %s using %q after %d failed attempts from that address. "+
				"If this was not you, treat the host as compromised.",
				nodeID, suspect.User, suspect.Address, suspect.Method, suspect.PriorFailures))
	}
}
