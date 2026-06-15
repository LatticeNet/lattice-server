package server

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// proxyDriftState records whether one proxy node's applied config still matches
// what the server would render now. Drift is a fail-safe operator signal: the
// renderer already excludes ineligible users (expiry/quota/disable), so a fresh
// render that differs from AppliedSHA256 means the live node config is serving
// users who should no longer have access — until a reviewed apply enforces the
// new render. It deliberately does NOT auto-apply: node mutation stays behind
// plan->approve->apply.
type proxyDriftState struct {
	Stale           bool
	AppliedSHA256   string
	PendingSHA256   string
	IneligibleUsers int
	Reason          string
	CheckedAt       time.Time
	Since           time.Time
}

// evaluateProxyConfigDrift recomputes drift for every applied proxy profile and
// audits each profile that newly transitions into a stale state. It is invoked
// from the scheduler tick and is safe to call concurrently with reads.
func (s *Server) evaluateProxyConfigDrift(now time.Time) {
	profiles := s.store.ProxyNodeProfiles()
	users := s.store.ProxyUsers()

	type transition struct {
		nodeID string
		state  proxyDriftState
	}
	var newlyStale []transition

	s.proxyDriftMu.Lock()
	prev := s.proxyDrift
	next := make(map[string]proxyDriftState, len(profiles))
	for _, profile := range profiles {
		if strings.TrimSpace(profile.AppliedSHA256) == "" {
			continue // never applied — nothing to enforce against yet
		}
		state := s.computeProxyDrift(profile, users, now)
		prior, had := prev[profile.NodeID]
		if state.Stale {
			if had && prior.Stale && !prior.Since.IsZero() {
				state.Since = prior.Since
			} else {
				state.Since = now
			}
		}
		next[profile.NodeID] = state
		if state.Stale && (!had || !prior.Stale) {
			newlyStale = append(newlyStale, transition{nodeID: profile.NodeID, state: state})
		}
	}
	s.proxyDrift = next
	s.proxyDriftMu.Unlock()

	for _, t := range newlyStale {
		s.recordAudit(model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   t.nodeID,
			Action:   "proxy.config.drift",
			Decision: "deny",
			Reason:   t.state.Reason,
			Metadata: map[string]string{
				"applied_sha256":   t.state.AppliedSHA256,
				"pending_sha256":   t.state.PendingSHA256,
				"ineligible_users": strconv.Itoa(t.state.IneligibleUsers),
			},
		})
	}
}

// computeProxyDrift renders the current authoritative config for a profile and
// compares it against the applied SHA. A render failure (most commonly an
// inbound left with zero eligible users) is itself drift: the applied config
// still serves the now-ineligible users.
func (s *Server) computeProxyDrift(profile model.ProxyNodeProfile, users []model.ProxyUser, now time.Time) proxyDriftState {
	state := proxyDriftState{
		AppliedSHA256: profile.AppliedSHA256,
		CheckedAt:     now,
	}
	ineligible := countIneligibleProfileUsers(profile, users, now)
	_, _, artifact, err := s.renderProxyCoreArtifact(profile.NodeID)
	if err != nil {
		state.Stale = true
		state.IneligibleUsers = ineligible
		state.Reason = proxyDriftReason(ineligible, "current config can no longer be rendered ("+err.Error()+")")
		return state
	}
	state.PendingSHA256 = artifact.ConfigSHA256
	if !strings.EqualFold(artifact.ConfigSHA256, profile.AppliedSHA256) {
		state.Stale = true
		state.IneligibleUsers = ineligible
		state.Reason = proxyDriftReason(ineligible, "applied config differs from the current policy render")
	}
	return state
}

// refreshProxyDriftFor recomputes a single profile's drift state immediately
// (e.g. right after a successful apply, so the dashboard banner clears without
// waiting for the next scheduler tick).
func (s *Server) refreshProxyDriftFor(nodeID string, now time.Time) {
	profile, ok := s.store.ProxyNodeProfile(nodeID)
	if !ok {
		s.proxyDriftMu.Lock()
		delete(s.proxyDrift, nodeID)
		s.proxyDriftMu.Unlock()
		return
	}
	if strings.TrimSpace(profile.AppliedSHA256) == "" {
		s.proxyDriftMu.Lock()
		delete(s.proxyDrift, nodeID)
		s.proxyDriftMu.Unlock()
		return
	}
	state := s.computeProxyDrift(profile, s.store.ProxyUsers(), now)
	s.proxyDriftMu.Lock()
	if state.Stale {
		if prior, had := s.proxyDrift[nodeID]; had && prior.Stale && !prior.Since.IsZero() {
			state.Since = prior.Since
		} else {
			state.Since = now
		}
	}
	s.proxyDrift[nodeID] = state
	s.proxyDriftMu.Unlock()
}

func (s *Server) proxyDriftFor(nodeID string) (proxyDriftState, bool) {
	s.proxyDriftMu.RLock()
	defer s.proxyDriftMu.RUnlock()
	state, ok := s.proxyDrift[nodeID]
	return state, ok
}

func countIneligibleProfileUsers(profile model.ProxyNodeProfile, users []model.ProxyUser, now time.Time) int {
	count := 0
	for _, user := range users {
		if !proxyUserAppliesToProfile(user, profile) {
			continue
		}
		if derivedProxyUserStatusAt(user, now) != model.ProxyUserStatusActive {
			count++
		}
	}
	return count
}

func proxyDriftReason(ineligible int, detail string) string {
	switch {
	case ineligible == 1:
		return "1 user is no longer eligible; review and apply to enforce"
	case ineligible > 1:
		return fmt.Sprintf("%d users are no longer eligible; review and apply to enforce", ineligible)
	default:
		return detail
	}
}
