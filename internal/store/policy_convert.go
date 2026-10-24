package store

import (
	"errors"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// ErrNetPolicyNotManual is ConvertNetPolicy's refusal when the node has no
// manually authored policy any more.
var ErrNetPolicyNotManual = errors.New("the node has no manually authored network policy to convert")

// ConvertNetPolicy retires a node's manually authored NetPolicy in favour of
// the selector-scoped outbound policy gp, in one write: gp is stored, and the
// node's document becomes derived (the group-derived materialization of gp
// and any other policy reaching the node) or, when derived is nil, is
// removed. It refuses with ErrNetPolicyNotManual when the node's document is
// missing or already group-derived, so two conversions cannot both land.
func (s *Store) ConvertNetPolicy(nodeID string, gp model.GroupNetPolicy, derived *model.NetPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.state.NetPolicies[nodeID]
	if !ok || current.GroupDerived {
		return ErrNetPolicyNotManual
	}
	now := time.Now().UTC()
	gp.UpdatedAt = now
	if gp.CreatedAt.IsZero() {
		gp.CreatedAt = now
	}
	s.state.GroupPolicies[gp.ID] = cloneGroupPolicy(gp)
	if derived == nil {
		delete(s.state.NetPolicies, nodeID)
	} else {
		policy := *derived
		policy.ID = nodeID
		policy.TargetNodeID = nodeID
		policy.GroupDerived = true
		policy.Rules = append([]model.NetRule(nil), policy.Rules...)
		policy.UpdatedAt = now
		if policy.CreatedAt.IsZero() {
			policy.CreatedAt = current.CreatedAt
		}
		s.state.NetPolicies[nodeID] = policy
	}
	return s.Save()
}
