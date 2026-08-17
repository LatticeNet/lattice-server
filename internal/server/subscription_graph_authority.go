package server

import (
	"context"
	"sync"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type subscriptionGraphAuthorityState struct {
	mu sync.RWMutex
}

type subscriptionGraphAuthorityContextKey struct{}

func (s *Server) subscriptionGraphAuthorityFor(pluginID string) *subscriptionGraphAuthorityState {
	s.subscriptionGraphAuthorityMu.Lock()
	defer s.subscriptionGraphAuthorityMu.Unlock()
	if s.subscriptionGraphAuthorities == nil {
		s.subscriptionGraphAuthorities = make(map[string]*subscriptionGraphAuthorityState)
	}
	state := s.subscriptionGraphAuthorities[pluginID]
	if state == nil {
		state = &subscriptionGraphAuthorityState{}
		s.subscriptionGraphAuthorities[pluginID] = state
	}
	return state
}

func subscriptionGraphAuthorityHeld(ctx context.Context, pluginID string) bool {
	held, _ := ctx.Value(subscriptionGraphAuthorityContextKey{}).(map[string]bool)
	return held[pluginID]
}

func (s *Server) acquireSubscriptionGraphRead(ctx context.Context, pluginID string) (context.Context, func()) {
	if subscriptionGraphAuthorityHeld(ctx, pluginID) {
		return ctx, func() {}
	}
	state := s.subscriptionGraphAuthorityFor(pluginID)
	if waiter := s.subscriptionGraphReadWaiter; waiter != nil {
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
	state.mu.RLock()
	held := make(map[string]bool)
	if existing, _ := ctx.Value(subscriptionGraphAuthorityContextKey{}).(map[string]bool); existing != nil {
		for id, value := range existing {
			held[id] = value
		}
	}
	held[pluginID] = true
	return context.WithValue(ctx, subscriptionGraphAuthorityContextKey{}, held), state.mu.RUnlock
}

func (s *Server) withSubscriptionGraphWrite(pluginID string, fn func() ([]byte, error)) ([]byte, error) {
	state := s.subscriptionGraphAuthorityFor(pluginID)
	if waiter := s.subscriptionGraphWriteWaiter; waiter != nil {
		select {
		case waiter <- struct{}{}:
		default:
		}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return fn()
}

func (s *Server) publishSingBoxInventory(nodeID string, inventory model.SingBoxInventory) {
	_ = s.withSubscriptionGraphWriteErr(vpnCorePluginID, func() error {
		s.singboxInvMu.Lock()
		defer s.singboxInvMu.Unlock()
		if s.singboxInv == nil {
			s.singboxInv = make(map[string]model.SingBoxInventory)
		}
		s.singboxInv[nodeID] = inventory
		return nil
	})
}

func (s *Server) withSubscriptionGraphWriteErr(pluginID string, fn func() error) error {
	_, err := s.withSubscriptionGraphWrite(pluginID, func() ([]byte, error) { return nil, fn() })
	return err
}

func (s *Server) putLineUUIDAuthority(hash, uuid, nodeID string) error {
	return s.withSubscriptionGraphWriteErr(vpnCorePluginID, func() error {
		return s.store.PutLineUUIDAuthority(hash, uuid, nodeID)
	})
}

func (s *Server) upsertGraphNode(node model.Node) error {
	return s.withSubscriptionGraphWriteErr(vpnCorePluginID, func() error { return s.store.UpsertNode(node) })
}

func (s *Server) deleteGraphNode(nodeID string) (report store.NodeCascadeReport, ok bool, err error) {
	_, err = s.withSubscriptionGraphWrite(vpnCorePluginID, func() ([]byte, error) {
		report, ok, err = s.store.DeleteNode(nodeID)
		if err != nil || !ok {
			return nil, err
		}
		s.singboxInvMu.Lock()
		delete(s.singboxInv, nodeID)
		s.singboxInvMu.Unlock()
		s.agentCapabilitiesMu.Lock()
		delete(s.agentCapabilities, nodeID)
		s.agentCapabilitiesMu.Unlock()
		return nil, err
	})
	return report, ok, err
}
