package plugin

import (
	"encoding/json"
	"fmt"
	"sync"
)

type stdioV2Session struct {
	mu         sync.Mutex
	generation uint64
	invocation string
	dispatched bool
}

func (s *stdioV2Session) dispatch(generation uint64, invocation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dispatched {
		return fmt.Errorf("stdio invocation already dispatched")
	}
	s.generation, s.invocation, s.dispatched = generation, invocation, true
	return nil
}

func (s *stdioV2Session) validate(f stdioJSONV2Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return validateStdioJSONV2Frame(f, s.generation, s.invocation, "")
}

func (s *stdioV2Session) reset() { s.mu.Lock(); s.dispatched = false; s.invocation = ""; s.mu.Unlock() }

// stdioJSONV2Frame is the correlated envelope used by pooled workers.
type stdioJSONV2Frame struct {
	Protocol     int             `json:"protocol"`
	Kind         string          `json:"kind"`
	Generation   uint64          `json:"generation"`
	InvocationID string          `json:"invocation_id"`
	HostCallID   string          `json:"host_call_id,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
}

func validateStdioJSONV2Frame(f stdioJSONV2Frame, generation uint64, invocationID, hostCallID string) error {
	if f.Protocol != 2 {
		return fmt.Errorf("unexpected stdio protocol %d", f.Protocol)
	}
	if f.Generation != generation || f.InvocationID != invocationID {
		return fmt.Errorf("stale stdio invocation correlation")
	}
	if hostCallID != "" && f.HostCallID != hostCallID {
		return fmt.Errorf("wrong host call correlation")
	}
	if f.Kind == "" {
		return fmt.Errorf("stdio frame kind is required")
	}
	return nil
}
