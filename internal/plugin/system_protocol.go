package plugin

import (
	"encoding/json"
	"fmt"
)

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
