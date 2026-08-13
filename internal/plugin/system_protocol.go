package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
)

func decodeStrictV2(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("v2 frame must be object")
	}
	seen := map[string]bool{}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := k.(string)
		if !ok {
			return fmt.Errorf("invalid v2 key")
		}
		if seen[key] {
			return fmt.Errorf("duplicate v2 key %q", key)
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err == nil {
		return fmt.Errorf("trailing v2 frame data")
	}
	return nil
}

func requireV2Fields(data []byte, fields ...string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for _, k := range fields {
		v, ok := m[k]
		if !ok || len(v) == 0 || string(v) == "null" {
			return fmt.Errorf("missing required v2 field %q", k)
		}
	}
	return nil
}

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
	Request      json.RawMessage `json:"request,omitempty"`
	Response     json.RawMessage `json:"response,omitempty"`
	HostCall     json.RawMessage `json:"host_call,omitempty"`
	HostResponse json.RawMessage `json:"host_response,omitempty"`
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
	nonempty := func(b json.RawMessage) bool { return len(b) != 0 && string(b) != "null" }
	switch f.Kind {
	case "runtime_ready":
		if f.InvocationID != "runtime" || f.HostCallID != "" || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostCall) || nonempty(f.HostResponse) {
			return fmt.Errorf("invalid runtime_ready schema")
		}
	case "invoke_result":
		if !nonempty(f.Response) || f.HostCallID != "" || nonempty(f.Request) || nonempty(f.HostCall) || nonempty(f.HostResponse) {
			return fmt.Errorf("invalid invoke_result schema")
		}
	case "invoke_ready":
		if f.HostCallID != "" || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostCall) || nonempty(f.HostResponse) {
			return fmt.Errorf("invalid invoke_ready schema")
		}
	case "host_call":
		if f.HostCallID == "" || !nonempty(f.HostCall) || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostResponse) {
			return fmt.Errorf("invalid host_call schema")
		}
	case "host_response":
		if f.HostCallID == "" || !nonempty(f.HostResponse) || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostCall) {
			return fmt.Errorf("invalid host_response schema")
		}
	default:
		return fmt.Errorf("unknown stdio frame kind %q", f.Kind)
	}
	return nil
}
