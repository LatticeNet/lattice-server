package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

func decodeStrictV2(data []byte, dst any) error {
	if err := rejectDuplicateV2Keys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("v2 frame must be object")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err == nil {
		return fmt.Errorf("trailing v2 frame data")
	} else if err != io.EOF {
		return fmt.Errorf("trailing v2 frame data: %w", err)
	}
	return nil
}

func rejectDuplicateV2Keys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("invalid v2 object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate v2 key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return fmt.Errorf("unexpected v2 delimiter %q", delim)
		}
	}
	return walk()
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

func strictV2Bound(data []byte, limits ...int) error {
	limit := HostMaxInvokeStdoutBytes
	if len(limits) > 0 && limits[0] > 0 {
		limit = limits[0]
	}
	if len(data) > limit {
		return fmt.Errorf("v2 frame exceeds %d bytes", limit)
	}
	return nil
}

func decodeStdioJSONV2Frame(data []byte, limits ...int) (stdioJSONV2Frame, error) {
	var f stdioJSONV2Frame
	if err := strictV2Bound(data, limits...); err != nil {
		return f, err
	}
	if err := decodeStrictV2(data, &f); err != nil {
		return f, err
	}
	if err := requireV2Fields(data, "protocol", "kind", "generation", "invocation_id"); err != nil {
		return f, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return f, err
	}
	allowed := map[string]bool{"protocol": true, "kind": true, "generation": true, "invocation_id": true}
	required := []string(nil)
	switch f.Kind {
	case "runtime_ready":
		allowed["features"] = true
		required = append(required, "features")
	case "stderr_complete", "invoke_ready":
	case "stderr_chunk":
		allowed["data"] = true
		required = append(required, "data")
	case "invoke_result":
		allowed["response"] = true
		required = append(required, "response")
	case "host_call":
		allowed["host_call_id"], allowed["host_call"] = true, true
		required = append(required, "host_call_id", "host_call")
	case "host_response":
		allowed["host_call_id"], allowed["host_response"] = true, true
		required = append(required, "host_call_id", "host_response")
	default:
		return f, fmt.Errorf("unknown stdio frame kind %q", f.Kind)
	}
	for key := range fields {
		if !allowed[key] {
			return f, fmt.Errorf("field %q is invalid for %s", key, f.Kind)
		}
	}
	if err := requireV2Fields(data, required...); err != nil {
		return f, err
	}
	if err := validateStdioJSONV2Frame(f, f.Generation, f.InvocationID, ""); err != nil {
		return f, err
	}
	return f, nil
}

func decodeStrictSystemHostCall(data []byte, outerID string, limits ...int) (systemHostCall, error) {
	var call systemHostCall
	if err := strictV2Bound(data, limits...); err != nil {
		return call, err
	}
	if err := decodeStrictV2(data, &call); err != nil {
		return call, err
	}
	if err := requireV2Fields(data, "id", "method", "params"); err != nil {
		return call, err
	}
	if call.ID == "" || call.ID != outerID || strings.TrimSpace(call.Method) == "" {
		return call, fmt.Errorf("invalid host_call payload")
	}
	return call, nil
}

func decodeSystemRunnerReply(data []byte, limits ...int) (systemRunnerReply, error) {
	if err := strictV2Bound(data, limits...); err != nil {
		return systemRunnerReply{}, err
	}
	var raw struct {
		OK       json.RawMessage `json:"ok"`
		Plan     json.RawMessage `json:"plan"`
		Message  json.RawMessage `json:"message"`
		Result   json.RawMessage `json:"result"`
		Error    json.RawMessage `json:"error"`
		Warnings json.RawMessage `json:"warnings"`
	}
	if err := decodeStrictV2(data, &raw); err != nil {
		return systemRunnerReply{}, err
	}
	if len(raw.OK) == 0 || bytes.Equal(raw.OK, []byte("null")) {
		return systemRunnerReply{}, fmt.Errorf("missing required v2 field %q", "ok")
	}
	var reply systemRunnerReply
	if err := json.Unmarshal(data, &reply); err != nil {
		return systemRunnerReply{}, err
	}
	if !reply.OK && strings.TrimSpace(reply.Error) == "" {
		return systemRunnerReply{}, fmt.Errorf("failed response requires error")
	}
	if reply.OK && strings.TrimSpace(reply.Error) != "" {
		return systemRunnerReply{}, fmt.Errorf("successful response cannot contain error")
	}
	if !reply.OK && len(reply.Result) != 0 && !bytes.Equal(reply.Result, []byte("null")) {
		return systemRunnerReply{}, fmt.Errorf("failed response cannot contain result")
	}
	return reply, nil
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
	Features     []string        `json:"features,omitempty"`
	Data         string          `json:"data,omitempty"`
}

func validateStdioJSONV2Frame(f stdioJSONV2Frame, generation uint64, invocationID, hostCallID string) error {
	if f.Protocol != 2 {
		return fmt.Errorf("unexpected stdio protocol %d", f.Protocol)
	}
	if f.Generation == 0 || f.InvocationID == "" || f.Generation != generation || f.InvocationID != invocationID {
		return fmt.Errorf("stale stdio invocation correlation")
	}
	if hostCallID != "" && f.HostCallID != hostCallID {
		return fmt.Errorf("wrong host call correlation")
	}
	if f.Kind == "" {
		return fmt.Errorf("stdio frame kind is required")
	}
	nonempty := func(b json.RawMessage) bool { return len(b) != 0 && string(b) != "null" }
	if f.Kind != "runtime_ready" && len(f.Features) != 0 {
		return fmt.Errorf("features are only valid on runtime_ready")
	}
	if f.Kind != "stderr_chunk" && f.Data != "" {
		return fmt.Errorf("data is only valid on stderr_chunk")
	}
	switch f.Kind {
	case "runtime_ready":
		if f.InvocationID != "runtime" || len(f.Features) != 1 || f.Features[0] != "stderr_frames_v1" || f.Data != "" || f.HostCallID != "" || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostCall) || nonempty(f.HostResponse) {
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
	case "stderr_complete":
		if len(f.Features) != 0 || f.Data != "" || f.HostCallID != "" || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostCall) || nonempty(f.HostResponse) {
			return fmt.Errorf("invalid stderr_complete schema")
		}
	case "stderr_chunk":
		if f.Data == "" || len(f.Features) != 0 || f.HostCallID != "" || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostCall) || nonempty(f.HostResponse) {
			return fmt.Errorf("invalid stderr_chunk schema")
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
