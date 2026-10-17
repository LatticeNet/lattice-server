package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/LatticeNet/lattice-sdk/strictjson"
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

// rejectDuplicateV2Keys refuses a frame with a duplicate key in any object.
// strictjson.Valid admits a well-formed, duplicate-free frame in one pass
// without allocating; whatever it refuses is judged by the token walk below,
// which stays the specification and words every error.
func rejectDuplicateV2Keys(data []byte) error {
	if strictjson.Valid(data) {
		return nil
	}
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
	return requireV2Present(m, fields...)
}

// requireV2Present is requireV2Fields over a frame's members already read.
func requireV2Present(m map[string]json.RawMessage, fields ...string) error {
	for _, k := range fields {
		v, ok := m[k]
		if !ok || len(v) == 0 || string(v) == "null" {
			return fmt.Errorf("missing required v2 field %q", k)
		}
	}
	return nil
}

// v2Members reads a frame's top-level members in one pass of
// strictjson.Fields when the frame is an object strictjson admits and every
// member is named exactly as one of names; ok is false otherwise, and the
// caller takes its encoding/json path. A frame it admits is one
// decodeStrictV2 admits too (well formed, no duplicate key at any depth, one
// object, every member known), and decoding each member on its own gives
// what the whole-struct decode gives, because no two members name the same
// field.
func v2Members(data []byte, names map[string]bool) (map[string]json.RawMessage, bool) {
	fields, ok := strictjson.Fields(data)
	if !ok {
		return nil, false
	}
	members := make(map[string]json.RawMessage, len(fields))
	for _, f := range fields {
		if !names[f.Key] {
			return nil, false
		}
		members[f.Key] = f.Value
	}
	return members, true
}

// v2FrameMembers are the JSON names of stdioJSONV2Frame's fields.
var v2FrameMembers = map[string]bool{
	"protocol": true, "kind": true, "generation": true, "invocation_id": true, "host_call_id": true,
	"request": true, "response": true, "host_call": true, "host_response": true, "features": true, "data": true,
}

// decodeV2FrameMembers decodes a frame from the members v2Members read; ok
// is false when any member does not decode, and the caller takes the
// encoding/json path, which words the error.
func decodeV2FrameMembers(m map[string]json.RawMessage) (stdioJSONV2Frame, bool) {
	var f stdioJSONV2Frame
	for key, value := range m {
		var err error
		switch key {
		case "protocol":
			err = json.Unmarshal(value, &f.Protocol)
		case "kind":
			err = json.Unmarshal(value, &f.Kind)
		case "generation":
			err = json.Unmarshal(value, &f.Generation)
		case "invocation_id":
			err = json.Unmarshal(value, &f.InvocationID)
		case "host_call_id":
			err = json.Unmarshal(value, &f.HostCallID)
		case "request":
			f.Request = append(json.RawMessage(nil), value...)
		case "response":
			f.Response = append(json.RawMessage(nil), value...)
		case "host_call":
			f.HostCall = append(json.RawMessage(nil), value...)
		case "host_response":
			f.HostResponse = append(json.RawMessage(nil), value...)
		case "features":
			err = json.Unmarshal(value, &f.Features)
		case "data":
			err = json.Unmarshal(value, &f.Data)
		default:
			return stdioJSONV2Frame{}, false
		}
		if err != nil {
			return stdioJSONV2Frame{}, false
		}
	}
	return f, true
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
	// The fast path reads the members once; any frame it does not admit
	// takes the encoding/json path, which decides and words every error.
	// Both run the checks below in the same order.
	fields, fast := v2Members(data, v2FrameMembers)
	if fast {
		f, fast = decodeV2FrameMembers(fields)
	}
	if !fast {
		f = stdioJSONV2Frame{}
		if err := decodeStrictV2(data, &f); err != nil {
			return f, err
		}
		if err := requireV2Fields(data, "protocol", "kind", "generation", "invocation_id"); err != nil {
			return f, err
		}
		fields = nil
		if err := json.Unmarshal(data, &fields); err != nil {
			return f, err
		}
	} else if err := requireV2Present(fields, "protocol", "kind", "generation", "invocation_id"); err != nil {
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
	// Keys are checked in sorted order so that a frame with two invalid
	// members names the same one every time; a map range named either.
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		if !allowed[key] {
			return f, fmt.Errorf("field %q is invalid for %s", key, f.Kind)
		}
	}
	if err := requireV2Present(fields, required...); err != nil {
		return f, err
	}
	if err := validateStdioJSONV2Frame(f, f.Generation, f.InvocationID, ""); err != nil {
		return f, err
	}
	return f, nil
}

func decodeStrictSystemHostCall(data []byte, outerID string, limits ...int) (systemHostCall, error) {
	var call systemHostCall
	if !validSystemHostCallID(outerID) {
		return call, fmt.Errorf("invalid host_call id")
	}
	if err := strictV2Bound(data, limits...); err != nil {
		return call, err
	}
	if err := decodeStrictV2(data, &call); err != nil {
		return call, err
	}
	if err := requireV2Fields(data, "id", "method", "params"); err != nil {
		return call, err
	}
	if !validSystemHostCallID(call.ID) || call.ID != outerID || strings.TrimSpace(call.Method) == "" {
		return call, fmt.Errorf("invalid host_call payload")
	}
	return call, nil
}

func decodeSystemRunnerReply(data []byte, limits ...int) (systemRunnerReply, error) {
	if err := strictV2Bound(data, limits...); err != nil {
		return systemRunnerReply{}, err
	}
	// The fast path reads the members once and decodes each into its field;
	// a reply it does not admit, or a member that does not decode, takes the
	// encoding/json path, which decides and words every error.
	reply, fast := systemRunnerReply{}, false
	if members, ok := v2Members(data, systemRunnerReplyMembers); ok {
		if okRaw := members["ok"]; len(okRaw) == 0 || bytes.Equal(okRaw, []byte("null")) {
			return systemRunnerReply{}, fmt.Errorf("missing required v2 field %q", "ok")
		}
		reply, fast = decodeSystemRunnerReplyMembers(members)
	}
	if !fast {
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
		reply = systemRunnerReply{}
		if err := json.Unmarshal(data, &reply); err != nil {
			return systemRunnerReply{}, err
		}
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

// systemRunnerReplyMembers are the JSON names a reply may carry.
var systemRunnerReplyMembers = map[string]bool{"ok": true, "plan": true, "message": true, "result": true, "error": true, "warnings": true}

// decodeSystemRunnerReplyMembers decodes a reply from the members v2Members
// read; ok is false when any member does not decode.
func decodeSystemRunnerReplyMembers(m map[string]json.RawMessage) (systemRunnerReply, bool) {
	var reply systemRunnerReply
	for key, value := range m {
		var err error
		switch key {
		case "ok":
			err = json.Unmarshal(value, &reply.OK)
		case "plan":
			reply.Plan = append(json.RawMessage(nil), value...)
		case "message":
			err = json.Unmarshal(value, &reply.Message)
		case "result":
			reply.Result = append(json.RawMessage(nil), value...)
		case "error":
			err = json.Unmarshal(value, &reply.Error)
		case "warnings":
			err = json.Unmarshal(value, &reply.Warnings)
		default:
			return systemRunnerReply{}, false
		}
		if err != nil {
			return systemRunnerReply{}, false
		}
	}
	return reply, true
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
	if f.Kind == "runtime_ready" {
		if f.InvocationID != "runtime" {
			return fmt.Errorf("invalid runtime invocation id")
		}
	} else if !validSystemInvocationID(f.InvocationID) {
		return fmt.Errorf("invalid invocation id")
	}
	if hostCallID != "" && f.HostCallID != hostCallID {
		return fmt.Errorf("wrong host call correlation")
	}
	if hostCallID != "" && !validSystemHostCallID(hostCallID) {
		return fmt.Errorf("invalid host call correlation")
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
		if !validSystemHostCallID(f.HostCallID) || !nonempty(f.HostCall) || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostResponse) {
			return fmt.Errorf("invalid host_call schema")
		}
	case "host_response":
		if !validSystemHostCallID(f.HostCallID) || !nonempty(f.HostResponse) || nonempty(f.Request) || nonempty(f.Response) || nonempty(f.HostCall) {
			return fmt.Errorf("invalid host_response schema")
		}
	default:
		return fmt.Errorf("unknown stdio frame kind %q", f.Kind)
	}
	return nil
}

func validSystemInvocationID(id string) bool {
	n, err := strconv.ParseInt(id, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == id
}

func validSystemHostCallID(id string) bool {
	if len(id) < 2 || id[0] != 'h' {
		return false
	}
	n, err := strconv.ParseUint(id[1:], 10, 64)
	return err == nil && n > 0 && "h"+strconv.FormatUint(n, 10) == id
}

func appendJSONString(dst []byte, s string) []byte {
	raw, _ := json.Marshal(s)
	return append(dst, raw...)
}

// encodeInvokeV2Frame is the invoke frame for req, newline included,
// exactly as json.NewEncoder(w).Encode writes the stdioJSONV2Frame whose
// Request is json.Marshal of the action and payload. A render or convert
// payload is up to several MiB that its caller's json.Marshal already wrote
// in canonical form, so it is spliced in once instead of compacted twice
// more; any other payload goes through encoding/json as before.
func encodeInvokeV2Frame(generation uint64, invocation string, req InvokeRequest) []byte {
	if len(req.Payload) == 0 || strictjson.CanonicalRaw(req.Payload) {
		out := make([]byte, 0, len(req.Payload)+128+len(invocation)+len(req.Action))
		out = append(out, `{"protocol":2,"kind":"invoke","generation":`...)
		out = strconv.AppendUint(out, generation, 10)
		out = appendJSONString(append(out, `,"invocation_id":`...), invocation)
		out = appendJSONString(append(out, `,"request":{"action":`...), req.Action)
		if len(req.Payload) > 0 {
			out = append(append(out, `,"payload":`...), req.Payload...)
		}
		return append(out, "}}\n"...)
	}
	frame := stdioJSONV2Frame{Protocol: 2, Kind: "invoke", Generation: generation, InvocationID: invocation}
	frame.Request, _ = json.Marshal(struct {
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{req.Action, req.Payload})
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(frame)
	return buf.Bytes()
}

// EncodeServiceCall is the body core's call action carries, exactly as
// json.Marshal writes struct{service, method, payload (omitempty)}, with a
// canonical payload spliced in rather than compacted again.
func EncodeServiceCall(service, method string, payload json.RawMessage) ([]byte, error) {
	if len(payload) == 0 || strictjson.CanonicalRaw(payload) {
		out := make([]byte, 0, len(payload)+64+len(service)+len(method))
		out = appendJSONString(append(out, `{"service":`...), service)
		out = appendJSONString(append(out, `,"method":`...), method)
		if len(payload) > 0 {
			out = append(append(out, `,"payload":`...), payload...)
		}
		return append(out, '}'), nil
	}
	return json.Marshal(struct {
		Service string          `json:"service"`
		Method  string          `json:"method"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{Service: service, Method: method, Payload: payload})
}
