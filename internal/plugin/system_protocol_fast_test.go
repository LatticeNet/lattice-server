package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The frame and reply decoders read the members of a well-formed frame in
// one pass (v2Members) and fall back to encoding/json for anything else.
// These tests hold the result, frame and error alike, to the decoders as
// they were before the fast path: the copies below, which run encoding/json
// over every frame with the token-walk duplicate check.

func legacyRejectDuplicateV2Keys(data []byte) error {
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

func legacyDecodeStrictV2(data []byte, dst any) error {
	if err := legacyRejectDuplicateV2Keys(data); err != nil {
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

func legacyRequireV2Fields(data []byte, fields ...string) error {
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

func legacyDecodeStdioJSONV2Frame(data []byte) (stdioJSONV2Frame, error) {
	var f stdioJSONV2Frame
	if err := strictV2Bound(data); err != nil {
		return f, err
	}
	if err := legacyDecodeStrictV2(data, &f); err != nil {
		return f, err
	}
	if err := legacyRequireV2Fields(data, "protocol", "kind", "generation", "invocation_id"); err != nil {
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
	// Sorted as the decoder now sorts them, so the oracle words a frame
	// with two invalid members the same way on every run.
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		if !allowed[key] {
			return f, fmt.Errorf("field %q is invalid for %s", key, f.Kind)
		}
	}
	if err := legacyRequireV2Fields(data, required...); err != nil {
		return f, err
	}
	if err := validateStdioJSONV2Frame(f, f.Generation, f.InvocationID, ""); err != nil {
		return f, err
	}
	return f, nil
}

func legacyDecodeSystemRunnerReply(data []byte) (systemRunnerReply, error) {
	if err := strictV2Bound(data); err != nil {
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
	if err := legacyDecodeStrictV2(data, &raw); err != nil {
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

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// sameFrameDecode fails when the decoders disagree on raw. A frame that
// fails decodes to whatever the decoder had filled in when it stopped, which
// no caller reads, so only a success compares frames.
func sameFrameDecode(t *testing.T, raw []byte) {
	t.Helper()
	got, gotErr := decodeStdioJSONV2Frame(raw)
	want, wantErr := legacyDecodeStdioJSONV2Frame(raw)
	if errText(gotErr) != errText(wantErr) {
		t.Fatalf("frame %q: error %q, before the fast path %q", raw, errText(gotErr), errText(wantErr))
	}
	if gotErr == nil && !reflect.DeepEqual(got, want) {
		t.Fatalf("frame %q: decoded %+v, before the fast path %+v", raw, got, want)
	}
	gotReply, gotErr := decodeSystemRunnerReply(raw)
	wantReply, wantErr := legacyDecodeSystemRunnerReply(raw)
	if errText(gotErr) != errText(wantErr) {
		t.Fatalf("reply %q: error %q, before the fast path %q", raw, errText(gotErr), errText(wantErr))
	}
	if gotErr == nil && !reflect.DeepEqual(gotReply, wantReply) {
		t.Fatalf("reply %q: decoded %+v, before the fast path %+v", raw, gotReply, wantReply)
	}
}

var fastDecodeCorpus = []string{
	`{"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1"}`,
	`{"protocol":2,"kind":"invoke_result","generation":7,"invocation_id":"1","response":{"ok":true,"result":{"plan":{"nodes":[{"a":1}]}}}}`,
	`{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"1","host_call_id":"h1","host_call":{"id":"h1","method":"log.write","params":{}}}`,
	`{"protocol":2,"kind":"runtime_ready","generation":7,"invocation_id":"runtime","features":["stderr_frames_v1"]}`,
	`{"protocol":2,"kind":"stderr_chunk","generation":7,"invocation_id":"1","data":"aGk="}`,
	`{"protocol":2,"kind":"invoke_result","generation":7,"invocation_id":"1","response":null}`,
	`{"protocol":2,"kind":"invoke_result","generation":7,"invocation_id":"1","response":{"ok":true,"result":{"a":1,"a":2}}}`,
	`{"Protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1"}`,
	`{"PROTOCOL":2,"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1"}`,
	`{"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1"}`,
	`{"protocol":2.0,"kind":"invoke_ready","generation":1,"invocation_id":"1"}`,
	`{"protocol":"2","kind":"invoke_ready","generation":1,"invocation_id":"1"}`,
	`{"protocol":2,"kind":"invoke_ready","generation":-1,"invocation_id":"1"}`,
	`{"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1","features":null}`,
	`{"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1","x":1}`,
	`{"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1"} `,
	`{"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1"}{}`,
	`[{"protocol":2}]`, `null`, `"x"`, `{}`, ``, `{"protocol":2,`, "{\"kind\":\"\xff\",\"protocol\":2,\"generation\":1,\"invocation_id\":\"1\"}",
	`{"ok":true}`, `{"ok":true,"result":{"x":[1,2,{"y":null}]},"warnings":["w"],"message":"m","plan":"p"}`, `{"ok":false,"error":"denied"}`,
	`{"ok":"true"}`, `{"OK":true}`, `{"ok":true,"OK":false}`, `{"ok":null}`, `{"result":{}}`, `{"ok":true,"warnings":"w"}`,
	`{"ok":true,"warnings":[1]}`, `{"ok":true,"error":""}`, `{"ok":false,"error":"x","result":null}`, `{"ok":false,"error":"x","result":{}}`,
	`{"ok":true,"plan":null,"result":null}`, `{"ok":true,"message":7}`, `{"ok":true,"result":1e999}`, `{"ok":true,"result":{"k":1,"k":1}}`,
}

func TestFastFrameDecodeMatchesTheDecodeBeforeIt(t *testing.T) {
	for _, raw := range fastDecodeCorpus {
		sameFrameDecode(t, []byte(raw))
	}
}

// A frame with two members its kind does not allow is refused naming the
// same one every time, so the fuzz comparison above cannot flake on it.
func TestFrameDecodeNamesTheSameInvalidMemberEveryTime(t *testing.T) {
	raw := []byte(`{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"1","host_call_id":"h1","host_call":{"id":"h1","method":"log.write","params":{}},"hOst_cAll":1,"features":[]}`)
	for i := 0; i < 50; i++ {
		_, err := decodeStdioJSONV2Frame(raw)
		if err == nil || err.Error() != `field "features" is invalid for host_call` {
			t.Fatalf("run %d: %v", i, err)
		}
		sameFrameDecode(t, raw)
	}
}

func FuzzFastFrameDecodeMatchesTheDecodeBeforeIt(f *testing.F) {
	for _, raw := range fastDecodeCorpus {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		sameFrameDecode(t, raw)
	})
}

// BenchmarkDecodeInvokeResultFrame decodes a render reply carrying a
// 1000-node plan the way the transport does: the frame, then its reply.
func BenchmarkDecodeInvokeResultFrame(b *testing.B) {
	var nodes bytes.Buffer
	for i := 0; i < 1000; i++ {
		if i > 0 {
			nodes.WriteByte(',')
		}
		fmt.Fprintf(&nodes, `{"line_uuid":"581ff4e6-e0a4-4f5c-9d2a-%012d","placeholders":{"uuid":"LATTICE-SYN-581ff4e6-e0a4-4f5c-9d2a-%012d-uuid-0123456789abcdef0123456789abcdef"},"node":{"name":"Node %d","type":"vless","server":"45.10.0.%d","port":443,"uuid":"x","tls":true,"servername":"www.example.com","network":"tcp","udp":true,"client-fingerprint":"chrome","reality-opts":{"public-key":"q8r5kKy9VQ6c5xHkC2x3l7m1ZtLwJ9dXQvW3p2H0aB4","short-id":"0a1b"},"addresses":["45.10.0.%d"],"geo":{"country":"JP","city":"Tokyo"},"tags":["edge","premium"]}}`, i, i, i, i%256, i%256)
	}
	raw := []byte(`{"protocol":2,"kind":"invoke_result","generation":1,"invocation_id":"1","response":{"ok":true,"result":{"content":"","target":"sing-box","plan":{"kind":"nodes","nodes":[` + nodes.String() + `]}}}}`)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		f, err := decodeStdioJSONV2Frame(raw, maxV2WireFrameBytes)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := decodeSystemRunnerReply(f.Response, HostMaxInvokeStdoutBytes); err != nil {
			b.Fatal(err)
		}
	}
}

// The outbound frames splice a canonical payload in place of encoding/json's
// compaction; the bytes must be the ones encoding/json writes.
func sameOutboundEncoding(t *testing.T, action string, payload []byte) {
	t.Helper()
	frame := stdioJSONV2Frame{Protocol: 2, Kind: "invoke", Generation: 9, InvocationID: "17"}
	frame.Request, _ = json.Marshal(struct {
		Action  string          `json:"action"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{action, payload})
	var want bytes.Buffer
	if err := json.NewEncoder(&want).Encode(frame); err != nil {
		t.Fatal(err)
	}
	if got := encodeInvokeV2Frame(9, "17", InvokeRequest{Action: action, Payload: payload}); !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("invoke frame for %q\n%s\nencoding/json\n%s", payload, got, want.Bytes())
	}
	wantBody, wantErr := json.Marshal(struct {
		Service string          `json:"service"`
		Method  string          `json:"method"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{Service: "svc<&>", Method: action, Payload: payload})
	gotBody, gotErr := EncodeServiceCall("svc<&>", action, payload)
	if errText(gotErr) != errText(wantErr) || !bytes.Equal(gotBody, wantBody) {
		t.Fatalf("call body for %q: %s (%v), encoding/json %s (%v)", payload, gotBody, gotErr, wantBody, wantErr)
	}
}

var outboundPayloads = []string{``, `{}`, `{"raw":"{\"rows\":[]}","target":"sing-box"}`, `{"a": 1}`, `{"a":"<b>"}`, "{\"a\":\" \"}",
	`[1,2]`, `"text"`, `null`, `{"a":1,"a":2}`, `{"a":`, "{\"a\":\"\xff\"}", ` {"a":1}`, `{"n":1e999}`}

func TestOutboundFramesAreWhatEncodingJSONWrites(t *testing.T) {
	for _, payload := range outboundPayloads {
		sameOutboundEncoding(t, "call", []byte(payload))
		sameOutboundEncoding(t, "a&b", []byte(payload))
	}
}

func FuzzOutboundFramesAreWhatEncodingJSONWrites(f *testing.F) {
	for _, payload := range outboundPayloads {
		f.Add("call", []byte(payload))
	}
	f.Fuzz(func(t *testing.T, action string, payload []byte) {
		sameOutboundEncoding(t, action, payload)
	})
}
