package plugin

import (
	"strings"
	"testing"
)

func TestValidateStdioJSONV2FrameCorrelation(t *testing.T) {
	base := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: 7, InvocationID: "1", Response: []byte(`{"ok":true}`)}
	for name, frame := range map[string]stdioJSONV2Frame{
		"valid":            base,
		"wrong protocol":   func() stdioJSONV2Frame { f := base; f.Protocol = 1; return f }(),
		"stale generation": func() stdioJSONV2Frame { f := base; f.Generation = 6; return f }(),
		"wrong invocation": func() stdioJSONV2Frame { f := base; f.InvocationID = "2"; return f }(),
		"wrong host call":  func() stdioJSONV2Frame { f := base; f.HostCallID = "h2"; return f }(),
		"missing kind":     func() stdioJSONV2Frame { f := base; f.Kind = ""; return f }(),
	} {
		t.Run(name, func(t *testing.T) {
			err := validateStdioJSONV2Frame(frame, 7, "1", "")
			if name == "valid" && err != nil {
				t.Fatal(err)
			}
			if name != "valid" && err == nil {
				t.Fatal("expected strict correlation failure")
			}
		})
	}
}

func TestValidateStdioJSONV2FrameRejectsNonCanonicalIDs(t *testing.T) {
	for _, id := range []string{"0", "01", "-1", "9223372036854775808", strings.Repeat("1", 128)} {
		frame := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: 7, InvocationID: id, Response: []byte(`{"ok":true}`)}
		if err := validateStdioJSONV2Frame(frame, 7, id, ""); err == nil {
			t.Fatalf("accepted invocation id %q", id)
		}
	}
	for _, id := range []string{"h0", "h01", "h-1", "h18446744073709551616", "h" + strings.Repeat("1", 128)} {
		frame := stdioJSONV2Frame{Protocol: 2, Kind: "host_call", Generation: 7, InvocationID: "1", HostCallID: id, HostCall: []byte(`{"id":"h1","method":"log.write","params":{}}`)}
		if err := validateStdioJSONV2Frame(frame, 7, "1", ""); err == nil {
			t.Fatalf("accepted host call id %q", id)
		}
	}
	runtimeReady := stdioJSONV2Frame{Protocol: 2, Kind: "runtime_ready", Generation: 7, InvocationID: "runtime", Features: []string{"stderr_frames_v1"}}
	if err := validateStdioJSONV2Frame(runtimeReady, 7, "runtime", ""); err != nil {
		t.Fatalf("runtime_ready must retain its reserved id: %v", err)
	}
}

func TestDecodeStrictV2RejectsDuplicateAndTrailing(t *testing.T) {
	var f stdioJSONV2Frame
	if err := decodeStrictV2([]byte(`{"protocol":2,"protocol":2,"kind":"runtime_ready"}`), &f); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if err := decodeStrictV2([]byte(`{"protocol":2,"kind":"runtime_ready"}{}`), &f); err == nil {
		t.Fatal("trailing frame accepted")
	}
}

func TestRequireV2FieldsRejectsMissingAndNull(t *testing.T) {
	valid := []byte(`{"protocol":2,"kind":"runtime_ready","generation":1,"invocation_id":"runtime","features":["stderr_frames_v1"]}`)
	if err := requireV2Fields(valid, "protocol", "kind", "generation", "invocation_id"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{[]byte(`{"protocol":2,"kind":null,"generation":1,"invocation_id":"runtime"}`), []byte(`{"protocol":2,"kind":"runtime_ready","generation":1}`)} {
		if err := requireV2Fields(raw, "protocol", "kind", "generation", "invocation_id"); err == nil {
			t.Fatal("accepted missing/null required field")
		}
	}
}

func TestDecodeStdioJSONV2FrameHostileMatrix(t *testing.T) {
	valid := `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"1","host_call_id":"h1","host_call":{"id":"h1","method":"log.write","params":{}}}`
	cases := map[string]string{
		"missing protocol":        `{"kind":"host_call","generation":7,"invocation_id":"1","host_call_id":"h1","host_call":{"id":"h1","method":"log.write","params":{}}}`,
		"null generation":         `{"protocol":2,"kind":"host_call","generation":null,"invocation_id":"1","host_call_id":"h1","host_call":{"id":"h1","method":"log.write","params":{}}}`,
		"unknown kind":            `{"protocol":2,"kind":"other","generation":7,"invocation_id":"1"}`,
		"forbidden null response": `{"protocol":2,"kind":"invoke_ready","generation":7,"invocation_id":"1","response":null}`,
		"missing host payload":    `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"1","host_call_id":"h1"}`,
		"null host payload":       `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"1","host_call_id":"h1","host_call":null}`,
		"duplicate root":          `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"1","host_call_id":"h1","host_call_id":"h2","host_call":{"id":"h1","method":"log.write","params":{}}}`,
		"unknown root":            `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"1","host_call_id":"h1","host_call":{"id":"h1","method":"log.write","params":{}},"x":1}`,
		"trailing garbage":        valid + ` trailing`,
	}
	if _, err := decodeStdioJSONV2Frame([]byte(valid)); err != nil {
		t.Fatalf("valid host_call rejected: %v", err)
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStdioJSONV2Frame([]byte(raw)); err == nil {
				t.Fatalf("hostile frame accepted: %s", raw)
			}
		})
	}
}

func TestDecodeSystemHostCallStrictNestedShape(t *testing.T) {
	valid := `{"id":"h1","method":"log.write","params":{}}`
	if _, err := decodeStrictSystemHostCall([]byte(valid), "h1"); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"missing params":   `{"id":"h1","method":"log.write"}`,
		"null params":      `{"id":"h1","method":"log.write","params":null}`,
		"wrong id":         `{"id":"h2","method":"log.write","params":{}}`,
		"duplicate nested": `{"id":"h1","id":"h1","method":"log.write","params":{}}`,
		"unknown nested":   `{"id":"h1","method":"log.write","params":{},"x":1}`,
		"trailing nested":  valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStrictSystemHostCall([]byte(raw), "h1"); err == nil {
				t.Fatalf("hostile host_call accepted: %s", raw)
			}
		})
	}
}

func TestDecodeSystemRunnerReplyRequiresOKAndUnion(t *testing.T) {
	for _, raw := range []string{`{"ok":true,"result":{}}`, `{"ok":false,"error":"denied"}`} {
		if _, err := decodeSystemRunnerReply([]byte(raw)); err != nil {
			t.Fatalf("valid reply rejected: %s: %v", raw, err)
		}
	}
	for name, raw := range map[string]string{
		"missing ok":       `{"result":{}}`,
		"null ok":          `{"ok":null,"result":{}}`,
		"failure no error": `{"ok":false}`,
		"failure result":   `{"ok":false,"error":"denied","result":{}}`,
		"success error":    `{"ok":true,"error":"bad"}`,
		"duplicate":        `{"ok":true,"ok":false}`,
		"unknown":          `{"ok":true,"x":1}`,
		"trailing":         `{"ok":true}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSystemRunnerReply([]byte(raw)); err == nil {
				t.Fatalf("hostile reply accepted: %s", raw)
			}
		})
	}
}

func FuzzDecodeStdioJSONV2Frame(f *testing.F) {
	f.Add([]byte(`{"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"1"}`))
	f.Add([]byte(`{"protocol":2,"kind":"host_call","generation":1,"invocation_id":"1","host_call_id":"h1","host_call":{"id":"h1","method":"m","params":{}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		frame, err := decodeStdioJSONV2Frame(raw)
		if err == nil {
			if frame.Protocol != 2 || frame.Generation == 0 || strings.TrimSpace(frame.InvocationID) == "" {
				t.Fatalf("invalid success: %+v", frame)
			}
		}
	})
}
