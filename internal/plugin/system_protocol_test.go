package plugin

import (
	"strings"
	"testing"
)

func TestValidateStdioJSONV2FrameCorrelation(t *testing.T) {
	base := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: 7, InvocationID: "i-1", Response: []byte(`{"ok":true}`)}
	for name, frame := range map[string]stdioJSONV2Frame{
		"valid":            base,
		"wrong protocol":   func() stdioJSONV2Frame { f := base; f.Protocol = 1; return f }(),
		"stale generation": func() stdioJSONV2Frame { f := base; f.Generation = 6; return f }(),
		"wrong invocation": func() stdioJSONV2Frame { f := base; f.InvocationID = "i-2"; return f }(),
		"wrong host call":  func() stdioJSONV2Frame { f := base; f.HostCallID = "h-2"; return f }(),
		"missing kind":     func() stdioJSONV2Frame { f := base; f.Kind = ""; return f }(),
	} {
		t.Run(name, func(t *testing.T) {
			err := validateStdioJSONV2Frame(frame, 7, "i-1", "")
			if name == "valid" && err != nil {
				t.Fatal(err)
			}
			if name != "valid" && err == nil {
				t.Fatal("expected strict correlation failure")
			}
		})
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
	valid := `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"i-1","host_call_id":"h-1","host_call":{"id":"h-1","method":"log.write","params":{}}}`
	cases := map[string]string{
		"missing protocol":        `{"kind":"host_call","generation":7,"invocation_id":"i-1","host_call_id":"h-1","host_call":{"id":"h-1","method":"log.write","params":{}}}`,
		"null generation":         `{"protocol":2,"kind":"host_call","generation":null,"invocation_id":"i-1","host_call_id":"h-1","host_call":{"id":"h-1","method":"log.write","params":{}}}`,
		"unknown kind":            `{"protocol":2,"kind":"other","generation":7,"invocation_id":"i-1"}`,
		"forbidden null response": `{"protocol":2,"kind":"invoke_ready","generation":7,"invocation_id":"i-1","response":null}`,
		"missing host payload":    `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"i-1","host_call_id":"h-1"}`,
		"null host payload":       `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"i-1","host_call_id":"h-1","host_call":null}`,
		"duplicate root":          `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"i-1","host_call_id":"h-1","host_call_id":"h-2","host_call":{"id":"h-1","method":"log.write","params":{}}}`,
		"unknown root":            `{"protocol":2,"kind":"host_call","generation":7,"invocation_id":"i-1","host_call_id":"h-1","host_call":{"id":"h-1","method":"log.write","params":{}},"x":1}`,
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
	valid := `{"id":"h-1","method":"log.write","params":{}}`
	if _, err := decodeStrictSystemHostCall([]byte(valid), "h-1"); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"missing params":   `{"id":"h-1","method":"log.write"}`,
		"null params":      `{"id":"h-1","method":"log.write","params":null}`,
		"wrong id":         `{"id":"h-2","method":"log.write","params":{}}`,
		"duplicate nested": `{"id":"h-1","id":"h-1","method":"log.write","params":{}}`,
		"unknown nested":   `{"id":"h-1","method":"log.write","params":{},"x":1}`,
		"trailing nested":  valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStrictSystemHostCall([]byte(raw), "h-1"); err == nil {
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
	f.Add([]byte(`{"protocol":2,"kind":"invoke_ready","generation":1,"invocation_id":"i"}`))
	f.Add([]byte(`{"protocol":2,"kind":"host_call","generation":1,"invocation_id":"i","host_call_id":"h","host_call":{"id":"h","method":"m","params":{}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		frame, err := decodeStdioJSONV2Frame(raw)
		if err == nil {
			if frame.Protocol != 2 || frame.Generation == 0 || strings.TrimSpace(frame.InvocationID) == "" {
				t.Fatalf("invalid success: %+v", frame)
			}
		}
	})
}
