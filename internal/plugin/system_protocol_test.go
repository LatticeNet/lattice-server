package plugin

import "testing"

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
			err := validateStdioJSONV2Frame(frame, 7, "i-1", "h-1")
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
	valid := []byte(`{"protocol":2,"kind":"runtime_ready","generation":1,"invocation_id":"runtime"}`)
	if err := requireV2Fields(valid, "protocol", "kind", "generation", "invocation_id"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{[]byte(`{"protocol":2,"kind":null,"generation":1,"invocation_id":"runtime"}`), []byte(`{"protocol":2,"kind":"runtime_ready","generation":1}`)} {
		if err := requireV2Fields(raw, "protocol", "kind", "generation", "invocation_id"); err == nil {
			t.Fatal("accepted missing/null required field")
		}
	}
}
