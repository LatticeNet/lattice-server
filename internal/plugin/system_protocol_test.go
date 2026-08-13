package plugin

import "testing"

func TestValidateStdioJSONV2FrameCorrelation(t *testing.T) {
	base := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: 7, InvocationID: "i-1", HostCallID: "h-1"}
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
