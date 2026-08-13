package plugin

import (
	"context"
	"encoding/json"
	"testing"
)

// These cases exercise malformed helper startup through the real SystemRunner
// boundary; each failed startup must be retired so a subsequent good helper can
// serve the invocation without manual process intervention.
func TestSystemRunnerPoolRetiresMalformedReadyHelpers(t *testing.T) {
	cases := []struct {
		name, bad string
	}{
		{"NO_READY_EOF", "#!/bin/sh\nexit 0\n"},
		{"MALFORMED_READY", "#!/bin/sh\nprintf '%s\\n' '{bad json}'\n"},
		{"WRONG_READY", "#!/bin/sh\nprintf '%s\\n' '{\"protocol\":99,\"kind\":\"runtime_ready\"}'\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRunner(t, SystemRunnerOptions{})
			bad := makeBundle(t, "p.bad", tc.bad, "")
			if _, err := r.Start(context.Background(), RunnerStartRequest{PluginID: "p", Loaded: bad}); err == nil {
				t.Fatal("malformed helper unexpectedly started")
			}
			good := makeBundle(t, "p.good", "#!/bin/sh\nread _\nprintf '%s\\n' '{\"ok\":true,\"result\":{\"pid\":1}}'\n", "")
			resp, err := startInvoke(t, r, good, "plan", json.RawMessage(`{}`))
			if err != nil || !resp.OK || len(resp.Result) == 0 {
				t.Fatalf("good helper failed: resp=%+v err=%v", resp, err)
			}
		})
	}
}
