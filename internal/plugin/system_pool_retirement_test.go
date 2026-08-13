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

/*
func TestSystemRunnerPoolUsesReplacementAfterMalformedTransport(t *testing.T) {
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_BAD_READY=1")
	bad, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	p := newSystemPool(256, time.Hour, 1)
	if err := p.publishTransport(1, bad, time.Now()); err != nil {
		t.Fatal(err)
	}
	r := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir()})
	goodEnv := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1")
	p.replenishFn = func(ctx context.Context) (*systemWorkerTransport, error) {
		tr, err := startSystemWorker(ctx, os.Args[0], t.TempDir(), goodEnv)
		if err != nil {
			return nil, err
		}
		if err := tr.awaitReady(1); err != nil {
			_ = tr.abort()
			return nil, err
		}
		return tr, nil
	}
	r.st["p"] = &systemPluginState{pool: p, isV2: true}
	good := makeBundle(t, "p", "#!/bin/sh\nread _\nprintf '%s\\n' '{\"ok\":true,\"result\":{\"pid\":1}}'\n", "")
	if _, err := r.Start(t.Context(), RunnerStartRequest{PluginID: "p", Loaded: good}); err != nil {
		t.Fatal(err)
	}
	resp, err := r.Invoke(t.Context(), InvokeRequest{PluginID: "p", Action: "x"})
	if err != nil || !resp.OK {
		t.Fatalf("replacement invoke resp=%+v err=%v", resp, err)
	}
}
*/
