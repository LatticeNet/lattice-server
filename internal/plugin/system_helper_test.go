package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("LATTICE_TEST_V2_HELPER") == "1" {
		runV2Helper()
		return
	}
	os.Exit(m.Run())
}

func TestRealV2ResultWithoutReadyPreservesReplyAndReaps(t *testing.T) {
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_NO_READY=1")
	tr, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	rsp, err := tr.invokeV2(ctx, 1, "nr", InvokeRequest{Action: "x"}, nil)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !rsp.OK {
		t.Fatalf("reply=%+v err=%v", rsp, err)
	}
	_ = tr.abort()
	if err := syscall.Kill(-tr.pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("pgid still alive: %v", err)
	}
}

func runV2Helper() {
	generation := uint64(1)
	if _, err := fmt.Fprintf(os.Stdout, `{"protocol":2,"kind":"runtime_ready","generation":%d,"invocation_id":"runtime"}
`, generation); err != nil {
		os.Exit(2)
	}
	s := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for s.Scan() {
		var f stdioJSONV2Frame
		if json.Unmarshal(s.Bytes(), &f) != nil {
			os.Exit(3)
		}
		if os.Getenv("LATTICE_TEST_V2_HOST") == "1" {
			b, _ := json.Marshal(stdioJSONV2Frame{Protocol: 2, Kind: "host_call", Generation: f.Generation, InvocationID: f.InvocationID, HostCallID: "h1", HostCall: json.RawMessage(`{"id":"h1","method":"ping"}`)})
			fmt.Fprintln(os.Stdout, string(b))
			br := bufio.NewReader(os.NewFile(uintptr(3), "host-response"))
			_, _ = br.ReadBytes('\n')
			if os.Getenv("LATTICE_TEST_V2_STALL") == "1" {
				select {}
			}
		}
		if os.Getenv("LATTICE_TEST_V2_NO_READY") == "1" {
			resp := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: f.Generation, InvocationID: f.InvocationID, Response: json.RawMessage(`{"ok":true,"result":{"once":true}}`)}
			_ = enc.Encode(resp)
			continue
		}
		resp := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: f.Generation, InvocationID: f.InvocationID}
		resp.Response = json.RawMessage(fmt.Sprintf(`{"ok":true,"result":{"helper":true,"pid":%d}}`, os.Getpid()))
		if enc.Encode(resp) != nil {
			os.Exit(4)
		}
		if enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "invoke_ready", Generation: f.Generation, InvocationID: f.InvocationID}) != nil {
			os.Exit(5)
		}
	}
	os.Exit(0)
}

func TestRealV2HelperTwoInvocations(t *testing.T) {
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_HOST=1")
	tr, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.abort()
	if err := tr.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	var pid int
	for i := 0; i < 2; i++ {
		r, err := tr.invokeV2(t.Context(), 1, fmt.Sprintf("i%d", i), InvokeRequest{Action: "x"}, func(systemHostCall) systemHostResponse { return systemHostResponse{ID: "h1", OK: true} })
		if err != nil || !r.OK {
			t.Fatalf("invoke %d: %+v %v", i, r, err)
		}
		var body struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal(r.Result, &body); err != nil || body.PID <= 0 {
			t.Fatalf("missing helper pid: %s", r.Result)
		}
		if i == 0 {
			pid = body.PID
		} else if body.PID != pid {
			t.Fatalf("pid changed: %d -> %d", pid, body.PID)
		}
	}
}
