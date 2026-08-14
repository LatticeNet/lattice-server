package plugin

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	if err != nil || rsp.Retirement == nil || (!errors.Is(rsp.Retirement, io.ErrUnexpectedEOF) && !errors.Is(rsp.Retirement, context.DeadlineExceeded)) || !rsp.Reply.OK {
		t.Fatalf("reply=%+v err=%v", rsp, err)
	}
	_ = tr.abort()
	if err := syscall.Kill(-tr.pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("pgid still alive: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel2()
	if _, err := tr.invokeV2(ctx2, 1, "nr2", InvokeRequest{Action: "x"}, nil); err == nil {
		t.Fatal("retired worker reused")
	}
}

func TestRealV2CanceledBeforeDispatchDoesNotWriteOrRetireWorker(t *testing.T) {
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1")
	tr, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	defer tr.abort()
	pid := tr.pgid
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	outcome, err := tr.invokeV2(ctx, 1, "canceled", InvokeRequest{Action: "x"}, nil)
	if !errors.Is(err, context.Canceled) || outcome.DispatchStarted {
		t.Fatalf("outcome=%+v error=%v", outcome, err)
	}
	outcome, err = tr.invokeV2(t.Context(), 1, "next", InvokeRequest{Action: "x"}, nil)
	if err != nil || !outcome.Reusable || !outcome.Reply.OK || tr.pgid != pid {
		t.Fatalf("worker was not reusable after pre-dispatch cancel: outcome=%+v err=%v pid=%d want=%d", outcome, err, tr.pgid, pid)
	}
}

func TestRealV2StalledHostCallCancellationReaps(t *testing.T) {
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_HOST=1", "LATTICE_TEST_V2_STALL=1")
	tr, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = tr.invokeV2(ctx, 1, "stall", InvokeRequest{Action: "x"}, func(systemHostCall) systemHostResponse { return systemHostResponse{ID: "h1", OK: true} })
	if err == nil {
		t.Fatal("expected cancellation or transport termination")
	}
	_ = tr.abort()
	if err := syscall.Kill(-tr.pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("pgid still alive: %v", err)
	}
}

func TestTransportWaitOrders(t *testing.T) {
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1")
	a, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	_ = a.abort()
	_ = a.wait()
	env = append(env, "LATTICE_TEST_V2_EXIT_AFTER_READY=1")
	b, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	_ = b.wait()
	_ = b.abort()
}

func TestV2AbortKillsIgnoreTermDescendantProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "descendant.pid")
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_DESCENDANT_PID="+pidFile)
	tr, err := startSystemWorker(t.Context(), os.Args[0], dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	descendant := waitForPIDFile(t, pidFile)
	pgid := tr.pgid
	if err := tr.abort(); err == nil {
		// SIGTERM/SIGKILL commonly makes the leader's Wait report a signal. The
		// important contract is extinction of the complete process group.
	}
	assertPIDGone(t, descendant)
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("v2 process group %d survived abort: %v", pgid, err)
	}
}

func TestRealV2MalformedReadyPreservesReply(t *testing.T) {
	env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1", "LATTICE_TEST_V2_BAD_READY=1")
	tr, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.awaitReady(1); err != nil {
		t.Fatal(err)
	}
	rsp, err := tr.invokeV2(t.Context(), 1, "bad", InvokeRequest{Action: "x"}, nil)
	if err != nil || rsp.Retirement == nil || !rsp.Reply.OK {
		t.Fatalf("reply=%+v err=%v", rsp, err)
	}
	_ = tr.abort()
	if err := syscall.Kill(-tr.pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("pgid alive: %v", err)
	}
}

func runV2Helper() {
	generation := uint64(1)
	if raw := os.Getenv("LATTICE_RUNTIME_GENERATION"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || parsed == 0 || os.Getenv("LATTICE_RUNTIME_PROTOCOL") != RuntimeProtocolStdioJSONV2 || os.Getenv("LATTICE_HOST_RESPONSE_FD") != "3" {
			os.Exit(6)
		}
		generation = parsed
	}
	if pidFile := os.Getenv("LATTICE_TEST_V2_DESCENDANT_PID"); pidFile != "" {
		child := exec.Command("/bin/sh", "-c", `trap '' TERM; while :; do sleep 1; done`)
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(7)
		}
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			os.Exit(8)
		}
	}
	if _, err := fmt.Fprintf(os.Stdout, `{"protocol":2,"kind":"runtime_ready","generation":%d,"invocation_id":"runtime","features":["stderr_frames_v1"]}
`, generation); err != nil {
		os.Exit(2)
	}
	if os.Getenv("LATTICE_TEST_V2_EXIT_AFTER_READY") == "1" {
		os.Exit(0)
	}
	s := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for s.Scan() {
		var f stdioJSONV2Frame
		if json.Unmarshal(s.Bytes(), &f) != nil {
			os.Exit(3)
		}
		if mode := os.Getenv("LATTICE_TEST_V2_HOSTILE_FRAME"); mode != "" {
			var raw string
			switch mode {
			case "missing":
				raw = fmt.Sprintf(`{"kind":"invoke_result","generation":%d,"invocation_id":%q,"response":{"ok":true}}`, f.Generation, f.InvocationID)
			case "duplicate":
				raw = fmt.Sprintf(`{"protocol":2,"protocol":2,"kind":"invoke_result","generation":%d,"invocation_id":%q,"response":{"ok":true}}`, f.Generation, f.InvocationID)
			case "unknown":
				raw = fmt.Sprintf(`{"protocol":2,"kind":"invoke_result","generation":%d,"invocation_id":%q,"response":{"ok":true},"x":1}`, f.Generation, f.InvocationID)
			case "null":
				raw = fmt.Sprintf(`{"protocol":2,"kind":"invoke_result","generation":%d,"invocation_id":%q,"response":null}`, f.Generation, f.InvocationID)
			case "trailing":
				raw = fmt.Sprintf(`{"protocol":2,"kind":"invoke_result","generation":%d,"invocation_id":%q,"response":{"ok":true}} trailing`, f.Generation, f.InvocationID)
			case "correlation":
				raw = fmt.Sprintf(`{"protocol":2,"kind":"invoke_result","generation":%d,"invocation_id":"wrong","response":{"ok":true}}`, f.Generation)
			case "nested_params_duplicate":
				raw = fmt.Sprintf(`{"protocol":2,"kind":"host_call","generation":%d,"invocation_id":%q,"host_call_id":"h1","host_call":{"id":"h1","method":"log.write","params":{"x":1,"x":2}}}`, f.Generation, f.InvocationID)
			case "nested_result_duplicate":
				raw = fmt.Sprintf(`{"protocol":2,"kind":"invoke_result","generation":%d,"invocation_id":%q,"response":{"ok":true,"result":{"x":1,"x":2}}}`, f.Generation, f.InvocationID)
			case "nested_warnings_duplicate":
				raw = fmt.Sprintf(`{"protocol":2,"kind":"invoke_result","generation":%d,"invocation_id":%q,"response":{"ok":true,"warnings":[{"x":1,"x":2}]}}`, f.Generation, f.InvocationID)
			}
			fmt.Fprintln(os.Stdout, raw)
			os.Exit(0)
		}
		if os.Getenv("LATTICE_TEST_V2_HOST") == "1" {
			calls := 1
			if raw := os.Getenv("LATTICE_TEST_V2_HOST_CALLS"); raw != "" {
				calls, _ = strconv.Atoi(raw)
			}
			br := bufio.NewReader(os.NewFile(uintptr(3), "host-response"))
			for i := 1; i <= calls; i++ {
				id := fmt.Sprintf("h%d", i)
				if os.Getenv("LATTICE_TEST_V2_DUPLICATE_HOST_CALL_ID") == "1" {
					id = "h1"
				}
				payload := json.RawMessage(fmt.Sprintf(`{"id":%q,"method":"log.write","params":{"level":"info","message":"observed"}}`, id))
				b, _ := json.Marshal(stdioJSONV2Frame{Protocol: 2, Kind: "host_call", Generation: f.Generation, InvocationID: f.InvocationID, HostCallID: id, HostCall: payload})
				fmt.Fprintln(os.Stdout, string(b))
				_, _ = br.ReadBytes('\n')
			}
			if os.Getenv("LATTICE_TEST_V2_STALL") == "1" {
				time.Sleep(30 * time.Second)
			}
		}
		if os.Getenv("LATTICE_TEST_V2_NO_READY") == "1" {
			resp := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: f.Generation, InvocationID: f.InvocationID}
			resp.Response = json.RawMessage(fmt.Sprintf(`{"ok":true,"result":{"once":true,"pid":%d}}`, os.Getpid()))
			_ = enc.Encode(resp)
			_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "stderr_complete", Generation: f.Generation, InvocationID: f.InvocationID})
			os.Exit(0)
			continue
		}
		resp := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_result", Generation: f.Generation, InvocationID: f.InvocationID}
		switch {
		case os.Getenv("LATTICE_TEST_V2_ERROR_RESPONSE") == "1":
			resp.Response = json.RawMessage(`{"ok":false,"error":"helper denied","warnings":["plugin warning"]}`)
		case os.Getenv("LATTICE_TEST_V2_MESSAGE_RESPONSE") == "1":
			resp.Response = json.RawMessage(`{"ok":true,"message":"done"}`)
		case os.Getenv("LATTICE_TEST_V2_PLAN_RESPONSE") == "1":
			resp.Response = json.RawMessage(`{"ok":true,"plan":"plan text"}`)
		case os.Getenv("LATTICE_TEST_V2_WARN_RESPONSE") == "1":
			resp.Response = json.RawMessage(fmt.Sprintf(`{"ok":true,"result":{"helper":true,"pid":%d},"warnings":["plugin warning"]}`, os.Getpid()))
		default:
			if raw := os.Getenv("LATTICE_TEST_V2_RESULT_BYTES"); raw != "" {
				n, _ := strconv.Atoi(raw)
				resp.Response = json.RawMessage(fmt.Sprintf(`{"ok":true,"result":{"data":%q}}`, strings.Repeat("x", n)))
			} else {
				resp.Response = json.RawMessage(fmt.Sprintf(`{"ok":true,"result":{"helper":true,"pid":%d}}`, os.Getpid()))
			}
		}
		complete := stdioJSONV2Frame{Protocol: 2, Kind: "stderr_complete", Generation: f.Generation, InvocationID: f.InvocationID}
		ready := stdioJSONV2Frame{Protocol: 2, Kind: "invoke_ready", Generation: f.Generation, InvocationID: f.InvocationID}
		switch os.Getenv("LATTICE_TEST_V2_STDERR_ORDER") {
		case "complete_before_result":
			_ = enc.Encode(complete)
			_ = enc.Encode(resp)
			_ = enc.Encode(ready)
			continue
		case "late_chunk":
			_ = enc.Encode(resp)
			_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "stderr_chunk", Generation: f.Generation, InvocationID: f.InvocationID, Data: "eA=="})
			_ = enc.Encode(complete)
			_ = enc.Encode(ready)
			continue
		case "duplicate_complete":
			_ = enc.Encode(resp)
			_ = enc.Encode(complete)
			_ = enc.Encode(complete)
			continue
		case "mismatch_complete":
			_ = enc.Encode(resp)
			complete.InvocationID = "wrong"
			_ = enc.Encode(complete)
			_ = enc.Encode(ready)
			continue
		}
		if raw := os.Getenv("LATTICE_TEST_V2_STDERR"); raw != "" {
			_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "stderr_chunk", Generation: f.Generation, InvocationID: f.InvocationID, Data: base64.StdEncoding.EncodeToString([]byte(raw))})
		}
		if os.Getenv("LATTICE_TEST_V2_STDERR_OVERSIZE") == "1" {
			_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "stderr_chunk", Generation: f.Generation, InvocationID: f.InvocationID, Data: strings.Repeat("A", base64.StdEncoding.EncodedLen(HostMaxInvokeStderrBytes)+4)})
		}
		if os.Getenv("LATTICE_TEST_V2_STDERR_TINY_FLOOD") == "1" {
			for range maxV2DiagnosticChunks + 1 {
				_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "stderr_chunk", Generation: f.Generation, InvocationID: f.InvocationID, Data: "eA=="})
			}
		}
		if mode := os.Getenv("LATTICE_TEST_V2_STDERR_MULTI"); mode != "" {
			first := strings.Repeat("a", HostMaxInvokeStderrBytes/2)
			secondLen := HostMaxInvokeStderrBytes - len(first)
			if mode == "over" {
				secondLen++
			}
			for _, chunk := range []string{first, strings.Repeat("b", secondLen)} {
				_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "stderr_chunk", Generation: f.Generation, InvocationID: f.InvocationID, Data: base64.StdEncoding.EncodeToString([]byte(chunk))})
			}
		}
		if mode := os.Getenv("LATTICE_TEST_V2_STDERR_SINGLE"); mode != "" {
			size := HostMaxInvokeStderrBytes
			if mode == "over" {
				size++
			}
			_ = enc.Encode(stdioJSONV2Frame{Protocol: 2, Kind: "stderr_chunk", Generation: f.Generation, InvocationID: f.InvocationID, Data: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", size)))})
		}
		if raw := os.Getenv("LATTICE_TEST_V2_RAW_STDERR"); raw != "" {
			_, _ = io.WriteString(os.Stderr, raw)
		}
		if enc.Encode(resp) != nil {
			os.Exit(4)
		}
		if enc.Encode(complete) != nil {
			os.Exit(4)
		}
		if os.Getenv("LATTICE_TEST_V2_NO_READY_AFTER_RESULT") == "1" {
			os.Exit(0)
		}
		if os.Getenv("LATTICE_TEST_V2_BAD_READY") == "1" {
			fmt.Fprintf(os.Stdout, `{"protocol":2,"kind":"invoke_ready","generation":999,"invocation_id":%q}`+"\n", f.InvocationID)
			continue
		}
		if os.Getenv("LATTICE_TEST_V2_WRONG_INVOCATION_READY") == "1" {
			fmt.Fprintf(os.Stdout, `{"protocol":2,"kind":"invoke_ready","generation":%d,"invocation_id":"wrong"}`+"\n", f.Generation)
			continue
		}
		if os.Getenv("LATTICE_TEST_V2_MALFORMED_READY") == "1" {
			fmt.Fprintln(os.Stdout, `{malformed`)
			os.Exit(0)
		}
		if enc.Encode(ready) != nil {
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
		if err != nil || !r.Reply.OK || !r.Reusable {
			t.Fatalf("invoke %d: %+v %v", i, r, err)
		}
		var body struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal(r.Reply.Result, &body); err != nil || body.PID <= 0 {
			t.Fatalf("missing helper pid: %s", r.Reply.Result)
		}
		if i == 0 {
			pid = body.PID
		} else if body.PID != pid {
			t.Fatalf("pid changed: %d -> %d", pid, body.PID)
		}
	}
}
