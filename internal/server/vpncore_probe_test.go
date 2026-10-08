package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// probeTestPassword is the credential the test chain's relay carries, and
// probeTestUUID the exit's. Finding either in an audit record or a log line
// means the outbound itself leaked.
const (
	probeTestPassword = "probe-secret-pw-7f3a9c"
	probeTestUUID     = "6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e"
)

const probeTestHealth = `{"probe_version":"0.1.0","engine":"sing-box","core_version":"1.13.19","uptime_s":3600,"inflight":1,"max_inflight":32,"targets":3}`

const probeTestAnswer = `{"valid":true,"stage":"ok","error":"","server":{"address":"203.0.113.7:443","reachable":true,"rtt_ms":41.2,"network":"tcp"},` +
	`"targets":[{"id":"gstatic-204","ok":5,"of":5,"cold_ms":{"min":212.1,"p50":230.4,"p90":268},"warm_ms":{"min":74,"p50":78.2,"p90":90},"status":204,"error":""}],` +
	`"exit":{"ip":"198.51.100.20","loc":"US","colo":"LAX"},"udp":null,"throughput":null,"engine":{"name":"sing-box","version":"1.13.19"},"took_ms":1840.5}`

// probeTestRequest is a two-outbound chain whose tested exit detours through
// a relay that carries probeTestPassword. The odd spacing and key order are
// deliberate: the server must forward these exact bytes.
func probeTestRequest(extra string) string {
	return `{ "test":"exit",  "outbounds":[` +
		`{"tag":"exit","type":"vless","server":"203.0.113.7","server_port":443,"uuid":"` + probeTestUUID + `","detour":"relay"},` +
		`{"type":"shadowsocks","tag":"relay","server":"198.51.100.4","server_port":8388,"method":"2022-blake3-aes-128-gcm","password":"` + probeTestPassword + `"}],` +
		`"targets":["gstatic-204","cloudflare-204"],"samples":5,"udp":true` + extra + `}`
}

// fakeProbe is lattice-probe's socket API with programmable answers.
type fakeProbe struct {
	socket   string
	mu       sync.Mutex
	handler  http.HandlerFunc
	runs     atomic.Int64
	lastBody []byte
}

func startFakeProbe(t *testing.T) *fakeProbe {
	t.Helper()
	// A unix socket path is limited to about 104 bytes on macOS, which a
	// t.TempDir path under a long test name can exceed.
	dir, err := os.MkdirTemp("", "lprobe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeProbe{socket: filepath.Join(dir, "probe.sock")}
	ln, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	f.answer(http.StatusOK, probeTestAnswer)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		if r.URL.Path == "/v1/probe" {
			f.lastBody = body
		}
		h := f.handler
		f.mu.Unlock()
		if r.URL.Path == "/v1/probe" {
			f.runs.Add(1)
		}
		h(w, r)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f
}

// answer makes /v1/probe answer status with body, while /v1/health and
// /v1/targets keep answering the canned health and target list.
func (f *fakeProbe) answer(status int, body string) {
	f.serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			_, _ = io.WriteString(w, probeTestHealth)
			return
		case "/v1/targets":
			_, _ = io.WriteString(w, `{"targets":[{"id":"gstatic-204","url":"https://www.gstatic.com/generate_204","expect":204}]}`)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func (f *fakeProbe) serve(h http.HandlerFunc) {
	f.mu.Lock()
	f.handler = h
	f.mu.Unlock()
}

func (f *fakeProbe) body() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.lastBody...)
}

// newProbeTestServer is a server whose probe client points at socket, with
// its log captured.
func newProbeTestServer(t *testing.T, socket string) (*Server, *store.Store, *probeLogBuffer) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	logs := &probeLogBuffer{}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true, ProbeSocket: socket, Logger: log.New(logs, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st, logs
}

type probeLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *probeLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *probeLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func probeOperator(actor string, scopes ...string) principal {
	return principal{Principal: rbac.Principal{ActorID: actor, Scopes: scopes}, CorrelationID: "req-" + actor}
}

// probeCtx is an operator's own call to the probe service, as the gateway's
// direct path (callCoreServiceForOperator) marks it.
func probeCtx(p principal) context.Context {
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, p)
	return context.WithValue(ctx, operatorCoreCallKey{}, vpnCoreProbeService)
}

// probeErrorOf unwraps the API error a probe method returned.
func probeErrorOf(t *testing.T, err error) (int, model.APIError) {
	t.Helper()
	var opErr *pluginOperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("want an API error, got %v", err)
	}
	var body model.APIErrorResponse
	if jerr := json.Unmarshal(opErr.Body, &body); jerr != nil {
		t.Fatalf("API error body %s: %v", opErr.Body, jerr)
	}
	return opErr.StatusCode, body.Error
}

// probeAudits lists the probe records, newest first as the store does.
func probeAudits(st *store.Store) []model.AuditEvent {
	var out []model.AuditEvent
	for _, ev := range st.AuditEvents() {
		if ev.Action == auditActionVPNCoreProbe {
			out = append(out, ev)
		}
	}
	return out
}

func TestProbeHealthReportsAvailabilityAndWhyNot(t *testing.T) {
	fake := startFakeProbe(t)
	srv, _, _ := newProbeTestServer(t, fake.socket)

	out, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "health", nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["available"] != true || got["engine"] != "sing-box" || got["core_version"] != "1.13.19" || got["probe_version"] != "0.1.0" ||
		got["uptime_s"] != float64(3600) || got["inflight"] != float64(1) || got["max_inflight"] != float64(32) || got["targets"] != float64(3) {
		t.Fatalf("health must be the probe's /v1/health plus available: %s", out)
	}
	if _, ok := got["reason"]; ok {
		t.Fatalf("an available probe carries no reason: %s", out)
	}

	refusing := filepath.Join(filepath.Dir(fake.socket), "refusing.sock")
	ln, err := net.Listen("unix", refusing)
	if err != nil {
		t.Fatal(err)
	}
	// Closing a unix listener removes its socket file; keep the file so the
	// dial reaches a path with nothing listening behind it.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()

	for name, tc := range map[string]struct {
		socket  string
		handler http.HandlerFunc
		want    string
	}{
		"socket missing":  {socket: filepath.Join(filepath.Dir(fake.socket), "absent.sock"), want: "absent.sock does not exist"},
		"nobody listens":  {socket: refusing, want: "nothing is listening"},
		"server error":    {handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, want: "HTTP 500"},
		"not a probe":     {handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"hello":"world"}`) }, want: "could not be read"},
		"wedged":          {handler: func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, want: "did not answer within 200ms"},
		"oversize answer": {handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, probeMaxResponseBytes+10)) }, want: "larger than"},
	} {
		t.Run(name, func(t *testing.T) {
			socket := tc.socket
			if socket == "" {
				other := startFakeProbe(t)
				other.serve(tc.handler)
				socket = other.socket
			}
			client := newProbeClient(socket)
			client.healthTimeout = 200 * time.Millisecond
			view := client.health(context.Background(), true)
			if view.Available || !strings.Contains(view.Reason, tc.want) || view.probeHealth != nil {
				t.Fatalf("want unavailable with %q, got %+v", tc.want, view)
			}
			wire, _ := json.Marshal(view)
			if string(wire) != fmt.Sprintf(`{"available":false,"reason":%q}`, view.Reason) {
				t.Fatalf("an unavailable probe answers only available and reason: %s", wire)
			}
		})
	}
}

// probeSystemView decodes the probe block of /api/system/health.
type probeSystemView struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	probeHealth
}

func TestSystemHealthShowsProbeHealth(t *testing.T) {
	f := newSelfMonFixture(t)
	fake := startFakeProbe(t)
	cookies, csrf := loginSession(t, f.handler)
	read := func() probeSystemView {
		t.Helper()
		res := doJSON(t, f.handler, http.MethodGet, "/api/system/health?range=1h", "", cookies, csrf)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("system health = %d", res.StatusCode)
		}
		var view struct {
			Probe probeSystemView `json:"probe"`
		}
		if err := json.NewDecoder(res.Body).Decode(&view); err != nil {
			t.Fatal(err)
		}
		return view.Probe
	}
	f.srv.probe = newProbeClient(fake.socket)
	if got := read(); !got.Available || got.Engine != "sing-box" || got.CoreVersion != "1.13.19" ||
		got.UptimeS != 3600 || got.Inflight != 1 || got.MaxInflight != 32 {
		t.Fatalf("System must show an available probe: %+v", got)
	}
	f.srv.probe = newProbeClient(fake.socket + ".gone")
	if got := read(); got.Available || got.Reason != "the probe socket does not exist; is the lattice-probe container running?" {
		t.Fatalf("System must say why the probe is unavailable: %+v", got)
	}
	// More principals read System than hold vpn:probe, so its reason leaves
	// the socket's path out; the vpn-core/probe health method keeps it.
	refusing := filepath.Join(filepath.Dir(fake.socket), "refusing.sock")
	ln, err := net.Listen("unix", refusing)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	f.srv.probe = newProbeClient(refusing)
	if got := read(); got.Available || got.Reason != "nothing is listening on the probe socket" {
		t.Fatalf("System must name no socket path: %+v", got)
	}
	if view := f.srv.probe.health(context.Background(), true); !strings.Contains(view.Reason, refusing) {
		t.Fatalf("the health method names the path for vpn:probe holders: %+v", view)
	}
}

func TestProbeTargetsPassThrough(t *testing.T) {
	fake := startFakeProbe(t)
	srv, _, _ := newProbeTestServer(t, fake.socket)
	out, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "targets", nil)
	if err != nil || string(out) != `{"targets":[{"id":"gstatic-204","url":"https://www.gstatic.com/generate_204","expect":204}]}` {
		t.Fatalf("targets: %s %v", out, err)
	}
	down, _, _ := newProbeTestServer(t, fake.socket+".gone")
	_, err = down.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "targets", nil)
	if status, apiErr := probeErrorOf(t, err); status != http.StatusServiceUnavailable || apiErr.Code != apiErrorProbeUnavailable {
		t.Fatalf("targets with no probe = %d %+v", status, apiErr)
	}
}

// The request reaches the probe byte for byte and the answer comes back byte
// for byte; the audit record carries the hash and never the outbound.
func TestProbeRunForwardsUnchangedAndAuditsOnlyTheHash(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, logs := newProbeTestServer(t, fake.socket)
	request := probeTestRequest("")
	out, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(request))
	if err != nil {
		t.Fatal(err)
	}
	if string(fake.body()) != request {
		t.Fatalf("the probe must receive the request unchanged:\n got %s\nwant %s", fake.body(), request)
	}
	if string(out) != probeTestAnswer {
		t.Fatalf("the probe's answer must come back unchanged: %s", out)
	}

	audits := probeAudits(st)
	if len(audits) != 1 {
		t.Fatalf("want one %s record, got %d", auditActionVPNCoreProbe, len(audits))
	}
	ev := audits[0]
	// The canonical form: keys sorted, no whitespace, numbers as written. The
	// hash must not depend on the key order or spacing the operator pasted.
	canonical := `[{"detour":"relay","server":"203.0.113.7","server_port":443,"tag":"exit","type":"vless","uuid":"` + probeTestUUID + `"},` +
		`{"method":"2022-blake3-aes-128-gcm","password":"` + probeTestPassword + `","server":"198.51.100.4","server_port":8388,"tag":"relay","type":"shadowsocks"}]`
	sum := sha256.Sum256([]byte(canonical))
	want := map[string]string{
		"types": "vless,shadowsocks", "server": "203.0.113.7:443", "config_sha256": hex.EncodeToString(sum[:]),
		"targets": "gstatic-204,cloudflare-204", "stage": "ok", "valid": "true", "took_ms": "1840",
	}
	for k, v := range want {
		if ev.Metadata[k] != v {
			t.Fatalf("audit metadata %s = %q, want %q (all: %v)", k, ev.Metadata[k], v, ev.Metadata)
		}
	}
	if len(ev.Metadata) != len(want) || ev.Decision != "allow" || ev.Scope != probeScope || ev.ActorID != "op" || ev.CorrelationID != "req-op" {
		t.Fatalf("audit record = %+v", ev)
	}

	// The same outbounds pasted with another key order and spacing hash the same.
	again := `{"outbounds":[ {"uuid":"` + probeTestUUID + `","detour":"relay","server_port":443,"server":"203.0.113.7","type":"vless","tag":"exit"},` +
		`{"password":"` + probeTestPassword + `", "method":"2022-blake3-aes-128-gcm","server_port":8388,"server":"198.51.100.4","tag":"relay","type":"shadowsocks"}],"test":"exit"}`
	if _, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(again)); err != nil {
		t.Fatal(err)
	}
	if got := probeAudits(st)[0].Metadata["config_sha256"]; got != want["config_sha256"] {
		t.Fatalf("a reordered paste must hash the same: %s vs %s", got, want["config_sha256"])
	}

	// A run whose transport fails is logged, and the log line carries nothing
	// from the request either.
	fake.serve(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})
	if _, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(request)); err == nil {
		t.Fatal("a probe that drops the connection must fail the run")
	}
	if !strings.Contains(logs.String(), "vpn-core/probe: run failed") {
		t.Fatalf("the transport failure must be logged: %q", logs.String())
	}

	every, _ := json.Marshal(st.AuditEvents())
	for _, secret := range []string{probeTestPassword, probeTestUUID, "2022-blake3"} {
		if bytes.Contains(every, []byte(secret)) || strings.Contains(logs.String(), secret) {
			t.Fatalf("the outbound leaked into the audit record or the log (%s)", secret)
		}
	}
}

func TestProbeRunMapsProbeRefusals(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	run := func() (int, model.APIError) {
		t.Helper()
		_, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(probeTestRequest("")))
		return probeErrorOf(t, err)
	}

	fake.answer(http.StatusBadRequest, `{"error":{"stage":"policy","message":"server 10.0.0.5 is a private address\nsecond line"}}`)
	status, apiErr := run()
	if status != http.StatusBadRequest || apiErr.Code != model.APIErrorBadRequest || apiErr.Message != "probe policy: server 10.0.0.5 is a private address" {
		t.Fatalf("a policy refusal reaches the operator as a 400 with the probe's first line: %d %+v", status, apiErr)
	}
	if last := probeAudits(st)[0]; last.Decision != "deny" || last.Metadata["stage"] != "policy" || strings.Contains(last.Reason, "10.0.0.5") {
		t.Fatalf("a refusal is audited by stage, without the probe's message: %+v", last)
	}
	fake.answer(http.StatusBadRequest, `{"error":{"stage":"request","message":"samples must be 1 to 10"}}`)
	if status, apiErr := run(); status != http.StatusBadRequest || apiErr.Message != "probe request: samples must be 1 to 10" {
		t.Fatalf("a request refusal = %d %+v", status, apiErr)
	}

	fake.answer(http.StatusTooManyRequests, `{"error":{"stage":"request","message":"32 probes in flight"}}`)
	if status, apiErr := run(); status != http.StatusTooManyRequests || apiErr.Code != model.APIErrorRateLimited || !strings.Contains(apiErr.Message, "retry in a few seconds") {
		t.Fatalf("a busy probe maps to 429: %d %+v", status, apiErr)
	}
	if last := probeAudits(st)[0]; last.Metadata["stage"] != "busy" {
		t.Fatalf("a busy probe is audited as busy: %+v", last)
	}
	fake.answer(http.StatusInternalServerError, `oops`)
	if status, apiErr := run(); status != http.StatusBadGateway || apiErr.Message != "the probe answered HTTP 500" {
		t.Fatalf("any other status is a bad gateway: %d %+v", status, apiErr)
	}
	fake.answer(http.StatusOK, `not json`)
	if status, _ := run(); status != http.StatusBadGateway {
		t.Fatalf("a malformed answer is a bad gateway: %d", status)
	}

	down, downStore, _ := newProbeTestServer(t, fake.socket+".gone")
	_, err := down.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(probeTestRequest("")))
	if status, apiErr := probeErrorOf(t, err); status != http.StatusServiceUnavailable || apiErr.Code != apiErrorProbeUnavailable || !strings.Contains(apiErr.Message, ".gone does not exist") {
		t.Fatalf("a run with no probe = %d %+v", status, apiErr)
	}
	if audits := probeAudits(downStore); len(audits) != 1 || audits[0].Metadata["stage"] != "unavailable" || audits[0].Decision != "deny" {
		t.Fatalf("a run with no probe is audited as unavailable: %+v", audits)
	}
}

func TestProbeRunBodyCapAndShape(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	op := probeCtx(probeOperator("op", probeScope))

	// Exactly at the cap goes through; one byte over does not.
	base := probeTestRequest(`,"pad":""`)
	atCap := probeTestRequest(`,"pad":"` + strings.Repeat("x", probeMaxRequestBytes-len(base)) + `"`)
	if len(atCap) != probeMaxRequestBytes {
		t.Fatalf("fixture is %d bytes", len(atCap))
	}
	if _, err := srv.vpnCoreProbeRPC(op, "run", []byte(atCap)); err != nil {
		t.Fatalf("a body of exactly 64 KiB is allowed: %v", err)
	}
	over := probeTestRequest(`,"pad":"` + strings.Repeat("x", probeMaxRequestBytes-len(base)+1) + `"`)
	_, err := srv.vpnCoreProbeRPC(op, "run", []byte(over))
	if status, apiErr := probeErrorOf(t, err); status != http.StatusBadRequest || !strings.Contains(apiErr.Message, "65536") {
		t.Fatalf("a body over 64 KiB = %d %+v", status, apiErr)
	}
	for _, bad := range []string{`[]`, `"exit"`, `null`, `not json`} {
		_, err = srv.vpnCoreProbeRPC(op, "run", []byte(bad))
		if status, _ := probeErrorOf(t, err); status != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", bad, status)
		}
	}
	if n := fake.runs.Load(); n != 1 {
		t.Fatalf("refused bodies must never reach the probe; it saw %d runs, want only the one at the cap", n)
	}
	if n := len(probeAudits(st)); n != 1 {
		t.Fatalf("a body refused before the probe leaves no probe record, got %d", n)
	}
	// The probe owns the request's meaning: a body that is an object but wrong
	// in every field still goes to it, unchanged, and its answer comes back.
	if _, err := srv.vpnCoreProbeRPC(op, "run", []byte(`{"outbounds":{"type":"vless"},"timeout_ms":99999}`)); err != nil {
		t.Fatalf("the server forwards what it cannot judge: %v", err)
	}
	if string(fake.body()) != `{"outbounds":{"type":"vless"},"timeout_ms":99999}` {
		t.Fatalf("forwarded %s", fake.body())
	}
}

func TestProbeRunDeadline(t *testing.T) {
	if probeRunGatewayTimeout <= probeCallTimeout || probeCallTimeout <= 30*time.Second {
		t.Fatalf("the socket deadline %s must exceed the probe's longest timeout_ms (30 s) and sit inside the gateway deadline %s",
			probeCallTimeout, probeRunGatewayTimeout)
	}
	fake := startFakeProbe(t)
	fake.serve(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	srv, st, _ := newProbeTestServer(t, fake.socket)
	srv.probe.callTimeout = 300 * time.Millisecond
	started := time.Now()
	_, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(probeTestRequest("")))
	if time.Since(started) > 5*time.Second {
		t.Fatal("the run must stop at its deadline")
	}
	if status, apiErr := probeErrorOf(t, err); status != http.StatusGatewayTimeout || apiErr.Code != apiErrorProbeUnavailable || !strings.Contains(apiErr.Message, "within 300ms") {
		t.Fatalf("a probe that never answers = %d %+v", status, apiErr)
	}
	audits := probeAudits(st)
	if len(audits) != 1 || audits[0].Metadata["stage"] != "timeout" || audits[0].Decision != "deny" {
		t.Fatalf("a timed-out run is audited: %+v", audits)
	}
}

func TestProbeRunLimitsConcurrencyPerPrincipal(t *testing.T) {
	fake := startFakeProbe(t)
	gate := make(chan struct{})
	entered := make(chan struct{}, 16)
	waitEntered := func(n int) {
		t.Helper()
		for range n {
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("runs did not reach the probe")
			}
		}
	}
	fake.serve(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/probe" {
			entered <- struct{}{}
			<-gate
		}
		_, _ = io.WriteString(w, probeTestAnswer)
	})
	srv, _, _ := newProbeTestServer(t, fake.socket)
	run := func(p principal) error {
		_, err := srv.vpnCoreProbeRPC(probeCtx(p), "run", []byte(probeTestRequest("")))
		return err
	}
	alice := probeOperator("alice", probeScope)
	errs := make(chan error, probeMaxRunsInFlight)
	for range probeMaxRunsInFlight {
		go func() { errs <- run(alice) }()
	}
	waitEntered(probeMaxRunsInFlight)
	status, apiErr := probeErrorOf(t, run(alice))
	if status != http.StatusTooManyRequests || apiErr.Code != model.APIErrorRateLimited || !strings.Contains(apiErr.Message, "retry when one finishes") {
		t.Fatalf("a fifth concurrent run = %d %+v", status, apiErr)
	}
	// A token Alice minted spends Alice's budget.
	aliceToken := principal{Principal: rbac.Principal{ActorID: "alice", TokenID: "tok_1", Scopes: []string{probeScope}}}
	if status, _ := probeErrorOf(t, run(aliceToken)); status != http.StatusTooManyRequests {
		t.Fatalf("a token must not buy its owner more concurrent runs: %d", status)
	}
	// Bob is not Alice.
	bob := make(chan error, 1)
	go func() { bob <- run(probeOperator("bob", probeScope)) }()
	waitEntered(1)
	close(gate)
	for range probeMaxRunsInFlight {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-bob; err != nil {
		t.Fatalf("another principal runs while Alice is at her limit: %v", err)
	}
	if err := run(alice); err != nil {
		t.Fatalf("finished runs free their slots: %v", err)
	}
}

func TestProbeLimiterRollingHour(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	var l probeLimiter
	for i := range probeMaxRunsPerHour {
		release, err := l.acquire("actor:alice", now)
		if err != nil {
			t.Fatalf("run %d refused: %v", i+1, err)
		}
		release(true)
		release(true) // releasing twice is harmless
		now = now.Add(10 * time.Second)
	}
	// The first run started 1200 s ago, so it leaves the window in 2400 s.
	_, err := l.acquire("actor:alice", now)
	status, apiErr := probeErrorOf(t, err)
	if status != http.StatusTooManyRequests || apiErr.Code != model.APIErrorRateLimited ||
		!strings.Contains(apiErr.Message, "retry in 40m (at 2026-10-08T13:00:00Z)") {
		t.Fatalf("run %d = %d %+v", probeMaxRunsPerHour+1, status, apiErr)
	}
	release, err := l.acquire("actor:bob", now)
	if err != nil {
		t.Fatal("the window is per principal")
	}
	release(true)
	if _, err := l.acquire("actor:alice", now.Add(2400*time.Second-time.Second)); err == nil {
		t.Fatal("a second before the oldest run leaves the window is still too soon")
	}
	release, err = l.acquire("actor:alice", now.Add(2400*time.Second))
	if err != nil {
		t.Fatalf("a run is allowed once the oldest leaves the window: %v", err)
	}
	release(true)
	// Principals with nothing in flight and nothing in the window are forgotten.
	if _, err := l.acquire("actor:carol", now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(l.entries) != 1 {
		t.Fatalf("idle principals must not accumulate: %d entries", len(l.entries))
	}
	if got := probeRetryWait(4500 * time.Millisecond); got != "5s" {
		t.Fatalf("retry wait rounds up to seconds: %s", got)
	}
}

func TestProbeLimiterHandsBackUnspentRuns(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	var l probeLimiter
	for i := range probeMaxRunsPerHour + 5 {
		release, err := l.acquire("actor:alice", now)
		if err != nil {
			t.Fatalf("run %d refused although no earlier run was spent: %v", i+1, err)
		}
		release(false)
		release(true) // the first release decides; a second changes nothing
	}
	if e := l.entries["actor:alice"]; e.inflight != 0 || len(e.starts) != 0 {
		t.Fatalf("unspent runs must leave nothing behind: %+v", e)
	}
}

// The hourly budget is spent only by runs that may have used the network.
func TestProbeRunSpendsTheHourOnlyOnNetworkRuns(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	op := probeCtx(probeOperator("op", probeScope))
	run := func() error {
		_, err := srv.vpnCoreProbeRPC(op, "run", []byte(probeTestRequest("")))
		return err
	}
	hourly := func(err error) bool {
		if err == nil {
			return false
		}
		status, apiErr := probeErrorOf(t, err)
		return status == http.StatusTooManyRequests && strings.Contains(apiErr.Message, "in the last hour")
	}
	stageAnswer := func(stage string) string {
		return strings.Replace(probeTestAnswer, `"valid":true,"stage":"ok"`, `"valid":false,"stage":"`+stage+`"`, 1)
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"malformed request", http.StatusBadRequest, `{"error":{"stage":"request","message":"body is not a valid probe request"}}`},
		{"busy probe", http.StatusTooManyRequests, `{"error":{"stage":"request","message":"probe is busy"}}`},
		{"outbound does not decode", http.StatusOK, stageAnswer("decode")},
		{"outbound does not create", http.StatusOK, stageAnswer("create")},
	} {
		fake.answer(tc.status, tc.body)
		for i := range probeMaxRunsPerHour + 1 {
			if err := run(); hourly(err) {
				t.Fatalf("%s: run %d spent the hourly budget although no run used the network", tc.name, i+1)
			}
		}
	}
	audited := len(probeAudits(st))
	if want := 4 * (probeMaxRunsPerHour + 1); audited != want {
		t.Fatalf("a handed-back run is still audited: %d records, want %d", audited, want)
	}

	// A policy refusal can come after the probe resolved or dialled, so it
	// counts, and so does a run the probe measured.
	fake.answer(http.StatusBadRequest, `{"error":{"stage":"policy","message":"server resolves to a private address"}}`)
	for range probeMaxRunsPerHour / 2 {
		if hourly(run()) {
			t.Fatal("the budget ran out early")
		}
	}
	fake.answer(http.StatusOK, stageAnswer("server"))
	for range probeMaxRunsPerHour - probeMaxRunsPerHour/2 {
		if err := run(); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(); !hourly(err) {
		t.Fatalf("run %d after %d policy refusals and measured runs must hit the hourly budget: %v",
			probeMaxRunsPerHour+1, probeMaxRunsPerHour/2, err)
	}
}

func TestAuditTruncateKeepsRunesWhole(t *testing.T) {
	for _, tc := range []struct {
		in   string
		max  int
		want string
	}{
		{"plain", 10, "plain"},
		{"abcdef", 3, "abc"},
		{"abé", 3, "ab"},                    // é is 2 bytes; the cut would split it
		{"ab漢x", 3, "ab"},                   // 3 bytes, cut after its first
		{"ab漢x", 4, "ab"},                   // and after its second
		{"ab漢x", 5, "ab漢"},                  // the bound falls right after it
		{"a😀", 4, "a"},                      // 4 bytes, cut after its third
		{"\x80\x80\x80\x80\x80", 4, "\x80"}, // invalid input still stays within the bound
	} {
		got := auditTruncate(tc.in, tc.max)
		if got != tc.want || len(got) > tc.max {
			t.Fatalf("auditTruncate(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}

	// The probe summary bounds operator-pasted fields with it.
	host := strings.Repeat("a", 252) + "é.example"
	request := `{"test":"x","targets":["` + strings.Repeat("t", 39) + `é"],"outbounds":[{"tag":"x","type":"` +
		strings.Repeat("v", 31) + `é","server":"` + host + `","server_port":443}]}`
	summary, ok := summarizeProbeRun([]byte(request))
	if !ok {
		t.Fatal("the request is a JSON object")
	}
	for name, v := range map[string]string{"server": summary.Server, "types": summary.Types, "targets": summary.Targets} {
		if !utf8.ValidString(v) || v == "" {
			t.Fatalf("summary %s must be valid UTF-8 and kept: %q", name, v)
		}
	}
	if summary.Server != strings.Repeat("a", 252)+":443" {
		t.Fatalf("the host is cut before the split character: %q", summary.Server)
	}
}

// probeTestManifest is vpn-core's probe interface as the manifest declares
// it, plus a sandbox view so the contributions view lists it.
func probeTestManifest(extra ...plugin.InterfaceContract) plugin.Manifest {
	return plugin.Manifest{
		Schema: plugin.ManifestSchemaV2, ID: vpnCorePluginID, Name: "vpn-core (sing-box)", Type: plugin.TypeSystem, Publisher: "latticenet",
		UI: &plugin.ManifestUI{
			Nav:   []plugin.NavContribution{{Section: "extensions", Title: "Probe", Route: "probe", Scopes: []string{probeScope}}},
			Views: []plugin.ViewContribution{{Route: "probe", Title: "Probe", Kind: "sandbox"}},
		},
		Interfaces: append([]plugin.InterfaceContract{{Service: vpnCoreProbeService, Backing: plugin.BackingCore, MethodSpecs: []plugin.InterfaceMethod{
			{Name: "health", Effect: plugin.InterfaceEffectRead, Scopes: []string{probeScope}},
			{Name: "targets", Effect: plugin.InterfaceEffectRead, Scopes: []string{probeScope}},
			{Name: "run", Effect: plugin.InterfaceEffectRead, Scopes: []string{probeScope}},
		}}}, extra...),
	}
}

// vpn:probe is its own grant: no vpncore or proxy scope implies it, a node
// restriction refuses it, and core re-checks it whatever the manifest says.
func TestProbeScope(t *testing.T) {
	for _, s := range []string{"vpn:probe", "vpn:*"} {
		if !rbac.ValidScope(s) {
			t.Fatalf("%s must be a grantable scope", s)
		}
	}
	for scopes, want := range map[string]bool{
		"*": true, "vpn:*": true, "vpn:probe": true,
		"vpncore:*": false, "vpncore:admin": false, "proxy:*": false, "proxy:admin": false, "substore:admin": false,
	} {
		if got := rbac.Allows(rbac.Principal{Scopes: []string{scopes}}, probeScope, ""); got != want {
			t.Fatalf("%s grants vpn:probe = %v, want %v", scopes, got, want)
		}
	}

	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = append(srv.plugins, plugin.Loaded{Manifest: probeTestManifest()})
	call := func(p principal, method, payload string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"id":%q,"service":%q,"method":%q,"payload":%s}`, vpnCorePluginID, vpnCoreProbeService, method, payload)
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.handlePluginCall(rec, req, p)
		return rec
	}
	if rec := call(probeOperator("op", probeScope), "health", `{}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"available":true`) {
		t.Fatalf("health through the gateway = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(probeOperator("op", probeScope), "run", probeTestRequest("")); rec.Code != http.StatusOK || rec.Body.String() != probeTestAnswer {
		t.Fatalf("run through the gateway = %d %s", rec.Code, rec.Body.String())
	}
	fake.answer(http.StatusTooManyRequests, `{"error":{"stage":"request","message":"busy"}}`)
	if rec := call(probeOperator("op", probeScope), "run", probeTestRequest("")); rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"code":"rate_limited"`) {
		t.Fatalf("a 429 must reach the browser as 429: %d %s", rec.Code, rec.Body.String())
	}
	fake.answer(http.StatusOK, probeTestAnswer)
	for name, p := range map[string]principal{
		"vpncore and proxy admin": probeOperator("op", "vpncore:*", "proxy:*"),
		"node-confined vpn:probe": {Principal: rbac.Principal{ActorID: "op", Scopes: []string{probeScope}, ServerAllowlist: []string{"node-a"}}},
	} {
		for _, method := range []string{"health", "targets", "run"} {
			if rec := call(p, method, probeTestRequest("")); rec.Code != http.StatusForbidden {
				t.Fatalf("%s calling %s through the gateway = %d, want 403", name, method, rec.Code)
			}
			_, err := srv.vpnCoreProbeRPC(probeCtx(p), method, []byte(probeTestRequest("")))
			if status, _ := probeErrorOf(t, err); status != http.StatusForbidden {
				t.Fatalf("%s calling %s in core = %d, want 403", name, method, status)
			}
		}
	}

	// A manifest that declared a weaker scope still cannot reach the probe:
	// core checks vpn:probe itself.
	weak := probeTestManifest()
	for i := range weak.Interfaces[0].MethodSpecs {
		weak.Interfaces[0].MethodSpecs[i].Scopes = []string{"vpncore:read"}
	}
	srv.plugins = []plugin.Loaded{{Manifest: weak}}
	if rec := call(probeOperator("op", "vpncore:read"), "run", probeTestRequest("")); rec.Code != http.StatusForbidden {
		t.Fatalf("a weaker manifest scope must not open the probe: %d %s", rec.Code, rec.Body.String())
	}

	// A plugin's rpc:call carries no operator, so core refuses it.
	srv.pluginRPC.AllowMethods("test.grantee", vpnCoreProbeService, []string{"run"})
	_, err := srv.pluginRPC.Call(context.Background(), "test.grantee", vpnCoreProbeService, "run", []byte(probeTestRequest("")))
	if status, _ := probeErrorOf(t, err); status != http.StatusForbidden {
		t.Fatalf("a run without an operator must fail closed: %d", status)
	}
	// A plugin's runtime serving an operator carries the operator's principal
	// but not the direct-call mark, so it cannot spend that operator's runs.
	actingFor := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, probeOperator("op", probeScope))
	_, err = srv.pluginRPC.Call(actingFor, "test.grantee", vpnCoreProbeService, "run", []byte(probeTestRequest("")))
	if status, _ := probeErrorOf(t, err); status != http.StatusForbidden {
		t.Fatalf("a plugin acting for an operator must not reach the probe: %d", status)
	}
	// Another core service's direct call does not stand in for this one.
	otherMark := context.WithValue(actingFor, operatorCoreCallKey{}, vpnCoreNodesService)
	if _, err := srv.vpnCoreProbeRPC(otherMark, "run", []byte(probeTestRequest(""))); err == nil {
		t.Fatal("a direct call to another core service must not open the probe")
	}
	if n := len(probeAudits(st)); n != 2 {
		t.Fatalf("only the two runs that reached the probe leave a probe record, got %d", n)
	}
}

func TestProbeServiceIsRegistered(t *testing.T) {
	srv, _, _ := newProbeTestServer(t, "")
	if srv.probe.socket != defaultProbeSocket {
		t.Fatalf("an empty socket option means %s, got %s", defaultProbeSocket, srv.probe.socket)
	}
	if !srv.pluginRPC.Owns(vpnCorePluginID, vpnCoreProbeService) {
		t.Fatalf("%s is not registered to %s", vpnCoreProbeService, vpnCorePluginID)
	}
	for _, method := range []string{"health", "targets", "run"} {
		_, err := srv.pluginRPC.CallOperator(probeCtx(probeOperator("op")), vpnCoreProbeService, method, nil)
		if errors.Is(err, plugin.ErrRPCNoMethod) {
			t.Fatalf("method %s is not registered", method)
		}
	}
}

// The gateway gives run the probe's own deadline, and the contributions view
// publishes every deadline that is not the default, the probe's and a
// budgeted plugin method's alike, so the console's bridge stops cutting them.
func TestPluginCallTimeoutsReachTheConsole(t *testing.T) {
	srv, st, _ := newProbeTestServer(t, "")
	activateCorePlugin(t, st, vpnCorePluginID)
	budgeted := plugin.InterfaceContract{Service: vpnCorePluginID + "/slow", Backing: plugin.BackingRuntime, MethodSpecs: []plugin.InterfaceMethod{
		{Name: "export", Effect: plugin.InterfaceEffectRead, Scopes: []string{probeScope},
			Budget: &plugin.InvokeBudgetSpec{TimeoutMS: 30_000, StdoutBytes: 1 << 20, StderrBytes: 1 << 20, HostCalls: 0}},
		{Name: "quick", Effect: plugin.InterfaceEffectRead, Scopes: []string{probeScope},
			Budget: &plugin.InvokeBudgetSpec{TimeoutMS: 2_000, StdoutBytes: 1 << 20, StderrBytes: 1 << 20, HostCalls: 0}},
		{Name: "plain", Effect: plugin.InterfaceEffectRead, Scopes: []string{probeScope}},
	}}
	manifest := probeTestManifest(budgeted)
	srv.plugins = []plugin.Loaded{{Manifest: manifest}}

	method := func(service, name string) plugin.InterfaceMethod {
		contract, _ := manifest.InterfaceFor(service)
		m, _ := contract.MethodContract(name)
		return m
	}
	for _, tc := range []struct {
		service, method string
		want            time.Duration
	}{
		{vpnCoreProbeService, "run", probeRunGatewayTimeout},
		{vpnCoreProbeService, "health", defaultPluginCallTimeout},
		{budgeted.Service, "export", 30 * time.Second},
		{budgeted.Service, "quick", 2 * time.Second},
		{budgeted.Service, "plain", defaultPluginCallTimeout},
	} {
		if got := srv.pluginGatewayTimeout(vpnCorePluginID, tc.service, method(tc.service, tc.method)); got != tc.want {
			t.Fatalf("%s %s gateway deadline = %s, want %s", tc.service, tc.method, got, tc.want)
		}
	}
	// The long deadline belongs to core's provider: another plugin declaring
	// the same method name on a service core does not own keeps its own.
	if got := srv.pluginGatewayTimeout("other.plugin", vpnCoreProbeService, method(vpnCoreProbeService, "run")); got != defaultPluginCallTimeout {
		t.Fatalf("only the owner's core provider sets the long deadline: %s", got)
	}

	contributions := func(p principal) []pluginView {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.handlePluginContributions(rec, httptest.NewRequest(http.MethodGet, "/api/plugin-contributions", nil), p)
		var views []pluginView
		if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
			t.Fatal(err)
		}
		return views
	}
	views := contributions(probeOperator("op", probeScope))
	if len(views) != 1 {
		t.Fatalf("want the vpn-core contribution, got %d", len(views))
	}
	want := map[string]map[string]int64{
		vpnCoreProbeService: {"run": probeRunGatewayTimeout.Milliseconds()},
		budgeted.Service:    {"export": 30_000, "quick": 2_000},
	}
	got, _ := json.Marshal(views[0].CallTimeoutsMS)
	wantJSON, _ := json.Marshal(want)
	if !bytes.Equal(got, wantJSON) {
		t.Fatalf("call_timeouts_ms = %s, want %s", got, wantJSON)
	}
	// A method the caller may not call is not in the frame's interfaces, and
	// its deadline is not published either.
	if views := contributions(probeOperator("op", "vpncore:read")); len(views) != 0 && views[0].CallTimeoutsMS != nil {
		t.Fatalf("deadlines of methods the caller cannot call leaked: %v", views[0].CallTimeoutsMS)
	}
}

// The probe tests the only outbound when the request omits test, so the
// audit record names that outbound's address instead of leaving it blank.
func TestProbeSummaryNamesTheOnlyOutboundWithoutTest(t *testing.T) {
	single := `{"outbounds":[{"tag":"solo","type":"trojan","server":"203.0.113.9","server_port":8443,"password":"` + probeTestPassword + `"}],"targets":["gstatic-204"]}`
	summary, ok := summarizeProbeRun([]byte(single))
	if !ok || summary.Server != "203.0.113.9:8443" || summary.Types != "trojan" {
		t.Fatalf("one outbound without test is audited by its own address and type: %+v", summary)
	}
	untagged := `{"outbounds":[{"type":"hysteria2","server":"2001:db8::7","server_port":443}]}`
	if summary, _ := summarizeProbeRun([]byte(untagged)); summary.Server != "[2001:db8::7]:443" || summary.Types != "hysteria2" {
		t.Fatalf("an untagged single outbound = %+v", summary)
	}
	// With two outbounds and no test the probe refuses the request, and the
	// record names no address rather than guessing one.
	chain := strings.Replace(probeTestRequest(""), `"test":"exit",`, "", 1)
	if summary, _ := summarizeProbeRun([]byte(chain)); summary.Server != "" || summary.Types != "vless,shadowsocks" {
		t.Fatalf("a chain without test names no server: %+v", summary)
	}
	if summary, _ := summarizeProbeRun([]byte(probeTestRequest(""))); summary.Server != "203.0.113.7:443" {
		t.Fatalf("test still picks the tested outbound: %+v", summary)
	}

	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	if _, err := srv.vpnCoreProbeRPC(probeCtx(probeOperator("op", probeScope)), "run", []byte(single)); err != nil {
		t.Fatal(err)
	}
	last := probeAudits(st)[0]
	if last.Metadata["server"] != "203.0.113.9:8443" || last.Metadata["types"] != "trojan" {
		t.Fatalf("the run's record = %+v", last.Metadata)
	}
	for _, v := range last.Metadata {
		if strings.Contains(v, probeTestPassword) {
			t.Fatalf("the record carries the credential: %+v", last.Metadata)
		}
	}
}

// A refusal mapped from the probe carries the request id in its body, the
// same id the X-Lattice-Request-ID header carries, as every other API error.
func TestProbeGatewayErrorsCarryTheRequestID(t *testing.T) {
	fake := startFakeProbe(t)
	srv, st, _ := newProbeTestServer(t, fake.socket)
	activateCorePlugin(t, st, vpnCorePluginID)
	srv.plugins = append(srv.plugins, plugin.Loaded{Manifest: probeTestManifest()})
	call := func(requestID string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"id":%q,"service":%q,"method":"run","payload":%s}`, vpnCorePluginID, vpnCoreProbeService, probeTestRequest(""))
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if requestID != "" {
			// withRequestID sets the header before any handler runs.
			rec.Header().Set(requestIDHeader, requestID)
		}
		srv.handlePluginCall(rec, req, probeOperator("op", probeScope))
		return rec
	}
	bodyError := func(rec *httptest.ResponseRecorder) model.APIError {
		t.Helper()
		var body model.APIErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("error body %s: %v", rec.Body.String(), err)
		}
		return body.Error
	}

	for _, tc := range []struct {
		name   string
		status int
		answer string
		want   int
		code   string
	}{
		{"policy refusal", http.StatusBadRequest, `{"error":{"stage":"policy","message":"server 10.0.0.5 is a private address"}}`, http.StatusBadRequest, model.APIErrorBadRequest},
		{"busy probe", http.StatusTooManyRequests, `{"error":{"stage":"request","message":"busy"}}`, http.StatusTooManyRequests, model.APIErrorRateLimited},
	} {
		fake.answer(tc.status, tc.answer)
		rec := call("req_gateway_" + tc.code)
		apiErr := bodyError(rec)
		if rec.Code != tc.want || apiErr.Code != tc.code || apiErr.Message == "" || apiErr.RequestID != "req_gateway_"+tc.code {
			t.Fatalf("%s = %d %+v, want request_id %q", tc.name, rec.Code, apiErr, "req_gateway_"+tc.code)
		}
	}

	// The per-principal limit refuses before the probe is asked; its 429
	// carries the id too.
	fake.answer(http.StatusOK, probeTestAnswer)
	release := make([]func(bool), 0, probeMaxRunsInFlight)
	for range probeMaxRunsInFlight {
		r, refusal := srv.probeLimits.acquire(probePrincipalKey(probeOperator("op", probeScope)), srv.now())
		if refusal != nil {
			t.Fatal(refusal)
		}
		release = append(release, r)
	}
	rec := call("req_gateway_limit")
	if apiErr := bodyError(rec); rec.Code != http.StatusTooManyRequests || apiErr.RequestID != "req_gateway_limit" {
		t.Fatalf("the in-flight limit = %d %+v", rec.Code, apiErr)
	}
	for _, r := range release {
		r(false)
	}

	// With no header yet the gateway mints one, and body and header agree.
	down, downStore, _ := newProbeTestServer(t, fake.socket+".gone")
	activateCorePlugin(t, downStore, vpnCorePluginID)
	down.plugins = append(down.plugins, plugin.Loaded{Manifest: probeTestManifest()})
	srv = down
	rec = call("")
	apiErr := bodyError(rec)
	if rec.Code != http.StatusServiceUnavailable || apiErr.Code != apiErrorProbeUnavailable || apiErr.RequestID == "" || apiErr.RequestID != rec.Header().Get(requestIDHeader) {
		t.Fatalf("an unavailable probe = %d %+v, header %q", rec.Code, apiErr, rec.Header().Get(requestIDHeader))
	}
}

// A run whose caller goes away is audited as canceled, not as an
// unavailable probe.
func TestProbeRunCanceledIsAuditedAsCanceled(t *testing.T) {
	fake := startFakeProbe(t)
	reached := make(chan struct{})
	fake.serve(func(_ http.ResponseWriter, r *http.Request) {
		close(reached)
		<-r.Context().Done()
	})
	srv, st, _ := newProbeTestServer(t, fake.socket)
	ctx, cancel := context.WithCancel(probeCtx(probeOperator("op", probeScope)))
	go func() {
		<-reached
		cancel()
	}()
	_, err := srv.vpnCoreProbeRPC(ctx, "run", []byte(probeTestRequest("")))
	if status, apiErr := probeErrorOf(t, err); status != http.StatusServiceUnavailable || !strings.Contains(apiErr.Message, "canceled") {
		t.Fatalf("a canceled run = %d %+v", status, apiErr)
	}
	audits := probeAudits(st)
	if len(audits) != 1 || audits[0].Metadata["stage"] != "canceled" || audits[0].Decision != "deny" {
		t.Fatalf("a canceled run is audited as canceled: %+v", audits)
	}
}
