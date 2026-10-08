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
	"io/fs"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// The control plane's outbound probe (design 27).
//
// lattice-probe is a separate GPL-3.0 program beside the server that listens
// on a unix socket. It embeds sing-box, creates each pasted outbound inside
// one running instance, measures it and removes it. This file is the server's
// half: the host service latticenet.vpn-core/probe that vpn-core's Probe layer
// calls, the socket client, the per-principal limits, the audit record, and
// the health reading Platform > System shows.
//
// A run request carries the outbound, and the outbound carries passwords and
// UUIDs. It passes through here byte for byte and is never stored, logged or
// audited: the audit record keeps a SHA-256 of its canonical JSON and the
// outcome, nothing else. Error messages and audit reasons are written here,
// never copied from the request.

const (
	// probeScope gates every method. No proxy or vpncore grant implies it.
	probeScope = "vpn:probe"
	// defaultProbeSocket is where the compose file mounts the shared volume.
	defaultProbeSocket = "/run/lattice-probe/probe.sock"

	// probeCallTimeout bounds one targets or run call over the socket. The
	// probe's own deadline is at most 30 s, so this leaves it room to answer.
	probeCallTimeout = 35 * time.Second
	// probeRunGatewayTimeout is the gateway's deadline for run, longer than the
	// socket call inside it so the probe's answer (or the socket deadline's
	// message) reaches the operator instead of a bare gateway timeout.
	probeRunGatewayTimeout = probeCallTimeout + time.Second
	// probeHealthTimeout bounds a health read. A probe that cannot say it is
	// alive in this long is unavailable, and System polls it every 30 s.
	probeHealthTimeout = 3 * time.Second

	probeMaxRequestBytes  = 64 << 10
	probeMaxResponseBytes = 1 << 20

	probeMaxRunsInFlight = 4
	probeMaxRunsPerHour  = 120
	probeRunWindow       = time.Hour

	// apiErrorProbeUnavailable: the socket is missing, refused, or did not
	// answer in time. The message says which.
	apiErrorProbeUnavailable = "probe_unavailable"

	auditActionVPNCoreProbe = "vpncore.probe"
)

// coreMethodTimeout is the gateway deadline of a core-owned method whose work
// runs longer than the default. The plugin contributions view publishes it so
// the console's bridge waits as long as the server does.
func coreMethodTimeout(service, method string) (time.Duration, bool) {
	if service == vpnCoreProbeService && method == "run" {
		return probeRunGatewayTimeout, true
	}
	return 0, false
}

// probeClient speaks HTTP/1.1 to lattice-probe over its unix socket.
// Keep-alive is off: a dial on a local socket costs microseconds, and a
// pooled connection the probe closed on restart would fail the next run.
type probeClient struct {
	socket string
	http   *http.Client
	// callTimeout bounds a targets or run call and healthTimeout a health
	// read; fields only so tests can shorten them.
	callTimeout   time.Duration
	healthTimeout time.Duration
}

func newProbeClient(socket string) *probeClient {
	if socket == "" {
		socket = defaultProbeSocket
	}
	var dialer net.Dialer
	return &probeClient{
		socket:        socket,
		callTimeout:   probeCallTimeout,
		healthTimeout: probeHealthTimeout,
		http: &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socket)
			},
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 16 << 10,
		}},
	}
}

// do sends one request and returns the status and the body, read up to
// probeMaxResponseBytes. A larger body is an error, not a truncation.
func (c *probeClient) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://lattice-probe"+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, probeMaxResponseBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(out) > probeMaxResponseBytes {
		return 0, nil, errProbeAnswerTooLarge
	}
	return resp.StatusCode, out, nil
}

var errProbeAnswerTooLarge = errors.New("probe answer exceeds the size limit")

// unavailableReason says in one line why a call did not get an answer. It is
// written here from the error's kind, so nothing the probe or the caller
// sent can reach it. showPath names the socket's path; System leaves it out,
// because more principals read System than hold vpn:probe.
func (c *probeClient) unavailableReason(err error, timeout time.Duration, showPath bool) string {
	socket := "the probe socket"
	if showPath {
		socket += " at " + c.socket
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("the probe did not answer within %s", timeout)
	case errors.Is(err, context.Canceled):
		return "the request was canceled before the probe answered"
	case errors.Is(err, errProbeAnswerTooLarge):
		return "the probe's answer was larger than the server accepts"
	case errors.Is(err, fs.ErrNotExist):
		return socket + " does not exist; is the lattice-probe container running?"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "nothing is listening on " + socket
	case errors.Is(err, fs.ErrPermission):
		return "the server may not open " + socket + "; it needs the probe's group"
	default:
		return socket + " could not be reached"
	}
}

// probeHealth is lattice-probe's GET /v1/health answer.
type probeHealth struct {
	ProbeVersion string  `json:"probe_version"`
	Engine       string  `json:"engine"`
	CoreVersion  string  `json:"core_version"`
	UptimeS      float64 `json:"uptime_s"`
	Inflight     int     `json:"inflight"`
	MaxInflight  int     `json:"max_inflight"`
	Targets      int     `json:"targets"`
}

// probeHealthView is what the health method and System show: the probe's own
// health with available true, or available false and the reason alone.
type probeHealthView struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	*probeHealth
}

// health reads the probe's health; showPath is unavailableReason's.
func (c *probeClient) health(ctx context.Context, showPath bool) probeHealthView {
	ctx, cancel := context.WithTimeout(ctx, c.healthTimeout)
	defer cancel()
	status, body, err := c.do(ctx, http.MethodGet, "/v1/health", nil)
	if err != nil {
		return probeHealthView{Reason: c.unavailableReason(err, c.healthTimeout, showPath)}
	}
	if status != http.StatusOK {
		return probeHealthView{Reason: fmt.Sprintf("the probe answered its health check with HTTP %d", status)}
	}
	var h probeHealth
	if err := json.Unmarshal(body, &h); err != nil || h.Engine == "" {
		return probeHealthView{Reason: "the probe's health answer could not be read"}
	}
	h.ProbeVersion = auditTruncate(h.ProbeVersion, 64)
	h.Engine = auditTruncate(h.Engine, 64)
	h.CoreVersion = auditTruncate(h.CoreVersion, 64)
	return probeHealthView{Available: true, probeHealth: &h}
}

// vpnCoreProbeRPC serves latticenet.vpn-core/probe. The gateway has already
// checked the manifest's declared scope; this checks vpn:probe itself, so a
// manifest that declared something weaker still cannot reach the probe.
//
// Only an operator's own call through the gateway reaches it (the console's
// Probe page). A plugin's runtime acting for an operator carries that
// operator's principal too, but not the direct-call mark, so a plugin with an
// rpc dependency on this service cannot spend the operator's probe budget.
func (s *Server) vpnCoreProbeRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	p, err := pluginOperatorPrincipal(ctx)
	if err != nil || operatorCalledCoreService(ctx) != vpnCoreProbeService {
		return nil, rpcAPIError(http.StatusForbidden, model.APIErrorForbidden, "vpn-core/probe answers only an operator's own call")
	}
	if ok, reason := pluginGatewayScopeAllowed(p, probeScope); !ok {
		return nil, rpcAPIError(http.StatusForbidden, model.APIErrorCapabilityDenied, reason)
	}
	switch method {
	case "health":
		return json.Marshal(s.probe.health(ctx, true))
	case "targets":
		return s.probeTargets(ctx)
	case "run":
		return s.probeRun(ctx, p, request)
	default:
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "vpn-core/probe: unknown method "+method)
	}
}

func (s *Server) probeTargets(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.probe.callTimeout)
	defer cancel()
	status, body, err := s.probe.do(ctx, http.MethodGet, "/v1/targets", nil)
	if err != nil {
		return nil, s.probeUnavailable(err)
	}
	if status != http.StatusOK || !json.Valid(body) {
		return nil, rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway, fmt.Sprintf("the probe answered its target list with HTTP %d", status))
	}
	return body, nil
}

func (s *Server) probeUnavailable(err error) error {
	status := http.StatusServiceUnavailable
	if errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusGatewayTimeout
	}
	return rpcAPIError(status, apiErrorProbeUnavailable, s.probe.unavailableReason(err, s.probe.callTimeout, true))
}

// probeRun forwards one run request to the probe unchanged and returns its
// answer. Every run that is admitted past the limits leaves one audit record.
//
// The hourly budget bounds what the probe sends to the network for an
// operator, so a run the probe answered without using the network is handed
// back: a malformed request, a busy probe, and an outbound that failed to
// decode or create. A policy refusal still counts, because the probe can
// refuse after it has resolved names or dialled (its guard refuses a private
// address at dial time), and so does a run whose answer never arrived.
func (s *Server) probeRun(ctx context.Context, p principal, request []byte) ([]byte, error) {
	if len(request) > probeMaxRequestBytes {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest,
			fmt.Sprintf("the probe request is %d bytes; the limit is %d", len(request), probeMaxRequestBytes))
	}
	summary, ok := summarizeProbeRun(request)
	if !ok {
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "the probe request must be a JSON object")
	}
	release, refusal := s.probeLimits.acquire(probePrincipalKey(p), s.now())
	if refusal != nil {
		return nil, refusal
	}
	spent := true
	defer func() { release(spent) }()

	callCtx, cancel := context.WithTimeout(ctx, s.probe.callTimeout)
	defer cancel()
	started := time.Now()
	status, body, err := s.probe.do(callCtx, http.MethodPost, "/v1/probe", request)
	took := time.Since(started)
	if err != nil {
		reason := s.probe.unavailableReason(err, s.probe.callTimeout, true)
		stage := "unavailable"
		if errors.Is(err, context.DeadlineExceeded) {
			stage = "timeout"
		}
		// The reason is written from the error's kind and names only the
		// socket, so the log line carries nothing from the request.
		s.logger.Printf("vpn-core/probe: run failed: %s", reason)
		s.auditProbeRun(p, summary, "deny", reason, stage, false, took.Milliseconds())
		return nil, s.probeUnavailable(err)
	}
	switch status {
	case http.StatusOK:
		var answer struct {
			Valid  bool     `json:"valid"`
			Stage  string   `json:"stage"`
			TookMS *float64 `json:"took_ms"`
		}
		if err := json.Unmarshal(body, &answer); err != nil {
			s.auditProbeRun(p, summary, "deny", "the probe's answer could not be read", "unavailable", false, took.Milliseconds())
			return nil, rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway, "the probe's answer could not be read")
		}
		tookMS := took.Milliseconds()
		if answer.TookMS != nil && *answer.TookMS >= 0 {
			tookMS = int64(*answer.TookMS)
		}
		stage := probeAnswerStage(answer.Stage)
		spent = stage != "decode" && stage != "create"
		s.auditProbeRun(p, summary, "allow", "", stage, answer.Valid, tookMS)
		return body, nil
	case http.StatusBadRequest:
		var refused struct {
			Error struct {
				Stage   string `json:"stage"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &refused)
		stage := "request"
		if refused.Error.Stage == "policy" {
			stage = "policy"
		}
		spent = stage == "policy"
		s.auditProbeRun(p, summary, "deny", "the probe refused the request at its "+stage+" check", stage, false, took.Milliseconds())
		message := oneLine(refused.Error.Message, 300)
		if message == "" {
			message = "refused without a reason"
		}
		return nil, rpcAPIError(http.StatusBadRequest, model.APIErrorBadRequest, "probe "+stage+": "+message)
	case http.StatusTooManyRequests:
		spent = false
		s.auditProbeRun(p, summary, "deny", "the probe was at its limit of tests in flight", "busy", false, took.Milliseconds())
		return nil, rpcAPIError(http.StatusTooManyRequests, model.APIErrorRateLimited, "the probe is running as many tests as it allows at once; retry in a few seconds")
	default:
		reason := fmt.Sprintf("the probe answered HTTP %d", status)
		s.auditProbeRun(p, summary, "deny", reason, "unavailable", false, took.Milliseconds())
		return nil, rpcAPIError(http.StatusBadGateway, model.APIErrorBadGateway, reason)
	}
}

func (s *Server) auditProbeRun(p principal, summary probeRunSummary, decision, reason, stage string, valid bool, tookMS int64) {
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: auditActionVPNCoreProbe, Scope: probeScope, Decision: decision, Reason: reason,
		Metadata: map[string]string{
			"types":         summary.Types,
			"server":        summary.Server,
			"config_sha256": summary.ConfigSHA256,
			"targets":       summary.Targets,
			"stage":         stage,
			"valid":         boolString(valid),
			"took_ms":       strconv.FormatInt(tookMS, 10),
		},
	})
}

// probeAnswerStages are the stages a completed probe reports.
var probeAnswerStages = map[string]bool{
	"ok": true, "decode": true, "create": true, "server": true, "handshake": true, "target": true, "timeout": true,
}

func probeAnswerStage(stage string) string {
	if probeAnswerStages[stage] {
		return stage
	}
	return "unknown"
}

// oneLine keeps the first line of s, bounded to max bytes.
func oneLine(s string, max int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return auditTruncate(strings.TrimSpace(s), max)
}

// probeRunSummary is everything about a run request the audit record keeps.
// None of it is a credential: outbound types, the tested outbound's server
// address, the target ids, and a hash of the outbounds.
type probeRunSummary struct {
	Types        string
	Server       string
	ConfigSHA256 string
	Targets      string
}

// summarizeProbeRun reads the audit summary out of a run request. It is
// lenient on purpose: the probe is the one authority on what a valid request
// is, so a field of the wrong type here leaves its summary empty and the
// request still goes to the probe, which answers why it is wrong. ok is false
// only when the body is not a JSON object at all.
func summarizeProbeRun(request []byte) (probeRunSummary, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(request, &fields); err != nil || fields == nil {
		return probeRunSummary{}, false
	}
	var summary probeRunSummary
	if raw, present := fields["outbounds"]; present {
		if canonical, err := canonicalJSON(raw); err == nil {
			sum := sha256.Sum256(canonical)
			summary.ConfigSHA256 = hex.EncodeToString(sum[:])
		}
	}
	var test string
	_ = json.Unmarshal(fields["test"], &test)
	var outbounds []map[string]json.RawMessage
	_ = json.Unmarshal(fields["outbounds"], &outbounds)
	types := make([]string, 0, len(outbounds))
	for _, outbound := range outbounds {
		var kind, tag string
		_ = json.Unmarshal(outbound["type"], &kind)
		_ = json.Unmarshal(outbound["tag"], &tag)
		types = append(types, auditTruncate(kind, 32))
		if test != "" && tag == test && summary.Server == "" {
			summary.Server = outboundServerAddress(outbound)
		}
	}
	summary.Types = joinBounded(types, 16, 256)
	var targets []string
	_ = json.Unmarshal(fields["targets"], &targets)
	for i := range targets {
		targets[i] = auditTruncate(targets[i], 40)
	}
	summary.Targets = joinBounded(targets, 16, 256)
	return summary, true
}

// outboundServerAddress is host:port of an outbound's server and server_port,
// or "" when either is missing.
func outboundServerAddress(outbound map[string]json.RawMessage) string {
	var host string
	if err := json.Unmarshal(outbound["server"], &host); err != nil || host == "" {
		return ""
	}
	var port json.Number
	dec := json.NewDecoder(bytes.NewReader(outbound["server_port"]))
	dec.UseNumber()
	if err := dec.Decode(&port); err != nil || port == "" {
		return ""
	}
	return auditTruncate(net.JoinHostPort(auditTruncate(host, 253), port.String()), 270)
}

// joinBounded joins at most n items with commas, notes how many it left out,
// and bounds the result to max bytes.
func joinBounded(items []string, n, max int) string {
	extra := 0
	if len(items) > n {
		extra = len(items) - n
		items = items[:n]
	}
	out := strings.Join(items, ",")
	if extra > 0 {
		out += fmt.Sprintf(",+%d", extra)
	}
	return auditTruncate(out, max)
}

// canonicalJSON re-encodes a JSON value with object keys sorted and no
// insignificant whitespace, numbers kept as written, so two requests that
// differ only in key order or spacing hash the same.
func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// probePrincipalKey names whose budget a run spends. It is the person, not
// the credential: an operator's session and every token they minted share
// one budget, so minting tokens does not multiply it.
func probePrincipalKey(p principal) string {
	switch {
	case p.ActorID != "":
		return "actor:" + p.ActorID
	case p.TokenID != "":
		return "token:" + p.TokenID
	default:
		return "anonymous"
	}
}

// probeLimiter holds each principal's runs in flight and the start times of
// its runs in the last rolling hour.
type probeLimiter struct {
	mu      sync.Mutex
	entries map[string]*probeLimitEntry
}

type probeLimitEntry struct {
	inflight int
	starts   []time.Time // admitted runs inside the window, oldest first
}

func (e *probeLimitEntry) prune(now time.Time) {
	cut := 0
	for cut < len(e.starts) && !e.starts[cut].After(now.Add(-probeRunWindow)) {
		cut++
	}
	if cut > 0 {
		e.starts = append(e.starts[:0], e.starts[cut:]...)
	}
}

// acquire admits one run for key or returns the 429 that says when to retry.
// The returned release must be called once the run is over; spent false
// takes the run back out of the hourly window, for a run that used no
// network.
func (l *probeLimiter) acquire(key string, now time.Time) (func(spent bool), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[string]*probeLimitEntry{}
	}
	// Forget principals with nothing in flight and nothing left in the
	// window, so the map holds only those who ran in the last hour.
	for k, e := range l.entries {
		e.prune(now)
		if e.inflight == 0 && len(e.starts) == 0 && k != key {
			delete(l.entries, k)
		}
	}
	e := l.entries[key]
	if e == nil {
		e = &probeLimitEntry{}
		l.entries[key] = e
	}
	if e.inflight >= probeMaxRunsInFlight {
		return nil, rpcAPIError(http.StatusTooManyRequests, model.APIErrorRateLimited,
			fmt.Sprintf("%d probe runs are already in flight for you; retry when one finishes", probeMaxRunsInFlight))
	}
	if len(e.starts) >= probeMaxRunsPerHour {
		retryAt := e.starts[0].Add(probeRunWindow)
		return nil, rpcAPIError(http.StatusTooManyRequests, model.APIErrorRateLimited,
			fmt.Sprintf("you ran %d probes in the last hour; retry in %s (at %s)",
				probeMaxRunsPerHour, probeRetryWait(retryAt.Sub(now)), retryAt.UTC().Format(time.RFC3339)))
	}
	e.inflight++
	e.starts = append(e.starts, now)
	var once sync.Once
	return func(spent bool) {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			e.inflight--
			if !spent {
				// Take back one start equal to this run's; which one does
				// not matter.
				if i := slices.IndexFunc(e.starts, now.Equal); i >= 0 {
					e.starts = slices.Delete(e.starts, i, i+1)
				}
			}
		})
	}, nil
}

// probeRetryWait is a wait rounded up to whole seconds under a minute and to
// whole minutes above it.
func probeRetryWait(d time.Duration) string {
	if d <= 0 {
		return "a moment"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int((d+time.Second-1)/time.Second))
	}
	return fmt.Sprintf("%dm", int((d+time.Minute-1)/time.Minute))
}
