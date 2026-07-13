package plugin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-server/internal/outbound"
)

const (
	capHTTPEgress         = "http:egress"
	capHTTPOperatorTarget = "http:operator-target"
	capKVRead             = "kv:read"
	capKVWrite            = "kv:write"
	capLogWrite           = "log:write"
	capNotifySend         = "notify:send"
	capRPCCall            = "rpc:call"
	capRPCExpose          = "rpc:expose"

	// kvBucketPrefix is prepended to a plugin id to derive the fixed,
	// server-visible KV bucket a plugin is confined to. The plugin never gets to
	// choose the bucket: the broker always pins it to "plugin:<pluginID>" so a
	// plugin with kv:read/kv:write can only touch its OWN namespace and cannot act
	// as a confused deputy against the shared operator KV store.
	kvBucketPrefix = "plugin:"

	// logMaxMessageBytes caps a plugin-authored log message. Anything longer is
	// truncated (with a marker) so a plugin cannot flood the operator log sink.
	logMaxMessageBytes = 8 * 1024
	// logMaxFields caps the number of structured fields a plugin may attach to a
	// single log entry. Fields beyond this are dropped.
	logMaxFields = 32
	// logTruncatedSuffix marks a message that was truncated to logMaxMessageBytes.
	logTruncatedSuffix = "...[truncated]"
)

// validLogLevels is the closed set of log levels a plugin may emit. An unknown
// or empty level is mapped to "info" rather than forwarded verbatim.
var validLogLevels = map[string]struct{}{
	"debug": {},
	"info":  {},
	"warn":  {},
	"error": {},
}

var (
	// ErrCapabilityDenied is returned when a plugin calls a host API without
	// declaring the matching capability in its verified manifest.
	ErrCapabilityDenied = errors.New("plugin capability denied")
	// ErrHostServiceUnavailable is returned when the capability is granted but
	// the server did not wire the corresponding host service into the broker.
	ErrHostServiceUnavailable = errors.New("plugin host service unavailable")
)

// CapabilityError describes the exact capability a plugin lacked.
type CapabilityError struct {
	PluginID   string
	Capability string
}

func (e *CapabilityError) Error() string {
	return fmt.Sprintf("plugin %q lacks capability %q", e.PluginID, e.Capability)
}

func (e *CapabilityError) Unwrap() error {
	return ErrCapabilityDenied
}

// HostServices are the real server-owned handles exposed through the broker.
// The broker keeps these handles behind per-call capability checks.
type HostServices struct {
	KV           KVHost
	Notify       NotifyHost
	HTTP         HTTPHost
	OperatorHTTP OperatorHTTPHost
	Log          LogHost
	Audit        HostAudit
	// RPC dispatches inter-plugin calls (design-09 §F). When nil, a plugin with
	// rpc:call gets ErrHostServiceUnavailable rather than a panic.
	RPC RPCHost
	// GuardURL, when set, validates an outbound HTTP target's URL/host BEFORE the
	// broker delegates to HTTP.Do. It makes SSRF/egress guarding structural at the
	// broker boundary rather than relying on every HTTPHost implementation to
	// remember to guard. A non-nil error rejects the request before any dial. When
	// nil, the broker falls back to a built-in guard (see defaultGuardURL) so an
	// HTTPHost is never trusted by convention alone.
	GuardURL         func(url string) error
	GuardOperatorURL func(url string) error
}

// KVHost is the plugin-facing KV subset. The implementation remains server-owned.
type KVHost interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Put(ctx context.Context, key string, value []byte) error
}

// NotifyHost sends an operator notification through server-owned channels.
type NotifyHost interface {
	Send(ctx context.Context, title, body string) error
}

// HTTPHost performs guarded outbound HTTP. Implementations must enforce the
// server's SSRF/egress policy before dialing.
type HTTPHost interface {
	Do(ctx context.Context, req HostHTTPRequest) (HostHTTPResponse, error)
}

// OperatorHTTPHost performs HTTP to an explicitly operator-selected endpoint.
// It is separate from ordinary egress so private-network access cannot be
// enabled by a caller-controlled flag on http.do.
type OperatorHTTPHost interface {
	DoOperator(ctx context.Context, req HostHTTPRequest) (HostHTTPResponse, error)
}

// LogHost records a plugin-authored log entry after the broker stamps plugin id.
type LogHost interface {
	Write(ctx context.Context, entry HostLogEntry) error
}

// HostAudit records broker allow/deny decisions for host API calls.
type HostAudit interface {
	RecordHostCall(ctx context.Context, event HostCallEvent)
}

// RPCHost dispatches an inter-plugin RPC call to a server-owned registry that
// resolves the target service, enforces the directed caller->callee allow-list,
// and invokes the callee's handler. caller is the VERIFIED id of the calling
// plugin, supplied by the broker; a plugin cannot spoof it.
type RPCHost interface {
	Call(ctx context.Context, caller, service, method string, request []byte) ([]byte, error)
}

// HostHTTPRequest is the broker's stable outbound HTTP request shape.
type HostHTTPRequest struct {
	Method string
	URL    string
	Header map[string]string
	Body   []byte
}

// HostHTTPResponse is the broker's stable outbound HTTP response shape.
type HostHTTPResponse struct {
	StatusCode int
	Header     map[string]string
	Body       []byte
}

// HostLogEntry is a plugin-authored structured log entry.
type HostLogEntry struct {
	PluginID string
	Level    string
	Message  string
	Fields   map[string]string
}

// HostCallEvent records one broker authorization decision.
type HostCallEvent struct {
	PluginID   string
	Action     string
	Capability string
	Decision   string
	Reason     string
}

// Broker is the capability-scoped facade a verified plugin uses to call back
// into server-owned host services.
type Broker struct {
	pluginID     string
	capabilities map[string]struct{}
	services     HostServices
	// kvBucket is the fixed, per-plugin KV namespace ("plugin:<pluginID>"). The
	// broker pins every KV access to this bucket so the plugin can never reach
	// another bucket in the shared operator KV store.
	kvBucket string
	// guardURL guards every outbound HTTP target before the broker delegates to
	// the HTTPHost. It is always non-nil after NewBroker (it defaults to the
	// built-in outbound guard) so egress filtering is structural, not by
	// convention.
	guardURL         func(url string) error
	guardOperatorURL func(url string) error
}

type operatorTargetsContextKey struct{}

// BindOperatorTargets attaches server-authorized base URLs to one invocation.
// Only the system runner and server tests should mint this context value.
func BindOperatorTargets(ctx context.Context, targets []string) (context.Context, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(targets) == 0 {
		return ctx, nil
	}
	if len(targets) > 4 {
		return nil, errors.New("too many invocation-bound operator targets")
	}
	bound := make([]string, 0, len(targets))
	seen := map[string]bool{}
	for _, target := range targets {
		if err := outbound.GuardOperatorURL(target); err != nil {
			return nil, fmt.Errorf("invalid invocation-bound operator target: %w", err)
		}
		if !seen[target] {
			seen[target] = true
			bound = append(bound, target)
		}
	}
	return context.WithValue(ctx, operatorTargetsContextKey{}, bound), nil
}

func operatorTargetBound(ctx context.Context, target string) error {
	if ctx == nil {
		return errors.New("operator target is not bound to this invocation")
	}
	bound, _ := ctx.Value(operatorTargetsContextKey{}).([]string)
	for _, base := range bound {
		if outbound.GuardOperatorTargetBinding(base, target) == nil {
			return nil
		}
	}
	return errors.New("operator target is not bound to this invocation")
}

// NewBroker binds a verified plugin registry entry to server-owned host services.
func NewBroker(loaded Loaded, services HostServices) (*Broker, error) {
	if loaded.Manifest.ID == "" {
		return nil, errors.New("plugin id is required")
	}
	if err := ValidateManifest(loaded.Manifest); err != nil {
		return nil, fmt.Errorf("invalid loaded manifest: %w", err)
	}
	if !sameStringSet(loaded.Capabilities, loaded.Manifest.Capabilities) {
		return nil, errors.New("loaded capabilities do not match manifest capabilities")
	}
	caps := append([]string(nil), loaded.Capabilities...)
	sort.Strings(caps)
	guard := services.GuardURL
	if guard == nil {
		// Fail safe: even if the host wired no guard, the broker must still filter
		// egress structurally rather than trusting the HTTPHost by convention.
		guard = defaultGuardURL
	}
	operatorGuard := services.GuardOperatorURL
	if operatorGuard == nil {
		operatorGuard = outbound.GuardOperatorURL
	}
	out := &Broker{
		pluginID:         loaded.Manifest.ID,
		capabilities:     make(map[string]struct{}, len(caps)),
		services:         services,
		kvBucket:         kvBucketPrefix + loaded.Manifest.ID,
		guardURL:         guard,
		guardOperatorURL: operatorGuard,
	}
	for _, cap := range caps {
		if _, ok := CapabilityRisk(cap); !ok {
			return nil, fmt.Errorf("capability %q is not recognized", cap)
		}
		out.capabilities[cap] = struct{}{}
	}
	return out, nil
}

// PluginID returns the verified plugin id attached to this broker.
func (b *Broker) PluginID() string {
	return b.pluginID
}

// HasCapability reports whether the verified plugin declared cap.
func (b *Broker) HasCapability(cap string) bool {
	_, ok := b.capabilities[cap]
	return ok
}

// CanExposeRPC reports whether the verified plugin declared rpc:expose, i.e. may
// register a callable service in the inter-plugin RPC registry. The server checks
// this before registering a plugin's handlers (design-09 §F).
func (b *Broker) CanExposeRPC() bool {
	return b.HasCapability(capRPCExpose)
}

// KVGet reads a KV value and requires kv:read. The plugin-supplied key names
// only the entry within the plugin's own namespace; the broker pins the bucket
// so a plugin can never read another plugin's or the operator's keys.
func (b *Broker) KVGet(ctx context.Context, key string) ([]byte, bool, error) {
	if err := b.require(ctx, "kv.get", capKVRead); err != nil {
		return nil, false, err
	}
	if b.services.KV == nil {
		return nil, false, fmt.Errorf("%w: kv", ErrHostServiceUnavailable)
	}
	scoped, err := b.scopedKVKey(key)
	if err != nil {
		return nil, false, err
	}
	value, ok, err := b.services.KV.Get(ctx, scoped)
	return append([]byte(nil), value...), ok, err
}

// KVPut writes a KV value and requires kv:write. As with KVGet, the bucket is
// fixed to the plugin's own namespace; the plugin only chooses the entry key.
func (b *Broker) KVPut(ctx context.Context, key string, value []byte) error {
	if err := b.require(ctx, "kv.put", capKVWrite); err != nil {
		return err
	}
	if b.services.KV == nil {
		return fmt.Errorf("%w: kv", ErrHostServiceUnavailable)
	}
	scoped, err := b.scopedKVKey(key)
	if err != nil {
		return err
	}
	return b.services.KV.Put(ctx, scoped, append([]byte(nil), value...))
}

// scopedKVKey rewrites a plugin-supplied entry key into the fixed composite
// "plugin:<pluginID>/<key>" shape the KVHost splits on. The plugin only controls
// the part AFTER the bucket: a key may not be empty and may not contain a "/",
// which would otherwise let the plugin smuggle its own bucket and escape its
// namespace (a confused-deputy escalation over the shared operator KV store).
func (b *Broker) scopedKVKey(key string) (string, error) {
	if key == "" {
		return "", errors.New("plugin kv key must not be empty")
	}
	if strings.ContainsAny(key, "/\\") {
		return "", errors.New("plugin kv key must not contain a slash")
	}
	return b.kvBucket + "/" + key, nil
}

// Notify sends an operator notification and requires notify:send.
func (b *Broker) Notify(ctx context.Context, title, body string) error {
	if err := b.require(ctx, "notify.send", capNotifySend); err != nil {
		return err
	}
	if b.services.Notify == nil {
		return fmt.Errorf("%w: notify", ErrHostServiceUnavailable)
	}
	return b.services.Notify.Send(ctx, title, body)
}

// HTTPDo performs guarded outbound HTTP and requires http:egress. The broker
// itself runs the SSRF/egress guard on req.URL BEFORE delegating to the
// HTTPHost, so egress filtering is structural at this boundary and every
// HTTPHost (including future ones) is guarded regardless of its own behavior.
func (b *Broker) HTTPDo(ctx context.Context, req HostHTTPRequest) (HostHTTPResponse, error) {
	if err := b.require(ctx, "http.do", capHTTPEgress); err != nil {
		return HostHTTPResponse{}, err
	}
	if b.services.HTTP == nil {
		return HostHTTPResponse{}, fmt.Errorf("%w: http", ErrHostServiceUnavailable)
	}
	// Structural guard: reject internal/loopback/link-local/metadata targets here,
	// before any Do call reaches the HTTPHost.
	if err := b.guardURL(req.URL); err != nil {
		return HostHTTPResponse{}, fmt.Errorf("plugin http egress blocked: %w", err)
	}
	req.Header = cloneStringMap(req.Header)
	req.Body = append([]byte(nil), req.Body...)
	resp, err := b.services.HTTP.Do(ctx, req)
	resp.Header = cloneStringMap(resp.Header)
	resp.Body = append([]byte(nil), resp.Body...)
	return resp, err
}

// HTTPOperatorDo reaches an explicitly operator-selected endpoint and requires
// the distinct system-only http:operator-target capability. It never weakens
// HTTPDo or its SSRF boundary.
func (b *Broker) HTTPOperatorDo(ctx context.Context, req HostHTTPRequest) (HostHTTPResponse, error) {
	if err := b.require(ctx, "http.operator.do", capHTTPOperatorTarget); err != nil {
		return HostHTTPResponse{}, err
	}
	if b.services.OperatorHTTP == nil {
		return HostHTTPResponse{}, fmt.Errorf("%w: operator http", ErrHostServiceUnavailable)
	}
	if err := operatorTargetBound(ctx, req.URL); err != nil {
		b.record(ctx, HostCallEvent{PluginID: b.pluginID, Action: "http.operator.do", Capability: capHTTPOperatorTarget, Decision: "deny", Reason: err.Error()})
		return HostHTTPResponse{}, err
	}
	if err := b.guardOperatorURL(req.URL); err != nil {
		return HostHTTPResponse{}, fmt.Errorf("plugin operator target blocked: %w", err)
	}
	req.Header = cloneStringMap(req.Header)
	req.Body = append([]byte(nil), req.Body...)
	resp, err := b.services.OperatorHTTP.DoOperator(ctx, req)
	resp.Header = cloneStringMap(resp.Header)
	resp.Body = append([]byte(nil), resp.Body...)
	return resp, err
}

// Log writes a plugin-authored log entry and requires log:write. The plugin
// controls the level/message/fields, so the broker bounds them before they reach
// the sink: the level is mapped to a known set, an oversize message is truncated,
// and the field count is capped. This prevents a plugin from flooding or
// poisoning the operator log through unbounded input.
func (b *Broker) Log(ctx context.Context, level, message string, fields map[string]string) error {
	if err := b.require(ctx, "log.write", capLogWrite); err != nil {
		return err
	}
	if b.services.Log == nil {
		return fmt.Errorf("%w: log", ErrHostServiceUnavailable)
	}
	return b.services.Log.Write(ctx, HostLogEntry{
		PluginID: b.pluginID,
		Level:    normalizeLogLevel(level),
		Message:  boundLogMessage(message),
		Fields:   boundLogFields(fields),
	})
}

// RPCCall invokes method on another plugin's exposed service and requires
// rpc:call. The broker stamps the VERIFIED caller id (b.pluginID) so the
// registry can authorize the directed edge; a plugin cannot impersonate another
// caller. Registry-level denials (ErrRPCDenied) are additionally recorded as a
// deny event for audit visibility (the capability check itself already recorded
// an allow). Service/method-not-found are client errors, not security denials,
// so they are returned without an extra deny event.
func (b *Broker) RPCCall(ctx context.Context, service, method string, request []byte) ([]byte, error) {
	if err := b.require(ctx, "rpc.call", capRPCCall); err != nil {
		return nil, err
	}
	if b.services.RPC == nil {
		return nil, fmt.Errorf("%w: rpc", ErrHostServiceUnavailable)
	}
	resp, err := b.services.RPC.Call(ctx, b.pluginID, service, method, append([]byte(nil), request...))
	if err != nil {
		if errors.Is(err, ErrRPCDenied) {
			b.record(ctx, HostCallEvent{
				PluginID:   b.pluginID,
				Action:     "rpc.call:" + service + "/" + method,
				Capability: capRPCCall,
				Decision:   "deny",
				Reason:     err.Error(),
			})
		}
		return nil, err
	}
	return append([]byte(nil), resp...), nil
}

// normalizeLogLevel maps an arbitrary plugin-supplied level to the closed set of
// allowed levels, defaulting unknown/empty values to "info".
func normalizeLogLevel(level string) string {
	lvl := strings.ToLower(strings.TrimSpace(level))
	if _, ok := validLogLevels[lvl]; ok {
		return lvl
	}
	return "info"
}

// boundLogMessage truncates a message longer than logMaxMessageBytes, appending a
// marker so the truncation is visible in the log. Truncation is by byte length on
// a rune boundary so the result stays valid UTF-8.
func boundLogMessage(message string) string {
	if len(message) <= logMaxMessageBytes {
		return message
	}
	cut := logMaxMessageBytes
	// Back up to a rune boundary so we never split a multi-byte rune.
	for cut > 0 && !utf8.RuneStart(message[cut]) {
		cut--
	}
	return message[:cut] + logTruncatedSuffix
}

// boundLogFields returns at most logMaxFields entries from the supplied fields.
// Selection is deterministic (sorted by key) so the dropped set is stable rather
// than depending on Go's randomized map iteration order.
func boundLogFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	if len(fields) <= logMaxFields {
		return cloneStringMap(fields)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, logMaxFields)
	for _, k := range keys[:logMaxFields] {
		out[k] = fields[k]
	}
	return out
}

func (b *Broker) require(ctx context.Context, action, cap string) error {
	if b.HasCapability(cap) {
		b.record(ctx, HostCallEvent{PluginID: b.pluginID, Action: action, Capability: cap, Decision: "allow"})
		return nil
	}
	err := &CapabilityError{PluginID: b.pluginID, Capability: cap}
	b.record(ctx, HostCallEvent{PluginID: b.pluginID, Action: action, Capability: cap, Decision: "deny", Reason: err.Error()})
	return err
}

func (b *Broker) record(ctx context.Context, event HostCallEvent) {
	if b.services.Audit != nil {
		b.services.Audit.RecordHostCall(ctx, event)
	}
}

// defaultGuardURL is the broker's built-in SSRF/egress guard, used whenever the
// host did not inject a HostServices.GuardURL. It delegates to the shared
// outbound guard so plugin egress is filtered with the same policy as
// operator-configured webhooks (loopback, private, link-local, metadata, etc.).
func defaultGuardURL(rawURL string) error {
	return outbound.GuardURL(rawURL)
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
