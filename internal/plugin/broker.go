package plugin

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

const (
	capHTTPEgress = "http:egress"
	capKVRead     = "kv:read"
	capKVWrite    = "kv:write"
	capLogWrite   = "log:write"
	capNotifySend = "notify:send"
)

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
	KV     KVHost
	Notify NotifyHost
	HTTP   HTTPHost
	Log    LogHost
	Audit  HostAudit
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

// LogHost records a plugin-authored log entry after the broker stamps plugin id.
type LogHost interface {
	Write(ctx context.Context, entry HostLogEntry) error
}

// HostAudit records broker allow/deny decisions for host API calls.
type HostAudit interface {
	RecordHostCall(ctx context.Context, event HostCallEvent)
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
	out := &Broker{
		pluginID:     loaded.Manifest.ID,
		capabilities: make(map[string]struct{}, len(caps)),
		services:     services,
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

// KVGet reads a KV value and requires kv:read.
func (b *Broker) KVGet(ctx context.Context, key string) ([]byte, bool, error) {
	if err := b.require(ctx, "kv.get", capKVRead); err != nil {
		return nil, false, err
	}
	if b.services.KV == nil {
		return nil, false, fmt.Errorf("%w: kv", ErrHostServiceUnavailable)
	}
	value, ok, err := b.services.KV.Get(ctx, key)
	return append([]byte(nil), value...), ok, err
}

// KVPut writes a KV value and requires kv:write.
func (b *Broker) KVPut(ctx context.Context, key string, value []byte) error {
	if err := b.require(ctx, "kv.put", capKVWrite); err != nil {
		return err
	}
	if b.services.KV == nil {
		return fmt.Errorf("%w: kv", ErrHostServiceUnavailable)
	}
	return b.services.KV.Put(ctx, key, append([]byte(nil), value...))
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

// HTTPDo performs guarded outbound HTTP and requires http:egress.
func (b *Broker) HTTPDo(ctx context.Context, req HostHTTPRequest) (HostHTTPResponse, error) {
	if err := b.require(ctx, "http.do", capHTTPEgress); err != nil {
		return HostHTTPResponse{}, err
	}
	if b.services.HTTP == nil {
		return HostHTTPResponse{}, fmt.Errorf("%w: http", ErrHostServiceUnavailable)
	}
	req.Header = cloneStringMap(req.Header)
	req.Body = append([]byte(nil), req.Body...)
	resp, err := b.services.HTTP.Do(ctx, req)
	resp.Header = cloneStringMap(resp.Header)
	resp.Body = append([]byte(nil), resp.Body...)
	return resp, err
}

// Log writes a plugin-authored log entry and requires log:write.
func (b *Broker) Log(ctx context.Context, level, message string, fields map[string]string) error {
	if err := b.require(ctx, "log.write", capLogWrite); err != nil {
		return err
	}
	if b.services.Log == nil {
		return fmt.Errorf("%w: log", ErrHostServiceUnavailable)
	}
	return b.services.Log.Write(ctx, HostLogEntry{
		PluginID: b.pluginID,
		Level:    level,
		Message:  message,
		Fields:   cloneStringMap(fields),
	})
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
