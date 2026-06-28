package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/notify"
	"github.com/LatticeNet/lattice-server/internal/outbound"
	"github.com/LatticeNet/lattice-server/internal/plugin"
)

const (
	pluginHTTPRequestLimit  = 256 * 1024
	pluginHTTPResponseLimit = 256 * 1024
)

type pluginHost struct {
	server *Server
}

func (s *Server) pluginHostServices() plugin.HostServices {
	host := &pluginHost{server: s}
	return plugin.HostServices{
		KV:     host,
		Notify: host,
		HTTP:   host,
		Log:    host,
		Audit:  host,
		RPC:    s.pluginRPC,
	}
}

func (h *pluginHost) Get(ctx context.Context, key string) ([]byte, bool, error) {
	bucket, entryKey, err := splitPluginKVKey(key)
	if err != nil {
		return nil, false, err
	}
	for _, entry := range h.server.store.KV(bucket) {
		if entry.Key == entryKey {
			return []byte(entry.Value), true, nil
		}
	}
	return nil, false, nil
}

func (h *pluginHost) Put(ctx context.Context, key string, value []byte) error {
	bucket, entryKey, err := splitPluginKVKey(key)
	if err != nil {
		return err
	}
	return h.server.store.PutKV(model.KVEntry{Bucket: bucket, Key: entryKey, Value: string(value)})
}

// pluginKVBucketPrefix is the namespace every plugin KV access must live under.
// The broker pins each plugin to "plugin:<pluginID>"; the host enforces the
// prefix as defense-in-depth so a plugin-supplied composite key can never resolve
// to a non-plugin bucket in the shared operator KV store.
const pluginKVBucketPrefix = "plugin:"

func (h *pluginHost) Send(ctx context.Context, title, body string) error {
	channels := h.server.store.EnabledNotifyChannels()
	if len(channels) == 0 {
		return nil
	}
	built := make([]notify.Channel, 0, len(channels))
	for _, c := range channels {
		ch, err := buildChannel(c.Kind, c.Config)
		if err != nil {
			return fmt.Errorf("notify channel %s: %w", c.ID, err)
		}
		built = append(built, ch)
	}
	ctx, cancel := contextWithDefaultTimeout(ctx, 15*time.Second)
	defer cancel()
	var errs []string
	for _, res := range notify.NewDispatcher(built...).Send(ctx, notify.Message{Title: title, Body: body}) {
		if res.Err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", res.Kind, res.Err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (h *pluginHost) Do(ctx context.Context, req plugin.HostHTTPRequest) (plugin.HostHTTPResponse, error) {
	if len(req.Body) > pluginHTTPRequestLimit {
		return plugin.HostHTTPResponse{}, errors.New("plugin http request body exceeds size limit")
	}
	method := strings.TrimSpace(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return plugin.HostHTTPResponse{}, err
	}
	for k, v := range req.Header {
		httpReq.Header.Set(k, v)
	}
	resp, err := outbound.NewClient(10 * time.Second).Do(httpReq)
	if err != nil {
		return plugin.HostHTTPResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, pluginHTTPResponseLimit+1))
	if err != nil {
		return plugin.HostHTTPResponse{}, err
	}
	if len(body) > pluginHTTPResponseLimit {
		return plugin.HostHTTPResponse{}, errors.New("plugin http response exceeds size limit")
	}
	return plugin.HostHTTPResponse{StatusCode: resp.StatusCode, Header: singleValueHeaders(resp.Header), Body: body}, nil
}

func (h *pluginHost) Write(ctx context.Context, entry plugin.HostLogEntry) error {
	fields := clonePluginFields(entry.Fields)
	h.server.logger.Printf("plugin log: plugin=%s level=%s message=%q fields=%v", entry.PluginID, entry.Level, entry.Message, fields)
	return nil
}

func (h *pluginHost) RecordHostCall(ctx context.Context, event plugin.HostCallEvent) {
	metadata := map[string]string{
		"plugin_id": event.PluginID,
	}
	ev := model.AuditEvent{
		ID:            id.New("audit"),
		Action:        "plugin.host." + event.Action,
		Scope:         event.Capability,
		Decision:      event.Decision,
		Reason:        event.Reason,
		CorrelationID: requestIDFromContext(ctx),
		Metadata:      metadata,
	}
	h.server.recordAudit(ev)
}

func splitPluginKVKey(key string) (string, string, error) {
	bucket, entryKey, ok := strings.Cut(key, "/")
	if !ok {
		return "", "", errors.New("plugin kv key must be bucket/key")
	}
	// Enforce the plugin namespace server-side. The broker always pins the bucket
	// to "plugin:<pluginID>"; rejecting any other bucket here means even a
	// hand-crafted composite key cannot reach a non-plugin bucket (confused-deputy
	// defense). The pluginID segment itself must be a non-empty storage name.
	pluginID, ok := strings.CutPrefix(bucket, pluginKVBucketPrefix)
	if !ok {
		return "", "", errors.New("plugin kv bucket must be namespaced to the plugin")
	}
	if err := validateStorageName(pluginID); err != nil {
		return "", "", fmt.Errorf("plugin id: %w", err)
	}
	if err := validateStorageName(bucket); err != nil {
		return "", "", fmt.Errorf("bucket: %w", err)
	}
	if err := validateStorageName(entryKey); err != nil {
		return "", "", fmt.Errorf("key: %w", err)
	}
	return bucket, entryKey, nil
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	return requestID
}

func contextWithDefaultTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func singleValueHeaders(header http.Header) map[string]string {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string]string, len(header))
	for k, values := range header {
		if len(values) > 0 {
			out[k] = values[0]
		}
	}
	return out
}

func clonePluginFields(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
