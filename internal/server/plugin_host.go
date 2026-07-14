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
		KV: host,
		// Secrets get their own host type rather than another method on pluginHost.
		// The two vaults must never be reachable through one another by a typo: KV is
		// plaintext at rest, the secret store is encrypted, and a value written to the
		// wrong one is a private key in cleartext.
		Secret:       &pluginSecretHost{server: s},
		Task:         &pluginTaskHost{server: s},
		Notify:       host,
		HTTP:         host,
		OperatorHTTP: host,
		Log:          host,
		Audit:        host,
		RPC:          s.pluginRPC,
	}
}

// pluginSecretHost implements plugin.SecretHost over the store's encrypted collection
// (spec §9.4). Every method resolves the plugin-pinned composite key, so a plugin can
// only ever reach its own vault.
type pluginSecretHost struct{ server *Server }

func (h *pluginSecretHost) Get(_ context.Context, key string) (string, bool, error) {
	bucket, entryKey, err := splitPluginSecretKey(key)
	if err != nil {
		return "", false, err
	}
	entry, ok := h.server.store.PluginSecret(bucket, entryKey)
	if !ok {
		return "", false, nil
	}
	return entry.Value, true, nil
}

func (h *pluginSecretHost) Put(_ context.Context, key, value string) error {
	bucket, entryKey, err := splitPluginSecretKey(key)
	if err != nil {
		return err
	}
	// The error deliberately carries the key name and never the value: this text
	// reaches the broker's audit record and the plugin's own error channel.
	if err := h.server.store.PutPluginSecret(model.KVEntry{Bucket: bucket, Key: entryKey, Value: value}); err != nil {
		return fmt.Errorf("store plugin secret %q: %w", entryKey, err)
	}
	return nil
}

func (h *pluginSecretHost) Delete(_ context.Context, key string) error {
	bucket, entryKey, err := splitPluginSecretKey(key)
	if err != nil {
		return err
	}
	return h.server.store.DeletePluginSecret(bucket, entryKey)
}

// pluginTaskHost implements plugin.TaskHost (spec §9.3 step 5). The broker has already
// checked that this invocation carries an approved operation grant and that the target
// is one the operator approved; this side enforces everything an OPERATOR queueing the
// same task would face, so a plugin can never reach a wider interpreter set, a longer
// timeout, or a bigger script than a human could.
type pluginTaskHost struct{ server *Server }

func (h *pluginTaskHost) Enqueue(_ context.Context, req plugin.HostTaskRequest) (string, error) {
	task := model.Task{
		ID: id.New("task"),
		// ApprovalID is the join key the generic result handler uses to reconcile the
		// approval once the agent reports back. Without it the approval would sit in
		// `approved` forever, having actually run.
		ApprovalID:  req.ApprovalID,
		ActorID:     "plugin:" + req.PluginID,
		Targets:     []string{req.NodeID},
		Interpreter: req.Interpreter,
		Script:      req.Script,
		TimeoutSec:  req.TimeoutSec,
		OutputLimit: pluginTaskOutputLimit,
		Status:      "pending",
		CreatedAt:   time.Now().UTC(),
	}
	if task.TimeoutSec <= 0 {
		task.TimeoutSec = pluginTaskDefaultTimeoutSec
	}
	// The same validation an operator's POST /api/tasks passes: the interpreter
	// allow-list, the timeout and output bounds, the script size cap.
	if err := validateTaskCreate(task.Interpreter, task.Script, task.TimeoutSec, task.OutputLimit); err != nil {
		return "", fmt.Errorf("plugin task rejected: %w", err)
	}
	// queueTask, never store.CreateTask: it is the sole enforcement point of the fleet
	// task-execution kill switch, and a plugin must not be able to route around it.
	if err := h.server.queueTask(task); err != nil {
		return "", err
	}
	h.server.recordAudit(model.AuditEvent{
		ID: id.New("audit"), At: time.Now().UTC(),
		Action: "plugin.task.enqueue", Scope: "task:run", Decision: "allow",
		NodeID: req.NodeID,
		Metadata: map[string]string{
			"plugin_id": req.PluginID, "approval_id": req.ApprovalID,
			"task_id": task.ID, "interpreter": task.Interpreter,
		},
	})
	return task.ID, nil
}

const (
	pluginTaskOutputLimit       = 64 * 1024
	pluginTaskDefaultTimeoutSec = 300
)

// pluginSecretBucketPrefix is the namespace every plugin secret access must live
// under. As with KV, the broker pins it and the host re-checks it, so a hand-crafted
// composite key cannot resolve into another plugin's vault.
const pluginSecretBucketPrefix = "pluginsecret:"

func splitPluginSecretKey(key string) (string, string, error) {
	bucket, entryKey, ok := strings.Cut(key, "/")
	if !ok {
		return "", "", errors.New("plugin secret key must be bucket/key")
	}
	pluginID, ok := strings.CutPrefix(bucket, pluginSecretBucketPrefix)
	if !ok {
		return "", "", errors.New("plugin secret bucket must be namespaced to the plugin")
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
	return h.doHTTP(ctx, req, outbound.NewClient(10*time.Second))
}

func (h *pluginHost) DoOperator(ctx context.Context, req plugin.HostHTTPRequest) (plugin.HostHTTPResponse, error) {
	return h.doHTTP(ctx, req, outbound.NewOperatorClient(10*time.Second))
}

func (h *pluginHost) doHTTP(ctx context.Context, req plugin.HostHTTPRequest, client *http.Client) (plugin.HostHTTPResponse, error) {
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
	resp, err := client.Do(httpReq)
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
