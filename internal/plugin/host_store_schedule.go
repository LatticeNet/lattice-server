package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
)

// Host calls added for design 28's first slice: kv.delete, the per-method HTTP
// response budget, the request verbs http.operator.do admits per method, and
// task.schedule with task.unschedule. Each goes through the same capability
// check and audit record as every other host call (Broker.require).

const (
	capTaskSchedule = sdkplugin.CapabilityTaskSchedule

	// hostMethodKVDelete removes one key from the plugin's own KV namespace.
	// It needs kv:write, as kv.put does. The SDK has no constant for it yet.
	hostMethodKVDelete = "kv.delete"
)

// KVDeleter is the optional delete half of a KVHost. A host that stores KV
// implements it; the broker answers ErrHostServiceUnavailable when it does
// not, so a host built before kv.delete existed fails closed.
type KVDeleter interface {
	Delete(ctx context.Context, key string) error
}

// TaskScheduleHost is the optional scheduling half of a TaskHost. Schedule
// stores a schedule under the verified plugin id, replacing one with the same
// id; Unschedule removes one and reports whether it existed. The host checks
// what the broker cannot see: that the service and method are the plugin's
// own declared runtime method, and the per-plugin count.
type TaskScheduleHost interface {
	Schedule(ctx context.Context, pluginID string, schedule sdkplugin.TaskSchedule) error
	Unschedule(ctx context.Context, pluginID, id string) (bool, error)
}

// KVDelete removes a key from the plugin's own KV namespace and requires
// kv:write. The bucket is pinned exactly as KVPut pins it, so a plugin can
// delete only a key it could have written.
func (b *Broker) KVDelete(ctx context.Context, key string) error {
	if err := b.require(ctx, hostMethodKVDelete, capKVWrite); err != nil {
		return err
	}
	deleter, ok := b.services.KV.(KVDeleter)
	if !ok {
		return fmt.Errorf("%w: kv delete", ErrHostServiceUnavailable)
	}
	scoped, err := b.scopedKVKey(key)
	if err != nil {
		return err
	}
	return deleter.Delete(ctx, scoped)
}

// TaskSchedule asks the server to call one of the plugin's own methods on a
// cron schedule and requires task:schedule. The shape (id, cron with its
// five-minute minimum, names, payload size) is checked here so every host
// gets the same refusal; the host checks the method and the count.
func (b *Broker) TaskSchedule(ctx context.Context, schedule sdkplugin.TaskSchedule) error {
	if err := b.require(ctx, sdkplugin.HostMethodTaskSchedule, capTaskSchedule); err != nil {
		return err
	}
	host, ok := b.services.Task.(TaskScheduleHost)
	if !ok {
		return fmt.Errorf("%w: task schedule", ErrHostServiceUnavailable)
	}
	if err := schedule.Validate(); err != nil {
		return err
	}
	if !strings.HasPrefix(schedule.Service, b.pluginID+"/") {
		return fmt.Errorf("task schedule service %q is not one of this plugin's own services", schedule.Service)
	}
	schedule.Payload = append(json.RawMessage(nil), schedule.Payload...)
	return host.Schedule(ctx, b.pluginID, schedule)
}

// TaskUnschedule removes one of the plugin's schedules and requires
// task:schedule. Removing an id that does not exist is not an error.
func (b *Broker) TaskUnschedule(ctx context.Context, id string) (bool, error) {
	if err := b.require(ctx, sdkplugin.HostMethodTaskUnschedule, capTaskSchedule); err != nil {
		return false, err
	}
	host, ok := b.services.Task.(TaskScheduleHost)
	if !ok {
		return false, fmt.Errorf("%w: task schedule", ErrHostServiceUnavailable)
	}
	if strings.TrimSpace(id) == "" || len(id) > sdkplugin.MaxTaskScheduleIDBytes {
		return false, fmt.Errorf("task schedule id %q is invalid", id)
	}
	return host.Unschedule(ctx, b.pluginID, id)
}

// invocationMethodKey carries the interface method an invocation serves and
// its resolved HTTP response budget. Private like the operator-target and
// operation keys, and never serialized to the child.
type invocationMethodKey struct{}

type invocationMethod struct {
	service           string
	method            string
	httpResponseBytes int
}

// BindInvocationMethod attaches the service, method and HTTP response budget
// of one invocation. Only the system runner and server tests should mint it.
func BindInvocationMethod(ctx context.Context, service, method string, httpResponseBytes int) context.Context {
	return bindInvocationMethod(ctx, service, method, httpResponseBytes)
}

func bindInvocationMethod(ctx context.Context, service, method string, httpResponseBytes int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, invocationMethodKey{}, invocationMethod{service: service, method: method, httpResponseBytes: httpResponseBytes})
}

func boundInvocationMethod(ctx context.Context) invocationMethod {
	if ctx == nil {
		return invocationMethod{}
	}
	inv, _ := ctx.Value(invocationMethodKey{}).(invocationMethod)
	return inv
}

// invocationHTTPResponseLimit is the response body bound for one HTTP host
// call: the invocation's signed budget, else the default, never above the
// host maximum.
func invocationHTTPResponseLimit(ctx context.Context) int {
	limit := boundInvocationMethod(ctx).httpResponseBytes
	if limit <= 0 {
		return DefaultInvokeHTTPResponseBytes
	}
	return min(limit, HostMaxInvokeHTTPResponseBytes)
}

// Interface methods that may read or remove what sits at an operator target.
// Every other method writes (PUT, POST, PATCH) and nothing else, so a
// destination the operator named for a publish cannot become a reader of
// whatever else is on that origin (design 28, sync and publish targets).
const (
	operatorHTTPArtifactService = "artifact"
	operatorHTTPRestoreMethod   = "restore"
	operatorHTTPDeleteMethod    = "delete"
)

// operatorHTTPLegacyGET lists methods that already read over http.operator.do
// when the verb rule arrived. The installed Sub-Store's migrate imports from a
// standalone Sub-Store's API with GET on the base URL the operator gives it.
// yagni: one closed entry; it goes when the legacy import leaves the plugin
// (design 28 S6), and nothing else is added here without a design change.
var operatorHTTPLegacyGET = map[string]map[string]bool{
	"latticenet.sub-store/subscription": {"migrate": true},
}

// operatorHTTPVerbAllowed normalizes a request method and admits it for the
// invocation's own method. An empty method is GET, as the host sends it.
func (b *Broker) operatorHTTPVerbAllowed(ctx context.Context, method string) (string, error) {
	verb := strings.ToUpper(strings.TrimSpace(method))
	if verb == "" {
		verb = http.MethodGet
	}
	switch verb {
	case http.MethodPut, http.MethodPost, http.MethodPatch:
		return verb, nil
	}
	inv := boundInvocationMethod(ctx)
	short, own := strings.CutPrefix(inv.service, b.pluginID+"/")
	switch verb {
	case http.MethodGet:
		if own && short == operatorHTTPArtifactService && inv.method == operatorHTTPRestoreMethod {
			return verb, nil
		}
		if operatorHTTPLegacyGET[inv.service][inv.method] && own {
			return verb, nil
		}
		return "", errors.New("http.operator.do admits GET only on artifact.restore")
	case http.MethodDelete:
		if own && short == operatorHTTPArtifactService && inv.method == operatorHTTPDeleteMethod {
			return verb, nil
		}
		return "", errors.New("http.operator.do admits DELETE only on artifact.delete")
	default:
		return "", fmt.Errorf("http.operator.do does not admit %s", verb)
	}
}

// dispatchStoreAndScheduleHostCall decodes the host calls this file adds.
func dispatchStoreAndScheduleHostCall(ctx context.Context, broker *Broker, call systemHostCall) (json.RawMessage, error) {
	switch call.Method {
	case hostMethodKVDelete:
		var req struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("kv.delete params: %w", err)
		}
		if err := broker.KVDelete(ctx, req.Key); err != nil {
			return nil, err
		}
		return json.RawMessage(`{}`), nil
	case sdkplugin.HostMethodTaskSchedule:
		var schedule sdkplugin.TaskSchedule
		dec := json.NewDecoder(bytes.NewReader(call.Params))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&schedule); err != nil {
			return nil, fmt.Errorf("task.schedule params: %w", err)
		}
		if err := ensureNoTrailingJSON(dec); err != nil {
			return nil, fmt.Errorf("task.schedule params: %w", err)
		}
		if err := broker.TaskSchedule(ctx, schedule); err != nil {
			return nil, err
		}
		return json.RawMessage(`{}`), nil
	case sdkplugin.HostMethodTaskUnschedule:
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(call.Params, &req); err != nil {
			return nil, fmt.Errorf("task.unschedule params: %w", err)
		}
		removed, err := broker.TaskUnschedule(ctx, req.ID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Removed bool `json:"removed"`
		}{Removed: removed})
	default:
		return nil, fmt.Errorf("unsupported host_call method %q", call.Method)
	}
}
