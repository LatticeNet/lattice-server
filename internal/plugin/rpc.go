package plugin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Inter-plugin RPC (design-09 §F). The registry is the server-owned bus that
// makes one first-party plugin's logic callable from another without exposing
// raw handles: a plugin with rpc:expose registers a service; a plugin with
// rpc:call invokes it through the broker. Every call is capability-gated at the
// broker, authorized here by a directed caller->callee allow-list, and audited.
var (
	// ErrRPCNoService is returned when no plugin has registered the target service.
	ErrRPCNoService = errors.New("rpc service not found")
	// ErrRPCNoMethod is returned when the target service does not expose the method.
	ErrRPCNoMethod = errors.New("rpc method not found")
	// ErrRPCDenied is returned when the caller is not on the service's directed
	// allow-list (and is not the service owner). Distinct from "not found" so the
	// broker can record it as a security deny event.
	ErrRPCDenied = errors.New("rpc call denied")
	// ErrRPCInvalid is returned for a malformed service registration.
	ErrRPCInvalid = errors.New("invalid rpc registration")
)

// RPCHandler serves one inter-plugin RPC method: it receives the method name and
// raw request bytes and returns raw response bytes. Implementations must be safe
// for concurrent use; the registry invokes them WITHOUT holding its lock.
type RPCHandler func(ctx context.Context, method string, request []byte) ([]byte, error)

// RPCServiceDescriptor is the discovery shape returned by RPCRegistry.Services.
// Handlers are never exposed.
type RPCServiceDescriptor struct {
	Service string   `json:"service"`
	Owner   string   `json:"owner"`
	Version string   `json:"version"`
	Methods []string `json:"methods"`
}

type rpcService struct {
	owner   string
	version string
	methods map[string]struct{}
	handler RPCHandler
}

// RPCRegistry is the server-owned inter-plugin RPC bus. It is safe for concurrent
// use and implements the broker's RPCHost interface.
type RPCRegistry struct {
	mu       sync.RWMutex
	services map[string]*rpcService
	grants   map[string]map[string]map[string]struct{} // service -> caller -> allowed methods ("*" grants all)
}

// NewRPCRegistry returns an empty registry.
func NewRPCRegistry() *RPCRegistry {
	return &RPCRegistry{
		services: map[string]*rpcService{},
		grants:   map[string]map[string]map[string]struct{}{},
	}
}

// Register adds (or replaces) a service exposed by ownerPluginID. service is the
// fully-qualified id (e.g. "latticenet.vpn-core/nodes"); it must carry >=1
// non-empty method and a non-nil handler. Re-registering the same id replaces it
// (used on plugin restart). The caller (server) is responsible for verifying the
// owner declared rpc:expose before registering.
func (r *RPCRegistry) Register(ownerPluginID, service, version string, methods []string, handler RPCHandler) error {
	if ownerPluginID == "" || service == "" {
		return fmt.Errorf("%w: owner and service are required", ErrRPCInvalid)
	}
	if handler == nil {
		return fmt.Errorf("%w: handler is required", ErrRPCInvalid)
	}
	if len(methods) == 0 {
		return fmt.Errorf("%w: at least one method is required", ErrRPCInvalid)
	}
	set := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		if m == "" {
			return fmt.Errorf("%w: method name must not be empty", ErrRPCInvalid)
		}
		set[m] = struct{}{}
	}
	r.mu.Lock()
	r.services[service] = &rpcService{owner: ownerPluginID, version: version, methods: set, handler: handler}
	r.mu.Unlock()
	return nil
}

// Unregister removes a service and any grants targeting it (e.g. on disable).
func (r *RPCRegistry) Unregister(service string) {
	r.mu.Lock()
	delete(r.services, service)
	delete(r.grants, service)
	r.mu.Unlock()
}

// Allow grants callerPluginID permission to call service. Grants are directed and
// additive; a service owner can always call its own service.
func (r *RPCRegistry) Allow(callerPluginID, service string) {
	r.AllowMethods(callerPluginID, service, []string{"*"})
}

// AllowMethods grants only the named methods. This prevents a plugin from
// inheriting future methods added to a dependency service.
func (r *RPCRegistry) AllowMethods(callerPluginID, service string, methods []string) {
	r.mu.Lock()
	if r.grants[service] == nil {
		r.grants[service] = map[string]map[string]struct{}{}
	}
	set := map[string]struct{}{}
	for _, method := range methods {
		if method != "" {
			set[method] = struct{}{}
		}
	}
	r.grants[service][callerPluginID] = set
	r.mu.Unlock()
}

// Revoke removes a previously granted directed edge.
func (r *RPCRegistry) Revoke(callerPluginID, service string) {
	r.mu.Lock()
	if set := r.grants[service]; set != nil {
		delete(set, callerPluginID)
	}
	r.mu.Unlock()
}

// Services returns descriptors for every registered service, sorted by id, for
// discovery (e.g. an rpc.List host call). Handlers are not exposed.
func (r *RPCRegistry) Services() []RPCServiceDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RPCServiceDescriptor, 0, len(r.services))
	for id, svc := range r.services {
		methods := make([]string, 0, len(svc.methods))
		for m := range svc.methods {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		out = append(out, RPCServiceDescriptor{Service: id, Owner: svc.owner, Version: svc.version, Methods: methods})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

// CallOperator dispatches a service method on behalf of the OPERATOR (the
// dashboard gateway), bypassing the plugin->plugin directed allow-list — the
// HTTP layer has already enforced the interface's declared RBAC scopes + audit.
// Service/method-not-found are still errors. The handler runs OUTSIDE the lock.
func (r *RPCRegistry) CallOperator(ctx context.Context, service, method string, request []byte) ([]byte, error) {
	r.mu.RLock()
	svc := r.services[service]
	r.mu.RUnlock()
	if svc == nil {
		return nil, fmt.Errorf("%w: %s", ErrRPCNoService, service)
	}
	if _, ok := svc.methods[method]; !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrRPCNoMethod, service, method)
	}
	return svc.handler(ctx, method, request)
}

// Call implements RPCHost: resolve the service, enforce the directed allow-list
// (the owner may always self-call), check the method, then dispatch to the
// handler OUTSIDE the lock so a slow or re-entrant handler cannot block the bus.
func (r *RPCRegistry) Call(ctx context.Context, caller, service, method string, request []byte) ([]byte, error) {
	r.mu.RLock()
	svc := r.services[service]
	allowed := false
	if svc != nil {
		if methods := r.grants[service][caller]; methods != nil {
			_, wildcard := methods["*"]
			_, exact := methods[method]
			allowed = wildcard || exact
		}
		if caller == svc.owner {
			allowed = true
		}
	}
	r.mu.RUnlock()

	if svc == nil {
		return nil, fmt.Errorf("%w: %s", ErrRPCNoService, service)
	}
	if !allowed {
		return nil, fmt.Errorf("%w: %s -> %s", ErrRPCDenied, caller, service)
	}
	if _, ok := svc.methods[method]; !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrRPCNoMethod, service, method)
	}
	return svc.handler(ctx, method, request)
}
