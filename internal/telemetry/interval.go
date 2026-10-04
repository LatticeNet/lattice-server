package telemetry

import (
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-server/internal/metricsdb"
)

// IntervalWindow is what the server did since the previous TakeInterval:
// one event summary per store caller, HTTP route group and plugin method,
// with counts, failures and a latency histogram. The self-monitor drains it
// once a minute into the metrics store, so the cumulative counters /metrics
// serves are untouched by it.
type IntervalWindow struct {
	StoreSaves map[string]*metricsdb.Event
	Routes     map[string]*metricsdb.Event
	Plugins    map[PluginCallKey]*metricsdb.Event
	// PluginProcesses is what each plugin's processes used, by plugin id,
	// counted as they exited.
	PluginProcesses map[string]*PluginProcessUsage
	// AuditAppends counts audit writes; their duration is not measured.
	AuditAppends metricsdb.Event
}

// PluginProcessUsage summarises the plugin processes that exited in a window:
// one CPU sample (user plus system seconds) and one peak resident set sample
// (bytes) per process, so CPU.Sum is the CPU time they used, CPU.Count how
// many exited and RSS.Max the largest of them.
type PluginProcessUsage struct {
	CPU metricsdb.Gauge
	RSS metricsdb.Gauge
}

// PluginCallKey names one plugin method. Method is the service and method
// the host dispatched, with the plugin's own id prefix dropped from the
// service ("subscription/fetch", not "latticenet.vpn-core/subscription/fetch").
type PluginCallKey struct {
	Plugin string
	Method string
}

// Window bounds. A window lasts a minute, so these only stop a burst of
// distinct labels from growing one window without limit; the metrics store
// caps the series it keeps for good.
const (
	maxWindowRoutes           = 128
	maxWindowPlugins          = 512
	maxWindowMethodsPerPlugin = 64
	// RouteOther and PluginMethodOther collect what a full window cannot name.
	RouteOther        = "other"
	PluginMethodOther = "other"
)

func newIntervalWindow() IntervalWindow {
	return IntervalWindow{
		StoreSaves: map[string]*metricsdb.Event{},
		Routes:     map[string]*metricsdb.Event{},
		Plugins:    map[PluginCallKey]*metricsdb.Event{},

		PluginProcesses: map[string]*PluginProcessUsage{},
	}
}

func observeEvent[K comparable](m map[K]*metricsdb.Event, key K, d time.Duration, failed bool) {
	e := m[key]
	if e == nil {
		e = &metricsdb.Event{}
		m[key] = e
	}
	e.Observe(d, failed)
}

// ObserveRoute records one HTTP request against its route group. A server
// error (5xx) is a failure; a client's 4xx is the client's.
func ObserveRoute(group string, status int, d time.Duration) {
	defaultRegistry.ObserveRoute(group, status, d)
}

func (r *Registry) ObserveRoute(group string, status int, d time.Duration) {
	if group == "" {
		group = RouteOther
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, seen := r.interval.Routes[group]; !seen && len(r.interval.Routes) >= maxWindowRoutes {
		group = RouteOther
	}
	observeEvent(r.interval.Routes, group, d, status >= http.StatusInternalServerError)
}

// ObservePluginCall records one call into a plugin: how long the host waited
// for it and whether it failed.
func ObservePluginCall(pluginID, method string, d time.Duration, err error) {
	defaultRegistry.ObservePluginCall(pluginID, method, d, err)
}

func (r *Registry) ObservePluginCall(pluginID, method string, d time.Duration, err error) {
	if pluginID == "" {
		return
	}
	if method == "" {
		method = PluginMethodOther
	}
	key := PluginCallKey{Plugin: pluginID, Method: method}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, seen := r.interval.Plugins[key]; !seen {
		methods := 0
		for k := range r.interval.Plugins {
			if k.Plugin == pluginID {
				methods++
			}
		}
		if methods >= maxWindowMethodsPerPlugin || len(r.interval.Plugins) >= maxWindowPlugins {
			key.Method = PluginMethodOther
		}
	}
	observeEvent(r.interval.Plugins, key, d, err != nil)
}

// ObservePluginProcess records one plugin process that exited: the CPU time
// it used and its peak resident set.
func ObservePluginProcess(pluginID string, cpu time.Duration, maxRSSBytes int64) {
	defaultRegistry.ObservePluginProcess(pluginID, cpu, maxRSSBytes)
}

func (r *Registry) ObservePluginProcess(pluginID string, cpu time.Duration, maxRSSBytes int64) {
	if pluginID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u := r.interval.PluginProcesses[pluginID]
	if u == nil {
		if len(r.interval.PluginProcesses) >= maxWindowPlugins {
			return
		}
		u = &PluginProcessUsage{}
		r.interval.PluginProcesses[pluginID] = u
	}
	u.CPU.Observe(cpu.Seconds())
	if maxRSSBytes > 0 {
		u.RSS.Observe(float64(maxRSSBytes))
	}
}

// TakeInterval returns the window since the previous call and starts a new one.
func TakeInterval() IntervalWindow {
	return defaultRegistry.TakeInterval()
}

func (r *Registry) TakeInterval() IntervalWindow {
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.interval
	r.interval = newIntervalWindow()
	return w
}
