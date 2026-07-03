package telemetry

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var defaultRegistry = NewRegistry()

type Registry struct {
	mu       sync.Mutex
	started  time.Time
	store    map[string]*durationStats
	audit    map[string]uint64
	http     map[httpKey]*durationStats
	httpSlow map[string]uint64
	agent    map[httpKey]*durationStats
}

type durationStats struct {
	Count uint64
	Sum   time.Duration
	Max   time.Duration
}

type httpKey struct {
	Path        string
	StatusClass string
}

type Snapshot struct {
	StartedAt time.Time
	Uptime    time.Duration
	Store     map[string]durationStats
	Audit     map[string]uint64
	HTTP      map[httpKey]durationStats
	HTTPSlow  map[string]uint64
	Agent     map[httpKey]durationStats
}

func NewRegistry() *Registry {
	return &Registry{
		started:  time.Now(),
		store:    map[string]*durationStats{},
		audit:    map[string]uint64{},
		http:     map[httpKey]*durationStats{},
		httpSlow: map[string]uint64{},
		agent:    map[httpKey]*durationStats{},
	}
}

func ResetForTest() {
	defaultRegistry.Reset()
}

func ObserveStoreSave(d time.Duration, err error) {
	defaultRegistry.ObserveStoreSave(d, err)
}

func ObserveAuditAppend(err error) {
	defaultRegistry.ObserveAuditAppend(err)
}

func ObserveHTTPRequest(path string, status int, d time.Duration, slow bool) {
	defaultRegistry.ObserveHTTPRequest(path, status, d, slow)
}

func ObserveAgentRequest(path string, status int, d time.Duration) {
	defaultRegistry.ObserveAgentRequest(path, status, d)
}

func Prometheus() string {
	return defaultRegistry.Prometheus()
}

func CurrentSnapshot() Snapshot {
	return defaultRegistry.Snapshot()
}

func (r *Registry) ObserveStoreSave(d time.Duration, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	observeDuration(r.store, result, d)
}

func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = time.Now()
	r.store = map[string]*durationStats{}
	r.audit = map[string]uint64{}
	r.http = map[httpKey]*durationStats{}
	r.httpSlow = map[string]uint64{}
	r.agent = map[httpKey]*durationStats{}
}

func (r *Registry) ObserveAuditAppend(err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audit[result]++
}

func (r *Registry) ObserveHTTPRequest(path string, status int, d time.Duration, slow bool) {
	path = normalizePath(path)
	key := httpKey{Path: path, StatusClass: statusClass(status)}
	r.mu.Lock()
	defer r.mu.Unlock()
	observeDurationKey(r.http, key, d)
	if slow {
		r.httpSlow[path]++
	}
}

func (r *Registry) ObserveAgentRequest(path string, status int, d time.Duration) {
	path = normalizePath(path)
	key := httpKey{Path: path, StatusClass: statusClass(status)}
	r.mu.Lock()
	defer r.mu.Unlock()
	observeDurationKey(r.agent, key, d)
}

func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Snapshot{
		StartedAt: r.started,
		Uptime:    time.Since(r.started),
		Store:     copyDurationMap(r.store),
		Audit:     copyCounterMap(r.audit),
		HTTP:      copyHTTPMap(r.http),
		HTTPSlow:  copyCounterMap(r.httpSlow),
		Agent:     copyHTTPMap(r.agent),
	}
}

func (r *Registry) Prometheus() string {
	snap := r.Snapshot()
	var b strings.Builder
	writeLine(&b, "# HELP lattice_process_uptime_seconds Server process uptime.")
	writeLine(&b, "# TYPE lattice_process_uptime_seconds gauge")
	writeLine(&b, "lattice_process_uptime_seconds %.6f", snap.Uptime.Seconds())

	writeLine(&b, "# HELP lattice_store_save_total Store Save calls by result.")
	writeLine(&b, "# TYPE lattice_store_save_total counter")
	writeLine(&b, "# HELP lattice_store_save_duration_seconds Store Save latency by result.")
	writeLine(&b, "# TYPE lattice_store_save_duration_seconds summary")
	for _, result := range sortedDurationKeys(snap.Store) {
		st := snap.Store[result]
		labels := fmt.Sprintf(`result="%s"`, escapeLabel(result))
		writeLine(&b, "lattice_store_save_total{%s} %d", labels, st.Count)
		writeLine(&b, "lattice_store_save_duration_seconds_count{%s} %d", labels, st.Count)
		writeLine(&b, "lattice_store_save_duration_seconds_sum{%s} %.9f", labels, st.Sum.Seconds())
		writeLine(&b, "lattice_store_save_duration_seconds_max{%s} %.9f", labels, st.Max.Seconds())
	}

	writeLine(&b, "# HELP lattice_audit_append_total Audit append attempts by result.")
	writeLine(&b, "# TYPE lattice_audit_append_total counter")
	for _, result := range sortedCounterKeys(snap.Audit) {
		writeLine(&b, "lattice_audit_append_total{result=\"%s\"} %d", escapeLabel(result), snap.Audit[result])
	}

	writeHTTPMetrics(&b, "lattice_http", "HTTP requests", snap.HTTP)
	writeLine(&b, "# HELP lattice_http_slow_requests_total HTTP requests at or above the configured slow-request threshold.")
	writeLine(&b, "# TYPE lattice_http_slow_requests_total counter")
	for _, path := range sortedCounterKeys(snap.HTTPSlow) {
		writeLine(&b, "lattice_http_slow_requests_total{path=\"%s\"} %d", escapeLabel(path), snap.HTTPSlow[path])
	}

	writeHTTPMetrics(&b, "lattice_agent", "Agent endpoint requests", snap.Agent)
	return b.String()
}

func writeHTTPMetrics(b *strings.Builder, prefix, help string, values map[httpKey]durationStats) {
	writeLine(b, "# HELP %s_requests_total %s by normalized path and status class.", prefix, help)
	writeLine(b, "# TYPE %s_requests_total counter", prefix)
	writeLine(b, "# HELP %s_request_duration_seconds %s latency by normalized path and status class.", prefix, help)
	writeLine(b, "# TYPE %s_request_duration_seconds summary", prefix)
	for _, key := range sortedHTTPKeys(values) {
		st := values[key]
		labels := fmt.Sprintf(`path="%s",status_class="%s"`, escapeLabel(key.Path), escapeLabel(key.StatusClass))
		writeLine(b, "%s_requests_total{%s} %d", prefix, labels, st.Count)
		writeLine(b, "%s_request_duration_seconds_count{%s} %d", prefix, labels, st.Count)
		writeLine(b, "%s_request_duration_seconds_sum{%s} %.9f", prefix, labels, st.Sum.Seconds())
		writeLine(b, "%s_request_duration_seconds_max{%s} %.9f", prefix, labels, st.Max.Seconds())
	}
}

func observeDuration(values map[string]*durationStats, key string, d time.Duration) {
	st := values[key]
	if st == nil {
		st = &durationStats{}
		values[key] = st
	}
	st.Count++
	st.Sum += d
	if d > st.Max {
		st.Max = d
	}
}

func observeDurationKey(values map[httpKey]*durationStats, key httpKey, d time.Duration) {
	st := values[key]
	if st == nil {
		st = &durationStats{}
		values[key] = st
	}
	st.Count++
	st.Sum += d
	if d > st.Max {
		st.Max = d
	}
}

func copyDurationMap(in map[string]*durationStats) map[string]durationStats {
	out := make(map[string]durationStats, len(in))
	for k, v := range in {
		out[k] = *v
	}
	return out
}

func copyHTTPMap(in map[httpKey]*durationStats) map[httpKey]durationStats {
	out := make(map[httpKey]durationStats, len(in))
	for k, v := range in {
		out[k] = *v
	}
	return out
}

func copyCounterMap(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedDurationKeys(values map[string]durationStats) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedCounterKeys(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedHTTPKeys(values map[httpKey]durationStats) []httpKey {
	keys := make([]httpKey, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Path == keys[j].Path {
			return keys[i].StatusClass < keys[j].StatusClass
		}
		return keys[i].Path < keys[j].Path
	})
	return keys
}

func statusClass(status int) string {
	if status < 100 {
		return "unknown"
	}
	return fmt.Sprintf("%dxx", status/100)
}

func normalizePath(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/agent/terminal/sessions/"):
		return "/api/agent/terminal/sessions/:id/:action"
	case strings.HasPrefix(path, "/api/terminal/sessions/"):
		return "/api/terminal/sessions/:id/:action"
	case strings.HasPrefix(path, "/sub/"):
		return "/sub/:token"
	case strings.HasPrefix(path, "/assets/"):
		return "/assets/:asset"
	default:
		if path == "" {
			return "/"
		}
		return path
	}
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func writeLine(b *strings.Builder, format string, args ...any) {
	fmt.Fprintf(b, format, args...)
	b.WriteByte('\n')
}
