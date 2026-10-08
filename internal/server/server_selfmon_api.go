package server

import (
	"errors"
	"math"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/metricsdb"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// The self-monitoring reads. Node history is a node read (node:read on that
// node, the node allowlist applies). Everything about the control plane's
// own internals (its process and host, data files, store writes, route
// groups, plugin calls, the metrics store) is for a full administrator only:
// scope "*" held by name and no node restriction. A token minted for one
// area of the fleet has no business reading the host's memory or which
// plugin is slow.

// metricsRanges are the named ranges the console offers.
var metricsRanges = map[string]time.Duration{
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour,
	"1y":  365 * 24 * time.Hour,
	"5y":  1826 * 24 * time.Hour,
}

// systemHealthSparkPoints is how many buckets a table row's sparkline has.
const systemHealthSparkPoints = 48

// The 503 codes of the self-monitoring reads. writeError replaces every 5xx
// message with a generic one, so the code is what tells the console which
// case it is; the detail of a store that would not open is in the log.
const (
	// apiErrorMetricsDisabled: the server runs without a data directory.
	apiErrorMetricsDisabled = "metrics_disabled"
	// apiErrorMetricsUnavailable: metrics.db could not be opened.
	apiErrorMetricsUnavailable = "metrics_unavailable"
)

// metricsUnavailable is the 503 answer when no metrics store is wired.
func (s *Server) metricsUnavailable() error {
	if s.selfmonUnavailable != "" {
		return apiError(apiErrorMetricsUnavailable, s.selfmonUnavailable)
	}
	return apiError(apiErrorMetricsDisabled, "this server keeps no metrics history (it runs without a data directory)")
}

func (s *Server) requireFullAdmin(w http.ResponseWriter, p principal, action string) bool {
	if rbac.HoldsExplicitScope(p.Scopes, "*") && !principalHasNodeRestriction(p) {
		return true
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: action, Scope: "*", Decision: "deny",
		Reason: "control-plane internals need a full administrator (scope *, no node restriction)",
	})
	writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "control-plane internals need a full administrator (scope *, no node restriction)"))
	return false
}

// parseMetricsWindow reads range (a name from metricsRanges, default def) or
// from and to (RFC 3339 or unix seconds), and points.
func parseMetricsWindow(q url.Values, now time.Time, def string) (from, to time.Time, label string, points int, err error) {
	to = now
	label = strings.TrimSpace(q.Get("range"))
	if label == "" {
		label = def
	}
	span, ok := metricsRanges[label]
	if !ok {
		return from, to, label, 0, errors.New("range must be one of 1h, 6h, 24h, 7d, 30d, 90d, 1y, 5y")
	}
	from = to.Add(-span)
	parseInstant := func(v string) (time.Time, error) {
		if unix, err := strconv.ParseInt(v, 10, 64); err == nil {
			return time.Unix(unix, 0).UTC(), nil
		}
		return time.Parse(time.RFC3339, v)
	}
	if v := strings.TrimSpace(q.Get("from")); v != "" {
		if from, err = parseInstant(v); err != nil {
			return from, to, label, 0, errors.New("from must be RFC 3339 or unix seconds")
		}
		label = ""
	}
	if v := strings.TrimSpace(q.Get("to")); v != "" {
		if to, err = parseInstant(v); err != nil {
			return from, to, label, 0, errors.New("to must be RFC 3339 or unix seconds")
		}
		label = ""
	}
	if !from.Before(to) {
		return from, to, label, 0, errors.New("from must be before to")
	}
	if v := strings.TrimSpace(q.Get("points")); v != "" {
		points, err = strconv.Atoi(v)
		if err != nil || points < 1 || points > metricsdb.MaxPoints {
			return from, to, label, 0, errors.New("points must be 1 to 2000")
		}
	}
	return from, to, label, points, nil
}

// compactFloats encodes with six significant digits: a chart cannot show
// more, and it keeps a 360-point series small. A value JSON cannot carry
// (NaN, an infinity) is written as null, so one bad value costs a point and
// never the whole answer.
type compactFloats []float64

func (f compactFloats) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, 2+len(f)*8)
	b = append(b, '[')
	for i, v := range f {
		if i > 0 {
			b = append(b, ',')
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			b = append(b, "null"...)
			continue
		}
		b = strconv.AppendFloat(b, v, 'g', 6, 64)
	}
	return append(b, ']'), nil
}

type metricsSeriesView struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Unit string `json:"unit,omitempty"`
	// T is each bucket's start, unix seconds. A bucket nothing was recorded
	// in is absent, so consecutive T values further apart than step_seconds
	// are a gap.
	T []int64 `json:"t"`
	// Avg, Min and Max are the samples' (a gauge) or the durations'
	// (an event, in seconds); N counts samples or events.
	Avg compactFloats `json:"avg"`
	Min compactFloats `json:"min"`
	Max compactFloats `json:"max"`
	N   []uint32      `json:"n"`
	// E, P50 and P95 are an event series' failures and duration quantiles.
	E   []uint32      `json:"e,omitempty"`
	P50 compactFloats `json:"p50,omitempty"`
	P95 compactFloats `json:"p95,omitempty"`
}

type metricsQueryView struct {
	Owner             string              `json:"owner"`
	Tier              string              `json:"tier"`
	ResolutionSeconds int64               `json:"resolution_seconds"`
	StepSeconds       int64               `json:"step_seconds"`
	From              time.Time           `json:"from"`
	To                time.Time           `json:"to"`
	RetainedFrom      time.Time           `json:"retained_from"`
	Series            []metricsSeriesView `json:"series"`
}

func quantileOr(e *metricsdb.Event, q float64) float64 {
	v, ok := e.Quantile(q)
	if !ok {
		return 0
	}
	return v
}

func metricsSeries(owner string, sp metricsdb.SeriesPoints) metricsSeriesView {
	v := metricsSeriesView{Name: sp.Name, Kind: sp.Kind.String(), Unit: selfMonUnit(owner, sp.Name), T: []int64{}, Avg: compactFloats{}, Min: compactFloats{}, Max: compactFloats{}, N: []uint32{}}
	for _, p := range sp.Points {
		v.T = append(v.T, p.At.Unix())
		switch p.Kind {
		case metricsdb.KindGauge:
			v.Avg = append(v.Avg, p.Gauge.Avg())
			v.Min = append(v.Min, p.Gauge.Min)
			v.Max = append(v.Max, p.Gauge.Max)
			v.N = append(v.N, p.Gauge.Count)
		case metricsdb.KindEvent:
			e := p.Event
			v.Avg = append(v.Avg, e.Avg())
			v.Min = append(v.Min, e.Min)
			v.Max = append(v.Max, e.Max)
			v.N = append(v.N, e.Count)
			v.E = append(v.E, e.Errors)
			v.P50 = append(v.P50, quantileOr(e, 0.5))
			v.P95 = append(v.P95, quantileOr(e, 0.95))
		}
	}
	return v
}

func metricsQuery(res metricsdb.QueryResult) metricsQueryView {
	out := metricsQueryView{
		Owner:             res.Owner,
		Tier:              res.Tier.Name,
		ResolutionSeconds: int64(res.Tier.Res / time.Second),
		StepSeconds:       int64(res.Step / time.Second),
		From:              res.From,
		To:                res.To,
		RetainedFrom:      res.RetainedFrom,
		Series:            []metricsSeriesView{},
	}
	for _, sp := range res.Series {
		out.Series = append(out.Series, metricsSeries(res.Owner, sp))
	}
	return out
}

// handleNodeHistory answers GET /api/nodes/history?node_id=&range=: the
// node's long-term cpu, memory, disk, load, network and beat gap. withAuth
// has already checked node:read against node_id.
func (s *Server) handleNodeHistory(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if _, ok := s.store.Node(nodeID); !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if s.selfmon == nil {
		writeError(w, http.StatusServiceUnavailable, s.metricsUnavailable())
		return
	}
	from, to, _, points, err := parseMetricsWindow(r.URL.Query(), s.now(), "24h")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	res, err := s.selfmon.db.Query(selfMonOwnerNodePrefix+nodeID, nil, from, to, points)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, metricsQuery(res))
}

// handleSystemSeries answers GET /api/system/series?owner=&series=a,b&range=
// for the System page's charts. Full administrator only.
func (s *Server) handleSystemSeries(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireFullAdmin(w, p, "system.series") {
		return
	}
	if s.selfmon == nil {
		writeError(w, http.StatusServiceUnavailable, s.metricsUnavailable())
		return
	}
	q := r.URL.Query()
	owner := strings.TrimSpace(q.Get("owner"))
	if owner == "" {
		owner = selfMonOwnerCP
	}
	var names []string
	for _, name := range strings.Split(q.Get("series"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	if len(names) > 64 {
		writeError(w, http.StatusBadRequest, errors.New("at most 64 series at once"))
		return
	}
	from, to, _, points, err := parseMetricsWindow(q, s.now(), "24h")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	res, err := s.selfmon.db.Query(owner, names, from, to, points)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, metricsQuery(res))
}

type systemProcessView struct {
	StartedAt         time.Time `json:"started_at"`
	UptimeSeconds     int64     `json:"uptime_seconds"`
	Version           string    `json:"version"`
	Commit            string    `json:"commit"`
	GoVersion         string    `json:"go_version"`
	CPUs              int       `json:"cpus"`
	CPUPercent        *float64  `json:"cpu_percent,omitempty"`
	RSSBytes          *uint64   `json:"rss_bytes,omitempty"`
	HeapBytes         uint64    `json:"heap_bytes"`
	GoTotalBytes      uint64    `json:"go_total_bytes"`
	Goroutines        int       `json:"goroutines"`
	GCPauseMaxSeconds float64   `json:"gc_pause_max_seconds"`
	OpenFDs           *int      `json:"open_fds,omitempty"`
}

type systemHostView struct {
	Load1          *float64 `json:"load1,omitempty"`
	Load5          *float64 `json:"load5,omitempty"`
	Load15         *float64 `json:"load15,omitempty"`
	MemTotalBytes  *uint64  `json:"mem_total_bytes,omitempty"`
	MemAvailBytes  *uint64  `json:"mem_available_bytes,omitempty"`
	DataDir        string   `json:"data_dir,omitempty"`
	DiskTotalBytes *uint64  `json:"disk_total_bytes,omitempty"`
	DiskFreeBytes  *uint64  `json:"disk_free_bytes,omitempty"`
	DiskUsedBytes  *uint64  `json:"disk_used_bytes,omitempty"`
}

type systemSparkView struct {
	StepSeconds int64         `json:"step_seconds"`
	T           []int64       `json:"t"`
	N           []uint32      `json:"n"`
	E           []uint32      `json:"e,omitempty"`
	P95         compactFloats `json:"p95,omitempty"`
	Avg         compactFloats `json:"avg,omitempty"`
}

type systemEventRow struct {
	Plugin     string          `json:"plugin,omitempty"`
	Name       string          `json:"name"`
	Calls      uint64          `json:"calls"`
	Errors     uint64          `json:"errors"`
	PerMinute  float64         `json:"per_minute"`
	P50Seconds float64         `json:"p50_seconds"`
	P95Seconds float64         `json:"p95_seconds"`
	MaxSeconds float64         `json:"max_seconds"`
	AvgSeconds float64         `json:"avg_seconds"`
	Spark      systemSparkView `json:"spark"`
}

type systemFileRow struct {
	Label     string          `json:"label"`
	Path      string          `json:"path"`
	SizeBytes *int64          `json:"size_bytes,omitempty"`
	Spark     systemSparkView `json:"spark"`
}

type systemMetricsStoreView struct {
	metricsdb.Stats
	LastWriteAt    time.Time `json:"last_write_at,omitzero"`
	LastWriteError string    `json:"last_write_error,omitempty"`
	SampleSeconds  int64     `json:"sample_seconds"`
}

type systemHealthView struct {
	ObservedAt time.Time         `json:"observed_at"`
	Range      string            `json:"range"`
	From       time.Time         `json:"from"`
	To         time.Time         `json:"to"`
	Process    systemProcessView `json:"process"`
	Host       systemHostView    `json:"host"`
	Files      []systemFileRow   `json:"files"`
	Store      []systemEventRow  `json:"store"`
	HTTP       []systemEventRow  `json:"http"`
	Plugins    []systemEventRow  `json:"plugins"`
	// PluginProcesses is what each plugin's processes used over the range,
	// counted as they exited.
	PluginProcesses []systemPluginProcessRow `json:"plugin_processes"`
	MetricsStore    systemMetricsStoreView   `json:"metrics_store"`
	// Probe is lattice-probe's health as latticenet.vpn-core/probe health
	// reports it: available with the engine and core versions, or why not.
	Probe probeHealthView `json:"probe"`
}

type systemPluginProcessRow struct {
	Plugin       string  `json:"plugin"`
	Processes    uint64  `json:"processes"`
	CPUSeconds   float64 `json:"cpu_seconds"`
	PeakRSSBytes float64 `json:"peak_rss_bytes"`
}

func sparkOf(sp metricsdb.SeriesPoints, step time.Duration) systemSparkView {
	v := systemSparkView{StepSeconds: int64(step / time.Second), T: []int64{}, N: []uint32{}}
	for _, p := range sp.Points {
		v.T = append(v.T, p.At.Unix())
		switch p.Kind {
		case metricsdb.KindEvent:
			v.N = append(v.N, p.Event.Count)
			v.E = append(v.E, p.Event.Errors)
			v.P95 = append(v.P95, quantileOr(p.Event, 0.95))
		case metricsdb.KindGauge:
			v.N = append(v.N, p.Gauge.Count)
			v.Avg = append(v.Avg, p.Gauge.Avg())
		}
	}
	return v
}

// eventRows summarises one owner's event series over the window: totals and
// quantiles from Aggregate, the sparkline from a 48-point Query.
func (s *Server) eventRows(owner, plugin string, from, to time.Time) ([]systemEventRow, error) {
	db := s.selfmon.db
	agg, _, err := db.Aggregate(owner, nil, from, to)
	if err != nil {
		return nil, err
	}
	spark, err := db.Query(owner, nil, from, to, systemHealthSparkPoints)
	if err != nil {
		return nil, err
	}
	sparks := map[string]metricsdb.SeriesPoints{}
	for _, sp := range spark.Series {
		sparks[sp.Name] = sp
	}
	minutes := to.Sub(from).Minutes()
	rows := []systemEventRow{}
	for name, p := range agg {
		if p.Kind != metricsdb.KindEvent || p.Event == nil {
			continue
		}
		e := p.Event
		rows = append(rows, systemEventRow{
			Plugin:     plugin,
			Name:       name,
			Calls:      uint64(e.Count),
			Errors:     uint64(e.Errors),
			PerMinute:  float64(e.Count) / max(minutes, 1),
			P50Seconds: quantileOr(e, 0.5),
			P95Seconds: quantileOr(e, 0.95),
			MaxSeconds: e.Max,
			AvgSeconds: e.Avg(),
			Spark:      sparkOf(sparks[name], spark.Step),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Calls != rows[j].Calls {
			return rows[i].Calls > rows[j].Calls
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, nil
}

// handleSystemHealth answers GET /api/system/health?range=24h: the latest
// reading of the process and host, the data files with their size over the
// range, store writes by caller, route groups and plugin methods with call
// counts, failures and latency, and the metrics store's account of itself.
// Full administrator only.
func (s *Server) handleSystemHealth(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireFullAdmin(w, p, "system.health") {
		return
	}
	if s.selfmon == nil {
		writeError(w, http.StatusServiceUnavailable, s.metricsUnavailable())
		return
	}
	now := s.now()
	from, to, label, _, err := parseMetricsWindow(r.URL.Query(), now, "24h")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// The probe answers over its socket while the store is read, so a probe
	// that hangs costs this page its health timeout at most, once.
	probeHealth := make(chan probeHealthView, 1)
	go func() { probeHealth <- s.probe.health(r.Context(), false) }()
	m := s.selfmon
	latest, _, lastWriteAt, lastWriteErr, sizes := m.snapshot()
	view := systemHealthView{
		ObservedAt: now,
		Range:      label,
		From:       from,
		To:         to,
		Process: systemProcessView{
			StartedAt:         m.startedAt,
			UptimeSeconds:     int64(now.Sub(m.startedAt) / time.Second),
			Version:           s.build.ServerVersion,
			Commit:            s.build.ServerCommit,
			GoVersion:         runtime.Version(),
			CPUs:              runtime.NumCPU(),
			HeapBytes:         latest.Heap,
			GoTotalBytes:      latest.GoTotal,
			Goroutines:        latest.Goroutines,
			GCPauseMaxSeconds: latest.GCPauseMax,
		},
		Host:            systemHostView{DataDir: m.dataDir},
		Files:           []systemFileRow{},
		Plugins:         []systemEventRow{},
		PluginProcesses: []systemPluginProcessRow{},
	}
	if latest.HaveCPU {
		view.Process.CPUPercent = &latest.CPUPercent
	}
	if latest.HaveRSS {
		view.Process.RSSBytes = &latest.RSS
	}
	if latest.HaveFDs {
		view.Process.OpenFDs = &latest.FDs
	}
	if latest.HaveLoad {
		view.Host.Load1, view.Host.Load5, view.Host.Load15 = &latest.Load1, &latest.Load5, &latest.Load15
	}
	if latest.HaveMem {
		view.Host.MemTotalBytes, view.Host.MemAvailBytes = &latest.MemTotal, &latest.MemAvail
	}
	if latest.HaveDisk {
		view.Host.DiskTotalBytes, view.Host.DiskFreeBytes, view.Host.DiskUsedBytes = &latest.DiskTotal, &latest.DiskFree, &latest.DiskUsed
	}
	db := m.db
	fileNames := make([]string, 0, len(m.files))
	for _, f := range m.files {
		fileNames = append(fileNames, seriesFilePrefix+f.Label)
	}
	fileSpark, err := db.Query(selfMonOwnerCP, fileNames, from, to, systemHealthSparkPoints)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	fileSparks := map[string]metricsdb.SeriesPoints{}
	for _, sp := range fileSpark.Series {
		fileSparks[sp.Name] = sp
	}
	for _, f := range m.files {
		row := systemFileRow{Label: f.Label, Path: f.Path, Spark: sparkOf(fileSparks[seriesFilePrefix+f.Label], fileSpark.Step)}
		if size, ok := sizes[f.Label]; ok {
			row.SizeBytes = &size
		}
		view.Files = append(view.Files, row)
	}
	if view.Store, err = s.eventRows(selfMonOwnerStore, "", from, to); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if view.HTTP, err = s.eventRows(selfMonOwnerHTTP, "", from, to); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	owners, err := db.Owners()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for _, o := range owners {
		if !strings.HasPrefix(o.Owner, selfMonOwnerPluginPrefix) {
			continue
		}
		pluginID := strings.TrimPrefix(o.Owner, selfMonOwnerPluginPrefix)
		rows, err := s.eventRows(o.Owner, pluginID, from, to)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		view.Plugins = append(view.Plugins, rows...)
		usage, _, err := db.Aggregate(o.Owner, []string{seriesPluginProcessCPU, seriesPluginProcessRSS}, from, to)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if cpu, ok := usage[seriesPluginProcessCPU]; ok && cpu.Gauge.Count > 0 {
			view.PluginProcesses = append(view.PluginProcesses, systemPluginProcessRow{
				Plugin:       pluginID,
				Processes:    uint64(cpu.Gauge.Count),
				CPUSeconds:   cpu.Gauge.Sum,
				PeakRSSBytes: usage[seriesPluginProcessRSS].Gauge.Max,
			})
		}
	}
	sort.SliceStable(view.Plugins, func(i, j int) bool {
		if view.Plugins[i].Plugin != view.Plugins[j].Plugin {
			return view.Plugins[i].Plugin < view.Plugins[j].Plugin
		}
		return view.Plugins[i].Calls > view.Plugins[j].Calls
	})
	stats, err := db.Stats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	view.MetricsStore = systemMetricsStoreView{Stats: stats, LastWriteAt: lastWriteAt, LastWriteError: lastWriteErr, SampleSeconds: int64(selfMonSampleEvery / time.Second)}
	view.Probe = <-probeHealth
	writeJSON(w, http.StatusOK, view)
}
