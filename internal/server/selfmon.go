package server

import (
	"context"
	"log"
	"math"
	"os"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/metricsdb"
	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

// SelfMonitorOptions wires the control plane's self-monitoring history.
type SelfMonitorOptions struct {
	// DB is the metrics store (metrics.db beside state.json). Nil keeps no
	// history: the System page and node history answer 503, and nothing is
	// sampled.
	DB *metricsdb.DB
	// Unavailable is why DB is nil when a data directory was configured
	// (metrics.db could not be opened); the 503 carries it. Empty means the
	// server runs without a data directory.
	Unavailable string
	// DataDir is the directory whose volume's used and free space is
	// recorded.
	DataDir string
	// Files are the data files whose sizes are recorded, by label.
	Files []MonitoredFile
}

// MonitoredFile is one data file the self-monitor records the size of.
type MonitoredFile struct {
	Label string `json:"label"`
	Path  string `json:"path"`
}

// Owners and series names in the metrics store. Owner is the unit of
// deletion: a node's or a plugin's history goes with it.
const (
	selfMonOwnerCP           = "cp"
	selfMonOwnerHTTP         = "cp.http"
	selfMonOwnerStore        = "cp.store"
	selfMonOwnerPluginPrefix = "plugin/"
	selfMonOwnerNodePrefix   = "node/"

	selfMonSampleEvery = 10 * time.Second
	selfMonFlushEvery  = time.Minute
	selfMonPruneEvery  = time.Hour
	// selfMonSeriesPruneEvery is how often series with no point left are
	// dropped from the catalog; it reads every row, so it runs daily.
	selfMonSeriesPruneEvery = 24 * time.Hour
	// selfMonPluginGrace is how long a plugin that is no longer loaded keeps
	// its history: a bundle that failed verification at one boot and comes
	// back at the next has not been deleted.
	selfMonPluginGrace = 30 * 24 * time.Hour
)

// Series names. The unit of each is in selfMonUnit.
const (
	seriesProcCPU        = "proc.cpu"
	seriesProcRSS        = "proc.rss"
	seriesProcHeap       = "proc.heap"
	seriesProcGoTotal    = "proc.go_total"
	seriesProcGoroutines = "proc.goroutines"
	seriesProcGCPause    = "proc.gc_pause_max"
	seriesProcFDs        = "proc.fds"
	seriesHostLoad1      = "host.load1"
	seriesHostMemUsed    = "host.mem_used"
	seriesHostMemTotal   = "host.mem_total"
	seriesHostDiskUsed   = "host.disk_used"
	seriesHostDiskFree   = "host.disk_free"
	seriesHostDiskTotal  = "host.disk_total"
	seriesFilePrefix     = "file."
	seriesMetricsWrite   = "metricsdb.write"
	seriesAuditAppend    = "audit.append"

	seriesNodeCPU     = "cpu"
	seriesNodeMem     = "mem"
	seriesNodeDisk    = "disk"
	seriesNodeLoad1   = "load1"
	seriesNodeRx      = "net_rx"
	seriesNodeTx      = "net_tx"
	seriesNodeBeatGap = "beat_gap"

	// A plugin owner's process series, beside its method (event) series.
	seriesPluginProcessCPU = "process.cpu"
	seriesPluginProcessRSS = "process.max_rss"
)

// selfMonUnit names the unit a series is recorded in, for the console.
func selfMonUnit(owner, name string) string {
	switch {
	case strings.HasPrefix(owner, selfMonOwnerPluginPrefix) && name == seriesPluginProcessRSS:
		return "bytes"
	case owner == selfMonOwnerHTTP || owner == selfMonOwnerStore || strings.HasPrefix(owner, selfMonOwnerPluginPrefix):
		return "seconds"
	case strings.HasPrefix(owner, selfMonOwnerNodePrefix):
		switch name {
		case seriesNodeCPU, seriesNodeMem, seriesNodeDisk:
			return "percent"
		case seriesNodeLoad1:
			return "load"
		case seriesNodeRx, seriesNodeTx:
			return "bytes_per_second"
		case seriesNodeBeatGap:
			return "seconds"
		}
	case owner == selfMonOwnerCP:
		switch {
		case name == seriesProcCPU:
			return "percent"
		case name == seriesProcGoroutines || name == seriesProcFDs:
			return "count"
		case name == seriesProcGCPause || name == seriesMetricsWrite || name == seriesAuditAppend:
			return "seconds"
		case name == seriesHostLoad1:
			return "load"
		case strings.HasPrefix(name, "proc.") || strings.HasPrefix(name, "host.") || strings.HasPrefix(name, seriesFilePrefix):
			return "bytes"
		}
	}
	return ""
}

type gaugeKey struct {
	owner string
	name  string
}

// selfSample is one reading of the process and the host. A field whose Have
// flag is false could not be read on this platform.
type selfSample struct {
	At         time.Time
	CPUPercent float64
	HaveCPU    bool
	RSS        uint64
	HaveRSS    bool
	Heap       uint64
	GoTotal    uint64
	Goroutines int
	GCPauseMax float64
	FDs        int
	HaveFDs    bool
	Load1      float64
	Load5      float64
	Load15     float64
	HaveLoad   bool
	MemTotal   uint64
	MemAvail   uint64
	HaveMem    bool
	DiskTotal  uint64
	DiskFree   uint64
	DiskUsed   uint64
	HaveDisk   bool
}

// selfMonitor samples the control plane's process and host every
// selfMonSampleEvery, folds node beats in as they arrive, and once a minute
// writes all of it, with the telemetry window (store writes, route groups,
// plugin calls), into the metrics store in one transaction.
type selfMonitor struct {
	db           *metricsdb.DB
	dataDir      string
	files        []MonitoredFile
	logger       *log.Logger
	now          func() time.Time
	nodeExists   func(id string) bool
	pluginLoaded func(id string) bool
	startedAt    time.Time

	mu        sync.Mutex
	gauges    map[gaugeKey]*metricsdb.Gauge
	lastBeat  map[string]time.Time
	latest    selfSample
	cpuPrev   float64
	cpuPrevAt time.Time
	gcPrev    []uint64
	// minute is the start of the minute being collected.
	minute          time.Time
	lastWrite       metricsdb.WriteResult
	lastWriteAt     time.Time
	lastWriteErr    string
	lastPrune       time.Time
	lastSeriesPrune time.Time
	fileSizes       map[string]int64

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

func newSelfMonitor(opts SelfMonitorOptions, logger *log.Logger, now func() time.Time, nodeExists, pluginLoaded func(string) bool) *selfMonitor {
	if opts.DB == nil {
		return nil
	}
	files := append([]MonitoredFile(nil), opts.Files...)
	files = append(files, MonitoredFile{Label: "metrics.db", Path: opts.DB.Path()})
	m := &selfMonitor{
		db:           opts.DB,
		dataDir:      opts.DataDir,
		files:        files,
		logger:       logger,
		now:          now,
		nodeExists:   nodeExists,
		pluginLoaded: pluginLoaded,
		startedAt:    now(),
		gauges:       map[gaugeKey]*metricsdb.Gauge{},
		lastBeat:     map[string]time.Time{},
		fileSizes:    map[string]int64{},
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	m.minute = m.startedAt.Truncate(selfMonFlushEvery)
	return m
}

func (m *selfMonitor) observeLocked(owner, name string, v float64) {
	k := gaugeKey{owner, name}
	g := m.gauges[k]
	if g == nil {
		g = &metricsdb.Gauge{}
		m.gauges[k] = g
	}
	g.Observe(v)
}

// observeBeat records one node heartbeat received at now: the gap since the
// node's previous beat that this process heard, and the metrics the beat
// carried when it carried a sample. The first beat after a restart has no gap:
// the time the control plane itself was down is not the node's.
func (m *selfMonitor) observeBeat(nodeID string, metrics model.Metrics, now time.Time) {
	if m == nil || nodeID == "" {
		return
	}
	owner := selfMonOwnerNodePrefix + nodeID
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.lastBeat[nodeID]; ok && now.After(prev) {
		m.observeLocked(owner, seriesNodeBeatGap, now.Sub(prev).Seconds())
	}
	m.lastBeat[nodeID] = now
	if metrics.CollectedAt.IsZero() {
		return
	}
	m.observeLocked(owner, seriesNodeCPU, metrics.CPUPercent)
	if metrics.MemoryTotal > 0 {
		m.observeLocked(owner, seriesNodeMem, 100*float64(metrics.MemoryUsed)/float64(metrics.MemoryTotal))
	}
	if metrics.DiskTotal > 0 {
		m.observeLocked(owner, seriesNodeDisk, 100*float64(metrics.DiskUsed)/float64(metrics.DiskTotal))
	}
	m.observeLocked(owner, seriesNodeLoad1, metrics.Load1)
	m.observeLocked(owner, seriesNodeRx, metrics.NetRxSpeed)
	m.observeLocked(owner, seriesNodeTx, metrics.NetTxSpeed)
}

// forgetNode drops a deleted node's history and anything still collected
// for it this minute, so the next flush cannot bring the owner back.
func (m *selfMonitor) forgetNode(nodeID string) (int, error) {
	if m == nil {
		return 0, nil
	}
	owner := selfMonOwnerNodePrefix + nodeID
	m.mu.Lock()
	for k := range m.gauges {
		if k.owner == owner {
			delete(m.gauges, k)
		}
	}
	delete(m.lastBeat, nodeID)
	m.mu.Unlock()
	return m.db.DeleteOwner(owner)
}

var selfMonRuntimeSamples = []string{
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/total:bytes",
	"/sched/goroutines:goroutines",
	"/sched/pauses/total/gc:seconds",
}

// sample reads the process and the host once and folds the reading into the
// minute being collected.
func (m *selfMonitor) sample(now time.Time) selfSample {
	s := selfSample{At: now}
	rs := make([]metrics.Sample, len(selfMonRuntimeSamples))
	for i, name := range selfMonRuntimeSamples {
		rs[i].Name = name
	}
	metrics.Read(rs)
	var gcCounts []uint64
	var gcBuckets []float64
	for _, r := range rs {
		switch r.Name {
		case "/memory/classes/heap/objects:bytes":
			if r.Value.Kind() == metrics.KindUint64 {
				s.Heap = r.Value.Uint64()
			}
		case "/memory/classes/total:bytes":
			if r.Value.Kind() == metrics.KindUint64 {
				s.GoTotal = r.Value.Uint64()
			}
		case "/sched/goroutines:goroutines":
			if r.Value.Kind() == metrics.KindUint64 {
				s.Goroutines = int(r.Value.Uint64())
			}
		case "/sched/pauses/total/gc:seconds":
			if r.Value.Kind() == metrics.KindFloat64Histogram {
				h := r.Value.Float64Histogram()
				gcCounts, gcBuckets = h.Counts, h.Buckets
			}
		}
	}
	if s.Goroutines == 0 {
		s.Goroutines = runtime.NumGoroutine()
	}
	s.RSS, s.HaveRSS = processRSS()
	s.FDs, s.HaveFDs = openFDs()
	s.Load1, s.Load5, s.Load15, s.HaveLoad = hostLoad()
	s.MemTotal, s.MemAvail, s.HaveMem = hostMemory()
	if m.dataDir != "" {
		s.DiskTotal, s.DiskFree, s.DiskUsed, s.HaveDisk = volumeBytes(m.dataDir)
	}
	cpu, haveCPU := processCPUSeconds()

	m.mu.Lock()
	defer m.mu.Unlock()
	if haveCPU {
		if !m.cpuPrevAt.IsZero() && now.After(m.cpuPrevAt) {
			s.CPUPercent = max(0, 100*(cpu-m.cpuPrev)/now.Sub(m.cpuPrevAt).Seconds())
			s.HaveCPU = true
		}
		m.cpuPrev, m.cpuPrevAt = cpu, now
	}
	// The largest GC pause since the previous sample: the highest histogram
	// bucket that gained a count, read at its upper bound.
	if gcCounts != nil {
		if len(m.gcPrev) == len(gcCounts) {
			for i := len(gcCounts) - 1; i >= 0; i-- {
				if gcCounts[i] > m.gcPrev[i] {
					upper := gcBuckets[i+1]
					if math.IsInf(upper, 1) {
						upper = gcBuckets[i]
					}
					s.GCPauseMax = upper
					break
				}
			}
		}
		m.gcPrev = append(m.gcPrev[:0], gcCounts...)
	}
	cp := selfMonOwnerCP
	if s.HaveCPU {
		m.observeLocked(cp, seriesProcCPU, s.CPUPercent)
	}
	if s.HaveRSS {
		m.observeLocked(cp, seriesProcRSS, float64(s.RSS))
	}
	m.observeLocked(cp, seriesProcHeap, float64(s.Heap))
	m.observeLocked(cp, seriesProcGoTotal, float64(s.GoTotal))
	m.observeLocked(cp, seriesProcGoroutines, float64(s.Goroutines))
	m.observeLocked(cp, seriesProcGCPause, s.GCPauseMax)
	if s.HaveFDs {
		m.observeLocked(cp, seriesProcFDs, float64(s.FDs))
	}
	if s.HaveLoad {
		m.observeLocked(cp, seriesHostLoad1, s.Load1)
	}
	if s.HaveMem {
		m.observeLocked(cp, seriesHostMemUsed, float64(s.MemTotal-min(s.MemAvail, s.MemTotal)))
		m.observeLocked(cp, seriesHostMemTotal, float64(s.MemTotal))
	}
	if s.HaveDisk {
		m.observeLocked(cp, seriesHostDiskUsed, float64(s.DiskUsed))
		m.observeLocked(cp, seriesHostDiskFree, float64(s.DiskFree))
		m.observeLocked(cp, seriesHostDiskTotal, float64(s.DiskTotal))
	}
	m.latest = s
	return s
}

// flushDue writes the collected minute when now has moved past it. final
// writes the minute still being collected, for shutdown: the next process
// merges its own first minute into the same bucket.
func (m *selfMonitor) flushDue(now time.Time, final bool) {
	m.mu.Lock()
	minute := m.minute
	current := now.Truncate(selfMonFlushEvery)
	if !final && !current.After(minute) {
		m.mu.Unlock()
		return
	}
	m.minute = current
	gauges := m.gauges
	m.gauges = map[gaugeKey]*metricsdb.Gauge{}
	lastWrite := m.lastWrite
	hadWrite := !m.lastWriteAt.IsZero()
	m.mu.Unlock()

	window := telemetry.TakeInterval()
	samples := make([]metricsdb.Sample, 0, len(gauges)+len(window.Routes)+len(window.StoreSaves)+len(window.Plugins)+16)
	for k, g := range gauges {
		samples = append(samples, metricsdb.Sample{Owner: k.owner, Name: k.name, Kind: metricsdb.KindGauge, Gauge: *g})
	}
	sizes := map[string]int64{}
	for _, f := range m.files {
		fi, err := os.Stat(f.Path)
		if err != nil {
			continue
		}
		sizes[f.Label] = fi.Size()
		var g metricsdb.Gauge
		g.Observe(float64(fi.Size()))
		samples = append(samples, metricsdb.Sample{Owner: selfMonOwnerCP, Name: seriesFilePrefix + f.Label, Kind: metricsdb.KindGauge, Gauge: g})
	}
	if hadWrite {
		var g metricsdb.Gauge
		g.Observe(lastWrite.Duration.Seconds())
		samples = append(samples, metricsdb.Sample{Owner: selfMonOwnerCP, Name: seriesMetricsWrite, Kind: metricsdb.KindGauge, Gauge: g})
	}
	if window.AuditAppends.Count > 0 {
		e := window.AuditAppends
		samples = append(samples, metricsdb.Sample{Owner: selfMonOwnerCP, Name: seriesAuditAppend, Kind: metricsdb.KindEvent, Event: &e})
	}
	for caller, e := range window.StoreSaves {
		samples = append(samples, metricsdb.Sample{Owner: selfMonOwnerStore, Name: caller, Kind: metricsdb.KindEvent, Event: e})
	}
	for group, e := range window.Routes {
		samples = append(samples, metricsdb.Sample{Owner: selfMonOwnerHTTP, Name: group, Kind: metricsdb.KindEvent, Event: e})
	}
	for key, e := range window.Plugins {
		samples = append(samples, metricsdb.Sample{Owner: selfMonOwnerPluginPrefix + key.Plugin, Name: key.Method, Kind: metricsdb.KindEvent, Event: e})
	}
	for pluginID, u := range window.PluginProcesses {
		owner := selfMonOwnerPluginPrefix + pluginID
		samples = append(samples,
			metricsdb.Sample{Owner: owner, Name: seriesPluginProcessCPU, Kind: metricsdb.KindGauge, Gauge: u.CPU},
			metricsdb.Sample{Owner: owner, Name: seriesPluginProcessRSS, Kind: metricsdb.KindGauge, Gauge: u.RSS})
	}
	res, err := m.db.Write(minute, samples)
	m.mu.Lock()
	m.fileSizes = sizes
	if err != nil {
		if m.lastWriteErr != err.Error() {
			m.logger.Printf("metrics store: write %s: %v", minute.Format(time.RFC3339), err)
		}
		m.lastWriteErr = err.Error()
	} else {
		if m.lastWriteErr != "" {
			m.logger.Printf("metrics store: writing again after: %s", m.lastWriteErr)
		}
		m.lastWrite, m.lastWriteAt, m.lastWriteErr = res, now, ""
		// Once per series, not once a minute for as long as it is refused.
		for _, r := range res.NewlyRefused {
			m.logger.Printf("metrics store: series %q of %q is not stored: %s", r.Name, r.Owner, selfMonRefusedReason(r.Reason))
		}
		if res.Late > 0 {
			m.logger.Printf("metrics store: the minute %s arrived after the store had moved past it (a clock stepped back?); %d samples were not stored", minute.Format(time.RFC3339), res.Late)
		}
	}
	prune := !final && now.Sub(m.lastPrune) >= selfMonPruneEvery
	if prune {
		m.lastPrune = now
	}
	pruneSeries := prune && now.Sub(m.lastSeriesPrune) >= selfMonSeriesPruneEvery
	if pruneSeries {
		m.lastSeriesPrune = now
	}
	m.mu.Unlock()
	if prune {
		m.prune(now, pruneSeries)
	}
}

func selfMonRefusedReason(reason string) string {
	switch reason {
	case metricsdb.RefusedTotalCap:
		return "the store's series cap is full (LATTICE_METRICS_MAX_SERIES raises it)"
	case metricsdb.RefusedOwnerCap:
		return "its owner has reached the per-owner series cap"
	case metricsdb.RefusedKindMismatch:
		return "it is already recorded as the other kind"
	default:
		return "its owner or name is not valid"
	}
}

// prune deletes the history of owners that are gone: a node no longer in the
// store at once, a plugin no longer loaded once its newest point is older
// than selfMonPluginGrace. With series set it also drops the series that no
// longer have a point anywhere, so they stop counting against the caps.
func (m *selfMonitor) prune(now time.Time, series bool) {
	if series {
		if n, err := m.db.PruneIdleSeries(); err != nil {
			m.logger.Printf("metrics store: prune idle series: %v", err)
		} else if n > 0 {
			m.logger.Printf("metrics store: dropped %d series with no point left from the catalog", n)
		}
	}
	gone, err := m.db.PruneOwners(func(owner string, newest time.Time) bool {
		switch {
		case strings.HasPrefix(owner, selfMonOwnerNodePrefix):
			return m.nodeExists != nil && !m.nodeExists(strings.TrimPrefix(owner, selfMonOwnerNodePrefix))
		case strings.HasPrefix(owner, selfMonOwnerPluginPrefix):
			id := strings.TrimPrefix(owner, selfMonOwnerPluginPrefix)
			return m.pluginLoaded != nil && !m.pluginLoaded(id) && now.Sub(newest) > selfMonPluginGrace
		}
		return false
	})
	if err != nil {
		m.logger.Printf("metrics store: prune: %v", err)
	}
	if len(gone) > 0 {
		m.logger.Printf("metrics store: removed the history of %s", strings.Join(gone, ", "))
	}
}

// start runs the sampler on ten-second boundaries, so the minute flush lands
// just after the minute closes.
func (m *selfMonitor) start() {
	go func() {
		defer close(m.done)
		m.sample(m.now())
		wait := selfMonSampleEvery - time.Duration(m.now().UnixNano())%selfMonSampleEvery + 500*time.Millisecond
		timer := time.NewTimer(wait)
		defer timer.Stop()
		for {
			select {
			case <-m.stop:
				m.sample(m.now())
				m.flushDue(m.now(), true)
				return
			case <-timer.C:
				now := m.now()
				m.flushDue(now, false)
				m.sample(now)
				timer.Reset(selfMonSampleEvery - time.Duration(m.now().UnixNano())%selfMonSampleEvery + 500*time.Millisecond)
			}
		}
	}()
}

// close stops the sampler after it writes the minute in progress, and
// returns when that write is done or ctx ends. A sampler that never started
// has nothing to write.
func (m *selfMonitor) close(ctx context.Context, started bool) {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() { close(m.stop) })
	if !started {
		return
	}
	select {
	case <-m.done:
	case <-ctx.Done():
	}
}

// snapshot is the latest reading and the last write, for the System page.
func (m *selfMonitor) snapshot() (selfSample, metricsdb.WriteResult, time.Time, string, map[string]int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sizes := make(map[string]int64, len(m.fileSizes))
	for k, v := range m.fileSizes {
		sizes[k] = v
	}
	return m.latest, m.lastWrite, m.lastWriteAt, m.lastWriteErr, sizes
}
