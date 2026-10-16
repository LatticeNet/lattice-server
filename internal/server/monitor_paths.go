package server

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// Monitoring paths (design 29): one series read for every path and one
// matrix of every path the caller may read.
//
// A path is a (monitor, source) result pair. A generated latency path is
// addressed by (source, target node) and joins every generated check that
// reaches the target from the source, so its line continues across a method
// change; in this release only the tcp check (mon_lat_<target>) exists. An
// operator's check is addressed by (monitor, source); a tls check's source
// is the control plane, an empty node id.
//
// Where a window comes from:
//
//   - Series: the finest tier that covers the window (raw rows up to one
//     hour, five-minute rollups up to the fine retention, one-hour rollups
//     beyond), merged on the server into the smallest multiple of that
//     tier's resolution that keeps the series within 720 points and is no
//     shorter than the check's interval (pathSeriesStep).
//   - Matrix: raw rows for 1 h, five-minute rollups for 6 h and 24 h, one-hour
//     rollups from 3 d up. Each window's figures are cached until the
//     window's next bucket closes; states are judged on every read from the
//     pairs' latest records.
//
// Unknown stays unknown: a bucket with no runs where runs were expected is a
// gap, and a path with no current result is unknown with the reason when
// the control plane knows it. Neither is ever drawn as up.

const (
	// pathSeriesMaxPoints bounds a series, the partial step at its end
	// included.
	pathSeriesMaxPoints = 720
	// pathMatrixCoarseFrom is the shortest matrix window read from the
	// one-hour tier.
	pathMatrixCoarseFrom = 72 * time.Hour
	// pathStaleAfterRuns and pathStaleFloor decide when a path's newest
	// result no longer says what it is doing now.
	pathStaleAfterRuns = 3
	pathStaleFloor     = 2 * time.Minute
	// pathDownAfter is how many failures in a row read as down: the alert
	// hold's count (notifyMonitorTransition).
	pathDownAfter = 2
	// pathControlPlaneName names the source of tls checks in the matrix.
	pathControlPlaneName = "Control plane"
)

var pathWindows = []struct {
	name string
	span time.Duration
}{
	{model.PathWindowHour, time.Hour},
	{model.PathWindowSixHours, 6 * time.Hour},
	{model.PathWindowDay, 24 * time.Hour},
	{model.PathWindowThreeDays, 3 * 24 * time.Hour},
	{model.PathWindowWeek, 7 * 24 * time.Hour},
	{model.PathWindowTwoWeeks, 14 * 24 * time.Hour},
}

func pathWindowSpan(name string) (time.Duration, bool) {
	for _, w := range pathWindows {
		if w.name == name {
			return w.span, true
		}
	}
	return 0, false
}

func pathWindowNames() string {
	names := make([]string, 0, len(pathWindows))
	for _, w := range pathWindows {
		names = append(names, w.name)
	}
	return strings.Join(names, ", ")
}

// pathTier is where a series or a matrix window is read from.
type pathTier int

const (
	pathTierRaw pathTier = iota
	pathTierFine
	pathTierCoarse
)

// resolution is the tier's base step. Raw rows are folded at one minute.
func (t pathTier) resolution() time.Duration {
	switch t {
	case pathTierRaw:
		return time.Minute
	case pathTierFine:
		return store.MonitorRollupFine
	default:
		return store.MonitorRollupCoarse
	}
}

// pathSeriesStep is the step rule. The tier is the finest that covers span:
// raw rows up to an hour, five-minute rollups up to fineDays, one-hour
// rollups beyond. The step is the smallest multiple of the tier's resolution
// that keeps the series within pathSeriesMaxPoints (the window starts on a
// step boundary, so it holds one partial step more than span/step) and that
// is no shorter than the interval, so every whole step expects a run.
func pathSeriesStep(span time.Duration, fineDays int, interval time.Duration) (pathTier, time.Duration) {
	tier := pathTierCoarse
	switch {
	case span <= time.Hour:
		tier = pathTierRaw
	case span <= time.Duration(fineDays)*24*time.Hour:
		tier = pathTierFine
	}
	base := tier.resolution()
	k := int64(1)
	if per := int64(base) * (pathSeriesMaxPoints - 1); int64(span) > per {
		k = (int64(span) + per - 1) / per
	}
	if interval > base {
		k = max(k, (int64(interval)+int64(base)-1)/int64(base))
	}
	return tier, time.Duration(k) * base
}

// pathMatrixTier is where the matrix reads a window.
func pathMatrixTier(span time.Duration) pathTier {
	switch {
	case span <= time.Hour:
		return pathTierRaw
	case span < pathMatrixCoarseFrom:
		return pathTierFine
	default:
		return pathTierCoarse
	}
}

func pathRound(v float64) *float64 {
	r := math.Round(v*10) / 10
	return &r
}

func pathLoss(b store.MonitorRollup) *float64 {
	if b.N <= 0 {
		return nil
	}
	loss := math.Round(float64(b.F)/float64(b.N)*10000) / 10000
	return &loss
}

func pathQuantile(b store.MonitorRollup, q float64) *float64 {
	if v, ok := b.Quantile(q); ok {
		return pathRound(v)
	}
	return nil
}

func pathJitter(b store.MonitorRollup) *float64 {
	if v, ok := b.Jitter(); ok {
		return pathRound(v)
	}
	return nil
}

func pathExpected(covered, interval time.Duration) int {
	if interval <= 0 || covered <= 0 {
		return 0
	}
	return int(covered / interval)
}

func pathBucketOf(b store.MonitorRollup, t time.Time, expected int) model.PathBucket {
	out := model.PathBucket{T: t, N: b.N, Fail: b.F, Expected: expected, Loss: pathLoss(b)}
	if b.Successes() > 0 {
		out.MinMs, out.MaxMs = pathRound(b.Min), pathRound(b.Max)
	}
	out.P50Ms = pathQuantile(b, 0.5)
	out.P95Ms = pathQuantile(b, 0.95)
	out.JitterMs = pathJitter(b)
	return out
}

// pathCheck is one check a path series reads: its id and its method.
type pathCheck struct {
	monitorID string
	method    string
}

// latencyCheckMethods are the generated check id prefixes and their
// methods. This release generates tcp checks only; the beacon and icmp
// checks of design 29 add their prefixes here, and the path series joins
// whichever exist.
var latencyCheckMethods = []struct{ prefix, method string }{
	{latencyMonitorPrefix, model.MonitorTypeTCP},
}

// generatedPathChecks lists the generated checks that reach target.
func (s *Server) generatedPathChecks(target string) []pathCheck {
	var out []pathCheck
	for _, m := range latencyCheckMethods {
		mon, ok := s.store.Monitor(m.prefix + target)
		if ok && mon.ManagedBy == model.MonitorManagedLatency {
			out = append(out, pathCheck{monitorID: mon.ID, method: m.method})
		}
	}
	return out
}

// latencyInterval is the interval generated checks run at.
func (s *Server) latencyInterval() time.Duration {
	if cfg, stored := s.store.LatencyProbeConfig(); stored && cfg.IntervalSec > 0 {
		return time.Duration(cfg.IntervalSec) * time.Second
	}
	return time.Duration(model.LatencyProbeDefaultIntervalSec) * time.Second
}

// pathSeriesFor reads one path over one window: every check's buckets for
// source, merged by step across checks, every step present.
func (s *Server) pathSeriesFor(checks []pathCheck, source, window string, interval time.Duration, now time.Time) (model.PathSeries, error) {
	span, ok := pathWindowSpan(window)
	if !ok {
		return model.PathSeries{}, fmt.Errorf("window must be one of %s", pathWindowNames())
	}
	now = now.UTC()
	fineDays := s.store.MonitorSettings().FineRetentionDays
	tier, step := pathSeriesStep(span, fineDays, interval)
	from := now.Add(-span).Truncate(step)
	end := now.Add(time.Nanosecond)
	merged := map[time.Time]*store.MonitorRollup{}
	// samples[i][t] is check i's runs in step t, which picks the step's
	// method when two checks both ran in it.
	samples := make([]map[time.Time]int, len(checks))
	add := func(i int, b store.MonitorRollup) {
		t := b.At.UTC().Truncate(step)
		if t.Before(from) {
			return
		}
		into := merged[t]
		if into == nil {
			into = &store.MonitorRollup{At: t}
			merged[t] = into
		}
		into.Merge(b)
		samples[i][t] += b.N
	}
	for i, check := range checks {
		samples[i] = map[time.Time]int{}
		if tier == pathTierRaw {
			limit := store.MonitorResultsPerPair
			if interval > 0 {
				// One row more than the window holds serves as the first
				// success's predecessor for jitter.
				limit = min(int(span/interval)+6, store.MonitorResultsPerPair)
			}
			rows, err := s.store.MonitorPairResults(check.monitorID, source, limit)
			if err != nil {
				return model.PathSeries{}, err
			}
			for _, b := range store.RollupMonitorResults(rows, step, from, end) {
				add(i, b)
			}
			continue
		}
		pair := store.MonitorPair{MonitorID: check.monitorID, NodeID: source}
		read, err := s.store.MonitorRollups([]store.MonitorPair{pair}, tier.resolution(), from, end)
		if err != nil {
			return model.PathSeries{}, err
		}
		for _, b := range read[pair] {
			add(i, b)
		}
	}
	out := model.PathSeries{
		Window:        window,
		StepSeconds:   int(step / time.Second),
		From:          from,
		To:            now,
		MethodChanges: []model.PathMethodChange{},
		Buckets:       []model.PathBucket{},
	}
	method := ""
	for t := from; !t.After(now); t = t.Add(step) {
		covered := step
		if stepEnd := t.Add(step); stepEnd.After(now) {
			covered = now.Sub(t)
		}
		var b store.MonitorRollup
		if m := merged[t]; m != nil {
			b = *m
		}
		out.Buckets = append(out.Buckets, pathBucketOf(b, t, pathExpected(covered, interval)))
		if b.N == 0 {
			continue
		}
		best, bestN := "", 0
		for i, check := range checks {
			if n := samples[i][t]; n > 0 && n >= bestN {
				best, bestN = check.method, n
			}
		}
		if best != method {
			out.MethodChanges = append(out.MethodChanges, model.PathMethodChange{T: t, Method: best})
			method = best
		}
	}
	return out, nil
}

// handleMonitorSeries answers GET /api/monitors/series, either
// ?source=&target_node=&window= for a generated path or
// ?monitor=&source=&window= for one check's path (source empty for a tls
// check).
func (s *Server) handleMonitorSeries(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	q := r.URL.Query()
	window := q.Get("window")
	if window == "" {
		window = model.PathWindowDay
	}
	if _, ok := pathWindowSpan(window); !ok {
		writeError(w, http.StatusBadRequest, fmt.Errorf("window must be one of %s", pathWindowNames()))
		return
	}
	source := strings.TrimSpace(q.Get("source"))
	var checks []pathCheck
	var interval time.Duration
	if monitorID := strings.TrimSpace(q.Get("monitor")); monitorID != "" {
		mon, ok := s.store.Monitor(monitorID)
		if !ok {
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "monitor not found"))
			return
		}
		if !monitorVisibleToPrincipal(p, "monitor:read", mon) || (source != "" && !latencyNodeVisible(p, source)) {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
			return
		}
		if (mon.Type == model.MonitorTypeTLS) != (source == "") {
			writeError(w, http.StatusBadRequest, errors.New("a tls check's path has no source; every other check's path needs one"))
			return
		}
		checks = []pathCheck{{monitorID: mon.ID, method: mon.Type}}
		interval = time.Duration(mon.IntervalSec) * time.Second
		if mon.ManagedBy == model.MonitorManagedLatency {
			interval = s.latencyInterval()
		}
	} else {
		target := strings.TrimSpace(q.Get("target_node"))
		if source == "" || target == "" {
			writeError(w, http.StatusBadRequest, errors.New("name source and target_node, or monitor and source"))
			return
		}
		if !latencyNodeVisible(p, source) || !latencyNodeVisible(p, target) {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
			return
		}
		checks = s.generatedPathChecks(target)
		if len(checks) == 0 {
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "no generated check reaches that node"))
			return
		}
		interval = s.latencyInterval()
	}
	series, err := s.pathSeriesFor(checks, source, window, interval, s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, series)
}

// pathEntry is one path of the matrix before the caller's scope narrows it.
type pathEntry struct {
	cell     model.PathCell
	monitor  *model.Monitor
	interval time.Duration
	// hasCheck is false for a generated path whose check does not exist.
	hasCheck     bool
	paused       bool
	notProbeable bool
}

func (e pathEntry) pair() store.MonitorPair {
	return store.MonitorPair{MonitorID: e.cell.MonitorID, NodeID: e.cell.Source}
}

// visibleTo is the matrix scope rule: the caller reads the source and the
// target node, and for an operator check the check itself.
func (e pathEntry) visibleTo(p principal) bool {
	if e.monitor != nil && e.monitor.ManagedBy == "" && !monitorVisibleToPrincipal(p, "monitor:read", *e.monitor) {
		return false
	}
	if e.cell.Source != "" && !latencyNodeVisible(p, e.cell.Source) {
		return false
	}
	return e.cell.TargetNode == "" || latencyNodeVisible(p, e.cell.TargetNode)
}

// pathEntries lists every path: the latency plan's pairs, then every
// source of every operator check.
func (s *Server) pathEntries(now time.Time, nodes map[string]model.Node) []pathEntry {
	var out []pathEntry
	monitors := map[string]model.Monitor{}
	for _, mon := range s.store.Monitors() {
		monitors[mon.ID] = mon
	}
	plan := s.pathPlan(now)
	planNodes := make(map[string]model.LatencyProbeNode, len(plan.Nodes))
	for _, n := range plan.Nodes {
		planNodes[n.NodeID] = n
	}
	interval := time.Duration(plan.Config.IntervalSec) * time.Second
	if interval <= 0 {
		interval = time.Duration(model.LatencyProbeDefaultIntervalSec) * time.Second
	}
	for _, pair := range plan.Pairs {
		pn := planNodes[pair.Target]
		e := pathEntry{
			cell: model.PathCell{
				Source: pair.Source, TargetNode: pair.Target, Target: pn.Endpoint,
				MonitorID: pair.MonitorID, Managed: true, Method: model.MonitorTypeTCP,
			},
			interval:     interval,
			paused:       !pair.Active,
			notProbeable: pn.Target == model.LatencyTargetNotProbeable,
		}
		if mon, ok := monitors[pair.MonitorID]; ok && pair.MonitorID != "" {
			e.monitor, e.hasCheck = &mon, true
			if e.cell.Target == "" {
				e.cell.Target = mon.Target
			}
		}
		out = append(out, e)
	}
	byAddress := pathNodesByAddress(nodes)
	ids := make([]string, 0, len(monitors))
	for id := range monitors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		mon := monitors[id]
		if mon.ManagedBy != "" {
			continue
		}
		var sources []string
		switch {
		case mon.Type == model.MonitorTypeTLS:
			sources = []string{""}
		case mon.AssignAll:
			for nodeID := range nodes {
				sources = append(sources, nodeID)
			}
			sort.Strings(sources)
		default:
			sources = slices.Clone(mon.NodeIDs)
		}
		targetNode := byAddress.get(pathTargetHost(mon))
		for _, source := range sources {
			m := mon
			out = append(out, pathEntry{
				cell: model.PathCell{
					Source: source, TargetNode: targetNode, Target: mon.Target,
					MonitorID: mon.ID, Method: mon.Type,
				},
				monitor:  &m,
				interval: time.Duration(mon.IntervalSec) * time.Second,
				hasCheck: true,
				paused:   !mon.Enabled || slices.Contains(mon.PausedNodeIDs, source),
			})
		}
	}
	return out
}

// pathTargetHost is the host an operator check dials, for matching it to a
// node.
func pathTargetHost(mon model.Monitor) string {
	target := strings.TrimSpace(mon.Target)
	if mon.Type == model.MonitorTypeHTTP {
		u, err := url.Parse(target)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}

// pathNodesByAddress maps each public address to the one node that holds
// it. An address two nodes claim resolves to neither.
func pathNodesByAddress(nodes map[string]model.Node) pathAddressLookup {
	out := pathAddressLookup{}
	taken := map[string]bool{}
	for _, n := range nodes {
		for _, raw := range []string{n.PublicIP, n.PublicIPv6} {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil {
				continue
			}
			addr := ip.String()
			if owner, ok := out[addr]; (ok && owner != n.ID) || taken[addr] {
				delete(out, addr)
				taken[addr] = true
				continue
			}
			out[addr] = n.ID
		}
	}
	return out
}

// pathAddressLookup finds the node an address literal names, in any
// spelling of it; a host name names no node.
type pathAddressLookup map[string]string

func (m pathAddressLookup) get(host string) string {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]"))
	if ip == nil {
		return ""
	}
	return m[ip.String()]
}

// pathFigures are one path's cached figures over a window and the window
// before it.
type pathFigures struct {
	samples, fails  int
	p50, p95        *float64
	jitter, loss    *float64
	prevSamples     int
	prevP50, prevLs *float64
}

func pathFiguresOf(sum store.MonitorWindowSummary) pathFigures {
	return pathFigures{
		samples: sum.Cur.N, fails: sum.Cur.F,
		p50: pathQuantile(sum.Cur, 0.5), p95: pathQuantile(sum.Cur, 0.95),
		jitter: pathJitter(sum.Cur), loss: pathLoss(sum.Cur),
		prevSamples: sum.Prev.N, prevP50: pathQuantile(sum.Prev, 0.5), prevLs: pathLoss(sum.Prev),
	}
}

// pathWindowFigures is one window's cached figures: read at at, over
// [from, at), valid until the window's next bucket closes. Its maps are
// replaced, never written to, once made, so a snapshot may keep reading
// them after the lock is released.
type pathWindowFigures struct {
	mu    sync.Mutex
	until time.Time
	read  map[store.MonitorPair]bool
	pathWindowSnapshot
}

// pathWindowSnapshot is what one matrix read uses of a window's figures.
type pathWindowSnapshot struct {
	at      time.Time
	from    time.Time
	figures map[store.MonitorPair]pathFigures
}

// monitorPathState is the server's monitoring-path state: the matrix cache,
// the latency plan the matrix last read, and the pruning sweep's guard and
// wake-up. The zero value is ready.
type monitorPathState struct {
	mu      sync.Mutex
	windows map[string]*pathWindowFigures
	plan    model.LatencyProbePlan
	planAt  time.Time
	wake    chan struct{}
	pruneMu sync.Mutex
}

// pathPlanFresh is how long the matrix reuses a latency plan. Planning
// reads the node, monitor, approval and guard records one store call at a
// time, and a console polls the matrix every few seconds; the sweep re-plans
// every two minutes and after each configuration save, and hands its plan
// over (notePlan).
const pathPlanFresh = 30 * time.Second

// notePlan keeps plan as the newest, made at at.
func (m *monitorPathState) notePlan(plan model.LatencyProbePlan, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if at.Before(m.planAt) {
		return
	}
	m.plan, m.planAt = plan, at
}

// pathPlan is the latency plan the matrix reads: the newest one if it is
// younger than pathPlanFresh, else a new one. A plan is never written to
// after it is made, so readers share it.
func (s *Server) pathPlan(now time.Time) model.LatencyProbePlan {
	m := &s.monitorPaths
	m.mu.Lock()
	if !m.planAt.IsZero() && !now.Before(m.planAt) && now.Sub(m.planAt) < pathPlanFresh {
		plan := m.plan
		m.mu.Unlock()
		return plan
	}
	m.mu.Unlock()
	plan := s.planLatencyProbes(now).plan
	m.notePlan(plan, now)
	return plan
}

func (m *monitorPathState) window(name string) *pathWindowFigures {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.windows == nil {
		m.windows = map[string]*pathWindowFigures{}
	}
	w := m.windows[name]
	if w == nil {
		w = &pathWindowFigures{}
		m.windows[name] = w
	}
	return w
}

// forget drops every cached window, so the next read goes to the store.
func (m *monitorPathState) forget() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.windows = nil
}

// pathWindowBounds is where a matrix window reads from and until when its
// figures hold: the window starts on its tier's step and the figures hold
// until that step's next boundary.
func pathWindowBounds(span time.Duration, now time.Time) (tier pathTier, from, until time.Time) {
	tier = pathMatrixTier(span)
	res := tier.resolution()
	if tier == pathTierRaw {
		return tier, now.Add(-span), now.Truncate(res).Add(res)
	}
	return tier, now.Add(-span).Truncate(res), now.Truncate(res).Add(res)
}

// pathFiguresFor returns the window's figures for pairs, reading the store
// when the cache has expired or lacks one of them. Concurrent reads of one
// window wait for one store read.
func (s *Server) pathFiguresFor(window string, span time.Duration, pairs []store.MonitorPair, now time.Time) (pathWindowSnapshot, error) {
	w := s.monitorPaths.window(window)
	w.mu.Lock()
	defer w.mu.Unlock()
	fresh := !w.at.IsZero() && now.Before(w.until) && !now.Before(w.at)
	if fresh {
		for _, pair := range pairs {
			if !w.read[pair] {
				fresh = false
				break
			}
		}
	}
	if fresh {
		return w.pathWindowSnapshot, nil
	}
	tier, from, until := pathWindowBounds(span, now)
	prevFrom := from.Add(-span)
	var sums map[store.MonitorPair]store.MonitorWindowSummary
	var err error
	if tier == pathTierRaw {
		sums, err = s.store.MonitorRowSummaries(pairs, prevFrom, from, now.Add(time.Nanosecond))
	} else {
		sums, err = s.store.MonitorRollupSummaries(pairs, tier.resolution(), prevFrom, from, now.Add(time.Nanosecond))
	}
	if err != nil {
		return pathWindowSnapshot{}, err
	}
	w.at, w.from, w.until = now, from, until
	w.read = make(map[store.MonitorPair]bool, len(pairs))
	w.figures = make(map[store.MonitorPair]pathFigures, len(sums))
	for _, pair := range pairs {
		w.read[pair] = true
	}
	for pair, sum := range sums {
		w.figures[pair] = pathFiguresOf(sum)
	}
	return w.pathWindowSnapshot, nil
}

// pathStateOf judges one path now.
func pathStateOf(e pathEntry, latest *store.MonitorLatest, nodes map[string]model.Node, now time.Time) (string, string) {
	switch {
	case e.notProbeable:
		return model.PathStateUnknown, model.PathReasonNotProbeable
	case e.paused:
		return model.PathStateUnknown, model.PathReasonSourcePaused
	case !e.hasCheck:
		return model.PathStateUnknown, model.PathReasonNoData
	}
	if e.cell.Source != "" {
		n, ok := nodes[e.cell.Source]
		if !ok || n.Disabled || !n.Online {
			return model.PathStateUnknown, model.PathReasonAgentOffline
		}
	}
	if latest == nil {
		return model.PathStateUnknown, model.PathReasonNoData
	}
	heard := latest.At
	if latest.ReceivedAt.After(heard) {
		heard = latest.ReceivedAt
	}
	if now.Sub(heard) > max(pathStaleAfterRuns*e.interval, pathStaleFloor) {
		return model.PathStateUnknown, model.PathReasonNoData
	}
	if !latest.Success && latest.FailStreak >= pathDownAfter {
		return model.PathStateDown, ""
	}
	return model.PathStateUp, ""
}

// pathMatrixFor builds the matrix the principal may read.
func (s *Server) pathMatrixFor(p principal, window string, now time.Time) (model.PathMatrix, error) {
	span, ok := pathWindowSpan(window)
	if !ok {
		return model.PathMatrix{}, fmt.Errorf("window must be one of %s", pathWindowNames())
	}
	now = now.UTC()
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	var entries []pathEntry
	var pairs []store.MonitorPair
	for _, e := range s.pathEntries(now, nodes) {
		if !e.visibleTo(p) {
			continue
		}
		entries = append(entries, e)
		if e.hasCheck {
			pairs = append(pairs, e.pair())
		}
	}
	out := model.PathMatrix{
		Window:     window,
		ObservedAt: now,
		Sources:    []model.PathSource{},
		Targets:    []model.PathTarget{},
		Paths:      make([]model.PathCell, 0, len(entries)),
	}
	if len(entries) == 0 {
		return out, nil
	}
	figures, err := s.pathFiguresFor(window, span, pairs, now)
	if err != nil {
		return out, err
	}
	latestByMonitor, err := s.store.LatestMonitorResults()
	if err != nil {
		return out, err
	}
	latest := map[store.MonitorPair]*store.MonitorLatest{}
	for monitorID, list := range latestByMonitor {
		for i := range list {
			latest[store.MonitorPair{MonitorID: monitorID, NodeID: list[i].NodeID}] = &list[i]
		}
	}
	covered := figures.at.Sub(figures.from)
	sources, targets := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		cell := e.cell
		pair := e.pair()
		var l *store.MonitorLatest
		if e.hasCheck {
			l = latest[pair]
		}
		cell.State, cell.Reason = pathStateOf(e, l, nodes, now)
		if l != nil {
			at := l.At
			cell.LastAt = &at
		}
		if e.hasCheck {
			cell.Expected = pathExpected(covered, e.interval)
			if f, ok := figures.figures[pair]; ok {
				cell.Samples, cell.P50Ms, cell.P95Ms, cell.JitterMs, cell.Loss = f.samples, f.p50, f.p95, f.jitter, f.loss
				if f.prevSamples > 0 {
					cell.Prev = &model.PathPrev{P50Ms: f.prevP50, Loss: f.prevLs}
				}
			}
		}
		out.Paths = append(out.Paths, cell)
		sources[cell.Source] = true
		if cell.TargetNode != "" {
			targets[cell.TargetNode] = true
		}
	}
	for nodeID := range sources {
		if nodeID == "" {
			out.Sources = append(out.Sources, model.PathSource{Name: pathControlPlaneName})
			continue
		}
		n := nodes[nodeID]
		_, region := latencyRegion(n)
		name := latencyNodeLabel(n)
		if n.ID == "" {
			name = nodeID
		}
		out.Sources = append(out.Sources, model.PathSource{NodeID: nodeID, Name: name, Region: region})
	}
	for nodeID := range targets {
		n := nodes[nodeID]
		country, region := latencyRegion(n)
		name := latencyNodeLabel(n)
		if n.ID == "" {
			name = nodeID
		}
		out.Targets = append(out.Targets, model.PathTarget{NodeID: nodeID, Name: name, Region: region, Country: country})
	}
	sort.Slice(out.Sources, func(i, j int) bool {
		a, b := out.Sources[i], out.Sources[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.NodeID < b.NodeID
	})
	sort.Slice(out.Targets, func(i, j int) bool {
		a, b := out.Targets[i], out.Targets[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.NodeID < b.NodeID
	})
	sort.SliceStable(out.Paths, func(i, j int) bool {
		a, b := out.Paths[i], out.Paths[j]
		if a.Managed != b.Managed {
			return a.Managed
		}
		if a.TargetNode != b.TargetNode {
			return a.TargetNode < b.TargetNode
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.MonitorID < b.MonitorID
	})
	return out, nil
}

// handleMonitorPaths answers GET /api/monitors/paths?window=.
func (s *Server) handleMonitorPaths(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = model.PathWindowDay
	}
	if _, ok := pathWindowSpan(window); !ok {
		writeError(w, http.StatusBadRequest, fmt.Errorf("window must be one of %s", pathWindowNames()))
		return
	}
	out, err := s.pathMatrixFor(p, window, s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
