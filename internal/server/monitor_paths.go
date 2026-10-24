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
// change between the tcp, icmp and beacon checks (latencyCheckMethods). An
// operator's check is addressed by (monitor, source); a tls check's source
// is the control plane, an empty node id.
//
// Where a window comes from:
//
//   - Series: the finest tier that covers the window (raw rows up to one
//     hour, five-minute rollups up to the fine retention, one-hour rollups
//     beyond), merged on the server into the smallest multiple of that
//     tier's resolution that keeps the series within 720 points and is no
//     shorter than the check's interval (pathSeriesStep). A window of span
//     holds ceil(span/step) steps, the last of them the step in progress
//     (pathSeriesFrom).
//   - Matrix: raw rows for 1 h, five-minute rollups for 6 h and 24 h, one-hour
//     rollups from 3 d up, over the window's whole buckets: span/resolution
//     of them, ending where the bucket in progress begins
//     (pathWindowBounds). Each window's figures are cached until that
//     bucket closes; states are judged on every read from the pairs' latest
//     records.
//
// Unknown stays unknown: a bucket with no runs where runs were expected is a
// gap, and a path with no current result is unknown with the reason when
// the control plane knows it. Neither is ever drawn as up.

const (
	// pathSeriesMaxPoints bounds a series, the step in progress included.
	pathSeriesMaxPoints = 720
	// pathMatrixCoarseFrom is the shortest matrix window read from the
	// one-hour tier.
	pathMatrixCoarseFrom = 72 * time.Hour
	// pathStaleAfterRuns and pathStaleFloor decide when a path's newest
	// result no longer says what it is doing now.
	pathStaleAfterRuns = 3
	pathStaleFloor     = 2 * time.Minute
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
// that keeps span/step under pathSeriesMaxPoints, one step to spare (a
// window holds ceil(span/step) steps, pathSeriesFrom; the console's
// expectedStepSeconds mirrors this rule), and that is no shorter than the
// interval, so every whole step expects a run.
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
	ratio, ok := b.Loss()
	if !ok {
		return nil
	}
	loss := math.Round(ratio*10000) / 10000
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

// pathSeriesFrom is where a series of span at step starts: as many steps as
// fit in span, ceil(span/step), the last of them the one holding now. A
// window of N steps then reads N buckets, not N+1 with a partial step at
// each end.
func pathSeriesFrom(span, step time.Duration, now time.Time) time.Time {
	steps := (span + step - 1) / step
	return now.Truncate(step).Add(-(steps - 1) * step)
}

// pathInProgressExpected is what the step in progress expects: the runs
// certainly due over the part that has passed (covered), and never fewer
// than it has heard, since a run lands anywhere in its interval and one that
// landed was expected. A step that has heard nothing reads a gap only once a
// whole interval has passed in it.
func pathInProgressExpected(covered, interval time.Duration, heard int) int {
	return max(pathExpected(covered, interval), heard)
}

func pathBucketOf(b store.MonitorRollup, t time.Time, expected int) model.PathBucket {
	out := model.PathBucket{T: t, N: b.N, Fail: b.F, Expected: expected, Loss: pathLoss(b), Sent: b.S, Lost: b.L}
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
// methods; the path series joins whichever exist. The beacon checks of
// design 29 M2b add their prefix here.
var latencyCheckMethods = []struct{ prefix, method string }{
	{latencyMonitorPrefix, model.MonitorTypeTCP},
	{latencyICMPMonitorPrefix, model.MonitorTypeICMP},
	{model.LatencyMonitorPrefixBeacon, model.MonitorTypeBeacon},
}

// generatedPathChecks lists the generated checks that reach target.
func (s *Server) generatedPathChecks(target string) []pathCheck {
	var out []pathCheck
	for _, m := range latencyCheckMethods {
		mon, ok := s.store.Monitor(m.prefix + target)
		if ok && store.MonitorOwnerOf(mon) == store.MonitorOwnerPathSet {
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
	from := pathSeriesFrom(span, step, now)
	if tier == pathTierFine {
		short, err := s.fineTierShort(checks, source, from, now)
		if err != nil {
			return model.PathSeries{}, err
		}
		if short {
			tier, step = pathSeriesStep(span, 0, interval)
			from = pathSeriesFrom(span, step, now)
		}
	}
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
			// The rows of the window, by time however many there are, and
			// the run or two before it, whose success is the first one's
			// predecessor for jitter.
			lead := max(2*interval, 2*time.Minute)
			rows, err := s.store.MonitorPairResultsBetween(check.monitorID, source, from.Add(-lead), end)
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
		var b store.MonitorRollup
		if m := merged[t]; m != nil {
			b = *m
		}
		expected := pathExpected(step, interval)
		if t.Add(step).After(now) {
			expected = pathInProgressExpected(now.Sub(t), interval, b.N)
		}
		out.Buckets = append(out.Buckets, pathBucketOf(b, t, expected))
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

// pathPreviousFor reads the series' previous period (compare=previous): the
// same checks for the same source one span earlier, as one median per step of
// series. Entry i covers [t_i - span, t_i - span + step). It reads the finest
// tier that holds the whole earlier window: raw rows for the hour (a path
// keeps 1440 rows, four hours at the 10 s interval floor), five-minute
// buckets while the fine retention reaches back far enough and the tier has
// filled, one-hour buckets beyond. When that tier is coarser than the
// series' step, one bucket gives its value to every step it covers.
func (s *Server) pathPreviousFor(checks []pathCheck, source string, series model.PathSeries, span time.Duration, now time.Time) (*model.PathPreviousSeries, error) {
	step := time.Duration(series.StepSeconds) * time.Second
	if step <= 0 {
		return nil, errors.New("series has no step")
	}
	from, to := series.From.Add(-span), series.To.Add(-span)
	end := to.Add(time.Nanosecond)
	tier := pathTierCoarse
	switch {
	case span <= time.Hour:
		tier = pathTierRaw
	case now.Sub(from) <= s.store.MonitorHistoryLimits().FineKeep:
		short, err := s.fineTierShort(checks, source, from, now)
		if err != nil {
			return nil, err
		}
		if !short {
			tier = pathTierFine
		}
	}
	res := tier.resolution()
	merged := map[time.Time]*store.MonitorRollup{}
	add := func(b store.MonitorRollup) {
		t := b.At.UTC().Truncate(res)
		into := merged[t]
		if into == nil {
			into = &store.MonitorRollup{At: t}
			merged[t] = into
		}
		into.Merge(b)
	}
	for _, check := range checks {
		if tier == pathTierRaw {
			rows, err := s.store.MonitorPairResultsBetween(check.monitorID, source, from, end)
			if err != nil {
				return nil, err
			}
			for _, b := range store.RollupMonitorResults(rows, res, from.Truncate(res), end) {
				add(b)
			}
			continue
		}
		pair := store.MonitorPair{MonitorID: check.monitorID, NodeID: source}
		read, err := s.store.MonitorRollups([]store.MonitorPair{pair}, res, from, end)
		if err != nil {
			return nil, err
		}
		for _, b := range read[pair] {
			add(b)
		}
	}
	out := &model.PathPreviousSeries{
		From: from, To: to, OffsetSeconds: int(span / time.Second),
		StepSeconds: int(max(res, step) / time.Second),
		P50Ms:       make([]*float64, len(series.Buckets)),
	}
	if res > step {
		for i, b := range series.Buckets {
			if m := merged[b.T.Add(-span).Truncate(res)]; m != nil {
				out.P50Ms[i] = pathQuantile(*m, 0.5)
			}
		}
		return out, nil
	}
	perStep := make([]store.MonitorRollup, len(series.Buckets))
	for t, m := range merged {
		shifted := t.Add(span)
		if shifted.Before(series.From) {
			continue
		}
		i := int(shifted.Sub(series.From) / step)
		if i < len(perStep) {
			perStep[i].Merge(*m)
		}
	}
	for i := range perStep {
		out.P50Ms[i] = pathQuantile(perStep[i], 0.5)
	}
	return out, nil
}

// fineTierShort reports whether the five-minute tier lacks part of the
// window that the hourly tier holds: hourly buckets exist between the
// window's start and the hour before the oldest five-minute bucket. That is
// the five-minute tier still filling, after the two days the previous
// release kept or a retention just raised. The series then reads the hourly
// tier rather than draw history that exists as a gap. A path that was
// silent (paused, down) in that span has no hourly buckets there either,
// and keeps the finer tier.
func (s *Server) fineTierShort(checks []pathCheck, source string, from, now time.Time) (bool, error) {
	pairs := make([]store.MonitorPair, 0, len(checks))
	for _, check := range checks {
		pairs = append(pairs, store.MonitorPair{MonitorID: check.monitorID, NodeID: source})
	}
	starts, err := s.store.MonitorOldestBuckets(pairs, store.MonitorRollupFine)
	if err != nil {
		return false, err
	}
	fine := now
	for _, t := range starts {
		if t.Before(fine) {
			fine = t
		}
	}
	if !fine.After(from) {
		return false, nil
	}
	missing := fine.Add(-store.MonitorRollupCoarse)
	if len(starts) == 0 {
		missing = now.Add(time.Nanosecond)
	}
	if !missing.After(from) {
		return false, nil
	}
	coarse, err := s.store.MonitorRollups(pairs, store.MonitorRollupCoarse, from, missing)
	if err != nil {
		return false, err
	}
	return len(coarse) > 0, nil
}

// operatorPathVisible is the scope rule for one source of an operator's
// check: the check, the source and, when the check's address is one node's,
// that node, as the matrix decides it.
func (s *Server) operatorPathVisible(p principal, mon model.Monitor, source string) bool {
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	m := mon
	targetNode := mon.TargetNode
	if targetNode == "" {
		targetNode = pathNodesByAddress(nodes).get(pathTargetHost(mon))
	}
	e := pathEntry{
		cell:    model.PathCell{Source: source, TargetNode: targetNode, MonitorID: mon.ID},
		monitor: &m,
	}
	return e.visibleTo(p)
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
	compare := false
	if values, ok := q["compare"]; ok {
		if len(values) != 1 || values[0] != "previous" {
			writeError(w, http.StatusBadRequest, errors.New(`compare must be "previous"`))
			return
		}
		compare = true
	}
	now := s.now()
	source := strings.TrimSpace(q.Get("source"))
	var checks []pathCheck
	var interval time.Duration
	// basePair is the pair the path is judged on now, whose baseline the
	// series carries, under rule; nil for a tls check or a generated path
	// with no current check.
	var basePair *store.MonitorPair
	var rule model.MonitorDegradedRule
	checkID := ""
	if monitorID := strings.TrimSpace(q.Get("monitor")); monitorID != "" {
		mon, ok := s.store.Monitor(monitorID)
		if !ok {
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "monitor not found"))
			return
		}
		visible := monitorVisibleToPrincipal(p, "monitor:read", mon) && (source == "" || latencyNodeVisible(p, source))
		if visible && store.MonitorOwnerOf(mon).Authored() {
			visible = s.operatorPathVisible(p, mon, source)
		}
		if !visible {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
			return
		}
		if (mon.Type == model.MonitorTypeTLS) != (source == "") {
			writeError(w, http.StatusBadRequest, errors.New("a tls check's path has no source; every other check's path needs one"))
			return
		}
		checks = []pathCheck{{monitorID: mon.ID, method: mon.Type}}
		interval = time.Duration(mon.IntervalSec) * time.Second
		if store.MonitorOwnerOf(mon) == store.MonitorOwnerPathSet {
			interval = s.latencyInterval()
		}
		if mon.Type != model.MonitorTypeTLS {
			basePair = &store.MonitorPair{MonitorID: mon.ID, NodeID: source}
			rule = s.monitorPolicy(mon).rule
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
		// A pair is keyed by its nodes whichever check measures it (design
		// 32 R1): ?check= names which one's series, else the first.
		pick, ok := s.pairCheckFor(p, source, target, strings.TrimSpace(q.Get("check")), now)
		if !ok {
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "no check measures that pair"))
			return
		}
		checks, interval, basePair, rule, checkID = pick.checks, pick.interval, pick.basePair, pick.rule, pick.id
	}
	series, err := s.pathSeriesFor(checks, source, window, interval, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	series.Check = checkID
	if basePair != nil {
		if series.Baseline, err = s.pathBaselineView(*basePair, rule, now); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if compare {
		span, _ := pathWindowSpan(window)
		if series.Previous, err = s.pathPreviousFor(checks, source, series, span, now); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, series)
}

// pairCheck is one check on a node pair as the series route reads it: a
// definition (all of its monitors that reached the pair, every method an
// auto definition used) or a single check, or the unmigrated path set.
type pairCheck struct {
	id       string
	name     string
	checks   []pathCheck
	interval time.Duration
	// basePair and rule are the pair the path is judged on now, nil when
	// nothing measures it now.
	basePair *store.MonitorPair
	rule     model.MonitorDegradedRule
	measured bool
}

// pairChecksFor lists the checks that reach the pair (source, target)
// that p may read: the path set's generated checks while it is not
// migrated, then every authored check whose target is the node or an
// address of it and which holds the source, its history included. Measured
// checks come first, then by name.
func (s *Server) pairChecksFor(p principal, source, target string, now time.Time) []pairCheck {
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	var out []pairCheck
	if generated := s.generatedPathChecks(target); len(generated) > 0 {
		// The unmigrated path set has no definition or monitor id to name,
		// so its series answers without one.
		pc := pairCheck{name: model.CheckFleetMeshName, checks: generated, interval: s.latencyInterval()}
		plan := s.pathPlan(now)
		for _, pair := range plan.Pairs {
			if pair.Source != source || pair.Target != target || pair.MonitorID == "" {
				continue
			}
			if _, ok := s.store.Monitor(pair.MonitorID); ok {
				pc.basePair = &store.MonitorPair{MonitorID: pair.MonitorID, NodeID: source}
				pc.rule = pathSetPolicy(plan.Config).rule
				pc.measured = pair.Active
			}
			break
		}
		out = append(out, pc)
	}
	byAddress := pathNodesByAddress(nodes)
	byKey := map[string]int{}
	var authored []pairCheck
	for _, mon := range s.store.Monitors() {
		if !store.MonitorOwnerOf(mon).Authored() || mon.Type == model.MonitorTypeTLS {
			continue
		}
		targetNode := mon.TargetNode
		if targetNode == "" {
			targetNode = byAddress.get(pathTargetHost(mon))
		}
		if targetNode != target || (!mon.AssignAll && !slices.Contains(mon.NodeIDs, source)) {
			continue
		}
		if !monitorVisibleToPrincipal(p, "monitor:read", mon) || !s.operatorPathVisible(p, mon, source) {
			continue
		}
		key, name := mon.ID, mon.Name
		if definitionID, ok := store.MonitorDefinitionID(mon); ok {
			key = definitionID
			if def, found := s.store.CheckDefinition(definitionID); found {
				name = def.Name
			}
		}
		i, seen := byKey[key]
		if !seen {
			i = len(authored)
			byKey[key] = i
			authored = append(authored, pairCheck{id: key, name: name, interval: time.Duration(mon.IntervalSec) * time.Second})
		}
		pc := &authored[i]
		pc.checks = append(pc.checks, pathCheck{monitorID: mon.ID, method: mon.Type})
		if mon.Enabled && !slices.Contains(mon.PausedNodeIDs, source) && !pc.measured {
			pc.measured = true
			pc.basePair = &store.MonitorPair{MonitorID: mon.ID, NodeID: source}
			pc.rule = s.monitorPolicy(mon).rule
			pc.interval = time.Duration(mon.IntervalSec) * time.Second
		}
	}
	for i := range authored {
		sort.Slice(authored[i].checks, func(a, b int) bool { return authored[i].checks[a].monitorID < authored[i].checks[b].monitorID })
	}
	sort.SliceStable(authored, func(a, b int) bool {
		if authored[a].measured != authored[b].measured {
			return authored[a].measured
		}
		if authored[a].name != authored[b].name {
			return authored[a].name < authored[b].name
		}
		return authored[a].id < authored[b].id
	})
	return append(out, authored...)
}

// pairCheckFor is the check named id on the pair, or the first when id is
// empty; false when none matches.
func (s *Server) pairCheckFor(p principal, source, target, id string, now time.Time) (pairCheck, bool) {
	for _, pc := range s.pairChecksFor(p, source, target, now) {
		if id == "" || pc.id == id {
			return pc, true
		}
	}
	return pairCheck{}, false
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
	// gate is why the source does not run the path's kind (a
	// model.PathReason* code), empty when it does.
	gate string
	// after is the failed runs in a row that read down: the check's own
	// hold, or the path set's for a generated check (design 29 D13).
	after int
}

func (e pathEntry) pair() store.MonitorPair {
	return store.MonitorPair{MonitorID: e.cell.MonitorID, NodeID: e.cell.Source}
}

// visibleTo is the matrix scope rule: the caller reads the source and the
// target node, and for an operator check the check itself.
func (e pathEntry) visibleTo(p principal) bool {
	if e.monitor != nil && store.MonitorOwnerOf(*e.monitor).Authored() && !monitorVisibleToPrincipal(p, "monitor:read", *e.monitor) {
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
	planned := s.pathPlanned(now)
	plan := planned.plan
	var targets *monitorTargets
	planNodes := make(map[string]model.LatencyProbeNode, len(plan.Nodes))
	for _, n := range plan.Nodes {
		planNodes[n.NodeID] = n
	}
	interval := time.Duration(plan.Config.IntervalSec) * time.Second
	if interval <= 0 {
		interval = time.Duration(model.LatencyProbeDefaultIntervalSec) * time.Second
	}
	pathSetAfter := pathSetPolicy(plan.Config).after
	for _, pair := range plan.Pairs {
		pn := planNodes[pair.Target]
		method, target := pair.Method, pn.Endpoint
		if method == "" {
			method = model.MonitorTypeTCP
		}
		switch method {
		case model.MonitorTypeICMP:
			target = pn.ICMPTarget
		case model.MonitorTypeBeacon:
			target = pn.BeaconTarget
		}
		e := pathEntry{
			cell: model.PathCell{
				Source: pair.Source, TargetNode: pair.Target, Target: target,
				MonitorID: pair.MonitorID, Managed: true, Method: method,
			},
			interval:     interval,
			after:        pathSetAfter,
			paused:       !pair.Active,
			notProbeable: pn.Target == model.LatencyTargetNotProbeable || pair.Reason == model.PathReasonNotProbeable,
		}
		if pair.Reason != model.PathReasonNotProbeable {
			e.gate = pair.Reason
		}
		if e.gate == "" && method == model.MonitorTypeBeacon {
			e.gate = s.beaconTargetListenGate(pair.Target, nodes)
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
	firstAuthored := len(out)
	for _, id := range ids {
		mon := monitors[id]
		owner := store.MonitorOwnerOf(mon)
		if !owner.Authored() {
			continue
		}
		definition := owner == store.MonitorOwnerDefinition
		definitionID, _ := store.MonitorDefinitionID(mon)
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
		targetNode := mon.TargetNode
		if targetNode == "" {
			targetNode = byAddress.get(pathTargetHost(mon))
		}
		target, resolvable := mon.Target, true
		if mon.TargetNode != "" {
			if targets == nil {
				t := monitorTargets{nodes: nodes, endpoints: planned.endpoints, beacons: s.store.BeaconTargets()}
				targets = &t
			}
			if resolved, ok := targets.resolved(mon); ok {
				target = resolved.Target
			} else {
				resolvable = false
			}
		}
		for _, source := range sources {
			m := mon
			e := pathEntry{
				cell: model.PathCell{
					Source: source, TargetNode: targetNode, Target: target,
					MonitorID: mon.ID, Method: mon.Type,
					CheckDefinitionID: definitionID,
					// The path set's definitions keep the deprecated mark on
					// their node cells for one release (design 32 R1).
					Managed: isFleetMeshID(definitionID) && mon.TargetNode != "",
				},
				monitor:      &m,
				interval:     time.Duration(mon.IntervalSec) * time.Second,
				after:        store.MonitorAlertAfter(mon),
				hasCheck:     true,
				paused:       !mon.Enabled || slices.Contains(mon.PausedNodeIDs, source),
				notProbeable: !resolvable,
			}
			if mon.Type == model.MonitorTypeBeacon && !resolvable {
				// The target's beacon is off: say so rather than reading
				// the node as one the method cannot reach.
				e.notProbeable = false
				e.gate = model.PathReasonBeaconNotEnabled
			} else if source != "" {
				e.gate = monitorProbeGate(nodes[source], mon)
				if e.gate == "" && mon.Type == model.MonitorTypeBeacon && mon.TargetNode != "" {
					if e.gate = s.beaconMonitorGate(nodes[source], mon.TargetNode, now); e.gate == "" {
						e.gate = s.beaconTargetListenGate(mon.TargetNode, nodes)
					}
				}
				if e.gate == "" && definition && mon.Enabled && slices.Contains(mon.PausedNodeIDs, source) {
					// A definition's paused sources are only ever its
					// packet budget pauses: its monitors refuse edits.
					e.gate = model.PathReasonPacketBudget
				}
			}
			out = append(out, e)
		}
	}
	return append(out[:firstAuthored], onePathPerCheck(out[firstAuthored:])...)
}

// onePathPerCheck keeps one path per (definition, source, target node): an
// auto definition holds a monitor per method it used, and only the method a
// pair uses now is its path; the others are that pair's history, which the
// series joins. A pair that no method runs now keeps one paused path.
func onePathPerCheck(entries []pathEntry) []pathEntry {
	kept := map[string]int{}
	out := entries[:0:0]
	for _, e := range entries {
		if e.cell.CheckDefinitionID == "" || e.cell.TargetNode == "" {
			out = append(out, e)
			continue
		}
		key := e.cell.CheckDefinitionID + "\x00" + e.cell.Source + "\x00" + e.cell.TargetNode
		i, seen := kept[key]
		switch {
		case !seen:
			kept[key] = len(out)
			out = append(out, e)
		case out[i].paused && !e.paused:
			out[i] = e
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

// pathWindowSnapshot is what one matrix read uses of a window's figures:
// read at at, over [from, to).
type pathWindowSnapshot struct {
	at      time.Time
	from    time.Time
	to      time.Time
	figures map[store.MonitorPair]pathFigures
}

// monitorPathState is the server's monitoring-path state: the matrix cache,
// the latency plan the matrix last read, and the pruning sweep's guard and
// wake-up. The zero value is ready.
type monitorPathState struct {
	mu      sync.Mutex
	windows map[string]*pathWindowFigures
	plan    latencyPlan
	planAt  time.Time
	// planBuild lets one caller at a time build a plan when the cached one
	// has gone stale.
	planBuild sync.Mutex
	wake      chan struct{}
	pruneMu   sync.Mutex
	// settingsMu holds a settings save and the read of what it replaced
	// together, so the audit and the sweep's wake-up see the value the
	// save actually replaced.
	settingsMu sync.Mutex
}

// pathPlanFresh is how long the matrix reuses a latency plan. Planning
// reads the node, monitor, approval and guard records one store call at a
// time, and a console polls the matrix every few seconds; the sweep re-plans
// every two minutes and after each configuration save, and hands its plan
// over (notePlan).
const pathPlanFresh = 30 * time.Second

// notePlan keeps plan as the newest, made at at.
func (m *monitorPathState) notePlan(plan latencyPlan, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if at.Before(m.planAt) {
		return
	}
	m.plan, m.planAt = plan, at
}

// dropPlan forgets the newest plan, so the next reader plans again: after
// the path set's migration, a plan made before it would still list the path
// set's pairs beside the definitions that now measure them.
func (m *monitorPathState) dropPlan() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plan, m.planAt = latencyPlan{}, time.Time{}
}

// pathPlan is the latency plan the matrix reads: the newest one if it is
// younger than pathPlanFresh, else a new one. A plan is never written to
// after it is made, so readers share it.
func (s *Server) pathPlan(now time.Time) model.LatencyProbePlan {
	return s.pathPlanned(now).plan
}

// pathPlanned is pathPlan with the node endpoints it was made from, which
// operator checks that name a node resolve against.
func (s *Server) pathPlanned(now time.Time) latencyPlan {
	m := &s.monitorPaths
	m.mu.Lock()
	if !m.planAt.IsZero() && !now.Before(m.planAt) && now.Sub(m.planAt) < pathPlanFresh {
		plan := m.plan
		m.mu.Unlock()
		return plan
	}
	m.mu.Unlock()
	// One caller plans; the others wait for its plan rather than each
	// planning the fleet again (agent pulls and matrix reads land at once).
	m.planBuild.Lock()
	defer m.planBuild.Unlock()
	m.mu.Lock()
	if !m.planAt.IsZero() && !now.Before(m.planAt) && now.Sub(m.planAt) < pathPlanFresh {
		plan := m.plan
		m.mu.Unlock()
		return plan
	}
	m.mu.Unlock()
	plan := s.planLatencyProbes(now)
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

// pathWindowBounds is what a matrix window reads, [from, to), and until
// when its figures hold: the span/resolution whole buckets of its tier that
// end where the bucket in progress begins, held until that bucket closes.
// Every matrix span is a whole number of its tier's buckets, so a path that
// ran every interval reads as many samples as it expected.
func pathWindowBounds(span time.Duration, now time.Time) (tier pathTier, from, to, until time.Time) {
	tier = pathMatrixTier(span)
	res := tier.resolution()
	to = now.Truncate(res)
	return tier, to.Add(-span), to, to.Add(res)
}

// pathFiguresFor returns the window's figures for pairs, reading the store
// when the cache has expired or lacks one of them. Concurrent reads of one
// window wait for one store read.
func (s *Server) pathFiguresFor(window string, span time.Duration, pairs []store.MonitorPair, now time.Time) (pathWindowSnapshot, error) {
	w := s.monitorPaths.window(window)
	w.mu.Lock()
	defer w.mu.Unlock()
	tier := pathMatrixTier(span)
	live := !w.at.IsZero() && now.Before(w.until) && !now.Before(w.at)
	var missing []store.MonitorPair
	for _, pair := range pairs {
		if !live || !w.read[pair] {
			missing = append(missing, pair)
		}
	}
	if len(missing) == 0 {
		return w.pathWindowSnapshot, nil
	}
	read := func(pairs []store.MonitorPair, from, to time.Time) (map[store.MonitorPair]store.MonitorWindowSummary, error) {
		prevFrom := from.Add(-span)
		if tier == pathTierRaw {
			return s.store.MonitorRowSummaries(pairs, prevFrom, from, to)
		}
		return s.store.MonitorRollupSummaries(pairs, tier.resolution(), prevFrom, from, to)
	}
	if live {
		// Within the same bucket, read only the paths this caller adds,
		// over the same window, and keep everyone else's: callers with
		// different scopes then share one cache instead of evicting each
		// other. The maps are copied, never written, so snapshots handed
		// out earlier stay as they were.
		sums, err := read(missing, w.from, w.to)
		if err != nil {
			return pathWindowSnapshot{}, err
		}
		readSet := make(map[store.MonitorPair]bool, len(w.read)+len(missing))
		figures := make(map[store.MonitorPair]pathFigures, len(w.figures)+len(sums))
		for pair := range w.read {
			readSet[pair] = true
		}
		for pair, f := range w.figures {
			figures[pair] = f
		}
		for _, pair := range missing {
			readSet[pair] = true
		}
		for pair, sum := range sums {
			figures[pair] = pathFiguresOf(sum)
		}
		w.read, w.figures = readSet, figures
		return w.pathWindowSnapshot, nil
	}
	_, from, to, until := pathWindowBounds(span, now)
	sums, err := read(pairs, from, to)
	if err != nil {
		return pathWindowSnapshot{}, err
	}
	w.at, w.from, w.to, w.until = now, from, to, until
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
	case e.gate != "":
		// The source is not handed a kind it does not run, so the path
		// is unknown for that reason, never down.
		return model.PathStateUnknown, e.gate
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
	if u := latest.Unknown; u != nil {
		if u.At.After(heard) {
			heard = u.At
		}
		if u.ReceivedAt.After(heard) {
			heard = u.ReceivedAt
		}
	}
	if now.Sub(heard) > max(pathStaleAfterRuns*e.interval, pathStaleFloor) {
		return model.PathStateUnknown, model.PathReasonNoData
	}
	if latest.Unknown != nil {
		// The newest run measured nothing (icmp not permitted, a refused
		// destination, an agent too old for the kind).
		return model.PathStateUnknown, latest.Unknown.Reason
	}
	if icmpFiltered(e.cell.Method, *latest) {
		return model.PathStateUnknown, model.PathReasonICMPFiltered
	}
	if beaconFiltered(e.cell.Method, *latest) {
		return model.PathStateUnknown, model.PathReasonBeaconFiltered
	}
	// Down follows the check's alert hold: its failures in a row
	// (store.MonitorAlertAfter), the path set's for a generated check.
	after := e.after
	if after < 1 {
		after = store.MonitorAlertAfter(model.Monitor{})
		if e.monitor != nil {
			after = store.MonitorAlertAfter(*e.monitor)
		}
	}
	if !latest.Success && latest.FailStreak >= after {
		return model.PathStateDown, ""
	}
	return model.PathStateUp, ""
}

// icmpFiltered reports whether a pair's failures read as ICMP filtering
// rather than down (design 29 D10): an icmp path failing that has never
// had an echo back. Once one has come back, failures are failures, so a
// node that really dies still reads down and pages.
func icmpFiltered(method string, latest store.MonitorLatest) bool {
	return method == model.MonitorTypeICMP && !latest.Success && latest.LastOKAt.IsZero()
}

// beaconFiltered is icmpFiltered for the beacon (design 29 D12): a beacon
// path losing every request that has never had a reply reads filtered, and
// once one has come back, failures are failures.
func beaconFiltered(method string, latest store.MonitorLatest) bool {
	return method == model.MonitorTypeBeacon && !latest.Success && latest.LastOKAt.IsZero()
}

// pathFiltered reports whether a pair's failures read filtered rather than
// down, by either rule. Such a pair never pages (resultMayPage), so it is
// neither pending nor paged in the incident lists.
func pathFiltered(method string, latest store.MonitorLatest) bool {
	return icmpFiltered(method, latest) || beaconFiltered(method, latest)
}

// beaconTargetListenGate is beacon_not_listening while the target is
// online and its agent reports no socket where its plan put one, so the
// path names the target's state instead of reading down for it.
func (s *Server) beaconTargetListenGate(target string, nodes map[string]model.Node) string {
	n, ok := nodes[target]
	if !ok || !n.Online || n.Disabled {
		return ""
	}
	facts := s.beaconFactsOf(n)
	if facts == nil {
		return ""
	}
	switch facts.State {
	case model.BeaconAgentBindFailed, model.BeaconAgentCircuitOpen:
		return model.PathReasonBeaconNotListening
	}
	return ""
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
		Window:        window,
		ObservedAt:    now,
		Sources:       []model.PathSource{},
		Targets:       []model.PathTarget{},
		Paths:         make([]model.PathCell, 0, len(entries)),
		BeaconReplans: s.beaconReplans(p, nodes, now),
	}
	degraded := s.pathDegradedSnapshot()
	if !degraded.evaluatedAt.IsZero() {
		at := degraded.evaluatedAt
		out.DegradedAt = &at
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
	covered := figures.to.Sub(figures.from)
	sources, targets := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		cell := e.cell
		pair := e.pair()
		var l *store.MonitorLatest
		if e.hasCheck {
			l = latest[pair]
		}
		cell.State, cell.Reason = pathStateOf(e, l, nodes, now)
		if d, ok := degraded.entries[pair]; ok && e.hasCheck && cell.State == model.PathStateUp && !d.pending {
			// Degraded only where the path would read up: down and
			// unknown say more about now. It is a state for now and does
			// not change with the window.
			cell.State, cell.Reason = model.PathStateDegraded, d.rec.Reason
			cell.Degraded = pathDegradationView(d.rec)
		}
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
