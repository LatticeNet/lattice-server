package server

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// Degraded paths (design 29 D13).
//
// A path answers but its loss or its median is well above its own last week.
// The evaluator judges every path whose check can have results once a minute
// on a server ticker, beside the latency probe sync, never on a console read:
//
//   - The windows come from raw rows in one store read: the last 15 minutes
//     (latency arm) and the last hour (loss arm), with exact edges.
//   - The baselines are the one-hour buckets of the week before the current
//     hour, read for every pair once the hour turns and held in memory.
//   - Each pair's record steps as the table in D13 says: found once is
//     pending (memory only), found twice in a row is degraded (written),
//     absent while degraded starts clearing (written), found again while
//     clearing cancels it (written), and absent for ten minutes leaves
//     (deleted). Only transitions write.
//   - The matrix reads a snapshot the evaluator publishes by swapping one map,
//     so neither waits for the other.
//
// path.degraded is an incident kind: the evaluator opens it for a degraded
// record when the check's policy is down_and_degraded and the path reads up
// apart from degradation, and resolves it when the record leaves. Dedupe,
// flaps, quiet hours and digests are the incident machinery's. A record that
// entered while the path read down or unknown is quiet for its whole
// episode: an outage leaves an hour of loss behind it, and the operator was
// told about the outage already.
//
// Lock order: pathDegradedState.evalMu, then incidentMu, then the store. The
// snapshot and baseline mutexes are leaves.

// Event types of degraded paths.
const (
	EventPathDegraded  = "path.degraded"
	EventPathRecovered = "path.recovered"
)

// checkPolicy is what a check does when its paths fail or degrade: the alert
// policy in force (model.EffectiveMonitorAlert), the failed runs in a row
// that read down and page, and the degraded thresholds with every default
// filled in.
type checkPolicy struct {
	alert string
	after int
	rule  model.MonitorDegradedRule
}

func (p checkPolicy) pagesDown() bool { return p.alert != model.MonitorAlertOff }

func (p checkPolicy) pagesDegraded() bool { return p.alert == model.MonitorAlertDownAndDegraded }

// pathSetPolicy is the policy the path set gives its generated checks.
func pathSetPolicy(cfg model.LatencyProbeConfig) checkPolicy {
	after := cfg.AlertAfter
	if after < 1 || after > model.MonitorAlertAfterMax {
		after = model.MonitorAlertAfterDefault
	}
	return checkPolicy{alert: model.EffectiveMonitorAlert(cfg.Alert, true), after: after, rule: cfg.Degraded.Effective()}
}

// monitorPolicyWith resolves mon's policy: an operator check's own fields,
// the path set's for a generated latency check, and never paging for any
// other generated check (a beacon's reachability check is not a path).
func monitorPolicyWith(mon model.Monitor, pathSet checkPolicy) checkPolicy {
	switch mon.ManagedBy {
	case "":
		return checkPolicy{alert: model.EffectiveMonitorAlert(mon.Alert, false), after: store.MonitorAlertAfter(mon), rule: mon.Degraded.Effective()}
	case model.MonitorManagedLatency:
		return pathSet
	default:
		return checkPolicy{alert: model.MonitorAlertOff, after: model.MonitorAlertAfterDefault, rule: (*model.MonitorDegradedRule)(nil).Effective()}
	}
}

// monitorPolicy is monitorPolicyWith for one check, reading the path set only
// when the check is generated.
func (s *Server) monitorPolicy(mon model.Monitor) checkPolicy {
	var pathSet checkPolicy
	if mon.ManagedBy == model.MonitorManagedLatency {
		cfg, _ := s.store.LatencyProbeConfig()
		pathSet = pathSetPolicy(cfg)
	}
	return monitorPolicyWith(mon, pathSet)
}

// degradedWindow is a pair's raw rows over the evaluator's windows: probes
// sent and lost in the last hour, and the successful runs of the last 15
// minutes with their median.
type degradedWindow struct {
	probes, lost int
	runs         int
	p50          float64
	hasP50       bool
}

// degradedBaseline is a pair's baseline: the hours with a run, the loss
// share and the median of the merged buckets.
type degradedBaseline struct {
	hours   int
	loss    float64
	hasLoss bool
	p50     float64
	hasP50  bool
}

func degradedBaselineOf(b store.MonitorBaseline) degradedBaseline {
	out := degradedBaseline{hours: b.Hours}
	out.loss, out.hasLoss = b.Merged.Loss()
	out.p50, out.hasP50 = b.Merged.Quantile(0.5)
	return out
}

func (b degradedBaseline) ready() bool { return b.hours >= model.PathBaselineMinHours }

// rollupProbes is a bucket's probes sent and lost, its runs in a bucket
// written before buckets counted probes.
func rollupProbes(b store.MonitorRollup) (sent, lost int) {
	if b.S > 0 {
		return b.S, b.L
	}
	return b.N, b.F
}

func degradedWindowOf(sum store.MonitorWindowSummary) degradedWindow {
	var hour store.MonitorRollup
	hour.Merge(sum.Prev)
	hour.Merge(sum.Cur)
	out := degradedWindow{runs: sum.Cur.Successes()}
	out.probes, out.lost = rollupProbes(hour)
	out.p50, out.hasP50 = sum.Cur.Quantile(0.5)
	return out
}

func roundShare(v float64) float64 { return math.Round(v*10000) / 10000 }

func roundMs(v float64) float64 { return math.Round(v*10) / 10 }

// judgeDegraded decides the condition for one pair. The loss arm needs the
// probe floor and a loss strictly above its trigger; the latency arm needs a
// baseline median, the run floor and a median strictly above its trigger.
// Neither is judged before the baseline holds PathBaselineMinHours hours.
// The evidence of each arm that held is rounded as the matrix rounds.
func judgeDegraded(rule model.MonitorDegradedRule, base degradedBaseline, win degradedWindow) (found bool, reason string, loss *model.PathLossEvidence, latency *model.PathLatencyEvidence) {
	if !base.ready() {
		return false, "", nil, nil
	}
	if win.probes >= model.PathDegradedMinProbes && win.probes > 0 {
		baseLoss := 0.0
		if base.hasLoss {
			baseLoss = base.loss
		}
		trigger := model.DegradedLossTrigger(rule, baseLoss)
		value := float64(win.lost) / float64(win.probes)
		if value > trigger {
			loss = &model.PathLossEvidence{Value: roundShare(value), Baseline: roundShare(baseLoss), Trigger: roundShare(trigger), Sent: win.probes, Lost: win.lost}
		}
	}
	if base.hasP50 && win.hasP50 && win.runs >= model.PathDegradedMinLatencyRuns {
		trigger := model.DegradedLatencyTrigger(rule, base.p50)
		if win.p50 > trigger {
			latency = &model.PathLatencyEvidence{P50Ms: roundMs(win.p50), Runs: win.runs, BaselineMs: roundMs(base.p50), TriggerMs: roundMs(trigger)}
		}
	}
	switch {
	case loss != nil && latency != nil:
		return true, model.PathReasonDegradedLossLatency, loss, latency
	case loss != nil:
		return true, model.PathReasonDegradedLoss, loss, nil
	case latency != nil:
		return true, model.PathReasonDegradedLatency, nil, latency
	}
	return false, "", nil, nil
}

// pathDegradedEntry is one pair the evaluator holds: pending (found on the
// last found evaluations in a row, in memory only), or degraded or clearing
// (rec, written to the store).
type pathDegradedEntry struct {
	pending bool
	found   int
	rec     store.PathDegradedRecord
	// wouldOpen is set on a pending entry that would open path.degraded on
	// entering, and subject is how the path reads in a message; both for the
	// pending incident list.
	wouldOpen bool
	subject   string
}

// pathDegradedStep is what one evaluation does to a pair's entry.
type pathDegradedStep int

const (
	stepNone          pathDegradedStep = iota
	stepEnter                          // pending to degraded: write
	stepStartClearing                  // degraded to clearing: write
	stepStopClearing                   // clearing to degraded: write
	stepLeave                          // clearing for the leave time: delete
)

// stepPathDegraded applies one evaluation to a pair's entry (nil when there
// is none) and says which transition, if any, must reach the store. The
// returned entry is nil when the pair holds nothing afterwards. Consecutive
// counts evaluations, not minutes, so a late tick does not reset a pending
// entry.
func stepPathDegraded(e *pathDegradedEntry, found bool, reason string, loss *model.PathLossEvidence, latency *model.PathLatencyEvidence, quiet bool, now time.Time) (*pathDegradedEntry, pathDegradedStep) {
	evidence := func(rec *store.PathDegradedRecord) {
		rec.Reason, rec.Loss, rec.Latency, rec.EvaluatedAt = reason, loss, latency, now
	}
	switch {
	case e == nil && !found:
		return nil, stepNone
	case e == nil:
		e = &pathDegradedEntry{pending: true, rec: store.PathDegradedRecord{Since: now}}
		evidence(&e.rec)
		e.found = 1
		if e.found < model.PathDegradedEnterAfter {
			return e, stepNone
		}
		e.pending = false
		e.rec.EnteredAt, e.rec.Quiet = now, quiet
		return e, stepEnter
	case e.pending && !found:
		return nil, stepNone
	case e.pending:
		next := *e
		next.found++
		evidence(&next.rec)
		if next.found < model.PathDegradedEnterAfter {
			return &next, stepNone
		}
		next.pending, next.wouldOpen = false, false
		next.rec.EnteredAt, next.rec.Quiet = now, quiet
		return &next, stepEnter
	case !e.rec.Clearing() && found:
		next := *e
		evidence(&next.rec)
		return &next, stepNone
	case !e.rec.Clearing():
		next := *e
		next.rec.ClearSince = now
		return &next, stepStartClearing
	case found:
		next := *e
		next.rec.ClearSince = time.Time{}
		evidence(&next.rec)
		return &next, stepStopClearing
	case now.Sub(e.rec.ClearSince) >= model.PathDegradedLeaveAfter:
		return nil, stepLeave
	default:
		return e, stepNone
	}
}

// pathDegradedState is the evaluator's state. The zero value is ready.
type pathDegradedState struct {
	loadOnce sync.Once
	// evalMu holds one evaluation at a time; it guards entries.
	evalMu  sync.Mutex
	entries map[store.MonitorPair]*pathDegradedEntry

	baseMu   sync.Mutex
	baseHour time.Time
	bases    map[store.MonitorPair]store.MonitorBaseline

	snapMu      sync.Mutex
	snap        map[store.MonitorPair]pathDegradedEntry
	evaluatedAt time.Time
}

// pathDegradedSnapshot is what a matrix read or the pending incident list
// uses: the entries as the last evaluation (or the load at start) left them,
// and when the evaluator last ran (zero before its first run).
type pathDegradedSnapshot struct {
	entries     map[store.MonitorPair]pathDegradedEntry
	evaluatedAt time.Time
}

func (s *Server) pathDegradedSnapshot() pathDegradedSnapshot {
	s.loadPathDegraded()
	d := &s.pathDegraded
	d.snapMu.Lock()
	defer d.snapMu.Unlock()
	return pathDegradedSnapshot{entries: d.snap, evaluatedAt: d.evaluatedAt}
}

// publishPathDegradedLocked swaps in a new snapshot of entries. The caller
// holds evalMu. A zero evaluatedAt keeps the previous stamp (the load).
func (s *Server) publishPathDegradedLocked(evaluatedAt time.Time) {
	d := &s.pathDegraded
	snap := make(map[store.MonitorPair]pathDegradedEntry, len(d.entries))
	for pair, e := range d.entries {
		snap[pair] = *e
	}
	d.snapMu.Lock()
	d.snap = snap
	if !evaluatedAt.IsZero() {
		d.evaluatedAt = evaluatedAt
	}
	d.snapMu.Unlock()
}

// loadPathDegraded reads the stored records once and publishes them as the
// first snapshot, so the matrix shows a degraded path with its original
// since from its first read after a start, and a clearing path keeps counting
// from its stored clear_since. Pending pairs are not stored and start over.
// It never runs under evalMu (it takes it), so callers call it first.
func (s *Server) loadPathDegraded() {
	d := &s.pathDegraded
	d.loadOnce.Do(func() {
		recs, err := s.store.PathDegradedRecords()
		if err != nil {
			s.logger.Printf("degraded paths: load records: %v", err)
		}
		d.evalMu.Lock()
		defer d.evalMu.Unlock()
		d.entries = make(map[store.MonitorPair]*pathDegradedEntry, len(recs))
		for pair, rec := range recs {
			d.entries[pair] = &pathDegradedEntry{rec: rec}
		}
		s.publishPathDegradedLocked(time.Time{})
	})
}

// startPathDegradedEvaluator loads the records and evaluates one minute
// after start and then every minute, until Close stops the latency sweeps.
func (s *Server) startPathDegradedEvaluator() {
	s.loadPathDegraded()
	s.runLatencyProbeSync(model.PathDegradedEvery, func() { s.evaluatePathDegraded(s.now()) })
}

// pathBaselines returns the baselines of pairs for the hour of now. When the
// hour has turned since the last refresh it reads every pair in one store
// read and replaces the cache; otherwise it reads only the pairs the cache
// lacks. A pair with no bucket in the window holds an empty baseline, so it
// is not read again within the hour.
func (s *Server) pathBaselines(pairs []store.MonitorPair, now time.Time) (map[store.MonitorPair]store.MonitorBaseline, error) {
	d := &s.pathDegraded
	hour := now.UTC().Truncate(time.Hour)
	d.baseMu.Lock()
	fresh := d.baseHour.Equal(hour) && d.bases != nil
	var missing []store.MonitorPair
	if fresh {
		for _, pair := range pairs {
			if _, ok := d.bases[pair]; !ok {
				missing = append(missing, pair)
			}
		}
	} else {
		missing = pairs
	}
	d.baseMu.Unlock()
	var read map[store.MonitorPair]store.MonitorBaseline
	if len(missing) > 0 {
		var err error
		read, err = s.store.MonitorRollupBaselines(missing, hour.Add(-model.PathBaselineSpan), hour)
		if err != nil {
			return nil, err
		}
	}
	d.baseMu.Lock()
	defer d.baseMu.Unlock()
	if !fresh || !d.baseHour.Equal(hour) {
		d.baseHour = hour
		d.bases = make(map[store.MonitorPair]store.MonitorBaseline, len(pairs))
	}
	for _, pair := range missing {
		d.bases[pair] = read[pair]
	}
	out := make(map[store.MonitorPair]store.MonitorBaseline, len(pairs))
	for _, pair := range pairs {
		out[pair] = d.bases[pair]
	}
	return out, nil
}

// pathBaselineOf is one pair's baseline for the hour of now: the
// evaluator's cache, or one read when the cache lacks it (a paused path,
// which the evaluator does not judge), kept for the rest of the hour.
func (s *Server) pathBaselineOf(pair store.MonitorPair, now time.Time) (store.MonitorBaseline, error) {
	d := &s.pathDegraded
	hour := now.UTC().Truncate(time.Hour)
	d.baseMu.Lock()
	if d.baseHour.Equal(hour) {
		if b, ok := d.bases[pair]; ok {
			d.baseMu.Unlock()
			return b, nil
		}
	}
	d.baseMu.Unlock()
	read, err := s.store.MonitorRollupBaselines([]store.MonitorPair{pair}, hour.Add(-model.PathBaselineSpan), hour)
	if err != nil {
		return store.MonitorBaseline{}, err
	}
	d.baseMu.Lock()
	if d.baseHour.Equal(hour) && d.bases != nil {
		d.bases[pair] = read[pair]
	}
	d.baseMu.Unlock()
	return read[pair], nil
}

// pathBaselineView is the series' baseline guide for one pair under rule.
func (s *Server) pathBaselineView(pair store.MonitorPair, rule model.MonitorDegradedRule, now time.Time) (*model.PathBaseline, error) {
	b, err := s.pathBaselineOf(pair, now)
	if err != nil {
		return nil, err
	}
	hour := now.UTC().Truncate(time.Hour)
	base := degradedBaselineOf(b)
	out := &model.PathBaseline{From: hour.Add(-model.PathBaselineSpan), To: hour, Hours: base.hours, Ready: base.ready(), Rule: rule}
	if base.hasP50 {
		out.P50Ms = pathRound(base.p50)
	}
	if base.hasLoss {
		v := roundShare(base.loss)
		out.Loss = &v
	}
	if out.Ready {
		baseLoss := 0.0
		if base.hasLoss {
			baseLoss = base.loss
		}
		v := roundShare(model.DegradedLossTrigger(rule, baseLoss))
		out.TriggerLoss = &v
		if base.hasP50 {
			out.TriggerP50Ms = pathRound(model.DegradedLatencyTrigger(rule, base.p50))
		}
	}
	return out, nil
}

// degradedJudged is one pair the evaluation judges.
type degradedJudged struct {
	entry  pathEntry
	policy checkPolicy
	// state is the path's state before degradation is considered.
	state, reason string
}

// pathDegradedPass reports one evaluation: the pairs it judged and the
// transitions it wrote.
type pathDegradedPass struct {
	judged, entered, cleared, left, dropped int
}

// evaluatePathDegraded runs one evaluation at now.
func (s *Server) evaluatePathDegraded(now time.Time) pathDegradedPass {
	s.loadPathDegraded()
	d := &s.pathDegraded
	d.evalMu.Lock()
	defer d.evalMu.Unlock()
	now = now.UTC()
	var pass pathDegradedPass

	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	cfg, _ := s.store.LatencyProbeConfig()
	pathSet := pathSetPolicy(cfg)
	latestByMonitor, err := s.store.LatestMonitorResults()
	if err != nil {
		s.logger.Printf("degraded paths: read latest results: %v", err)
		return pass
	}
	latest := map[store.MonitorPair]*store.MonitorLatest{}
	for monitorID, list := range latestByMonitor {
		for i := range list {
			latest[store.MonitorPair{MonitorID: monitorID, NodeID: list[i].NodeID}] = &list[i]
		}
	}
	judged := map[store.MonitorPair]degradedJudged{}
	unjudged := map[store.MonitorPair]pathEntry{}
	var pairs []store.MonitorPair
	for _, e := range s.pathEntries(now, nodes) {
		if !pathDegradedEligible(e) {
			if _, seen := unjudged[e.pair()]; !seen && e.hasCheck {
				unjudged[e.pair()] = e
			}
			continue
		}
		pair := e.pair()
		if _, dup := judged[pair]; dup {
			continue
		}
		j := degradedJudged{entry: e, policy: monitorPolicyWith(*e.monitor, pathSet)}
		j.state, j.reason = pathStateOf(e, latest[pair], nodes, now)
		judged[pair] = j
		pairs = append(pairs, pair)
	}
	pass.judged = len(pairs)

	var windows map[store.MonitorPair]store.MonitorWindowSummary
	var bases map[store.MonitorPair]store.MonitorBaseline
	if len(pairs) > 0 {
		windows, err = s.store.MonitorRowSummaries(pairs, now.Add(-model.PathDegradedLossWindow), now.Add(-model.PathDegradedLatencyWindow), now.Add(time.Nanosecond))
		if err != nil {
			s.logger.Printf("degraded paths: read windows: %v", err)
			return pass
		}
		bases, err = s.pathBaselines(pairs, now)
		if err != nil {
			s.logger.Printf("degraded paths: read baselines: %v", err)
			return pass
		}
	}
	if d.entries == nil {
		d.entries = map[store.MonitorPair]*pathDegradedEntry{}
	}

	// A pair that is no longer judged (paused, its check disabled or gone,
	// its target no longer resolving, its source no longer running the
	// kind) drops its entry, and its open incident closes with the reason.
	for pair, e := range d.entries {
		if _, ok := judged[pair]; ok {
			continue
		}
		delete(d.entries, pair)
		if e.pending {
			continue
		}
		pass.dropped++
		if err := s.store.DeletePathDegradedRecord(pair); err != nil {
			s.logger.Printf("degraded paths: drop %s/%s: %v", pair.MonitorID, pair.NodeID, err)
		}
		reason := "it is no longer measured"
		if ue, ok := unjudged[pair]; ok {
			if state, why := pathStateOf(ue, latest[pair], nodes, now); state == model.PathStateUnknown && why != "" {
				reason = "it reads unknown (" + why + ")"
			}
		}
		s.resolvePathDegradedDropped(pair, reason, now)
	}

	for _, pair := range pairs {
		j := judged[pair]
		win := degradedWindowOf(windows[pair])
		base := degradedBaselineOf(bases[pair])
		found, reason, loss, latency := judgeDegraded(j.policy.rule, base, win)
		quiet := j.state != model.PathStateUp
		prior := d.entries[pair]
		next, step := stepPathDegraded(prior, found, reason, loss, latency, quiet, now)
		switch step {
		case stepEnter, stepStartClearing, stepStopClearing:
			if err := s.store.PutPathDegradedRecord(pair, next.rec); err != nil {
				s.logger.Printf("degraded paths: write %s/%s: %v", pair.MonitorID, pair.NodeID, err)
			}
		case stepLeave:
			if err := s.store.DeletePathDegradedRecord(pair); err != nil {
				s.logger.Printf("degraded paths: delete %s/%s: %v", pair.MonitorID, pair.NodeID, err)
			}
		}
		switch step {
		case stepEnter:
			pass.entered++
		case stepStartClearing:
			pass.cleared++
		case stepLeave:
			pass.left++
		}
		if next == nil {
			delete(d.entries, pair)
		} else {
			d.entries[pair] = next
		}
		subject := s.pathDegradedSubject(j.entry, nodes)
		switch {
		case step == stepLeave:
			s.resolveIncident(pathDegradedKey(pair), now, pathRecoveredMessage(subject, *prior))
		case next != nil && next.pending:
			next.subject = subject
			next.wouldOpen = j.policy.pagesDegraded() && j.state == model.PathStateUp
		case next != nil && !next.rec.Clearing() && !next.rec.Quiet && j.policy.pagesDegraded() && j.state == model.PathStateUp:
			// An open on a key already open changes nothing; a policy
			// turned on mid-episode opens here at the next evaluation.
			s.openIncident(incidentSignal{
				kind: EventPathDegraded, nodeID: pair.NodeID, monitorID: pair.MonitorID,
				subject: subject, since: next.rec.Since, sortKey: subject,
				msg: pathDegradedMessage(subject, next.rec),
			}, now)
		}
	}
	s.publishPathDegradedLocked(now)
	return pass
}

// pathDegradedEligible reports whether a path can have results now, which is
// when the evaluator judges it: its check exists, is enabled and is not tls,
// the source is assigned and not paused, the source runs the kind and the
// target resolves.
func pathDegradedEligible(e pathEntry) bool {
	return e.hasCheck && e.monitor != nil && e.monitor.Type != model.MonitorTypeTLS && e.monitor.Enabled &&
		e.cell.Source != "" && !e.paused && e.gate == "" && !e.notProbeable
}

func pathDegradedKey(pair store.MonitorPair) string {
	return incidentKey(EventPathDegraded, pair.NodeID, pair.MonitorID)
}

// pathDegradedSubject is how a path reads in a message: "source to target"
// for a path that reaches a node, a check's name on its source otherwise.
func (s *Server) pathDegradedSubject(e pathEntry, nodes map[string]model.Node) string {
	label := func(nodeID string) string {
		if n, ok := nodes[nodeID]; ok && strings.TrimSpace(n.Name) != "" {
			return strings.TrimSpace(n.Name)
		}
		return nodeID
	}
	if e.cell.Managed && e.cell.TargetNode != "" {
		return label(e.cell.Source) + " to " + label(e.cell.TargetNode)
	}
	name := e.cell.MonitorID
	if e.monitor != nil && strings.TrimSpace(e.monitor.Name) != "" {
		name = strings.TrimSpace(e.monitor.Name)
	}
	return name + " on " + label(e.cell.Source)
}

// formatShare is a share as a percentage with at most one decimal place.
func formatShare(v float64) string {
	return strconv.FormatFloat(math.Round(v*1000)/10, 'f', -1, 64) + "%"
}

func formatMs(v float64) string {
	return strconv.FormatFloat(math.Round(v), 'f', -1, 64) + " ms"
}

func formatClock(t time.Time) string { return t.UTC().Format("15:04") + " UTC" }

// formatDegradedSpan is a duration as hours and minutes: "1 h 8 min".
func formatDegradedSpan(d time.Duration) string {
	if d < time.Minute {
		return "under a minute"
	}
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
	switch {
	case h == 0:
		return fmt.Sprintf("%d min", m)
	case m == 0:
		return fmt.Sprintf("%d h", h)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

// pathDegradedEvidence is the evidence as sentences and as a digest line.
func pathDegradedEvidence(rec store.PathDegradedRecord) (sentences, line string) {
	var parts, lines []string
	if l := rec.Loss; l != nil {
		parts = append(parts, fmt.Sprintf("Loss %s over the last hour (%d of %d probes), above its trigger of %s (7-day loss %s).",
			formatShare(l.Value), l.Lost, l.Sent, formatShare(l.Trigger), formatShare(l.Baseline)))
		lines = append(lines, fmt.Sprintf("loss %s (usual %s)", formatShare(l.Value), formatShare(l.Baseline)))
	}
	if l := rec.Latency; l != nil {
		parts = append(parts, fmt.Sprintf("Median %s over the last 15 minutes (%d runs), above its trigger of %s (7-day median %s).",
			formatMs(l.P50Ms), l.Runs, formatMs(l.TriggerMs), formatMs(l.BaselineMs)))
		lines = append(lines, fmt.Sprintf("median %s (usual %s)", formatMs(l.P50Ms), formatMs(l.BaselineMs)))
	}
	return strings.Join(parts, " "), strings.Join(lines, ", ")
}

func pathDegradedMessage(subject string, rec store.PathDegradedRecord) incidentMessage {
	sentences, line := pathDegradedEvidence(rec)
	detail := strings.TrimSpace(sentences + " Degraded since " + formatClock(rec.Since) + ".")
	return incidentMessage{
		title:  "Path degraded: " + subject,
		detail: detail,
		line:   subject + ": " + line,
	}
}

func pathRecoveredMessage(subject string, e pathDegradedEntry) incidentMessage {
	back := e.rec.ClearSince
	return incidentMessage{
		title:  "Path recovered: " + subject,
		detail: fmt.Sprintf("Back to its usual level since %s after %s degraded.", formatClock(back), formatDegradedSpan(back.Sub(e.rec.Since))),
		line:   subject + ": back to its usual level",
	}
}

// resolvePathDegradedDropped closes the open incident of a record the
// evaluator dropped, saying why the path is no longer judged, so no incident
// outlives its record.
func (s *Server) resolvePathDegradedDropped(pair store.MonitorPair, reason string, now time.Time) {
	key := pathDegradedKey(pair)
	inc, ok := s.store.ActiveIncident(key)
	if !ok {
		return
	}
	subject := inc.Subject
	s.resolveIncident(key, now, incidentMessage{
		title:  "Path no longer judged: " + subject,
		detail: fmt.Sprintf("%s is no longer judged because %s, so its degraded state is closed without a recovery.", subject, reason),
		line:   subject + ": no longer judged",
	})
}

// pathDegradationView is a record as the matrix carries it.
func pathDegradationView(rec store.PathDegradedRecord) *model.PathDegradation {
	out := &model.PathDegradation{Since: rec.Since, EvaluatedAt: rec.EvaluatedAt, Loss: rec.Loss, Latency: rec.Latency}
	if rec.Clearing() {
		at := rec.ClearSince
		out.ClearingSince = &at
	}
	return out
}

// pendingPathDegraded lists, for the incident list, a pending path.degraded
// for every pending pair that would open on entering, opening at the next
// evaluation.
func (s *Server) pendingPathDegraded() []store.Incident {
	snap := s.pathDegradedSnapshot()
	var out []store.Incident
	for pair, e := range snap.entries {
		if !e.pending || !e.wouldOpen {
			continue
		}
		opensAt := snap.evaluatedAt.Add(model.PathDegradedEvery)
		msg := pathDegradedMessage(e.subject, e.rec)
		out = append(out, store.Incident{
			Key: pathDegradedKey(pair), Kind: EventPathDegraded, NodeID: pair.NodeID, MonitorID: pair.MonitorID,
			Subject: e.subject, Since: e.rec.Since, Title: msg.title,
			Detail: msg.detail + " A second evaluation that finds it opens the incident.", UpdatedAt: opensAt,
		})
	}
	return out
}
