package server

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/groups"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The incident evaluator (keepalive P3).
//
// Emitters still decide when their condition is true past its hold: the
// offline delay and its tags (node_offline_alerts.go), the 90 s sing-box
// hold (server_singbox_liveness.go), two failed monitor results in a row
// (notifyMonitorTransition) and a stalled agent loop (agent_health.go). What
// changed is what they do then. Instead of sending, each calls openIncident
// or resolveIncident, and the record decides what the phone is told:
//
//   - One incident per (kind, subject): an emitter that reports the same open
//     problem again changes nothing.
//   - An open owes one open message and a resolve owes one recovery, and only
//     if the open message was actually sent. Owed messages are stored on the
//     record (OwedOpen, OwedRecovery), so a decision taken just before a crash
//     is still sent after it.
//   - The sweep (evaluateIncidents, every 20 s) sends what is owed, one
//     message per event type for everything that fell due together: twenty
//     cores breaking in one roll page once, as the digests did before.
//   - A maintenance window covering the node, or a snooze, holds the open
//     message (recorded in the Sent log as suppressed, with the reason) and it
//     goes out once neither applies and the incident is still open and
//     unacknowledged. A recovery is never held by either: when the phone was
//     told "down", it is told "up".
//   - An incident that reopens within 30 minutes of resolving reopens the same
//     record and counts a flap. From the third flap it is flapping: at most
//     one message an hour, which always tells the current state, until it has
//     stayed resolved for an hour.
//   - An open critical incident nobody acknowledged is re-sent once per rule
//     after the rule's escalation delay (default 30 minutes) at the rule's
//     Bark level (default critical), and never again.
//
// Event types do not change (node.offline and node.online, service.down and
// service.recovered, monitor.down and monitor.recovered), so the operator's
// rules and templates route exactly as before. Pending incidents (a hold
// still running) are not records; GET /api/incidents derives them from the
// emitters' own evidence.
//
// Lock order: nodeAlerts.mu, then incidentMu, then the store. Nothing here
// takes nodeAlerts.mu.

// Event types this evaluator adds. agent.stalled is new with loop health.
const (
	EventAgentStalled   = "agent.stalled"
	EventAgentRecovered = "agent.recovered"
)

const (
	incidentSeverityInfo     = "info"
	incidentSeverityWarning  = "warning"
	incidentSeverityCritical = "critical"

	// incidentFlapWindow is how soon after resolving a reopening counts as a
	// flap of the same incident; from incidentFlapsToDamp flaps on, messages
	// go out at most once per incidentDampEvery.
	incidentFlapWindow  = 30 * time.Minute
	incidentFlapsToDamp = 3
	incidentDampEvery   = time.Hour

	// The operator's escalation default (2026-10-02): re-send an
	// unacknowledged critical incident once, after 30 minutes, at Bark's
	// critical level.
	incidentEscalateAfterDefault   = 30 * time.Minute
	incidentEscalationLevelDefault = "critical"
	minIncidentEscalateAfter       = 5 * time.Minute
	maxIncidentEscalateAfter       = 24 * time.Hour

	incidentPruneEvery = time.Hour
	maxIncidentSnooze  = 7 * 24 * time.Hour
)

// incidentKind is what the evaluator knows about an open event type.
type incidentKind struct {
	recovery string
	severity string
	// noun names a digest's subjects ("nodes"), empty for a bare count.
	noun string
}

// incidentKinds lists the event types that open incidents. Severity follows
// the keepalive design table (r1-keepalive 6.2): a silent node and a failed
// monitor are warnings, a dead proxy core is critical. Only critical
// incidents escalate and only critical events break through quiet hours.
var incidentKinds = map[string]incidentKind{
	EventNodeOffline:  {recovery: EventNodeOnline, severity: incidentSeverityWarning, noun: "nodes"},
	EventServiceDown:  {recovery: EventServiceRecovered, severity: incidentSeverityCritical, noun: "nodes"},
	EventMonitorDown:  {recovery: EventMonitorRecovered, severity: incidentSeverityWarning},
	EventAgentStalled: {recovery: EventAgentRecovered, severity: incidentSeverityWarning, noun: "nodes"},
}

// incidentRecoveryOf maps each recovery event type to the open it answers.
var incidentRecoveryOf = func() map[string]string {
	out := make(map[string]string, len(incidentKinds))
	for open, k := range incidentKinds {
		out[k.recovery] = open
	}
	return out
}()

// notifyEventSeverity is the severity quiet hours judge an event by. A
// recovery has the severity of the incident it closes: the recovery of a
// critical incident breaks through quiet hours as its open did, so the phone
// is not left saying "down" all night, and the recovery of a warning waits
// with the warnings.
func notifyEventSeverity(eventType string) string {
	if k, ok := incidentKinds[eventType]; ok {
		return k.severity
	}
	if open, ok := incidentRecoveryOf[eventType]; ok {
		return incidentKinds[open].severity
	}
	if eventType == EventSSHCompromiseSuspected {
		return incidentSeverityCritical
	}
	return incidentSeverityWarning
}

// incidentKey names one problem on one subject.
func incidentKey(kind, nodeID, monitorID string) string {
	if monitorID != "" {
		return kind + "/" + monitorID + "/" + nodeID
	}
	return kind + "/" + nodeID
}

// incidentMessage is what one incident contributes to a message: its own
// title and body when it goes out alone, and a line in a digest.
type incidentMessage struct {
	title, detail, line string
}

// incidentSignal is an emitter's report that a problem is open.
type incidentSignal struct {
	kind              string
	nodeID, monitorID string
	subject           string
	since             time.Time
	sortKey           string
	msg               incidentMessage
}

// openIncident records that sig's problem is open past its hold. An incident
// already open for the key is left alone; a key that resolved within the flap
// window reopens its record.
func (s *Server) openIncident(sig incidentSignal, now time.Time) {
	kind, ok := incidentKinds[sig.kind]
	if !ok {
		s.logger.Printf("incidents: %s is not an incident kind", sig.kind)
		return
	}
	key := incidentKey(sig.kind, sig.nodeID, sig.monitorID)
	s.incidentMu.Lock()
	defer s.incidentMu.Unlock()
	if _, ok := s.store.ActiveIncident(key); ok {
		return
	}
	var inc store.Incident
	if last, ok := s.store.LatestIncident(key); ok && !last.Active() && !last.ResolvedAt.IsZero() && now.Sub(last.ResolvedAt) <= incidentFlapWindow {
		inc = last
		inc.Flaps++
		if inc.Flaps >= incidentFlapsToDamp {
			inc.Flapping = true
		}
	} else {
		inc = store.Incident{
			ID: id.New("inc"), Key: key, Kind: sig.kind, Severity: kind.severity,
			NodeID: sig.nodeID, MonitorID: sig.monitorID, FirstOpenedAt: now,
		}
	}
	inc.State = store.IncidentStateOpen
	inc.Subject = sig.subject
	inc.Since = sig.since
	inc.OpenedAt = now
	inc.ResolvedAt = time.Time{}
	inc.UpdatedAt = now
	inc.Title, inc.Detail, inc.Line = sig.msg.title, sig.msg.detail, sig.msg.line
	inc.RecoveryTitle, inc.RecoveryDetail, inc.RecoveryLine = "", "", ""
	// A reopening is a new occurrence: whoever acknowledged the last one has
	// not seen this one.
	inc.AckedBy, inc.AckedAt = "", time.Time{}
	if inc.Notified == store.IncidentNotifiedOpen {
		// The phone still says down (a damped recovery never went out), which
		// is true again: nothing is owed in either direction.
		inc.OwedOpen, inc.OwedRecovery = false, false
	} else {
		inc.OwedOpen, inc.OwedRecovery = true, false
	}
	if err := s.store.PutIncidents(inc); err != nil {
		s.logger.Printf("incidents: record open %s: %v", key, err)
	}
}

// resolveIncident records that key's problem is over. A recovery is owed only
// if the open message was sent; nothing happens when no incident is open.
func (s *Server) resolveIncident(key string, now time.Time, msg incidentMessage) {
	s.incidentMu.Lock()
	defer s.incidentMu.Unlock()
	inc, ok := s.store.ActiveIncident(key)
	if !ok {
		return
	}
	inc.State = store.IncidentStateResolved
	inc.ResolvedAt = now
	inc.UpdatedAt = now
	inc.RecoveryTitle, inc.RecoveryDetail, inc.RecoveryLine = msg.title, msg.detail, msg.line
	inc.OwedOpen = false
	inc.OwedRecovery = inc.Notified == store.IncidentNotifiedOpen
	if err := s.store.PutIncidents(inc); err != nil {
		s.logger.Printf("incidents: record resolve %s: %v", key, err)
	}
}

// maintenanceCover answers which active window, if any, covers a node.
type maintenanceCover func(nodeID string) (store.MaintenanceWindow, bool)

func (s *Server) maintenanceCoverAt(now time.Time) maintenanceCover {
	var active []store.MaintenanceWindow
	needGroups := false
	for _, w := range s.store.MaintenanceWindows() {
		if w.ActiveAt(now) {
			active = append(active, w)
			needGroups = needGroups || len(w.GroupIDs) > 0
		}
	}
	if len(active) == 0 {
		return func(string) (store.MaintenanceWindow, bool) { return store.MaintenanceWindow{}, false }
	}
	// A group covers its resolved members, explicit and selector-matched,
	// the same set the console shows for it.
	var members map[string][]string
	if needGroups {
		members = groups.ResolveAll(s.store.Groups(), s.store.Nodes())
	}
	return func(nodeID string) (store.MaintenanceWindow, bool) {
		if nodeID == "" {
			return store.MaintenanceWindow{}, false
		}
		for _, w := range active {
			if slices.Contains(w.NodeIDs, nodeID) {
				return w, true
			}
			for _, g := range w.GroupIDs {
				if slices.Contains(members[g], nodeID) {
					return w, true
				}
			}
		}
		return store.MaintenanceWindow{}, false
	}
}

// incidentFlapDamped reports a flapping incident that was told something
// less than incidentDampEvery ago.
func incidentFlapDamped(inc store.Incident, now time.Time) bool {
	return inc.Flapping && !inc.NotifiedAt.IsZero() && now.Sub(inc.NotifiedAt) < incidentDampEvery
}

// incidentOpenHold is why an incident's open message must wait, or "".
func incidentOpenHold(inc store.Incident, now time.Time, cover maintenanceCover) string {
	if w, ok := cover(inc.NodeID); ok {
		return fmt.Sprintf("held by maintenance window %q until %s", w.Name, stamp(w.EndsAt))
	}
	if inc.SnoozedUntil.After(now) {
		return "snoozed until " + stamp(inc.SnoozedUntil)
	}
	if incidentFlapDamped(inc, now) {
		return fmt.Sprintf("flapping (%d reopenings within %s), at most one message an hour", inc.Flaps, livenessSpan(incidentFlapWindow))
	}
	return ""
}

// incidentOutgoing is one incident's share of a message about to be sent.
type incidentOutgoing struct {
	incidentID string
	sortKey    string
	msg        incidentMessage
}

func incidentSortKey(inc store.Incident) string {
	return inc.Subject + "\x00" + inc.Key
}

func flappingSuffix(inc store.Incident) string {
	if !inc.Flapping {
		return ""
	}
	return fmt.Sprintf(" (flapping, %d reopenings)", inc.Flaps)
}

// evaluateIncidents is the incident sweep: it settles snoozes and flapping,
// sends every owed message that nothing holds, records the held ones, and
// escalates what is due. Called by the liveness sweep and once by Close.
func (s *Server) evaluateIncidents(now time.Time) {
	s.incidentMu.Lock()
	defer s.incidentMu.Unlock()
	if now.Sub(s.incidentPrunedAt) >= incidentPruneEvery {
		s.incidentPrunedAt = now
		if _, err := s.store.PruneIncidents(now.Add(-store.IncidentRetention)); err != nil {
			s.logger.Printf("incidents: prune: %v", err)
		}
	}
	candidates := s.store.IncidentsWhere(func(inc store.Incident) bool {
		return inc.Active() || inc.OwedRecovery || inc.Flapping || !inc.SnoozedUntil.IsZero()
	})
	if len(candidates) == 0 {
		return
	}
	cover := s.maintenanceCoverAt(now)
	// The store's delete cascades remove a node's and a monitor's incidents;
	// one this sweep finds anyway (written back by a sweep that read it just
	// before the delete) is dropped here.
	nodeExists := map[string]bool{}
	for _, n := range s.store.Nodes() {
		nodeExists[n.ID] = true
	}
	monitors := map[string]model.Monitor{}
	monitorKnown := map[string]bool{}
	monitorOf := func(monitorID string) (model.Monitor, bool) {
		if _, seen := monitorKnown[monitorID]; !seen {
			mon, ok := s.store.Monitor(monitorID)
			monitorKnown[monitorID] = ok
			monitors[monitorID] = mon
		}
		return monitors[monitorID], monitorKnown[monitorID]
	}

	opens := map[string][]incidentOutgoing{}
	recoveries := map[string][]incidentOutgoing{}
	var changed []store.Incident
	var gone []string
	var suppressed []store.NotifyDelivery
	var escalating []*store.Incident
	idx := map[string]int{}
	mark := func(inc store.Incident) {
		if i, ok := idx[inc.ID]; ok {
			changed[i] = inc
			return
		}
		idx[inc.ID] = len(changed)
		changed = append(changed, inc)
	}
	hold := func(inc *store.Incident, eventType, reason, title, body string) {
		if inc.Suppressed == reason {
			return
		}
		inc.Suppressed, inc.SuppressedAt = reason, now
		suppressed = append(suppressed, store.NotifyDelivery{
			ID: id.New("nd"), EventID: id.New("evt"), EventType: eventType,
			Source: store.NotifySourceServer, SourceID: inc.ID, Reason: reason,
			Title: title, Body: body, CreatedAt: now, SettledAt: now,
		})
	}

	for i := range candidates {
		inc := candidates[i]
		dirty := false
		kind := incidentKinds[inc.Kind]

		if inc.NodeID != "" && !nodeExists[inc.NodeID] {
			gone = append(gone, inc.ID)
			continue
		}
		// A monitor pair that no longer exists or is no longer assigned will
		// never report again; its incident would stay open for good.
		if inc.Active() && inc.MonitorID != "" {
			mon, ok := monitorOf(inc.MonitorID)
			if !ok {
				gone = append(gone, inc.ID)
				continue
			}
			if !monitorPairAssigned(mon, inc.NodeID) {
				inc.State = store.IncidentStateResolved
				inc.ResolvedAt = now
				inc.RecoveryTitle = fmt.Sprintf("Monitor no longer checks %s", inc.Subject)
				inc.RecoveryDetail = fmt.Sprintf("%s is no longer assigned, so its down state is closed without a recovery result.", inc.Subject)
				inc.RecoveryLine = inc.Subject + ": no longer checked"
				inc.OwedOpen = false
				inc.OwedRecovery = inc.Notified == store.IncidentNotifiedOpen
				dirty = true
			}
		}

		// A snooze that ran out on an incident still open and unacknowledged
		// sends one reminder.
		if !inc.SnoozedUntil.IsZero() && !now.Before(inc.SnoozedUntil) {
			inc.SnoozedUntil, inc.SnoozedBy = time.Time{}, ""
			if inc.State == store.IncidentStateOpen {
				inc.OwedOpen = true
			}
			dirty = true
		}

		if inc.OwedOpen {
			switch {
			case !inc.Active() || inc.State == store.IncidentStateAcknowledged:
				// Someone has seen it, or it is over: no open is owed.
				inc.OwedOpen = false
				dirty = true
			default:
				title := inc.Title + flappingSuffix(inc)
				if reason := incidentOpenHold(inc, now, cover); reason != "" {
					before := inc.Suppressed
					hold(&inc, inc.Kind, reason, title, inc.Detail)
					dirty = dirty || before != inc.Suppressed
				} else {
					line := inc.Line
					if inc.Flapping {
						line += " (flapping)"
					}
					opens[inc.Kind] = append(opens[inc.Kind], incidentOutgoing{
						incidentID: inc.ID,
						sortKey:    incidentSortKey(inc),
						msg:        incidentMessage{title: title, detail: inc.Detail, line: line},
					})
					inc.OwedOpen = false
					inc.Notified, inc.NotifiedAt, inc.OpenNotifiedAt = store.IncidentNotifiedOpen, now, now
					inc.Suppressed, inc.SuppressedAt = "", time.Time{}
					dirty = true
				}
			}
		}

		if inc.OwedRecovery {
			title := inc.RecoveryTitle + flappingSuffix(inc)
			if incidentFlapDamped(inc, now) {
				before := inc.Suppressed
				hold(&inc, kind.recovery, fmt.Sprintf("flapping (%d reopenings within %s), at most one message an hour", inc.Flaps, livenessSpan(incidentFlapWindow)), title, inc.RecoveryDetail)
				dirty = dirty || before != inc.Suppressed
			} else {
				line := inc.RecoveryLine
				if inc.Flapping {
					line += " (flapping)"
				}
				recoveries[kind.recovery] = append(recoveries[kind.recovery], incidentOutgoing{
					incidentID: inc.ID,
					sortKey:    incidentSortKey(inc),
					msg:        incidentMessage{title: title, detail: inc.RecoveryDetail, line: line},
				})
				inc.OwedRecovery = false
				inc.Notified, inc.NotifiedAt = store.IncidentNotifiedResolved, now
				inc.Suppressed, inc.SuppressedAt = "", time.Time{}
				dirty = true
			}
		}

		// A flapping incident that stayed resolved for an hour has settled.
		if inc.Flapping && !inc.Active() && !inc.OwedRecovery && now.Sub(inc.ResolvedAt) >= incidentDampEvery {
			inc.Flapping = false
			dirty = true
		}

		if dirty {
			inc.UpdatedAt = now
			mark(inc)
		}
		if inc.Active() && inc.State == store.IncidentStateOpen && inc.Severity == incidentSeverityCritical &&
			inc.Notified == store.IncidentNotifiedOpen && !inc.NoEscalate && !inc.Flapping &&
			incidentOpenHold(inc, now, cover) == "" {
			c := inc
			escalating = append(escalating, &c)
		}
	}

	// Into the outbox first, then the records: a crash in between sends the
	// message again at the next start, which is the side an alert errs on.
	for _, kind := range sortedMapKeys(opens) {
		s.sendIncidentMessages(kind, opens[kind])
	}
	for _, kind := range sortedMapKeys(recoveries) {
		s.sendIncidentMessages(kind, recoveries[kind])
	}
	for _, inc := range s.escalateIncidents(escalating, now) {
		if i, ok := idx[inc.ID]; ok {
			changed[i].Escalated = inc.Escalated
			continue
		}
		inc.UpdatedAt = now
		mark(inc)
	}
	if len(gone) > 0 {
		if err := s.store.DeleteIncidents(gone...); err != nil {
			s.logger.Printf("incidents: delete for deleted nodes and monitors: %v", err)
		}
	}
	if len(changed) > 0 {
		if err := s.store.PutIncidents(changed...); err != nil {
			s.logger.Printf("incidents: record sweep: %v", err)
		}
	}
	for _, row := range suppressed {
		if err := s.store.RecordNotifySuppressed(row); err != nil {
			s.logger.Printf("notify: record suppressed %s: %v", row.EventType, err)
		}
	}
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sendIncidentMessages sends one message for every item of one event type: a
// single item keeps its own title and body, several become a digest. Each
// message carries the ids of the incidents it reports.
func (s *Server) sendIncidentMessages(eventType string, items []incidentOutgoing) {
	if len(items) == 0 {
		return
	}
	if len(items) == 1 {
		s.emitIncidentNotice(eventType, items[0].msg.title, items[0].msg.detail, []string{items[0].incidentID})
		return
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].sortKey < items[j].sortKey })
	lines := make([]string, len(items))
	ids := make([]string, len(items))
	for i, item := range items {
		lines[i] = item.msg.line
		ids[i] = item.incidentID
	}
	s.emitIncidentNotice(eventType, incidentDigestTitle(eventType, len(items)), strings.Join(lines, "\n"), ids)
}

// notifyIncidentEvent is the production emitIncidentNotice.
func (s *Server) notifyIncidentEvent(eventType, title, body string, incidentIDs []string) {
	s.enqueueNotifyEvent(eventType, title, body, notifyEnqueue{source: store.NotifySourceServer, incidentIDs: incidentIDs})
}

func incidentDigestTitle(eventType string, n int) string {
	switch eventType {
	case EventNodeOffline:
		return fmt.Sprintf("Lattice node offline digest: %d nodes", n)
	case EventNodeOnline:
		return fmt.Sprintf("Lattice node online digest: %d nodes", n)
	case EventAgentStalled:
		return fmt.Sprintf("Lattice agent stalled digest: %d nodes", n)
	case EventAgentRecovered:
		return fmt.Sprintf("Lattice agent recovered digest: %d nodes", n)
	}
	return alertDigestTitle(eventType, n)
}

// incidentEscalation is one rule's escalation policy; rule is nil for the
// zero-rules broadcast, whose key is "".
type incidentEscalation struct {
	key   string
	rule  *model.NotifyRule
	after time.Duration
	level string
}

// escalationPolicy resolves a rule's escalation options to their effective
// values: on, after 30 minutes, at Bark level critical unless set.
func escalationPolicy(opts store.NotifyRuleOptions) (on bool, after time.Duration, level string) {
	after = incidentEscalateAfterDefault
	if opts.EscalateAfterMinutes > 0 {
		after = time.Duration(opts.EscalateAfterMinutes) * time.Minute
	}
	level = incidentEscalationLevelDefault
	if opts.EscalationBarkLevel != "" {
		level = opts.EscalationBarkLevel
	}
	return !opts.EscalationOff, after, level
}

// escalationsFor lists the escalations that apply to an event type: one per
// enabled rule routing it with escalation on, or the broadcast with the
// defaults when no rule is enabled at all.
func escalationsFor(eventType string, rules []model.NotifyRule, opts map[string]store.NotifyRuleOptions) []incidentEscalation {
	if len(rules) == 0 {
		_, after, level := escalationPolicy(store.NotifyRuleOptions{})
		return []incidentEscalation{{key: "", after: after, level: level}}
	}
	var out []incidentEscalation
	for i := range rules {
		rule := rules[i]
		if !notifyRuleMatches(rule, eventType) {
			continue
		}
		on, after, level := escalationPolicy(opts[rule.ID])
		if !on {
			continue
		}
		out = append(out, incidentEscalation{key: rule.ID, rule: &rule, after: after, level: level})
	}
	return out
}

// escalateIncidents re-sends each due incident once per rule, grouped per
// rule and event type, and returns the incidents whose Escalated changed.
func (s *Server) escalateIncidents(incs []*store.Incident, now time.Time) []store.Incident {
	if len(incs) == 0 {
		return nil
	}
	rules := s.store.EnabledNotifyRules()
	opts := s.store.NotifyRuleOptionsByRule()
	type batchKey struct{ rule, kind string }
	type batch struct {
		esc   incidentEscalation
		items []*store.Incident
	}
	batches := map[batchKey]*batch{}
	var order []batchKey
	touched := map[string]*store.Incident{}
	for _, inc := range incs {
		start := inc.OpenedAt
		if inc.OpenNotifiedAt.After(start) {
			start = inc.OpenNotifiedAt
		}
		for _, esc := range escalationsFor(inc.Kind, rules, opts) {
			if !inc.Escalated[esc.key].IsZero() || now.Sub(start) < esc.after {
				continue
			}
			if inc.Escalated == nil {
				inc.Escalated = map[string]time.Time{}
			}
			inc.Escalated[esc.key] = now
			touched[inc.ID] = inc
			k := batchKey{esc.key, inc.Kind}
			b, ok := batches[k]
			if !ok {
				b = &batch{esc: esc}
				batches[k] = b
				order = append(order, k)
			}
			b.items = append(b.items, inc)
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].rule != order[j].rule {
			return order[i].rule < order[j].rule
		}
		return order[i].kind < order[j].kind
	})
	for _, k := range order {
		b := batches[k]
		sort.SliceStable(b.items, func(i, j int) bool { return incidentSortKey(*b.items[i]) < incidentSortKey(*b.items[j]) })
		var title, body string
		span := livenessSpan(b.esc.after)
		if len(b.items) == 1 {
			inc := b.items[0]
			title = fmt.Sprintf("Not acknowledged after %s: %s", span, inc.Title)
			body = fmt.Sprintf("%s\n\nOpen since %s and not acknowledged. This is the only reminder; acknowledge or snooze it in Lattice.", inc.Detail, stamp(inc.OpenedAt))
		} else {
			title = fmt.Sprintf("Not acknowledged after %s: %d incidents", span, len(b.items))
			lines := make([]string, len(b.items))
			for i, inc := range b.items {
				lines[i] = inc.Line
			}
			body = strings.Join(lines, "\n")
		}
		ids := make([]string, len(b.items))
		for i, inc := range b.items {
			ids[i] = inc.ID
		}
		how := notifyEnqueue{source: store.NotifySourceServer, barkLevel: b.esc.level, incidentIDs: ids}
		if b.esc.rule == nil {
			how.broadcast = true
		} else {
			how.onlyRule = b.esc.rule
		}
		s.commitNotifyPlan(s.planNotifyEvent(k.kind, title, body, how))
	}
	out := make([]store.Incident, 0, len(touched))
	for _, inc := range touched {
		out = append(out, *inc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// adoptLegacyAlerts turns pages sent before incident records existed into
// incidents, once per boot and only where no incident exists: the offline
// spells the old alert map persisted, sing-box episodes that paged down, and
// monitor pairs past their two-failure hold. Each adopted incident has its
// open message marked sent, so its recovery still goes out, and is never
// escalated (nobody can say when its page went out). The old offline map is
// emptied afterwards; the other two keep their own records.
func (s *Server) adoptLegacyAlerts(now time.Time) {
	s.incidentMu.Lock()
	defer s.incidentMu.Unlock()
	var adopted []store.Incident
	adopt := func(inc store.Incident) {
		if _, ok := s.store.ActiveIncident(inc.Key); ok {
			return
		}
		inc.ID = id.New("inc")
		inc.State = store.IncidentStateOpen
		inc.Severity = incidentKinds[inc.Kind].severity
		inc.FirstOpenedAt, inc.OpenedAt, inc.UpdatedAt = now, now, now
		inc.Notified, inc.NotifiedAt, inc.OpenNotifiedAt = store.IncidentNotifiedOpen, now, now
		inc.NoEscalate = true
		adopted = append(adopted, inc)
	}
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	legacy := s.store.NodeOfflineAlerts()
	for nodeID, lastSeen := range legacy {
		n, ok := nodes[nodeID]
		if !ok {
			continue
		}
		name := nodeLabel(n)
		inc := store.Incident{
			Key: incidentKey(EventNodeOffline, nodeID, ""), Kind: EventNodeOffline, NodeID: nodeID,
			Subject: name, Since: lastSeen,
		}
		msg := nodeOfflineIncidentMessage(n, now.Sub(lastSeen), lastSeen)
		inc.Title, inc.Detail, inc.Line = msg.title, msg.detail, msg.line
		adopt(inc)
	}
	for nodeID, rec := range s.store.SingBoxLivenessAll() {
		if rec.NotifiedDownAt.IsZero() {
			continue
		}
		n, ok := nodes[nodeID]
		if !ok {
			continue
		}
		name := nodeLabel(n)
		msg := singBoxDownMessage(name, nodeID, rec.State, rec.ProblemSince, &rec.Runtime)
		adopt(store.Incident{
			Key: incidentKey(EventServiceDown, nodeID, ""), Kind: EventServiceDown, NodeID: nodeID,
			Subject: name, Since: rec.ProblemSince, Title: msg.title, Detail: msg.detail, Line: msg.line,
		})
	}
	if latest, err := s.store.LatestMonitorResults(); err == nil {
		for monitorID, pairs := range latest {
			mon, ok := s.store.Monitor(monitorID)
			if !ok {
				continue
			}
			for _, pair := range pairs {
				if pair.Success || pair.FailStreak < 2 || !monitorPairAssigned(mon, pair.NodeID) {
					continue
				}
				name, where := s.monitorNames(mon, pair.NodeID)
				msg := monitorDownMessage(name, where, pair.Error)
				adopt(store.Incident{
					Key: incidentKey(EventMonitorDown, pair.NodeID, monitorID), Kind: EventMonitorDown,
					NodeID: pair.NodeID, MonitorID: monitorID, Subject: name + " on " + where, Since: pair.Since,
					Title: msg.title, Detail: msg.detail, Line: msg.line,
				})
			}
		}
	}
	if len(adopted) > 0 {
		if err := s.store.PutIncidents(adopted...); err != nil {
			s.logger.Printf("incidents: adopt %d page(s) sent before incident records: %v", len(adopted), err)
		} else {
			s.logger.Printf("incidents: adopted %d page(s) sent before incident records", len(adopted))
		}
	}
	if len(legacy) > 0 {
		if err := s.store.SetNodeOfflineAlerts(map[string]time.Time{}); err != nil {
			s.logger.Printf("incidents: clear the old offline alert map: %v", err)
		}
	}
}
