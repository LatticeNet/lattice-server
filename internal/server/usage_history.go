package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Daily history and the period read side. Ingestion adds one report's deltas
// into the current UTC day (usage_day_node and usage_day_user); everything
// period-shaped (monthly quota usage, last_7d, allocated node traffic) is
// summed from those rows at read time and is never a stored counter.

const (
	vpnQuotaPeriodNone    = "none"
	vpnQuotaPeriodMonthly = "monthly"

	usagePeriodDefault = "30d"
	usageWireTimeFmt   = "2006-01-02T15:04:05Z07:00"
)

// usageIngestDeltas is what one report contributes beyond the legacy
// per-user path: the node-day row, the user-day rows, and the inbound bytes
// the credential and binding rules assign to identities, which the caller
// adds to the monotonic user totals.
type usageIngestDeltas struct {
	DayNode  *store.UsageDayNode
	DayUsers map[string]*store.UsageDayUser
	// Attributed is keyed by accounting id (the ProxyUser projection id).
	Attributed map[string]usageCounter
	// Split records which accounting ids had a named uplink/downlink split
	// this round, so the legacy unsplit path does not count them twice.
	Split        map[string]bool
	UnknownLines int
	Rows         []usageLineRow
}

func (d *usageIngestDeltas) dayUser(userID, day string) *store.UsageDayUser {
	row, ok := d.DayUsers[userID]
	if !ok {
		row = &store.UsageDayUser{UserID: userID, Day: day, ByLine: map[string]store.UsageDayUserLine{}}
		d.DayUsers[userID] = row
	}
	return row
}

// usageIngest derives the day rows for one report. legacyDelta is the
// per-accounting-id delta the UserBytes path already computed (it carries
// no direction); lineUserDelta is the same split by line from LineUserBytes.
// Legacy collectors report one number per user, which is recorded as
// downlink so period sums stay right; the split only exists where the core
// reported it.
func (s *Server) usageIngest(ctx *usageAttributionContext, snapshot, previous model.ProxyUsageSnapshot, hadPrevious, reset bool, now time.Time, legacyDelta map[string]int64, lineUserDelta map[string]map[string]int64) usageIngestDeltas {
	day := store.UsageDay(now)
	out := usageIngestDeltas{
		DayNode:    &store.UsageDayNode{NodeID: snapshot.NodeID, Day: day, Lines: map[string]store.UsageDayLine{}},
		DayUsers:   map[string]*store.UsageDayUser{},
		Attributed: map[string]usageCounter{},
		Split:      map[string]bool{},
	}
	inboundDelta := diffTrafficCounters(snapshot.InboundTraffic, previous.InboundTraffic, hadPrevious, reset)
	namedDelta := diffTrafficCounters(snapshot.UserTraffic, previous.UserTraffic, hadPrevious, reset)

	// Named counters grouped by the line they live on.
	namedByLine := map[string]map[string]usageCounter{}
	for name, delta := range namedDelta {
		target, ok := ctx.nameIndex[name]
		if !ok {
			continue
		}
		if namedByLine[target.LineHashID] == nil {
			namedByLine[target.LineHashID] = map[string]usageCounter{}
		}
		c := namedByLine[target.LineHashID][target.VpnUserID]
		c.add(delta)
		namedByLine[target.LineHashID][target.VpnUserID] = c
		out.Split[ctx.accounting[target.VpnUserID]] = true
	}

	// Every inbound tag with a delta, plus every line that only had named
	// counters this round (an inbound map capped by the agent still leaves
	// the user counters attributable).
	tags := make([]string, 0, len(inboundDelta))
	for tag := range inboundDelta {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	seen := map[string]bool{}
	nodeLines := ctx.byNodeTag[snapshot.NodeID]
	attribute := func(tag string, f *usageLineFacts, traffic usageLineTraffic) {
		rows := ctx.attributeLine(snapshot.NodeID, tag, f, traffic)
		out.Rows = append(out.Rows, rows...)
		line := out.DayNode.Lines[tag]
		if f != nil {
			line.LineHashID = f.Line.LineHashID
		}
		line.Uplink += traffic.Inbound.Uplink
		line.Downlink += traffic.Inbound.Downlink
		for _, row := range rows {
			if !row.Counted || row.UserID == "" {
				continue
			}
			c := usageCounter{Uplink: row.Uplink, Downlink: row.Downlink}
			if line.Users == nil {
				line.Users = map[string]store.UsageDayBytes{}
			}
			ub := line.Users[row.UserID]
			ub.Uplink += c.Uplink
			ub.Downlink += c.Downlink
			line.Users[row.UserID] = ub
			u := out.dayUser(row.UserID, day)
			u.Uplink += c.Uplink
			u.Downlink += c.Downlink
			u.LastSeenAt = now
			bl := u.ByLine[row.LineHashID]
			bl.Uplink += c.Uplink
			bl.Downlink += c.Downlink
			bl.LastSeenAt = now
			u.ByLine[row.LineHashID] = bl
			if row.Attribution != usageAttributionNamed {
				acct := ctx.accounting[row.UserID]
				a := out.Attributed[acct]
				a.add(c)
				out.Attributed[acct] = a
			}
		}
		out.DayNode.Lines[tag] = line
	}
	for _, tag := range tags {
		f := nodeLines[tag]
		traffic := usageLineTraffic{Inbound: inboundDelta[tag]}
		if f != nil {
			traffic.Named = namedByLine[f.Line.LineHashID]
			seen[f.Line.LineHashID] = true
		} else {
			out.UnknownLines++
		}
		attribute(tag, f, traffic)
	}
	namedOnly := make([]string, 0)
	for hash := range namedByLine {
		if !seen[hash] {
			namedOnly = append(namedOnly, hash)
		}
	}
	sort.Strings(namedOnly)
	for _, hash := range namedOnly {
		f, ok := ctx.byHash[hash]
		if ok && f.Line.NodeID != snapshot.NodeID {
			continue
		}
		if !ok {
			// The read model does not carry the line right now (discovery is
			// stale or the node is between reports). The counter is still a
			// proof for that user on that line hash, so the user-day row is
			// written; only the node-day line, which needs the tag, waits.
			for userID, c := range namedByLine[hash] {
				u := out.dayUser(userID, day)
				u.Uplink += c.Uplink
				u.Downlink += c.Downlink
				u.LastSeenAt = now
				bl := u.ByLine[hash]
				bl.Uplink += c.Uplink
				bl.Downlink += c.Downlink
				bl.LastSeenAt = now
				u.ByLine[hash] = bl
			}
			continue
		}
		total := usageCounter{}
		for _, c := range namedByLine[hash] {
			total.add(c)
		}
		attribute(f.Line.Tag, f, usageLineTraffic{Inbound: total, Named: namedByLine[hash]})
	}

	// Legacy path: users whose bytes arrived without a direction.
	for acct, delta := range legacyDelta {
		if delta <= 0 || out.Split[acct] {
			continue
		}
		userID := ctx.vpnByAcct[acct]
		if userID == "" {
			userID = acct
		}
		u := out.dayUser(userID, day)
		u.Downlink += delta
		u.LastSeenAt = now
		for hash, byUser := range lineUserDelta {
			if v := byUser[acct]; v > 0 {
				bl := u.ByLine[hash]
				bl.Downlink += v
				bl.LastSeenAt = now
				u.ByLine[hash] = bl
			}
		}
	}
	if len(out.DayNode.Lines) == 0 {
		out.DayNode = nil
	}
	return out
}

// maybePruneUsageDays runs the retention sweep once per UTC day, on the first
// ingestion that sees the day roll. Caller holds proxyUsageMu.
func (s *Server) maybePruneUsageDays(now time.Time) {
	day := store.UsageDay(now)
	if s.usageDayLast == day {
		return
	}
	s.usageDayLast = day
	cutoff := store.UsageDay(now.AddDate(0, 0, -store.UsageDayRetentionDays))
	if pruned, err := s.store.PruneUsageDays(cutoff); err != nil {
		s.logger.Printf("usage: prune day rows before %s: %v", cutoff, err)
	} else if pruned > 0 {
		s.logger.Printf("usage: pruned %d day rows before %s", pruned, cutoff)
	}
}

// ── quota periods ─────────────────────────────────────────────────────────────

// vpnUserQuotaPeriod reports the identity's current period window, or false
// when the quota is lifetime.
func vpnUserQuotaPeriod(u VpnUser, now time.Time) (start, end time.Time, ok bool) {
	if u.QuotaPeriod != vpnQuotaPeriodMonthly {
		return time.Time{}, time.Time{}, false
	}
	start, end = quotaPeriodBounds(now, u.QuotaResetDay)
	return start, end, true
}

// periodUsage sums an identity's user-day rows over [from, to] (inclusive
// days) and returns the rows for callers that need the per-day shape.
func (s *Server) periodUsage(userID string, from, to time.Time) (usageCounter, []store.UsageDayUser) {
	rows, err := s.store.UsageDayUserRows(userID, store.UsageDay(from), store.UsageDay(to))
	if err != nil {
		s.logger.Printf("usage: read day rows for %s: %v", userID, err)
		return usageCounter{}, nil
	}
	total := usageCounter{}
	for _, row := range rows {
		total.add(usageCounter{Uplink: row.Uplink, Downlink: row.Downlink})
	}
	return total, rows
}

// quotaEvaluate derives status and quota alerts for one user projection. For
// a lifetime quota that is the monotonic total; for a monthly quota it is the
// period sum from the day rows plus whatever this report is about to add.
// Only the status and notification cursors flow back: UsedBytes stays the
// lifetime total.
func (s *Server) quotaEvaluate(user model.ProxyUser, vpnUser *VpnUser, now time.Time, pending usageCounter) (model.ProxyUser, []proxyUserNotificationFire) {
	user.Status = derivedProxyUserStatusAt(user, now)
	if vpnUser == nil {
		return nextProxyUserNotifications(user, now)
	}
	start, _, ok := vpnUserQuotaPeriod(*vpnUser, now)
	if !ok {
		return nextProxyUserNotifications(user, now)
	}
	used, _ := s.periodUsage(vpnUser.ID, start, now)
	projection := user
	projection.UsedBytes = used.total() + pending.total()
	projection.Status = derivedProxyUserStatusAt(projection, now)
	projection, alerts := nextProxyUserNotificationsForPeriod(projection, now, store.UsageDay(start))
	user.Status = projection.Status
	user.LastQuotaNotifiedKey = projection.LastQuotaNotifiedKey
	user.LastExpiryNotifiedKey = projection.LastExpiryNotifiedKey
	return user, alerts
}

// vpnUsersByAccounting indexes identities by the ProxyUser projection id that
// carries their total (the legacy id for a migrated identity).
func (s *Server) vpnUsersByAccounting() map[string]VpnUser {
	out := map[string]VpnUser{}
	for _, u := range s.listVpnUsers() {
		acct := strings.TrimSpace(u.MigratedFromProxyUser)
		if acct == "" {
			acct = u.ID
		}
		out[acct] = u
	}
	return out
}

// vpnUserForAccounting finds the identity behind one ProxyUser projection id.
func (s *Server) vpnUserForAccounting(acct string) *VpnUser {
	if u, ok := s.vpnUsersByAccounting()[acct]; ok {
		return &u
	}
	return nil
}

// ── period window and read model ─────────────────────────────────────────────

// usageWindow is an inclusive day range plus the loaded node-day rows for it.
type usageWindow struct {
	From, To time.Time
	Label    string
	nodes    map[string][]store.UsageDayNode
}

func (w usageWindow) fromDay() string { return store.UsageDay(w.From) }
func (w usageWindow) toDay() string   { return store.UsageDay(w.To) }

// parseUsagePeriod accepts today, 7d, 30d, all, or yyyymmdd..yyyymmdd. quota
// is resolved by the caller, who knows the identity.
func parseUsagePeriod(period string, now time.Time) (usageWindow, error) {
	period = strings.TrimSpace(strings.ToLower(period))
	if period == "" {
		period = usagePeriodDefault
	}
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	switch period {
	case "today":
		return usageWindow{From: today, To: today, Label: period}, nil
	case "7d":
		return usageWindow{From: today.AddDate(0, 0, -6), To: today, Label: period}, nil
	case "30d":
		return usageWindow{From: today.AddDate(0, 0, -29), To: today, Label: period}, nil
	case "all":
		return usageWindow{From: today.AddDate(0, 0, -store.UsageDayRetentionDays), To: today, Label: period}, nil
	}
	if from, to, ok := strings.Cut(period, ".."); ok {
		start, err1 := store.ParseUsageDay(from)
		end, err2 := store.ParseUsageDay(to)
		if err1 != nil || err2 != nil || end.Before(start) {
			return usageWindow{}, errors.New("period range must be yyyymmdd..yyyymmdd")
		}
		if end.After(today) {
			end = today
		}
		return usageWindow{From: start, To: end, Label: period}, nil
	}
	return usageWindow{}, fmt.Errorf("unknown period %q", period)
}

// loadUsageWindow reads every node's day rows for the window once.
func (s *Server) loadUsageWindow(w usageWindow, nodeIDs []string) usageWindow {
	w.nodes = map[string][]store.UsageDayNode{}
	for _, nodeID := range nodeIDs {
		rows, err := s.store.UsageDayNodeRows(nodeID, w.fromDay(), w.toDay())
		if err != nil {
			s.logger.Printf("usage: read day rows for node %s: %v", nodeID, err)
			continue
		}
		if len(rows) > 0 {
			w.nodes[nodeID] = rows
		}
	}
	return w
}

// usageDayLineEverAttributed reports whether ingestion ever recorded a line for
// this stored day row. EVER is the whole of it: this decides nothing about
// whether that line still exists, still resolves, or is still on that node.
//
// It is deliberately the exact common subset of what its two callers need, and
// nothing more. sumWindow carries the hash forward so the read path can
// re-resolve a line the live index has lost; holdUnresolvableInboundTags reads
// it as proof that a tag naming no line right now has named one before and will
// again. The read path's stronger requirement, that the hash still resolves,
// lives in attributeWindow as its own lookup and must stay there: the hold
// cannot survive that check, because during a cold window nothing resolves.
//
// The rule that makes sharing safe, and the one to apply before adding a third
// caller: a shared predicate is safe only when every caller's real requirement
// is a subset of what it checks. Widening this to answer "does it still
// resolve" would silently break the hold, so widen a caller instead.
func usageDayLineEverAttributed(line store.UsageDayLine) bool {
	return line.LineHashID != ""
}

// usageWindowLine is one line's summed traffic over a window.
type usageWindowLine struct {
	NodeID, Tag, LineHashID string
	Inbound                 usageCounter
	Users                   map[string]usageCounter
}

// sumWindow folds the window's node-day rows per (node, tag), optionally
// restricted to [from, to]. The tag is the key: a line the read model has
// since lost keeps its bytes under its tag.
func (w usageWindow) sumWindow(from, to string) map[string]map[string]*usageWindowLine {
	out := map[string]map[string]*usageWindowLine{}
	for nodeID, rows := range w.nodes {
		for _, row := range rows {
			if row.Day < from || row.Day > to {
				continue
			}
			for tag, line := range row.Lines {
				if out[nodeID] == nil {
					out[nodeID] = map[string]*usageWindowLine{}
				}
				wl := out[nodeID][tag]
				if wl == nil {
					wl = &usageWindowLine{NodeID: nodeID, Tag: tag, Users: map[string]usageCounter{}}
					out[nodeID][tag] = wl
				}
				if usageDayLineEverAttributed(line) {
					wl.LineHashID = line.LineHashID
				}
				wl.Inbound.add(usageCounter{Uplink: line.Uplink, Downlink: line.Downlink})
				for userID, b := range line.Users {
					c := wl.Users[userID]
					c.add(usageCounter{Uplink: b.Uplink, Downlink: b.Downlink})
					wl.Users[userID] = c
				}
			}
		}
	}
	return out
}

// usageLinesReport is the per-line read model over a window.
type usageLinesReport struct {
	Rows                        []usageLineRow
	DoubleCountedViaChainsBytes int64
}

// attributeWindow attributes every line's summed traffic with the current
// facts. Chain targets get their relayed portion from the upstream lines'
// sums over the same days, which is what makes the shared-line estimate
// day-aligned rather than a subtraction of two unrelated core lifetimes.
func (ctx *usageAttributionContext) attributeWindow(sums map[string]map[string]*usageWindowLine) usageLinesReport {
	byHash := map[string]*usageWindowLine{}
	for _, byTag := range sums {
		for _, wl := range byTag {
			if wl.LineHashID != "" {
				byHash[wl.LineHashID] = wl
			}
		}
	}
	report := usageLinesReport{Rows: []usageLineRow{}}
	nodeIDs := make([]string, 0, len(sums))
	for nodeID := range sums {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	for _, nodeID := range nodeIDs {
		tags := make([]string, 0, len(sums[nodeID]))
		for tag := range sums[nodeID] {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		for _, tag := range tags {
			wl := sums[nodeID][tag]
			f := ctx.byNodeTag[nodeID][tag]
			if f == nil && wl.LineHashID != "" {
				f = ctx.byHash[wl.LineHashID]
			}
			traffic := usageLineTraffic{Inbound: wl.Inbound}
			if f != nil {
				traffic.Named = map[string]usageCounter{}
				for userID, c := range wl.Users {
					if ctx.reported[f.Line.LineHashID][userID] {
						traffic.Named[userID] = c
					}
				}
				if len(f.Upstream) > 0 {
					upstream := usageCounter{}
					for _, hash := range f.Upstream {
						if up, ok := byHash[hash]; ok {
							upstream.add(up.Inbound)
						}
					}
					traffic.Upstream = &upstream
				}
			}
			rows := ctx.attributeLine(nodeID, tag, f, traffic)
			if f == nil && wl.LineHashID != "" {
				// The tag is not unknown. Ingestion recorded which line it
				// belonged to and the day rows still carry that hash; what is
				// missing is live topology for the line, which is a node
				// reachability problem and recovers on its own. Reporting it as
				// "no line carries this tag" sends an operator hunting for a
				// config change that never happened.
				for i := range rows {
					if rows[i].Attribution != usageAttributionUnknownLine {
						continue
					}
					rows[i].LineHashID = wl.LineHashID
					rows[i].AttributionReason = "this tag's line is known but the node reports no live topology"
				}
			}
			for _, row := range rows {
				if row.CountedAt != "" {
					report.DoubleCountedViaChainsBytes += row.UsedBytes
				}
			}
			report.Rows = append(report.Rows, rows...)
		}
	}
	return report
}

// buildUsageLines is the per-line read model for a period: every node's day
// rows summed and attributed with the current facts.
func (s *Server) buildUsageLines(ctx *usageAttributionContext, w usageWindow) (usageLinesReport, usageWindow) {
	nodeIDs := make([]string, 0, len(ctx.byNodeTag))
	for nodeID := range ctx.byNodeTag {
		nodeIDs = append(nodeIDs, nodeID)
	}
	for _, snap := range s.store.ProxyUsageSnapshots() {
		nodeIDs = appendUniqueSorted(nodeIDs, snap.NodeID)
	}
	w = s.loadUsageWindow(w, nodeIDs)
	report := ctx.attributeWindow(w.sumWindow(w.fromDay(), w.toDay()))
	return report, w
}

// ── users list enrichment ────────────────────────────────────────────────────

type allocatedLineView struct {
	LineHashID     string `json:"line_hash_id"`
	Tag            string `json:"tag,omitempty"`
	Role           string `json:"role"`
	Allocation     string `json:"allocation"` // binding | substore | relay
	PeriodUplink   int64  `json:"period_uplink"`
	PeriodDownlink int64  `json:"period_downlink"`
	LastSeenAt     string `json:"last_seen_at,omitempty"`
	Counted        bool   `json:"counted"`
	Estimate       bool   `json:"estimate,omitempty"`
	ViaRelay       bool   `json:"via_relay,omitempty"`
}

type allocatedNodeView struct {
	NodeID         string              `json:"node_id"`
	NodeName       string              `json:"node_name,omitempty"`
	CollectorState string              `json:"collector_state"`
	Lines          []allocatedLineView `json:"lines"`
}

// vpnUserUsageView is the users list row: the identity plus its usage facts.
//
// UsedTotalBytes and UsedPeriodBytes are both summed from the identity's
// user-day rows, so they carry the same attribution decisions and the total
// can never be smaller than the period inside it. The total covers the
// retained day rows only: they are pruned at store.UsageDayRetentionDays, so
// UsedTotalFrom names the first day it accounts for, and UsedTotalTruncated
// says the identity is older than that day and traffic before it is gone.
// The total is then a floor, not a true lifetime, and the field says so
// rather than presenting a truncated number as complete.
type vpnUserUsageView struct {
	vpnUserView
	UsedTotalBytes     int64               `json:"used_total_bytes"`
	UsedTotalFrom      string              `json:"used_total_from,omitempty"`
	UsedTotalTruncated bool                `json:"used_total_truncated,omitempty"`
	UsedPeriodBytes    int64               `json:"used_period_bytes"`
	PeriodStart        string              `json:"period_start,omitempty"`
	PeriodEnd          string              `json:"period_end,omitempty"`
	Last7d             []int64             `json:"last_7d"`
	LastSeenAt         string              `json:"last_seen_at,omitempty"`
	AllocatedNodes     []allocatedNodeView `json:"allocated_nodes"`
}

// vpnUserUsageViews enriches identities with their usage. One context, one
// window load (the widest period any listed identity needs), one pass.
func (s *Server) vpnUserUsageViews(users []VpnUser, now time.Time) []vpnUserUsageView {
	ctx := s.usageAttributionContext()
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	earliest := today.AddDate(0, 0, -29)
	type period struct {
		start, end time.Time
		set        bool
	}
	periods := make([]period, len(users))
	for i, u := range users {
		if start, end, ok := vpnUserQuotaPeriod(u, now); ok {
			periods[i] = period{start: start, end: end, set: true}
			if start.Before(earliest) {
				earliest = start
			}
		} else {
			periods[i] = period{start: today.AddDate(0, 0, -29), end: today.AddDate(0, 0, 1)}
		}
	}
	if sevenDays := today.AddDate(0, 0, -6); sevenDays.Before(earliest) {
		earliest = sevenDays
	}
	// The user-day read runs from the retention floor so the lifetime total
	// and the period sum come out of one scan of one set of rows. earliest is
	// the widest window any listed period needs, so taking the older of the
	// two keeps every period row inside the read and makes "the total is at
	// least the period" hold by construction rather than by coincidence. The
	// node-day window below stays at earliest: it feeds last_7d and the
	// per-line report, neither of which reaches past it.
	retained := today.AddDate(0, 0, -store.UsageDayRetentionDays)
	if earliest.Before(retained) {
		retained = earliest
	}
	retainedDay := store.UsageDay(retained)
	window := usageWindow{From: earliest, To: today, Label: "list"}
	nodeIDs := make([]string, 0, len(ctx.byNodeTag))
	for nodeID := range ctx.byNodeTag {
		nodeIDs = append(nodeIDs, nodeID)
	}
	window = s.loadUsageWindow(window, nodeIDs)
	profiles := map[string]model.ProxyNodeProfile{}
	for _, p := range s.store.ProxyNodeProfiles() {
		profiles[p.NodeID] = p
	}
	collectorState := func(nodeID string) string {
		if p, ok := profiles[nodeID]; ok {
			return usageCollectorState(p)
		}
		return usageCollectorStateNoCollector
	}

	// Attribution over a period window depends only on the window, so users
	// sharing a period share one pass.
	reports := map[string]usageLinesReport{}
	windowReport := func(from, to string) usageLinesReport {
		key := from + ".." + to
		report, ok := reports[key]
		if !ok {
			report = ctx.attributeWindow(window.sumWindow(from, to))
			reports[key] = report
		}
		return report
	}
	out := make([]vpnUserUsageView, 0, len(users))
	for i, u := range users {
		view := vpnUserUsageView{vpnUserView: toVpnUserView(u), Last7d: make([]int64, 7), AllocatedNodes: []allocatedNodeView{}}
		acct := ctx.accounting[u.ID]
		if acct == "" {
			acct = u.ID
		}
		var lastSeen time.Time
		// The legacy ProxyUser projection still carries last_seen_at, and it
		// sees reports the day rows do not. Its UsedBytes is the other
		// accounting path and is deliberately not read here: it is written
		// per report from the node's own deltas and diverges from the day
		// rows, which is what put a total below its own period on this screen.
		if pu, ok := s.store.ProxyUser(acct); ok {
			lastSeen = pu.LastSeenAt
		}
		p := periods[i]
		rows, err := s.store.UsageDayUserRows(u.ID, retainedDay, store.UsageDay(today))
		if err != nil {
			s.logger.Printf("usage: read day rows for %s: %v", u.ID, err)
		}
		periodFrom, periodTo := store.UsageDay(p.start), store.UsageDay(today)
		byLine := map[string]store.UsageDayUserLine{}
		periodUsed, totalUsed := usageCounter{}, usageCounter{}
		for _, row := range rows {
			totalUsed.add(usageCounter{Uplink: row.Uplink, Downlink: row.Downlink})
			if row.LastSeenAt.After(lastSeen) {
				lastSeen = row.LastSeenAt
			}
			if day, err := store.ParseUsageDay(row.Day); err == nil {
				if idx := int(today.Sub(day).Hours() / 24); idx >= 0 && idx < 7 {
					view.Last7d[6-idx] = row.Uplink + row.Downlink
				}
			}
			if row.Day < periodFrom || row.Day > periodTo {
				continue
			}
			periodUsed.add(usageCounter{Uplink: row.Uplink, Downlink: row.Downlink})
			for hash, line := range row.ByLine {
				cur := byLine[hash]
				cur.Uplink += line.Uplink
				cur.Downlink += line.Downlink
				if line.LastSeenAt.After(cur.LastSeenAt) {
					cur.LastSeenAt = line.LastSeenAt
				}
				byLine[hash] = cur
			}
		}
		view.UsedTotalBytes = totalUsed.total()
		view.UsedTotalFrom = retained.UTC().Format(usageWireTimeFmt)
		view.UsedTotalTruncated = u.CreatedAt.Before(retained)
		if p.set {
			view.UsedPeriodBytes = periodUsed.total()
			view.PeriodStart = p.start.UTC().Format(usageWireTimeFmt)
			view.PeriodEnd = p.end.UTC().Format(usageWireTimeFmt)
		} else {
			view.UsedPeriodBytes = view.UsedTotalBytes
		}
		if !lastSeen.IsZero() {
			view.LastSeenAt = lastSeen.UTC().Format(usageWireTimeFmt)
		}

		// Allocated lines: enabled bindings plus Sub-Store selections, then
		// the chain targets those lines relay to.
		report := windowReport(periodFrom, periodTo)
		estimates := map[string]usageLineRow{}
		for _, row := range report.Rows {
			if row.UserID == u.ID && row.Estimate {
				estimates[row.LineHashID] = row
			}
		}
		allocation := map[string]string{}
		for _, b := range u.Bindings {
			if b.Enabled {
				if _, ok := ctx.byHash[b.LineHashID]; ok {
					allocation[b.LineHashID] = "binding"
				}
			}
		}
		for _, rec := range ctx.substore {
			if rec.VPNIdentity != u.ID {
				continue
			}
			for _, root := range rec.EntryRoots {
				if f, ok := ctx.byUUID[strings.ToLower(strings.TrimSpace(root))]; ok {
					if _, bound := allocation[f.Line.LineHashID]; !bound {
						allocation[f.Line.LineHashID] = "substore"
					}
				}
			}
		}
		relayReached := map[string]bool{}
		for hash := range allocation {
			for _, target := range ctx.reachableExits(hash) {
				if _, direct := allocation[target]; !direct {
					relayReached[target] = true
				}
			}
		}
		byNode := map[string]*allocatedNodeView{}
		addLine := func(hash string, line allocatedLineView) {
			f := ctx.byHash[hash]
			node := byNode[f.Line.NodeID]
			if node == nil {
				node = &allocatedNodeView{NodeID: f.Line.NodeID, NodeName: ctx.nodeName[f.Line.NodeID], CollectorState: collectorState(f.Line.NodeID), Lines: []allocatedLineView{}}
				byNode[f.Line.NodeID] = node
			}
			line.LineHashID, line.Tag, line.Role = hash, f.Line.Tag, f.Role
			node.Lines = append(node.Lines, line)
		}
		for hash, how := range allocation {
			line := allocatedLineView{Allocation: how}
			if exact, ok := byLine[hash]; ok && (exact.Uplink > 0 || exact.Downlink > 0) {
				line.PeriodUplink, line.PeriodDownlink, line.Counted = exact.Uplink, exact.Downlink, true
				if !exact.LastSeenAt.IsZero() {
					line.LastSeenAt = exact.LastSeenAt.UTC().Format(usageWireTimeFmt)
				}
			} else if est, ok := estimates[hash]; ok {
				line.PeriodUplink, line.PeriodDownlink, line.Estimate = est.Uplink, est.Downlink, true
			}
			addLine(hash, line)
		}
		for hash := range relayReached {
			addLine(hash, allocatedLineView{Allocation: "relay", ViaRelay: true})
		}
		for _, node := range byNode {
			sort.Slice(node.Lines, func(i, j int) bool { return node.Lines[i].LineHashID < node.Lines[j].LineHashID })
			view.AllocatedNodes = append(view.AllocatedNodes, *node)
		}
		sort.Slice(view.AllocatedNodes, func(i, j int) bool { return view.AllocatedNodes[i].NodeID < view.AllocatedNodes[j].NodeID })
		out = append(out, view)
	}
	return out
}

// reachableExits walks the chain from a line and returns every target it
// reaches, bounded so a cycle in inferred edges cannot spin.
func (ctx *usageAttributionContext) reachableExits(hash string) []string {
	out := []string{}
	seen := map[string]bool{hash: true}
	queue := append([]string(nil), ctx.byHash[hash].Downstream...)
	for len(queue) > 0 && len(seen) < 64 {
		next := queue[0]
		queue = queue[1:]
		if seen[next] {
			continue
		}
		seen[next] = true
		out = append(out, next)
		if f, ok := ctx.byHash[next]; ok {
			queue = append(queue, f.Downstream...)
		}
	}
	sort.Strings(out)
	return out
}

// ── usage_query ──────────────────────────────────────────────────────────────

type usageQueryRequest struct {
	UserID     string `json:"user_id"`
	NodeID     string `json:"node_id"`
	LineHashID string `json:"line_hash_id"`
	Period     string `json:"period"`
}

type usageQueryDay struct {
	Day       string `json:"day"`
	Uplink    int64  `json:"uplink"`
	Downlink  int64  `json:"downlink"`
	UsedBytes int64  `json:"used_bytes"`
}

type usageQueryResponse struct {
	Scope                       map[string]string `json:"scope"`
	Period                      string            `json:"period"`
	From                        string            `json:"from"`
	To                          string            `json:"to"`
	Uplink                      int64             `json:"uplink"`
	Downlink                    int64             `json:"downlink"`
	UsedBytes                   int64             `json:"used_bytes"`
	Days                        []usageQueryDay   `json:"days"`
	Lines                       []usageLineRow    `json:"lines"`
	DoubleCountedViaChainsBytes int64             `json:"double_counted_via_chains_bytes"`
}

// vpnUsageQuery serves users-admin usage_query: one identity, one node or one
// line over a period. The user scope sums user-day rows (what the quota
// counts); the node and line scopes attribute node-day rows (what the node
// actually moved).
func (s *Server) vpnUsageQuery(request []byte) ([]byte, error) {
	var req usageQueryRequest
	if len(strings.TrimSpace(string(request))) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, fmt.Errorf("vpn-core/users-admin usage_query: invalid request: %w", err)
		}
	}
	req.UserID, req.NodeID, req.LineHashID = strings.TrimSpace(req.UserID), strings.TrimSpace(req.NodeID), strings.TrimSpace(req.LineHashID)
	scopes := 0
	for _, v := range []string{req.UserID, req.NodeID, req.LineHashID} {
		if v != "" {
			scopes++
		}
	}
	if scopes != 1 {
		return nil, errors.New("usage_query takes exactly one of user_id, node_id, line_hash_id")
	}
	now := s.now()
	var window usageWindow
	var user *VpnUser
	if req.UserID != "" {
		u, ok := s.getVpnUser(req.UserID)
		if !ok {
			return nil, fmt.Errorf("vpn-core/users-admin usage_query: user %q not found", req.UserID)
		}
		user = &u
	}
	if strings.EqualFold(strings.TrimSpace(req.Period), "quota") {
		if user == nil {
			return nil, errors.New("period quota needs user_id")
		}
		start, _, ok := vpnUserQuotaPeriod(*user, now)
		if !ok {
			return nil, errors.New("user has no quota period")
		}
		window = usageWindow{From: start, To: now, Label: "quota"}
	} else {
		w, err := parseUsagePeriod(req.Period, now)
		if err != nil {
			return nil, err
		}
		window = w
	}
	resp := usageQueryResponse{Scope: map[string]string{}, Period: window.Label, From: window.fromDay(), To: window.toDay(), Days: []usageQueryDay{}, Lines: []usageLineRow{}}
	ctx := s.usageAttributionContext()
	switch {
	case user != nil:
		resp.Scope["user_id"] = user.ID
		_, rows := s.periodUsage(user.ID, window.From, window.To)
		byLine := map[string]usageCounter{}
		for _, row := range rows {
			c := usageCounter{Uplink: row.Uplink, Downlink: row.Downlink}
			resp.Uplink += c.Uplink
			resp.Downlink += c.Downlink
			resp.Days = append(resp.Days, usageQueryDay{Day: row.Day, Uplink: c.Uplink, Downlink: c.Downlink, UsedBytes: c.total()})
			for hash, line := range row.ByLine {
				l := byLine[hash]
				l.add(usageCounter{Uplink: line.Uplink, Downlink: line.Downlink})
				byLine[hash] = l
			}
		}
		hashes := make([]string, 0, len(byLine))
		for hash := range byLine {
			hashes = append(hashes, hash)
		}
		sort.Strings(hashes)
		for _, hash := range hashes {
			c := byLine[hash]
			row := usageLineRow{LineHashID: hash, Role: usageRoleDirect, Uplink: c.Uplink, Downlink: c.Downlink, UsedBytes: c.total(),
				Attribution: usageAttributionNamed, AttributionProof: usageProofProof, AttributionReason: "counted for this identity", UserID: user.ID, Email: user.Email, Counted: true}
			if f, ok := ctx.byHash[hash]; ok {
				row.NodeID, row.NodeName, row.Tag, row.Role = f.Line.NodeID, ctx.nodeName[f.Line.NodeID], f.Line.Tag, f.Role
				switch {
				case ctx.reported[hash][user.ID]:
				case f.CredentialUser == user.ID:
					row.Attribution, row.AttributionReason = usageAttributionCredential, f.CredentialReason
				default:
					row.Attribution, row.AttributionProof, row.AttributionReason = usageAttributionBinding, usageProofInferred, "only enabled binding on this line"
				}
			}
			resp.Lines = append(resp.Lines, row)
		}
	default:
		nodeIDs := []string{req.NodeID}
		if req.LineHashID != "" {
			f, ok := ctx.byHash[req.LineHashID]
			if !ok {
				return nil, fmt.Errorf("line %q is not a known line on any node", req.LineHashID)
			}
			resp.Scope["line_hash_id"] = req.LineHashID
			nodeIDs = []string{f.Line.NodeID}
			// The relayed portion of a chain target needs its upstream nodes.
			for _, up := range f.Upstream {
				if uf, ok := ctx.byHash[up]; ok {
					nodeIDs = appendUniqueSorted(nodeIDs, uf.Line.NodeID)
				}
			}
		} else {
			resp.Scope["node_id"] = req.NodeID
			if _, ok := s.store.Node(req.NodeID); !ok {
				return nil, fmt.Errorf("node %q not found", req.NodeID)
			}
		}
		window = s.loadUsageWindow(window, nodeIDs)
		report := ctx.attributeWindow(window.sumWindow(window.fromDay(), window.toDay()))
		days := map[string]*usageQueryDay{}
		for _, row := range report.Rows {
			if req.LineHashID != "" && row.LineHashID != req.LineHashID {
				continue
			}
			if req.NodeID != "" && row.NodeID != req.NodeID {
				continue
			}
			resp.Lines = append(resp.Lines, row)
			if row.CountedAt != "" {
				resp.DoubleCountedViaChainsBytes += row.UsedBytes
			}
		}
		for _, rows := range window.nodes {
			for _, row := range rows {
				if req.NodeID != "" && row.NodeID != req.NodeID {
					continue
				}
				for _, line := range row.Lines {
					if req.LineHashID != "" && line.LineHashID != req.LineHashID {
						continue
					}
					d := days[row.Day]
					if d == nil {
						d = &usageQueryDay{Day: row.Day}
						days[row.Day] = d
					}
					d.Uplink += line.Uplink
					d.Downlink += line.Downlink
					d.UsedBytes += line.Uplink + line.Downlink
					resp.Uplink += line.Uplink
					resp.Downlink += line.Downlink
				}
			}
		}
		for _, d := range days {
			resp.Days = append(resp.Days, *d)
		}
		sort.Slice(resp.Days, func(i, j int) bool { return resp.Days[i].Day < resp.Days[j].Day })
	}
	resp.UsedBytes = resp.Uplink + resp.Downlink
	return json.Marshal(resp)
}
