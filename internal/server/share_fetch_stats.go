package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// A successful link fetch used to write one audit event before the handler
// returned: an anchor rewrite, two or more fsyncs and a bbolt commit under the
// global store mutex, about 21 of the 23 ms a cache hit cost. Clients poll
// links on a timer, so per-fetch events were mostly the same line repeated.
//
// Successful fetches are now counted per link per hour in memory and written
// as one summary event when the hour closes. The first fetch of a link by a
// client family this process has not seen for it is still written at once,
// off the request path, with the requester's address, so a link turning up
// in a new kind of client is visible the moment it happens. Refusals are
// unchanged: every one still goes through the refusal throttle.
//
// One summary event per link per hour still cost an audit append each, about
// 21 ms of fsyncs under the store mutex, all written back to back when the
// hour closed: a thousand active links held the store for some 20 s at every
// hour boundary, and identity links multiply the link count. Closed hours are
// therefore queued and written by the minute flush as packed events, each
// carrying up to shareFetchSummaryLinksPerEvent links of one hour, so a
// thousand links cost 25 appends. Each link is one metadata entry keyed
// "share.<share id>" whose value names the slug, the counts, the client
// families, the last fetch time and a token hash prefix. A batch append in
// the audit store would keep one event per link at the same cost, but the
// WAL anchor reconciles exactly one pending record after a crash, so a
// partly written batch would stop the next boot; that change belongs to the
// audit chain, not to link serving.
//
// What a restart costs: the open hours are written as partial summaries on a
// clean shutdown, and the seen families start empty again, so the first
// fetch per family after a restart is recorded once more. Neither is a
// whole-state write; both are audit appends.

const (
	shareFetchSummaryReason        = "hourly fetch summary"
	shareFetchFirstSeenReason      = "first fetch from this client family"
	shareFetchStatsFlushEvery      = time.Minute
	shareFetchSummaryLinksPerEvent = 40
	shareFetchSummaryKeyPrefix     = "share."
)

type shareFetchHour struct {
	shareID, slug, tokenHash  string
	start, last               time.Time
	fetches, hits, unmodified int
	stale                     int
	families                  map[string]int
}

type shareFetchStats struct {
	mu    sync.Mutex
	hours map[string]*shareFetchHour
	// closed holds hours a later fetch closed, until the next flush writes
	// them with the rest.
	closed []*shareFetchHour
	seen   map[string]map[string]struct{}
}

func newShareFetchStats() *shareFetchStats {
	return &shareFetchStats{hours: map[string]*shareFetchHour{}, seen: map[string]map[string]struct{}{}}
}

// shareFetch is one successful fetch as the counters see it.
type shareFetch struct {
	shareID, slug, tokenHash, family string
	cacheHit, notModified, stale     bool
}

// record counts one fetch and reports whether the family is new for the
// link. The first fetch of a new hour queues the hour it closed.
func (st *shareFetchStats) record(now time.Time, f shareFetch) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	hour := now.UTC().Truncate(time.Hour)
	h := st.hours[f.shareID]
	if h != nil && !h.start.Equal(hour) {
		st.closed = append(st.closed, h)
		h = nil
	}
	if h == nil {
		h = &shareFetchHour{shareID: f.shareID, start: hour, families: map[string]int{}}
		st.hours[f.shareID] = h
	}
	h.slug, h.tokenHash, h.last = f.slug, f.tokenHash, now.UTC()
	h.fetches++
	if f.cacheHit {
		h.hits++
	}
	if f.notModified {
		h.unmodified++
	}
	if f.stale {
		h.stale++
	}
	h.families[f.family]++
	families := st.seen[f.shareID]
	if families == nil {
		families = map[string]struct{}{}
		st.seen[f.shareID] = families
	}
	_, known := families[f.family]
	families[f.family] = struct{}{}
	return !known
}

// takeClosed removes and returns the queued hours and the hours that ended
// before now, or every open hour as well when all is set (shutdown), ordered
// by hour and then link.
func (st *shareFetchStats) takeClosed(now time.Time, all bool) []*shareFetchHour {
	st.mu.Lock()
	defer st.mu.Unlock()
	current := now.UTC().Truncate(time.Hour)
	out := st.closed
	st.closed = nil
	for shareID, h := range st.hours {
		if all || h.start.Before(current) {
			out = append(out, h)
			delete(st.hours, shareID)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].start.Equal(out[j].start) {
			return out[i].start.Before(out[j].start)
		}
		return out[i].shareID < out[j].shareID
	})
	return out
}

// forget drops what the counters hold for links that no longer exist.
func (st *shareFetchStats) forget(exists func(string) bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for shareID := range st.seen {
		if _, open := st.hours[shareID]; !open && !exists(shareID) {
			delete(st.seen, shareID)
		}
	}
}

// shareFetchSummaryEvents packs closed hours, sorted by hour and link, into
// events of at most shareFetchSummaryLinksPerEvent links of one hour each.
func shareFetchSummaryEvents(hours []*shareFetchHour, partial bool) []model.AuditEvent {
	var events []model.AuditEvent
	for i := 0; i < len(hours); {
		j := i + 1
		for j < len(hours) && hours[j].start.Equal(hours[i].start) {
			j++
		}
		group := hours[i:j]
		parts := (len(group) + shareFetchSummaryLinksPerEvent - 1) / shareFetchSummaryLinksPerEvent
		for part := 0; part < parts; part++ {
			chunk := group[part*shareFetchSummaryLinksPerEvent : min((part+1)*shareFetchSummaryLinksPerEvent, len(group))]
			md := map[string]string{"hour_start": chunk[0].start.Format(time.RFC3339), "links": strconv.Itoa(len(chunk))}
			fetches := 0
			for _, h := range chunk {
				fetches += h.fetches
				md[shareFetchSummaryKeyPrefix+h.shareID] = shareFetchHourSummary(h)
			}
			md["fetches"] = strconv.Itoa(fetches)
			if parts > 1 {
				md["part"] = strconv.Itoa(part+1) + "/" + strconv.Itoa(parts)
			}
			if partial {
				md["partial"] = "true"
			}
			events = append(events, model.AuditEvent{ID: id.New("audit"), Action: auditActionShareFetch, Decision: "allow", Reason: shareFetchSummaryReason, Metadata: md})
		}
		i = j
	}
	return events
}

// shareFetchHourSummary is one link's entry in a packed summary. The slug is
// a validated path segment and the families are bounded class names, so the
// space-separated fields cannot run into each other.
func shareFetchHourSummary(h *shareFetchHour) string {
	names := make([]string, 0, len(h.families))
	for family := range h.families {
		names = append(names, family)
	}
	sort.Strings(names)
	families := make([]string, 0, len(names))
	for _, family := range names {
		families = append(families, family+"="+strconv.Itoa(h.families[family]))
	}
	token := h.tokenHash
	if len(token) > 16 {
		token = token[:16]
	}
	return "slug=" + h.slug + " fetches=" + strconv.Itoa(h.fetches) + " cache_hits=" + strconv.Itoa(h.hits) +
		" not_modified=" + strconv.Itoa(h.unmodified) + " stale_served=" + strconv.Itoa(h.stale) +
		" families=" + strings.Join(families, ",") + " last_fetch_at=" + h.last.Format(time.RFC3339) +
		" token_sha256_prefix=" + token
}

// noteShareFetch counts a successful fetch after the response was written.
// Any audit it causes is built here, from the request, and written on its
// own goroutine, so the handler never waits on the audit store. The
// first-seen metadata is built only when it is needed.
func (s *Server) noteShareFetch(r *http.Request, f shareFetch, firstSeenMeta func() map[string]string) {
	if !s.shareFetchStats.record(s.now(), f) {
		return
	}
	md := firstSeenMeta()
	md["source_ip"] = s.clientIP(r)
	ev := model.AuditEvent{ID: id.New("audit"), Action: auditActionShareFetch, Decision: "allow",
		Reason: shareFetchFirstSeenReason, Metadata: md, CorrelationID: requestIDFromRequest(r)}
	s.shareFetchAudits.Add(1)
	go func() {
		defer s.shareFetchAudits.Done()
		if hook := s.shareFetchAuditHook; hook != nil {
			hook()
		}
		s.recordAudit(ev)
	}()
}

// flushShareFetchStats writes the summaries of hours that have ended, or of
// every open hour at shutdown, as packed events.
func (s *Server) flushShareFetchStats(now time.Time, shutdown bool) {
	for _, ev := range shareFetchSummaryEvents(s.shareFetchStats.takeClosed(now, false), false) {
		s.recordAudit(ev)
	}
	if shutdown {
		for _, ev := range shareFetchSummaryEvents(s.shareFetchStats.takeClosed(now, true), true) {
			s.recordAudit(ev)
		}
	}
	s.shareFetchStats.forget(func(shareID string) bool {
		_, ok := s.store.SubscriptionShare(shareID)
		return ok
	})
}

func (s *Server) startShareFetchStatsFlush() {
	go func() {
		ticker := time.NewTicker(shareFetchStatsFlushEvery)
		defer ticker.Stop()
		for range ticker.C {
			s.flushShareFetchStats(s.now(), false)
		}
	}()
}
