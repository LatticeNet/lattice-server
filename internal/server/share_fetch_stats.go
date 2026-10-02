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
// What a restart costs: the open hour's counts are written as a partial
// summary on a clean shutdown, and the seen families start empty again, so
// the first fetch per family after a restart is recorded once more. Neither
// is a whole-state write; both are audit appends.

const (
	shareFetchSummaryReason   = "hourly fetch summary"
	shareFetchFirstSeenReason = "first fetch from this client family"
	shareFetchStatsFlushEvery = time.Minute
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
	seen  map[string]map[string]struct{}
}

func newShareFetchStats() *shareFetchStats {
	return &shareFetchStats{hours: map[string]*shareFetchHour{}, seen: map[string]map[string]struct{}{}}
}

// shareFetch is one successful fetch as the counters see it.
type shareFetch struct {
	shareID, slug, tokenHash, family string
	cacheHit, notModified, stale     bool
}

// record counts one fetch. It returns whether the family is new for the link
// and, when this fetch is the first of a new hour, the hour it closed.
func (st *shareFetchStats) record(now time.Time, f shareFetch) (bool, *shareFetchHour) {
	st.mu.Lock()
	defer st.mu.Unlock()
	hour := now.UTC().Truncate(time.Hour)
	var closed *shareFetchHour
	h := st.hours[f.shareID]
	if h != nil && !h.start.Equal(hour) {
		closed, h = h, nil
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
	return !known, closed
}

// takeClosed removes and returns the hours that ended before now, or every
// open hour when all is set (shutdown).
func (st *shareFetchStats) takeClosed(now time.Time, all bool) []*shareFetchHour {
	st.mu.Lock()
	defer st.mu.Unlock()
	current := now.UTC().Truncate(time.Hour)
	var out []*shareFetchHour
	for shareID, h := range st.hours {
		if all || h.start.Before(current) {
			out = append(out, h)
			delete(st.hours, shareID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].shareID < out[j].shareID })
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

func shareFetchSummaryEvent(h *shareFetchHour, partial bool) model.AuditEvent {
	names := make([]string, 0, len(h.families))
	for family := range h.families {
		names = append(names, family)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, family := range names {
		parts = append(parts, family+"="+strconv.Itoa(h.families[family]))
	}
	md := map[string]string{
		"share_id": h.shareID, "slug": h.slug, "token_sha256": h.tokenHash,
		"hour_start": h.start.Format(time.RFC3339), "last_fetch_at": h.last.Format(time.RFC3339),
		"fetches": strconv.Itoa(h.fetches), "cache_hits": strconv.Itoa(h.hits),
		"not_modified": strconv.Itoa(h.unmodified), "stale_served": strconv.Itoa(h.stale),
		"families": strings.Join(parts, ","),
	}
	if partial {
		md["partial"] = "true"
	}
	return model.AuditEvent{ID: id.New("audit"), Action: auditActionShareFetch, Decision: "allow", Reason: shareFetchSummaryReason, Metadata: md}
}

// noteShareFetch counts a successful fetch after the response was written.
// Any audit it causes is built here, from the request, and written on its
// own goroutine, so the handler never waits on the audit store. The
// first-seen metadata is built only when it is needed.
func (s *Server) noteShareFetch(r *http.Request, f shareFetch, firstSeenMeta func() map[string]string) {
	firstSeen, closed := s.shareFetchStats.record(s.now(), f)
	var events []model.AuditEvent
	if closed != nil {
		events = append(events, shareFetchSummaryEvent(closed, false))
	}
	if firstSeen {
		md := firstSeenMeta()
		md["source_ip"] = s.clientIP(r)
		events = append(events, model.AuditEvent{ID: id.New("audit"), Action: auditActionShareFetch, Decision: "allow",
			Reason: shareFetchFirstSeenReason, Metadata: md, CorrelationID: requestIDFromRequest(r)})
	}
	if len(events) == 0 {
		return
	}
	s.shareFetchAudits.Add(1)
	go func() {
		defer s.shareFetchAudits.Done()
		if hook := s.shareFetchAuditHook; hook != nil {
			hook()
		}
		for _, ev := range events {
			s.recordAudit(ev)
		}
	}()
}

// flushShareFetchStats writes the summaries of hours that have ended, or of
// every open hour at shutdown.
func (s *Server) flushShareFetchStats(now time.Time, shutdown bool) {
	for _, h := range s.shareFetchStats.takeClosed(now, shutdown) {
		s.recordAudit(shareFetchSummaryEvent(h, shutdown))
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
