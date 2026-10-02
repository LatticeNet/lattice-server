package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// Refused /sub/ requests come from anyone on the internet, and each audit
// append costs an anchor rewrite, several fsyncs and a bbolt commit under the
// global store mutex. Without a bound, every refused request (including the
// ones the share limiter refuses) was a durable write an unauthenticated
// caller could buy for free, and the caller also waited on that write before
// it saw the decoy.
//
// Refusals now go through their own throttle, keyed by bucketed source
// address: the first refusal from a source in a window is recorded, repeats
// fold into a count that rides on the next recorded event or on the periodic
// summary, and a global bucket caps the write rate whatever the number of
// sources. It is a separate instance from authFailAuditThrottle so a share
// flood cannot spend the budget that records failed logins.
//
// A refusal after a valid token resolved (render failed, refresh failed,
// target refused) is keyed by the share as well, so a prober from the same
// network cannot fold a real share's failure out of sight. A caller cannot
// widen that key space without holding valid tokens.
const (
	shareRefusalAuditWindow       = time.Minute
	shareRefusalAuditBurst        = 20
	shareRefusalAuditRefillPerSec = 0.2
	shareRefusalAuditFlushEvery   = time.Minute
	shareRefusalSummaryReason     = "refusals throttled"
)

func newShareRefusalAuditThrottle() *auditFailureThrottle {
	return newAuditFailureThrottle(shareRefusalAuditWindow, shareRefusalAuditBurst, shareRefusalAuditRefillPerSec)
}

// auditShareRefusal records a /sub/ refusal through the refusal throttle and
// off the request path. The caller writes the decoy; this never blocks on the
// audit store. The event is built here, synchronously, so nothing reads the
// request after the handler returns.
func (s *Server) auditShareRefusal(r *http.Request, reason string, meta map[string]string) {
	sourceIP := s.clientIP(r)
	key := "share|" + auditBucketedIP(sourceIP)
	if shareID := meta["share_id"]; shareID != "" {
		key += "|" + shareID
	}
	emit, suppressed, dropped := s.shareRefusalAudit.Allow(key, s.now())
	if !emit {
		return
	}
	md := make(map[string]string, len(meta)+3)
	for k, v := range meta {
		md[k] = v
	}
	md["source_ip"] = sourceIP
	if suppressed > 0 {
		md["suppressed_repeats"] = strconv.Itoa(suppressed)
	}
	if dropped > 0 {
		md["global_suppressed"] = strconv.Itoa(dropped)
	}
	ev := model.AuditEvent{
		ID: id.New("audit"), Action: auditActionShareFetch, Decision: "deny",
		Reason: reason, Metadata: md, CorrelationID: requestIDFromRequest(r),
	}
	s.shareRefusalAudits.Add(1)
	go func() {
		defer s.shareRefusalAudits.Done()
		if hook := s.shareRefusalAuditHook; hook != nil {
			hook()
		}
		s.recordAudit(ev)
	}()
}

// flushShareRefusalAudit writes one summary event for refusals the throttle
// folded or dropped and that no later event carried. It writes nothing when
// there is nothing to report, so a quiet server pays nothing.
func (s *Server) flushShareRefusalAudit(now time.Time) {
	sources, suppressed, dropped := s.shareRefusalAudit.Flush(now)
	if suppressed == 0 && dropped == 0 {
		return
	}
	md := map[string]string{}
	if suppressed > 0 {
		md["suppressed_repeats"] = strconv.Itoa(suppressed)
		md["sources"] = strconv.Itoa(sources)
	}
	if dropped > 0 {
		md["global_suppressed"] = strconv.Itoa(dropped)
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), Action: auditActionShareFetch, Decision: "deny",
		Reason: shareRefusalSummaryReason, Metadata: md,
	})
}

func (s *Server) startShareRefusalAuditFlush() {
	go func() {
		ticker := time.NewTicker(shareRefusalAuditFlushEvery)
		defer ticker.Stop()
		for range ticker.C {
			s.flushShareRefusalAudit(s.now())
		}
	}()
}
