package server

import (
	"log"
	"time"

	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	// auditWALVerifyInterval is how often the tamper-evident chain is walked.
	// The walk is the expensive part of the check, so it is paid on a timer
	// rather than by whoever happens to probe readiness.
	auditWALVerifyInterval = 15 * time.Minute
	// auditWALVerifyStaleAfter is when a readiness probe stops trusting the
	// last result. It is deliberately several intervals wide: one slow or
	// skipped walk is not an outage, a verifier that has stopped is.
	auditWALVerifyStaleAfter = 3 * auditWALVerifyInterval
)

// auditWALVerifier walks the audit chain on a timer and leaves the outcome in
// the store, so readiness can report it without doing the walk itself.
//
// The chain is verified once when the store opens, which is what makes the
// first probe meaningful; this keeps that answer from going stale.
type auditWALVerifier struct {
	store    *store.Store
	logger   *log.Logger
	interval time.Duration
}

func newAuditWALVerifier(st *store.Store, logger *log.Logger, interval time.Duration) *auditWALVerifier {
	if st == nil {
		return nil
	}
	if interval <= 0 {
		interval = auditWALVerifyInterval
	}
	return &auditWALVerifier{store: st, logger: logger, interval: interval}
}

func (v *auditWALVerifier) start() {
	if v == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(v.interval)
		defer ticker.Stop()
		for range ticker.C {
			v.verifyOnce()
		}
	}()
}

func (v *auditWALVerifier) verifyOnce() {
	res, enabled, err := v.store.AuditWALVerify()
	if !enabled {
		return
	}
	if err != nil && v.logger != nil {
		// A broken chain is the one thing this exists to find. It must be loud
		// in the log as well as visible on the readiness endpoint.
		v.logger.Printf("audit wal verify: chain did not verify: %v", err)
		return
	}
	if v.logger != nil {
		v.logger.Printf("audit wal verify: ok, %d records", res.Count)
	}
}
