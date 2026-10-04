package server

import (
	"time"

	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

// stateWriteSummaryInterval is how often the server logs its state.json
// writes by caller. /metrics carries the same counts cumulatively, but only
// where LATTICE_METRICS_TOKEN is set; the log line needs no token and no new
// endpoint.
const stateWriteSummaryInterval = time.Hour

// startStateWriteSummary logs, once per interval, how many times state.json
// was written since the previous line and which store methods asked for it.
// An interval with no writes logs nothing.
func (s *Server) startStateWriteSummary() {
	go func() {
		ticker := time.NewTicker(stateWriteSummaryInterval)
		defer ticker.Stop()
		last := time.Now()
		for range ticker.C {
			now := time.Now()
			if line, ok := telemetry.TakeStoreSaveSummary(now.Sub(last)); ok {
				s.logger.Printf("%s", line)
			}
			last = now
		}
	}()
}
