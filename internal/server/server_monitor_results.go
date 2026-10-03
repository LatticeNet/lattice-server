package server

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// defaultMonitorResultsLimit is how many results GET /api/monitors/results
// returns across a monitor's nodes when the caller names no limit: the size
// the old per-monitor cap gave every response.
const defaultMonitorResultsLimit = 500

// maxMonitorResultsLimit is the most one results read returns: more than one
// pair's whole history, and a bound on the response either way.
const maxMonitorResultsLimit = 2000

// agentMonitorResultsResponse answers both agent monitor result routes.
// Accepted counts new rows; Duplicates counts results the pair already held
// at the same instant (a batch sent again after a lost response), which an
// agent treats as delivered. Dropped results were refused for good and must
// not be sent again: the reason says why.
type agentMonitorResultsResponse struct {
	OK         bool                     `json:"ok"`
	Accepted   int                      `json:"accepted"`
	Duplicates int                      `json:"duplicates"`
	Dropped    []agentMonitorResultDrop `json:"dropped,omitempty"`
}

type agentMonitorResultDrop struct {
	Index     int    `json:"index"`
	MonitorID string `json:"monitor_id"`
	Reason    string `json:"reason"`
}

// maxAgentMonitorResultsBatch bounds one batch: fifteen minutes of six
// monitors at the 30 s default is 180 results, and 500 results with their
// error text capped fit well inside the agent body limit.
const maxAgentMonitorResultsBatch = 500

// handleAgentMonitorResults ingests a batch of probe outcomes from an
// authenticated agent: {"node_id": ..., "results": [{...}, ...]}.
//
// The batch is a separate path rather than a second shape on the single
// route on purpose. Older servers decode agent bodies leniently and would
// read a batch posted to the single route as one empty result and answer
// 200, so the agent would believe it delivered results that were dropped.
// On this path an older server answers 404, and the agent falls back to
// posting one result per request.
//
// Results are judged in array order, so an agent sends a buffered backlog
// oldest first. All admitted results are stored in one transaction: on a
// 5xx nothing was stored and the whole batch can be sent again; results an
// earlier attempt did store come back as duplicates.
func (s *Server) handleAgentMonitorResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		agentAuthRequest
		Results []model.MonitorResult `json:"results"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	if len(req.Results) == 0 || len(req.Results) > maxAgentMonitorResultsBatch {
		writeError(w, http.StatusBadRequest, fmt.Errorf("results must hold 1 to %d entries", maxAgentMonitorResultsBatch))
		return
	}
	resp, err := s.ingestAgentMonitorResults(req.NodeID, req.Results)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAgentMonitorResult ingests one probe outcome from an authenticated
// agent: {"node_id": ..., "result": {...}}. Every agent released so far
// posts here, one request per probe, and it answers the same body as the
// batch route.
func (s *Server) handleAgentMonitorResult(w http.ResponseWriter, r *http.Request) {
	var req struct {
		agentAuthRequest
		Result model.MonitorResult `json:"result"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	resp, err := s.ingestAgentMonitorResults(req.NodeID, []model.MonitorResult{req.Result})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ingestAgentMonitorResults stores an agent's results for its own node and
// runs the alert hold on each new row, in order. The node id inside each
// result is ignored: an agent reports for the node its token belongs to.
func (s *Server) ingestAgentMonitorResults(nodeID string, results []model.MonitorResult) (agentMonitorResultsResponse, error) {
	receivedAt := s.now()
	outcomes, err := s.store.IngestAgentMonitorResults(nodeID, results, receivedAt)
	if err != nil {
		return agentMonitorResultsResponse{}, err
	}
	if len(outcomes) != len(results) {
		return agentMonitorResultsResponse{}, errors.New("monitor result ingest returned a short outcome list")
	}
	resp := agentMonitorResultsResponse{OK: true}
	// firstDrop is the first dropped index per reason, kept in the order the
	// reasons appeared, so the log names one example of each.
	var dropReasons []string
	firstDrop, dropCount := map[string]int{}, map[string]int{}
	for i, out := range outcomes {
		switch {
		case out.Dropped != "":
			resp.Dropped = append(resp.Dropped, agentMonitorResultDrop{Index: i, MonitorID: results[i].MonitorID, Reason: out.Dropped})
			if _, seen := firstDrop[out.Dropped]; !seen {
				firstDrop[out.Dropped] = i
				dropReasons = append(dropReasons, out.Dropped)
			}
			dropCount[out.Dropped]++
		case out.Duplicate:
			resp.Duplicates++
		default:
			resp.Accepted++
			s.notifyMonitorTransition(nodeID, out.Result.MonitorResult, out.PriorFailStreak)
		}
	}
	for _, reason := range dropReasons {
		s.logMonitorResultDrops(nodeID, reason, dropCount[reason], results[firstDrop[reason]], receivedAt)
	}
	return resp, nil
}

// monitorDropLogInterval is how often one node's drops for one reason may
// reach the log.
const monitorDropLogInterval = 15 * time.Minute

// monitorDropLog is the server's own record of the agent results it refuses.
// A drop answers 200 with the reason in the body, and the agents released so
// far ignore the body, so without it a node whose clock runs a day behind or
// a minute ahead, or whose monitor list is stale, would lose every result
// with no line on either side. Each node and reason gets at most one line per
// monitorDropLogInterval, which counts the drops since the line before.
//
// Entries are keyed by authenticated node id and one of the fixed drop
// reasons, so the map is bounded by the nodes ever enrolled times six.
type monitorDropLog struct {
	mu      sync.Mutex
	entries map[monitorDropKey]*monitorDropEntry
}

type monitorDropKey struct{ nodeID, reason string }

type monitorDropEntry struct {
	logged   time.Time
	unlogged int
}

// note adds n drops and reports whether a line is due, with the count it
// should carry.
func (l *monitorDropLog) note(nodeID, reason string, n int, now time.Time) (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[monitorDropKey]*monitorDropEntry{}
	}
	key := monitorDropKey{nodeID: nodeID, reason: reason}
	e := l.entries[key]
	if e == nil {
		e = &monitorDropEntry{}
		l.entries[key] = e
	}
	e.unlogged += n
	if !e.logged.IsZero() && now.Sub(e.logged) < monitorDropLogInterval {
		return 0, false
	}
	count := e.unlogged
	e.logged, e.unlogged = now, 0
	return count, true
}

// logMonitorResultDrops writes the rate-limited line for one request's drops
// of one reason. sample is the first of them; for a stamp outside the window
// the line says how far off it was, which is how a broken agent clock shows.
func (s *Server) logMonitorResultDrops(nodeID, reason string, n int, sample model.MonitorResult, receivedAt time.Time) {
	count, due := s.monitorDrops.note(nodeID, reason, n, receivedAt)
	if !due {
		return
	}
	// The monitor id is the agent's text: bounded here and quoted below.
	monitorID := sample.MonitorID
	if len(monitorID) > 64 {
		monitorID = monitorID[:64]
	}
	detail := ""
	if reason == store.MonitorResultDropOutOfWindow {
		if skew := sample.At.Sub(receivedAt); skew > 0 {
			detail = fmt.Sprintf(", stamped %s ahead of the control plane", skew.Round(time.Second))
		} else {
			detail = fmt.Sprintf(", stamped %s behind the control plane", (-skew).Round(time.Second))
		}
	}
	s.logger.Printf("agent monitor results: dropped %d from node %s (%s) as %s since the last such line; monitor %q%s",
		count, s.nodeDisplayName(nodeID), nodeID, reason, monitorID, detail)
}
