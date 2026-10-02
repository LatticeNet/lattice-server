package server

import (
	"errors"
	"net/http"

	"github.com/LatticeNet/lattice-sdk/model"
)

// defaultMonitorResultsLimit is how many results GET /api/monitors/results
// returns across a monitor's nodes when the caller names no limit: the size
// the old per-monitor cap gave every response.
const defaultMonitorResultsLimit = 500

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

// handleAgentMonitorResult ingests one probe outcome from an authenticated
// agent: {"node_id": ..., "result": {...}}. Every agent released so far
// posts here, one request per probe.
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
	outcomes, err := s.store.IngestAgentMonitorResults(nodeID, results, s.now())
	if err != nil {
		return agentMonitorResultsResponse{}, err
	}
	if len(outcomes) != len(results) {
		return agentMonitorResultsResponse{}, errors.New("monitor result ingest returned a short outcome list")
	}
	resp := agentMonitorResultsResponse{OK: true}
	for i, out := range outcomes {
		switch {
		case out.Dropped != "":
			resp.Dropped = append(resp.Dropped, agentMonitorResultDrop{Index: i, MonitorID: results[i].MonitorID, Reason: out.Dropped})
		case out.Duplicate:
			resp.Duplicates++
		default:
			resp.Accepted++
			s.notifyMonitorTransition(nodeID, out.Result.MonitorResult, out.PriorFailStreak)
		}
	}
	return resp, nil
}
