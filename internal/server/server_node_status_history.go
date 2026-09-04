package server

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// GET /api/nodes/status-history?days=7[&node_id=]: each readable node's
// online record over the window, summarised here so the table, the card and
// the detail strip read one rule, as node_status.go does for the current word.
//
// Three states: online, offline and unknown. Unknown is what nobody observed,
// which is the time before a node's first recorded edge and the time the
// control plane itself was down (the rows the store writes under
// NodeStatusServerID at start). A node's rows are transitions, so its state
// at any instant is the last row at or before it; the initial state is the
// one at the window start, and every later row in the window is echoed back
// with the cause that wrote it, control-plane edges included, so a strip is
// drawn by walking events from initial with nothing else to know.
//
// Episodes count offline stretches that begin in the window plus one for a
// window that opens offline. A control-plane gap pauses a stretch rather than
// ending it: the node was offline on both sides, and the gap says nothing.
const (
	nodeStatusHistoryDefaultDays = 7
	nodeStatusHistoryMaxDays     = int(store.NodeStatusEventRetention / (24 * time.Hour))

	NodeStatusUnknown = "unknown"
)

type nodeStatusHistory struct {
	Initial               string                  `json:"initial"`
	Events                []store.NodeStatusEvent `json:"events"`
	OnlineSeconds         int64                   `json:"online_seconds"`
	OfflineSeconds        int64                   `json:"offline_seconds"`
	UnknownSeconds        int64                   `json:"unknown_seconds"`
	Episodes              int                     `json:"episodes"`
	LongestOfflineSeconds int64                   `json:"longest_offline_seconds"`
}

type nodeStatusHistoryResponse struct {
	Since           time.Time                    `json:"since"`
	Until           time.Time                    `json:"until"`
	Now             time.Time                    `json:"now"`
	ServerStartedAt time.Time                    `json:"server_started_at"`
	Nodes           map[string]nodeStatusHistory `json:"nodes"`
}

func (s *Server) handleNodeStatusHistory(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	days := nodeStatusHistoryDefaultDays
	if raw := r.URL.Query().Get("days"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > nodeStatusHistoryMaxDays {
			writeError(w, http.StatusBadRequest, fmt.Errorf("days must be between 1 and %d", nodeStatusHistoryMaxDays))
			return
		}
		days = v
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	now := s.now()
	since := now.Add(-time.Duration(days) * 24 * time.Hour)
	control, err := s.store.NodeStatusEvents(store.NodeStatusServerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resp := nodeStatusHistoryResponse{Since: since, Until: now, Now: now, Nodes: map[string]nodeStatusHistory{}}
	for i := len(control) - 1; i >= 0; i-- {
		if control[i].To == store.NodeStatusOnline {
			resp.ServerStartedAt = control[i].At
			break
		}
	}
	for _, n := range s.store.Nodes() {
		if (nodeID != "" && n.ID != nodeID) || !rbac.Allows(p.Principal, "node:read", n.ID) {
			continue
		}
		rows, err := s.store.NodeStatusEvents(n.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		resp.Nodes[n.ID] = summarizeNodeStatus(n, rows, control, since, now)
	}
	if nodeID != "" && len(resp.Nodes) == 0 {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// nodeStatusEdges is the node's own rows with the edges its record still
// carries filled in. The hooks only started writing rows when this shipped,
// so a node that has not flapped since has none, and one that has flapped
// once has only that edge. OnlineSince is the start of its current or last
// online stretch and LastSeen the last contact of an offline node, and both
// predate the rows. A record from before OnlineSince existed (zero, with
// contact) was online from before the field shipped until its first row.
func nodeStatusEdges(n model.Node, rows []store.NodeStatusEvent) (string, []store.NodeStatusEvent) {
	if n.LastSeen.IsZero() {
		return NodeStatusUnknown, rows
	}
	initial := NodeStatusUnknown
	if n.OnlineSince.IsZero() {
		initial = store.NodeStatusOnline
	} else if len(rows) == 0 || n.OnlineSince.Before(rows[0].At) {
		online := store.NodeStatusEvent{At: n.OnlineSince, To: store.NodeStatusOnline, Cause: store.NodeStatusCauseBeat}
		rows = append([]store.NodeStatusEvent{online}, rows...)
	}
	if !n.Online && (len(rows) == 0 || rows[len(rows)-1].To == store.NodeStatusOnline) {
		rows = append(rows, store.NodeStatusEvent{At: n.LastSeen, To: store.NodeStatusOffline, Cause: store.NodeStatusCauseLivenessSweep})
	}
	return initial, rows
}

// summarizeNodeStatus walks the node's edges and the control plane's edges
// together over [since, until]. Pure, so the arithmetic is a table test.
func summarizeNodeStatus(n model.Node, rows, control []store.NodeStatusEvent, since, until time.Time) nodeStatusHistory {
	initial, rows := nodeStatusEdges(n, rows)
	nodeState, up := initial, true
	i := 0
	for ; i < len(rows) && !rows[i].At.After(since); i++ {
		nodeState = rows[i].To
	}
	j := 0
	for ; j < len(control) && !control[j].At.After(since); j++ {
		up = control[j].To == store.NodeStatusOnline
	}
	effective := func() string {
		if !up {
			return NodeStatusUnknown
		}
		return nodeState
	}
	out := nodeStatusHistory{Initial: effective(), Events: []store.NodeStatusEvent{}}
	if nodeState == store.NodeStatusOffline {
		out.Episodes = 1
	}
	var online, offline, unknown, run, longest time.Duration
	state, at := out.Initial, since
	spend := func(to time.Time) {
		d := to.Sub(at)
		switch state {
		case store.NodeStatusOnline:
			online += d
		case store.NodeStatusOffline:
			offline += d
			run += d
		default:
			unknown += d
		}
		at = to
	}
	step := func(ev store.NodeStatusEvent, fromNode bool) {
		spend(ev.At)
		next := effective()
		if next == state {
			return
		}
		if fromNode && state == store.NodeStatusOffline {
			longest, run = max(longest, run), 0
		}
		if fromNode && next == store.NodeStatusOffline {
			out.Episodes++
		}
		out.Events = append(out.Events, store.NodeStatusEvent{At: ev.At, To: next, Cause: ev.Cause})
		state = next
	}
	for i < len(rows) || j < len(control) {
		fromNode := j >= len(control) || (i < len(rows) && !rows[i].At.After(control[j].At))
		var ev store.NodeStatusEvent
		if fromNode {
			ev = rows[i]
			i++
		} else {
			ev = control[j]
			j++
		}
		if ev.At.After(until) {
			break
		}
		if fromNode {
			nodeState = ev.To
		} else {
			up = ev.To == store.NodeStatusOnline
		}
		step(ev, fromNode)
	}
	spend(until)
	longest = max(longest, run)
	out.OnlineSeconds = wholeSeconds(online)
	out.OfflineSeconds = wholeSeconds(offline)
	out.UnknownSeconds = wholeSeconds(unknown)
	out.LongestOfflineSeconds = wholeSeconds(longest)
	return out
}

func wholeSeconds(d time.Duration) int64 {
	return int64(math.Round(d.Seconds()))
}
