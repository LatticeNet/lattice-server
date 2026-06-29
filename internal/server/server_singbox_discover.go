package server

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// Adoption bridge — discovery side (read-only). Agents that run with
// -singbox-discover report the sing-box nodes already present on the machine
// (via read-only `sb --json list`). The server holds the latest report per node
// in memory as a live mirror (singboxInv) and exposes it so the dashboard can
// see proxies on machines provisioned out-of-band — without Lattice owning or
// mutating them. Nothing here writes node config.

// handleAgentSingBoxInventory ingests one node's on-box sing-box inventory.
func (s *Server) handleAgentSingBoxInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		agentAuthRequest
		Inventory model.SingBoxInventory `json:"inventory"`
	}
	if !decodeAgentJSON(w, r, &req) {
		return
	}
	if _, ok := s.authenticateAgentRequest(r, req.NodeID); !ok {
		writeError(w, http.StatusUnauthorized, apiError(model.APIErrorInvalidNodeToken, "invalid node token"))
		return
	}
	inv := req.Inventory
	inv.NodeID = req.NodeID // force from auth; never trust the body's node id
	if inv.At.IsZero() {
		inv.At = time.Now().UTC()
	}
	if inv.Nodes == nil {
		inv.Nodes = []model.SingBoxNode{}
	}
	s.singboxInvMu.Lock()
	if s.singboxInv == nil {
		s.singboxInv = map[string]model.SingBoxInventory{}
	}
	s.singboxInv[req.NodeID] = inv
	s.singboxInvMu.Unlock()

	s.recordRequestAudit(r, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "singbox.discover.report",
		Decision: "allow",
		NodeID:   req.NodeID,
		Metadata: map[string]string{
			"nodes":  strconv.Itoa(len(inv.Nodes)),
			"status": inv.Status,
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": len(inv.Nodes)})
}

// singBoxInventory returns the latest discovered inventory for a node.
func (s *Server) singBoxInventory(nodeID string) (model.SingBoxInventory, bool) {
	s.singboxInvMu.RLock()
	defer s.singboxInvMu.RUnlock()
	inv, ok := s.singboxInv[nodeID]
	return inv, ok
}

// liveSingBoxInventories returns discovered inventories for nodes that still
// exist AND reported within the liveness threshold, sorted by node id. It
// OPPORTUNISTICALLY EVICTS stale/orphaned entries from the in-memory map so a
// deleted or silent node drops out — the map is a live mirror, not history (the
// same correctness rule as the node-liveness sweep; without this a deleted node's
// discovery lingered, e.g. a duplicate node that was removed).
func (s *Server) liveSingBoxInventories(now time.Time) []model.SingBoxInventory {
	s.singboxInvMu.Lock()
	defer s.singboxInvMu.Unlock()
	out := make([]model.SingBoxInventory, 0, len(s.singboxInv))
	for id, inv := range s.singboxInv {
		if _, ok := s.store.Node(id); !ok || (!inv.At.IsZero() && now.Sub(inv.At) > nodeOfflineThreshold) {
			delete(s.singboxInv, id)
			continue
		}
		out = append(out, inv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// removeSingBoxInventory drops a node's discovered inventory (called on delete).
func (s *Server) removeSingBoxInventory(nodeID string) {
	s.singboxInvMu.Lock()
	delete(s.singboxInv, nodeID)
	s.singboxInvMu.Unlock()
}

// handleProxyDiscovered lists every live node's discovered on-box sing-box
// inventory, sorted by node id. proxy:read.
func (s *Server) handleProxyDiscovered(w http.ResponseWriter, _ *http.Request, p principal) {
	if !s.requireScope(w, p, "proxy:read") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"inventories": s.liveSingBoxInventories(s.now())})
}
