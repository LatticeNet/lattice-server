package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// Adoption bridge — discovery side (read-only). Agents that run with
// -singbox-discover report the sing-box nodes already present on the machine
// (via read-only `sb --json list`). The server holds the latest report per node
// in memory as a live mirror (singboxInv) and exposes it so the dashboard can
// see proxies on machines provisioned out-of-band — without Lattice owning or
// mutating them. Nothing here writes node config.

const singBoxDiscoveryAuditInterval = 6 * time.Hour

type singBoxDiscoveryAuditState struct {
	fingerprint string
	auditedAt   time.Time
}

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
	if err := s.withSubscriptionGraphWriteErr(vpnCorePluginID, func() error {
		s.singboxInvMu.Lock()
		if s.singboxInv == nil {
			s.singboxInv = map[string]model.SingBoxInventory{}
		}
		s.singboxInv[req.NodeID] = inv
		s.singboxInvMu.Unlock()
		s.invalidateLineReadModel()
		return s.reconcileLineChainsForNodeUnlocked(req.NodeID)
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// design-19: the liveness half of the report is derived, persisted, and
	// debounce-notified separately from the volatile inventory mirror.
	s.noteSingBoxLiveness(req.NodeID, inv.Runtime)

	// design-15 D2: a changed line set queues a sidecar sync (pending approval —
	// discovery still never mutates the node by itself).
	s.maybeQueueLineMetaSyncOnDiscovery(req.NodeID, inv)

	if s.shouldAuditSingBoxDiscovery(req.NodeID, inv, s.now()) {
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
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": len(inv.Nodes)})
}

func (s *Server) shouldAuditSingBoxDiscovery(nodeID string, inv model.SingBoxInventory, now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	fingerprint := singBoxDiscoveryFingerprint(inv)
	s.singboxDiscoverAuditMu.Lock()
	defer s.singboxDiscoverAuditMu.Unlock()
	if s.singboxDiscoverAudit == nil {
		s.singboxDiscoverAudit = map[string]singBoxDiscoveryAuditState{}
	}
	prev, ok := s.singboxDiscoverAudit[nodeID]
	if !ok || prev.fingerprint != fingerprint || now.Sub(prev.auditedAt) >= singBoxDiscoveryAuditInterval {
		s.singboxDiscoverAudit[nodeID] = singBoxDiscoveryAuditState{
			fingerprint: fingerprint,
			auditedAt:   now,
		}
		return true
	}
	return false
}

func singBoxDiscoveryFingerprint(inv model.SingBoxInventory) string {
	inv.NodeID = ""
	inv.At = time.Time{}
	inv.Nodes = append([]model.SingBoxNode(nil), inv.Nodes...)
	sort.Slice(inv.Nodes, func(i, j int) bool {
		a, b := inv.Nodes[i], inv.Nodes[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.ShareURL < b.ShareURL
	})
	data, _ := json.Marshal(inv)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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
	return s.liveSingBoxInventoriesWithNodeExists(now, func(nodeID string) bool {
		_, ok := s.store.Node(nodeID)
		return ok
	})
}

// liveSingBoxInventoriesWithNodeExists keeps Store lookups outside
// singboxInvMu. Line-chain result classification intentionally holds the Store
// lock while reading the inventory mirror, so taking these locks in the reverse
// order here would deadlock result commits against inventory pruning.
func (s *Server) liveSingBoxInventoriesWithNodeExists(now time.Time, nodeExists func(string) bool) []model.SingBoxInventory {
	s.singboxInvMu.RLock()
	snapshot := make(map[string]model.SingBoxInventory, len(s.singboxInv))
	for id, inv := range s.singboxInv {
		inv.Nodes = append([]model.SingBoxNode(nil), inv.Nodes...)
		snapshot[id] = inv
	}
	s.singboxInvMu.RUnlock()

	live := make(map[string]model.SingBoxInventory, len(snapshot))
	stale := make(map[string]model.SingBoxInventory)
	staleNodeExists := make(map[string]bool)
	for id, inv := range snapshot {
		exists := nodeExists(id)
		if !exists || (!inv.At.IsZero() && now.Sub(inv.At) > nodeOfflineThreshold) {
			stale[id] = inv
			staleNodeExists[id] = exists
			continue
		}
		live[id] = inv
	}

	// Delete only the exact entry inspected above. Pruning is optional read-path
	// hygiene, so it must never attempt an R-to-W upgrade when a subscription
	// preview/save already holds graph authority. If a writer cannot be acquired
	// immediately, return the copied live view and let a later read prune.
	graph := s.subscriptionGraphAuthorityFor(vpnCorePluginID)
	if graph.mu.TryLock() {
		s.singboxInvMu.Lock()
		for id, inspected := range stale {
			current, ok := s.singboxInv[id]
			if !ok {
				continue
			}
			if reflect.DeepEqual(current, inspected) {
				delete(s.singboxInv, id)
				continue
			}
			if staleNodeExists[id] && (current.At.IsZero() || now.Sub(current.At) <= nodeOfflineThreshold) {
				current.Nodes = append([]model.SingBoxNode(nil), current.Nodes...)
				live[id] = current
			}
		}
		s.singboxInvMu.Unlock()
		graph.mu.Unlock()
	} else if skipped := s.subscriptionGraphPruneSkipped; skipped != nil {
		select {
		case skipped <- struct{}{}:
		default:
		}
	}

	out := make([]model.SingBoxInventory, 0, len(live))
	for _, inv := range live {
		out = append(out, inv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// removeSingBoxInventory drops a node's discovered inventory (called on delete).
func (s *Server) removeSingBoxInventory(nodeID string) {
	_ = s.withSubscriptionGraphWriteErr(vpnCorePluginID, func() error {
		s.singboxInvMu.Lock()
		delete(s.singboxInv, nodeID)
		s.singboxInvMu.Unlock()
		return nil
	})
	s.singboxDiscoverAuditMu.Lock()
	delete(s.singboxDiscoverAudit, nodeID)
	s.singboxDiscoverAuditMu.Unlock()
}

// handleProxyDiscovered lists every live node's discovered on-box sing-box
// inventory, sorted by node id. proxy:read.
func (s *Server) handleProxyDiscovered(w http.ResponseWriter, _ *http.Request, p principal) {
	if !s.requireScope(w, p, "proxy:read") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"inventories": filterSingBoxInventoriesForPrincipal(s.liveSingBoxInventories(s.now()), p),
	})
}

func filterSingBoxInventoriesForPrincipal(inventories []model.SingBoxInventory, p principal) []model.SingBoxInventory {
	out := make([]model.SingBoxInventory, 0, len(inventories))
	for _, inv := range inventories {
		if rbac.Allows(p.Principal, "proxy:read", inv.NodeID) {
			out = append(out, inv)
		}
	}
	return out
}
