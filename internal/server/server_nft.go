package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

type nftInputsView struct {
	ID            string    `json:"id"`
	NodeID        string    `json:"node_id"`
	NodeName      string    `json:"node_name,omitempty"`
	InterfaceName string    `json:"interface_name"`
	WireGuardCIDR string    `json:"wireguard_cidr"`
	PublicTCP     []int     `json:"public_tcp,omitempty"`
	PublicUDP     []int     `json:"public_udp,omitempty"`
	WireGuardTCP  []int     `json:"wireguard_tcp,omitempty"`
	WireGuardUDP  []int     `json:"wireguard_udp,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (s *Server) handleNFTInputs(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		inputs := s.store.AllNFTInputs()
		views := make([]nftInputsView, 0, len(inputs))
		for _, entry := range inputs {
			if rbac.Allows(p.Principal, "network:plan", entry.NodeID) {
				views = append(views, s.toNFTInputsView(entry))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"inputs": views})
	case http.MethodPost:
		var req struct {
			NodeID string `json:"node_id"`
			network.NFTPlan
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if req.NodeID == "" {
			writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
			return
		}
		if _, ok := s.store.Node(req.NodeID); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		if !s.requireNodeScope(w, p, "network:plan", req.NodeID) {
			return
		}
		inputs, err := nftInputsFromPlan(req.NodeID, req.NFTPlan)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if existing, ok := s.store.NFTInputs(req.NodeID); ok {
			inputs.CreatedAt = existing.CreatedAt
		}
		if err := s.store.UpsertNFTInputs(inputs); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if stored, ok := s.store.NFTInputs(req.NodeID); ok {
			inputs = stored
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   req.NodeID,
			Action:   "network.nft.inputs.upsert",
			Scope:    "network:plan",
			Metadata: map[string]string{"node_id": req.NodeID},
		})
		writeJSON(w, http.StatusOK, s.toNFTInputsView(inputs))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteNFTInputs(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "network:plan", req.NodeID) {
		return
	}
	if err := s.store.DeleteNFTInputs(req.NodeID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		NodeID:   req.NodeID,
		Action:   "network.nft.inputs.delete",
		Scope:    "network:plan",
		Metadata: map[string]string{"node_id": req.NodeID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func nftInputsFromPlan(nodeID string, plan network.NFTPlan) (model.NFTInputs, error) {
	normalized, err := network.NormalizeNFTPlan(plan)
	if err != nil {
		return model.NFTInputs{}, err
	}
	return model.NFTInputs{
		ID:            nodeID,
		NodeID:        nodeID,
		InterfaceName: normalized.InterfaceName,
		WireGuardCIDR: normalized.WireGuardCIDR,
		PublicTCP:     append([]int(nil), normalized.PublicTCP...),
		PublicUDP:     append([]int(nil), normalized.PublicUDP...),
		WireGuardTCP:  append([]int(nil), normalized.WireGuardTCP...),
		WireGuardUDP:  append([]int(nil), normalized.WireGuardUDP...),
	}, nil
}

func nftPlanFromStoredInputs(inputs model.NFTInputs) network.NFTPlan {
	return network.NFTPlan{
		InterfaceName: inputs.InterfaceName,
		WireGuardCIDR: inputs.WireGuardCIDR,
		PublicTCP:     append([]int(nil), inputs.PublicTCP...),
		PublicUDP:     append([]int(nil), inputs.PublicUDP...),
		WireGuardTCP:  append([]int(nil), inputs.WireGuardTCP...),
		WireGuardUDP:  append([]int(nil), inputs.WireGuardUDP...),
	}
}

func nftPlanRequestHasInputs(plan network.NFTPlan) bool {
	return plan.InterfaceName != "" ||
		plan.WireGuardCIDR != "" ||
		len(plan.PublicTCP) > 0 ||
		len(plan.PublicUDP) > 0 ||
		len(plan.WireGuardTCP) > 0 ||
		len(plan.WireGuardUDP) > 0
}

func (s *Server) toNFTInputsView(inputs model.NFTInputs) nftInputsView {
	nodeName := ""
	if node, ok := s.store.Node(inputs.NodeID); ok {
		nodeName = node.Name
	}
	return nftInputsView{
		ID:            inputs.ID,
		NodeID:        inputs.NodeID,
		NodeName:      nodeName,
		InterfaceName: inputs.InterfaceName,
		WireGuardCIDR: inputs.WireGuardCIDR,
		PublicTCP:     append([]int(nil), inputs.PublicTCP...),
		PublicUDP:     append([]int(nil), inputs.PublicUDP...),
		WireGuardTCP:  append([]int(nil), inputs.WireGuardTCP...),
		WireGuardUDP:  append([]int(nil), inputs.WireGuardUDP...),
		UpdatedAt:     inputs.UpdatedAt,
	}
}
