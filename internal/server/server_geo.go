package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

var countryCodePattern = regexp.MustCompile(`^[A-Z]{2}$`)

type nodeGeoView struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Role   string         `json:"role,omitempty"`
	Online bool           `json:"online"`
	Geo    *model.NodeGeo `json:"geo,omitempty"`
}

type nodeGeoInput struct {
	Country  string   `json:"country,omitempty"`
	City     string   `json:"city,omitempty"`
	Lat      *float64 `json:"lat,omitempty"`
	Lon      *float64 `json:"lon,omitempty"`
	ASN      *int     `json:"asn,omitempty"`
	ASOrg    string   `json:"as_org,omitempty"`
	Provider string   `json:"provider,omitempty"`
}

func (s *Server) handleNodesGeo(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		nodes := s.store.Nodes()
		views := make([]nodeGeoView, 0, len(nodes))
		for _, node := range nodes {
			if rbac.Allows(p.Principal, "node:read", node.ID) {
				views = append(views, toNodeGeoView(node))
			}
		}
		writeJSON(w, http.StatusOK, views)
	case http.MethodPost:
		var req struct {
			NodeID string       `json:"node_id"`
			Geo    nodeGeoInput `json:"geo"`
			Clear  bool         `json:"clear,omitempty"`
		}
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.NodeID = strings.TrimSpace(req.NodeID)
		if req.NodeID == "" {
			writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
			return
		}
		if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
			return
		}
		var geo *model.NodeGeo
		var err error
		if !req.Clear {
			geo, err = normalizeNodeGeo(req.Geo, s.now())
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		node, ok, err := s.store.UpdateNodeGeo(req.NodeID, geo)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		action := "node.geo.update"
		if req.Clear {
			action = "node.geo.clear"
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			NodeID:   req.NodeID,
			Action:   action,
			Scope:    "node:admin",
			Metadata: map[string]string{"node_id": req.NodeID},
		})
		writeJSON(w, http.StatusOK, toNodeGeoView(node))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func toNodeGeoView(node model.Node) nodeGeoView {
	return nodeGeoView{
		ID:     node.ID,
		Name:   node.Name,
		Role:   node.Role,
		Online: node.Online,
		Geo:    node.Geo,
	}
}

func normalizeNodeGeo(in nodeGeoInput, now time.Time) (*model.NodeGeo, error) {
	if in.Lat == nil || in.Lon == nil {
		return nil, errors.New("lat and lon are required")
	}
	lat, lon := *in.Lat, *in.Lon
	if lat < -90 || lat > 90 {
		return nil, fmt.Errorf("lat must be between -90 and 90")
	}
	if lon < -180 || lon > 180 {
		return nil, fmt.Errorf("lon must be between -180 and 180")
	}
	country := strings.ToUpper(strings.TrimSpace(in.Country))
	if country != "" && !countryCodePattern.MatchString(country) {
		return nil, errors.New("country must be an ISO-3166 alpha-2 code")
	}
	asn := 0
	if in.ASN != nil {
		if *in.ASN < 0 {
			return nil, errors.New("asn must be non-negative")
		}
		asn = *in.ASN
	}
	return &model.NodeGeo{
		Country:   country,
		City:      clampPrintable(in.City, 96),
		Lat:       lat,
		Lon:       lon,
		ASN:       asn,
		ASOrg:     clampPrintable(in.ASOrg, 128),
		Provider:  clampPrintable(in.Provider, 96),
		UpdatedAt: now.UTC(),
	}, nil
}
