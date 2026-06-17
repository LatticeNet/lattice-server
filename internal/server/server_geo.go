package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/geoip"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

var countryCodePattern = regexp.MustCompile(`^[A-Z]{2}$`)

type nodeGeoView struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Role       string         `json:"role,omitempty"`
	Online     bool           `json:"online"`
	PublicIP   string         `json:"public_ip,omitempty"`
	PublicIPv6 string         `json:"public_ipv6,omitempty"`
	Geo        *model.NodeGeo `json:"geo,omitempty"`
}

type nodeGeoInput struct {
	Country  string   `json:"country,omitempty"`
	Region   string   `json:"region,omitempty"`
	City     string   `json:"city,omitempty"`
	Lat      *float64 `json:"lat,omitempty"`
	Lon      *float64 `json:"lon,omitempty"`
	ASN      *int     `json:"asn,omitempty"`
	ASOrg    string   `json:"as_org,omitempty"`
	Provider string   `json:"provider,omitempty"`
}

type nodeGeoResolveRequest struct {
	NodeID      string `json:"node_id,omitempty"`
	All         bool   `json:"all,omitempty"`
	MissingOnly bool   `json:"missing_only,omitempty"`
	Overwrite   bool   `json:"overwrite,omitempty"`
}

type nodeGeoResolveResponse struct {
	Results []nodeGeoResolveResult `json:"results"`
}

type nodeGeoResolveResult struct {
	NodeID  string         `json:"node_id"`
	IP      string         `json:"ip,omitempty"`
	Status  string         `json:"status"`
	Message string         `json:"message,omitempty"`
	Node    *nodeGeoView   `json:"node,omitempty"`
	Geo     *model.NodeGeo `json:"geo,omitempty"`
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
		ID:         node.ID,
		Name:       node.Name,
		Role:       node.Role,
		Online:     node.Online,
		PublicIP:   node.PublicIP,
		PublicIPv6: node.PublicIPv6,
		Geo:        node.Geo,
	}
}

func (s *Server) handleNodesGeoResolve(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req nodeGeoResolveRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" && !req.All {
		writeError(w, http.StatusBadRequest, errors.New("node_id or all=true is required"))
		return
	}

	var nodes []model.Node
	if req.All {
		for _, node := range s.store.Nodes() {
			if rbac.Allows(p.Principal, "node:admin", node.ID) {
				nodes = append(nodes, node)
			}
		}
	} else {
		if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
			return
		}
		node, ok := s.store.Node(req.NodeID)
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		nodes = append(nodes, node)
	}

	results := make([]nodeGeoResolveResult, 0, len(nodes))
	for _, node := range nodes {
		results = append(results, s.resolveNodeGeo(r, p, node, req))
	}
	writeJSON(w, http.StatusOK, nodeGeoResolveResponse{Results: results})
}

func (s *Server) resolveNodeGeo(r *http.Request, p principal, node model.Node, req nodeGeoResolveRequest) nodeGeoResolveResult {
	result := nodeGeoResolveResult{NodeID: node.ID}
	if s.geoResolver == nil {
		result.Status = "resolver_disabled"
		result.Message = "geoip resolver is not configured"
		return result
	}
	if hasStoredGeoCoordinates(node.Geo) && !req.Overwrite {
		result.Status = "skipped_existing"
		result.Geo = node.Geo
		return result
	}
	ip := selectNodeGeoLookupIP(node)
	result.IP = ip
	if ip == "" {
		result.Status = "no_public_ip"
		result.Message = "node has no reported public IP"
		return result
	}
	lookup, err := s.geoResolver.Lookup(r.Context(), ip)
	if err != nil {
		result.Status = "lookup_failed"
		result.Message = err.Error()
		return result
	}
	geo := nodeGeoFromLookup(lookup, s.now())
	updated, ok, err := s.store.UpdateNodeGeo(node.ID, geo)
	if err != nil {
		result.Status = "store_failed"
		result.Message = err.Error()
		return result
	}
	if !ok {
		result.Status = "not_found"
		result.Message = "node not found"
		return result
	}
	view := toNodeGeoView(updated)
	result.Status = "updated"
	result.Node = &view
	result.Geo = view.Geo
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: node.ID,
		Action: "node.geo.resolve",
		Scope:  "node:admin",
		Metadata: map[string]string{
			"node_id": node.ID,
			"ip":      ip,
			"country": geo.Country,
			"source":  geo.Source,
		},
	})
	return result
}

func selectNodeGeoLookupIP(node model.Node) string {
	if strings.TrimSpace(node.PublicIP) != "" {
		return strings.TrimSpace(node.PublicIP)
	}
	return strings.TrimSpace(node.PublicIPv6)
}

func hasStoredGeoCoordinates(geo *model.NodeGeo) bool {
	if geo == nil {
		return false
	}
	return geo.Lat != 0 || geo.Lon != 0
}

func nodeGeoFromLookup(lookup geoip.Result, now time.Time) *model.NodeGeo {
	country := strings.ToUpper(strings.TrimSpace(lookup.Country))
	if country != "" && !countryCodePattern.MatchString(country) {
		country = ""
	}
	return &model.NodeGeo{
		Country:   country,
		Region:    clampPrintable(lookup.Region, 96),
		City:      clampPrintable(lookup.City, 96),
		Lat:       lookup.Lat,
		Lon:       lookup.Lon,
		IP:        clampPrintable(lookup.IP, 64),
		ASN:       lookup.ASN,
		ASOrg:     clampPrintable(lookup.ASOrg, 128),
		Provider:  clampPrintable(lookup.Provider, 96),
		Source:    "auto",
		UpdatedAt: now.UTC(),
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
		Region:    clampPrintable(in.Region, 96),
		City:      clampPrintable(in.City, 96),
		Lat:       lat,
		Lon:       lon,
		ASN:       asn,
		ASOrg:     clampPrintable(in.ASOrg, 128),
		Provider:  clampPrintable(in.Provider, 96),
		Source:    "operator",
		UpdatedAt: now.UTC(),
	}, nil
}
