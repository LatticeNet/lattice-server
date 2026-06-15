package server

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/georouting"
	"github.com/LatticeNet/lattice-server/internal/id"
)

// buildGeoInput projects a GeoRouting record + live node state into the render
// input. Health = online and not disabled; geo = the node has NodeGeo
// coordinates. The renderer omits ineligible nodes with warnings.
func (s *Server) buildGeoInput(gr model.GeoRouting) georouting.Input {
	nodes := make([]georouting.GeoNode, 0, len(gr.NodeIDs))
	for _, nodeID := range gr.NodeIDs {
		node, ok := s.store.Node(nodeID)
		if !ok {
			nodes = append(nodes, georouting.GeoNode{ID: nodeID})
			continue
		}
		gn := georouting.GeoNode{
			ID:      node.ID,
			Name:    node.Name,
			IPv4:    node.PublicIP,
			IPv6:    node.PublicIPv6,
			Healthy: node.Online && !node.Disabled,
		}
		if node.Geo != nil {
			gn.Lat = node.Geo.Lat
			gn.Lon = node.Geo.Lon
			gn.HasGeo = true
		}
		nodes = append(nodes, gn)
	}
	return georouting.Input{
		Hostname:    gr.Hostname,
		TTL:         gr.TTL,
		Strategy:    gr.Strategy,
		GeoIPDBPath: gr.GeoIPDBPath,
		Nodes:       nodes,
	}
}

func (s *Server) handleGeoRoutings(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		records := s.store.GeoRoutings()
		writeJSON(w, http.StatusOK, map[string]any{"geo_routings": records})
	case http.MethodPost:
		if !s.requireScope(w, p, "geo:admin") {
			return
		}
		var req model.GeoRouting
		if !decodeClientJSON(w, r, &req) {
			return
		}
		gr, err := s.normalizeGeoRouting(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertGeoRouting(gr); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if stored, ok := s.store.GeoRouting(gr.ID); ok {
			gr = stored
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			Action: "geo.routing.upsert",
			Scope:  "geo:admin",
			Metadata: map[string]string{
				"geo_routing_id": gr.ID,
				"hostname":       gr.Hostname,
				"strategy":       gr.Strategy,
				"nodes":          strings.Join(gr.NodeIDs, ","),
			},
		})
		writeJSON(w, http.StatusOK, gr)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteGeoRouting(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "geo:admin") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if err := s.store.DeleteGeoRouting(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		Action:   "geo.routing.delete",
		Scope:    "geo:admin",
		Metadata: map[string]string{"geo_routing_id": req.ID},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type geoRoutingPlanView struct {
	GeoRoutingID    string            `json:"geo_routing_id"`
	Hostname        string            `json:"hostname"`
	Strategy        string            `json:"strategy"`
	Config          string            `json:"config"`
	SHA256          string            `json:"sha256"`
	Warnings        []string          `json:"warnings,omitempty"`
	ContinentChoice map[string]string `json:"continent_choice,omitempty"`
}

func (s *Server) handleGeoRoutingPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !s.requireScope(w, p, "geo:read") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	gr, ok := s.store.GeoRouting(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("geo routing not found"))
		return
	}
	res, err := georouting.Render(s.buildGeoInput(gr))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		Action: "geo.routing.plan",
		Scope:  "geo:read",
		Metadata: map[string]string{
			"geo_routing_id": gr.ID,
			"sha256":         res.SHA256,
			"warnings":       strings.Join(res.Warnings, "; "),
		},
	})
	writeJSON(w, http.StatusOK, geoRoutingPlanView{
		GeoRoutingID:    gr.ID,
		Hostname:        gr.Hostname,
		Strategy:        gr.Strategy,
		Config:          res.Config,
		SHA256:          res.SHA256,
		Warnings:        res.Warnings,
		ContinentChoice: res.ContinentChoice,
	})
}

func (s *Server) normalizeGeoRouting(req model.GeoRouting) (model.GeoRouting, error) {
	out := model.GeoRouting{}
	if strings.TrimSpace(req.ID) != "" {
		if existing, ok := s.store.GeoRouting(strings.TrimSpace(req.ID)); ok {
			out = existing
		}
		out.ID = strings.TrimSpace(req.ID)
	}
	if out.ID == "" {
		out.ID = id.New("georoute")
	}
	out.Name = strings.TrimSpace(req.Name)
	if out.Name == "" {
		return model.GeoRouting{}, errors.New("name is required")
	}
	if strings.ContainsFunc(out.Name, proxyUnsafeControl) || len(out.Name) > 128 {
		return model.GeoRouting{}, errors.New("invalid name")
	}
	host, err := normalizeDNSName(strings.TrimSpace(req.Hostname), false, false)
	if err != nil {
		return model.GeoRouting{}, errors.New("invalid hostname")
	}
	out.Hostname = host

	out.Strategy = strings.TrimSpace(req.Strategy)
	if out.Strategy == "" {
		out.Strategy = model.GeoRoutingStrategyGeoIP
	}
	if out.Strategy != model.GeoRoutingStrategyGeoIP && out.Strategy != model.GeoRoutingStrategyAllHealthy {
		return model.GeoRouting{}, errors.New("strategy must be geoip or all-healthy")
	}

	nodeIDs, err := s.normalizeGeoNodeList(req.NodeIDs)
	if err != nil {
		return model.GeoRouting{}, err
	}
	if len(nodeIDs) == 0 {
		return model.GeoRouting{}, errors.New("at least one participating node_id is required")
	}
	out.NodeIDs = nodeIDs

	dnsNodeIDs, err := s.normalizeGeoNodeList(req.DNSNodeIDs)
	if err != nil {
		return model.GeoRouting{}, err
	}
	if len(dnsNodeIDs) == 0 {
		return model.GeoRouting{}, errors.New("at least one dns_node_id is required (the authoritative DNS node)")
	}
	out.DNSNodeIDs = dnsNodeIDs

	out.TTL = req.TTL
	if out.TTL <= 0 {
		out.TTL = georouting.DefaultTTL
	}
	if out.TTL < 10 || out.TTL > 3600 {
		return model.GeoRouting{}, errors.New("ttl must be between 10 and 3600 seconds")
	}
	out.GeoIPDBPath = strings.TrimSpace(req.GeoIPDBPath)
	if out.GeoIPDBPath != "" {
		if err := validateProxyConfigPath(out.GeoIPDBPath); err != nil {
			return model.GeoRouting{}, errors.New("geoip_db_path: " + err.Error())
		}
	}
	out.PublishNS = req.PublishNS
	out.DDNSProfileID = strings.TrimSpace(req.DDNSProfileID)
	out.Status = "configured"
	return out, nil
}

// normalizeGeoNodeList dedups, validates existence, and sorts node ids.
func (s *Server) normalizeGeoNodeList(values []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := s.store.Node(v); !ok {
			return nil, errors.New("node not found: " + v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, nil
}

// reRenderGeoRoutingsForNode is a hook for the IP/geo/health-change trigger to
// mark dependent geo-routings stale (a full re-apply is operator-initiated).
func (s *Server) touchGeoRoutingsForNode(nodeID string, now time.Time) {
	for _, gr := range s.store.GeoRoutingsForNode(nodeID) {
		gr.Status = "node-changed"
		gr.UpdatedAt = now
		_ = s.store.UpsertGeoRouting(gr)
	}
}
