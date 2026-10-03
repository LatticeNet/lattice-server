package server

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The incident and maintenance window routes.
//
//	GET  /api/incidents                  monitor:read, filtered to the caller's nodes
//	POST /api/incidents/ack              monitor:admin on the incident's node
//	POST /api/incidents/snooze           monitor:admin on the incident's node
//	GET  /api/maintenance-windows        monitor:read, filtered to the caller's nodes
//	POST /api/maintenance-windows        monitor:admin on every covered node
//	POST /api/maintenance-windows/delete monitor:admin on every covered node
//
// An incident with no node (a tls monitor evaluated by the server) and a
// window that covers groups are fleet-wide: a node-confined token can neither
// see nor change them, since group membership can change under it. Every
// acknowledgement, snooze and window change is audited; an incident opening
// or resolving is not, because that is probe traffic and stays out of the
// audit stream.

const (
	defaultIncidentListLimit = 500
	maxIncidentListLimit     = store.MaxIncidents
	// incidentListResolvedWithin is how far back the default list reaches
	// for resolved incidents.
	incidentListResolvedWithin = 7 * 24 * time.Hour
	maxMaintenanceWindowSpan   = 30 * 24 * time.Hour
	maxMaintenanceNameLen      = 120
	maxMaintenanceReasonLen    = 500
)

// incidentStatePending is a derived state: the condition is true and its hold
// is still running, so nothing has been recorded or sent.
const incidentStatePending = "pending"

// incidentView is an incident as the console reads it.
type incidentView struct {
	store.Incident
	RecoveryKind string `json:"recovery_kind,omitempty"`
	NodeName     string `json:"node_name,omitempty"`
	// Maintenance names the active window that covers the incident's node.
	Maintenance   string `json:"maintenance,omitempty"`
	MaintenanceID string `json:"maintenance_id,omitempty"`
	Snoozed       bool   `json:"snoozed,omitempty"`
	// OpensAt is when a pending incident opens if its condition holds; zero
	// when that depends on the next probe (a monitor's second failure).
	OpensAt time.Time `json:"opens_at,omitzero"`
}

type incidentListResponse struct {
	Incidents []incidentView `json:"incidents"`
	// Windows are the active maintenance windows the caller may see, for the
	// banner.
	Windows []store.MaintenanceWindow `json:"windows"`
	// Durable says whether incidents survive a restart (the bolt hot store).
	Durable bool      `json:"durable"`
	Now     time.Time `json:"now"`
}

func incidentVisible(p principal, nodeID string) bool {
	if nodeID == "" {
		return !principalHasNodeRestriction(p) && rbac.Allows(p.Principal, "monitor:read", "")
	}
	return rbac.Allows(p.Principal, "monitor:read", nodeID)
}

func (s *Server) toIncidentView(inc store.Incident, now time.Time, cover maintenanceCover, names map[string]string) incidentView {
	v := incidentView{Incident: inc, RecoveryKind: incidentKinds[inc.Kind].recovery, NodeName: names[inc.NodeID]}
	if inc.Active() || inc.State == incidentStatePending {
		if w, ok := cover(inc.NodeID); ok {
			v.Maintenance, v.MaintenanceID = w.Name, w.ID
		}
	}
	v.Snoozed = inc.Active() && inc.SnoozedUntil.After(now)
	return v
}

// handleIncidents lists incidents: pending, open and acknowledged ones, and
// resolved ones from the last seven days, newest first, unless state names
// the states wanted (comma separated: pending, open, acknowledged, resolved).
// node_id narrows to one node, limit bounds the list (default 500).
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	q := r.URL.Query()
	limit := defaultIncidentListLimit
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxIncidentListLimit {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit must be 1 to %d", maxIncidentListLimit))
			return
		}
		limit = n
	}
	wanted := map[string]bool{}
	explicit := false
	if raw := strings.TrimSpace(q.Get("state")); raw != "" {
		explicit = true
		for _, st := range strings.Split(raw, ",") {
			st = strings.TrimSpace(st)
			switch st {
			case incidentStatePending, store.IncidentStateOpen, store.IncidentStateAcknowledged, store.IncidentStateResolved:
				wanted[st] = true
			default:
				writeError(w, http.StatusBadRequest, fmt.Errorf("unknown state %q", st))
				return
			}
		}
	} else {
		for _, st := range []string{incidentStatePending, store.IncidentStateOpen, store.IncidentStateAcknowledged, store.IncidentStateResolved} {
			wanted[st] = true
		}
	}
	nodeFilter := q.Get("node_id")
	if q.Has("node_id") && nodeFilter != "" && !rbac.Allows(p.Principal, "monitor:read", nodeFilter) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return
	}
	now := s.now()
	keep := func(inc store.Incident) bool {
		if !wanted[inc.State] || !incidentVisible(p, inc.NodeID) {
			return false
		}
		if q.Has("node_id") && inc.NodeID != nodeFilter {
			return false
		}
		if inc.State == store.IncidentStateResolved && !explicit && now.Sub(inc.ResolvedAt) > incidentListResolvedWithin {
			return false
		}
		return true
	}
	var rows []store.Incident
	for _, inc := range s.store.Incidents() {
		if keep(inc) {
			rows = append(rows, inc)
		}
	}
	if wanted[incidentStatePending] {
		for _, inc := range s.pendingIncidents(now) {
			if keep(inc) {
				rows = append(rows, inc)
			}
		}
	}
	// Active and pending first (worst first, then newest), then resolved,
	// newest resolution first.
	rank := func(inc store.Incident) int {
		switch inc.State {
		case store.IncidentStateOpen:
			return 0
		case store.IncidentStateAcknowledged:
			return 1
		case incidentStatePending:
			return 2
		}
		return 3
	}
	severity := map[string]int{incidentSeverityCritical: 0, incidentSeverityWarning: 1, incidentSeverityInfo: 2}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if a.State == store.IncidentStateResolved {
			return a.ResolvedAt.After(b.ResolvedAt)
		}
		if severity[a.Severity] != severity[b.Severity] {
			return severity[a.Severity] < severity[b.Severity]
		}
		return a.Since.After(b.Since)
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	cover := s.maintenanceCoverAt(now)
	names := s.nodeNames()
	resp := incidentListResponse{Incidents: make([]incidentView, 0, len(rows)), Windows: []store.MaintenanceWindow{}, Durable: s.store.IncidentsDurable(), Now: now}
	for _, inc := range rows {
		v := s.toIncidentView(inc, now, cover, names)
		if inc.State == incidentStatePending {
			v.OpensAt = inc.UpdatedAt
			v.UpdatedAt = time.Time{}
		}
		resp.Incidents = append(resp.Incidents, v)
	}
	for _, mw := range s.store.MaintenanceWindows() {
		if mw.ActiveAt(now) && maintenanceWindowVisible(p, mw) {
			resp.Windows = append(resp.Windows, maintenanceWindowFor(p, mw))
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) nodeNames() map[string]string {
	nodes := s.store.Nodes()
	out := make(map[string]string, len(nodes))
	for _, n := range nodes {
		out[n.ID] = nodeLabel(n)
	}
	return out
}

// pendingIncidents derives the incidents whose condition is true and whose
// hold has not elapsed, from the same evidence the emitters decide on. They
// carry state pending, an id of "pending:<key>", and the instant they open in
// UpdatedAt (zero when the next probe decides).
func (s *Server) pendingIncidents(now time.Time) []store.Incident {
	var out []store.Incident
	pending := func(inc store.Incident, opensAt time.Time) {
		if _, ok := s.store.ActiveIncident(inc.Key); ok {
			return
		}
		inc.ID = "pending:" + inc.Key
		inc.State = incidentStatePending
		inc.Severity = incidentKinds[inc.Kind].severity
		inc.UpdatedAt = opensAt
		out = append(out, inc)
	}
	nodes := s.store.Nodes()
	byID := make(map[string]model.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
		if n.Disabled || n.LastSeen.IsZero() {
			continue
		}
		name := nodeLabel(n)
		if !n.Online || now.Sub(n.LastSeen) > nodeOfflineThreshold {
			delay, pages := nodeOfflineDelay(n)
			if !pages || !now.Before(n.LastSeen.Add(delay)) {
				continue
			}
			pending(store.Incident{
				Key: incidentKey(EventNodeOffline, n.ID, ""), Kind: EventNodeOffline, NodeID: n.ID,
				Subject: name, Since: n.LastSeen, Title: "Lattice node offline: " + name,
				Detail: fmt.Sprintf("%s (%s) has not reported since %s.", name, n.ID, stamp(n.LastSeen)),
			}, n.LastSeen.Add(delay))
			continue
		}
		if rec, ok := s.freshAgentHealth(n); ok {
			for _, p := range agentLoopProblems(rec, now) {
				if p.kind == agentProblemResultsDropped || p.incident {
					continue
				}
				pending(store.Incident{
					Key: incidentKey(EventAgentStalled, n.ID, ""), Kind: EventAgentStalled, NodeID: n.ID,
					Subject: name, Since: p.since, Title: "Lattice agent stalled on " + name,
					Detail: fmt.Sprintf("%s (%s) is reporting, but %s.", name, n.ID, p.reason),
				}, p.opensAt)
				break
			}
		}
	}
	for nodeID, rec := range s.store.SingBoxLivenessAll() {
		n, ok := byID[nodeID]
		if !ok || n.Disabled || rec.ProblemSince.IsZero() || !rec.NotifiedDownAt.IsZero() {
			continue
		}
		if rec.State != serviceStateDown && rec.State != serviceStateRestarting {
			continue
		}
		if n.LastSeen.Sub(rec.ReceivedAt) > nodeStatusEvidenceStaleAfter {
			continue
		}
		name := nodeLabel(n)
		pending(store.Incident{
			Key: incidentKey(EventServiceDown, nodeID, ""), Kind: EventServiceDown, NodeID: nodeID,
			Subject: name, Since: rec.ProblemSince, Title: fmt.Sprintf("sing-box %s on %s", rec.State, name),
			Detail: fmt.Sprintf("%s (%s): sing-box has been %s since %s.", name, nodeID, rec.State, stamp(rec.ProblemSince)),
		}, rec.ProblemSince.Add(serviceDownHold))
	}
	if latest, err := s.store.LatestMonitorResults(); err == nil {
		for monitorID, pairs := range latest {
			mon, ok := s.store.Monitor(monitorID)
			if !ok {
				continue
			}
			for _, pair := range pairs {
				if pair.Success || pair.FailStreak != 1 || !monitorPairAssigned(mon, pair.NodeID) {
					continue
				}
				name, where := s.monitorNames(mon, pair.NodeID)
				msg := monitorDownMessage(name, where, pair.Error)
				pending(store.Incident{
					Key: incidentKey(EventMonitorDown, pair.NodeID, monitorID), Kind: EventMonitorDown,
					NodeID: pair.NodeID, MonitorID: monitorID, Subject: name + " on " + where,
					Since: pair.ReceivedAt, Title: msg.title,
					Detail: fmt.Sprintf("%s on %s failed once: %s. A second failure in a row opens it.", name, where, strings.TrimSpace(pair.Error)),
				}, time.Time{})
			}
		}
	}
	return out
}

// incidentActionTarget loads an incident for a write and checks the caller
// may act on it: monitor:admin on its node, or an unrestricted monitor:admin
// for an incident with no node.
func (s *Server) incidentActionTarget(w http.ResponseWriter, p principal, incidentID, action string) (store.Incident, bool) {
	if strings.TrimSpace(incidentID) == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return store.Incident{}, false
	}
	inc, ok := s.store.Incident(incidentID)
	if !ok || !incidentVisible(p, inc.NodeID) {
		writeError(w, http.StatusNotFound, errors.New("incident not found"))
		return store.Incident{}, false
	}
	if inc.NodeID == "" {
		if s.refuseConfinedFleetWrite(w, p, action, "monitor:admin") || !s.requireScope(w, p, "monitor:admin") {
			return store.Incident{}, false
		}
	} else if !s.requireNodeScope(w, p, "monitor:admin", inc.NodeID) {
		return store.Incident{}, false
	}
	return inc, true
}

func principalLabel(p principal) string {
	switch {
	case p.ActorID != "":
		return p.ActorID
	case p.TokenID != "":
		return "token:" + p.TokenID
	}
	return "unknown"
}

// handleIncidentAck acknowledges an open incident: it stops the escalation
// and the snooze reminder, and never the recovery.
func (s *Server) handleIncidentAck(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if _, ok := s.incidentActionTarget(w, p, req.ID, "incident.ack"); !ok {
		return
	}
	now := s.now()
	s.incidentMu.Lock()
	inc, ok := s.store.Incident(req.ID)
	if !ok || !inc.Active() {
		s.incidentMu.Unlock()
		writeError(w, http.StatusConflict, errors.New("only an open incident can be acknowledged"))
		return
	}
	if inc.State != store.IncidentStateAcknowledged {
		inc.State = store.IncidentStateAcknowledged
		inc.AckedBy, inc.AckedAt = principalLabel(p), now
		inc.OwedOpen = false
		inc.UpdatedAt = now
		if err := s.store.PutIncidents(inc); err != nil {
			s.logger.Printf("incidents: record ack %s: %v", inc.ID, err)
		}
	}
	s.incidentMu.Unlock()
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: inc.NodeID, Action: "incident.ack", Scope: "monitor:admin",
		Metadata: map[string]string{"incident_id": inc.ID, "kind": inc.Kind}})
	writeJSON(w, http.StatusOK, s.toIncidentView(inc, now, s.maintenanceCoverAt(now), s.nodeNames()))
}

// handleIncidentSnooze holds an open incident's messages until a time:
// minutes from now (1 to 10080), or 0 to end the snooze. When the snooze
// runs out with the incident still open and unacknowledged, one reminder
// goes out.
func (s *Server) handleIncidentSnooze(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID      string `json:"id"`
		Minutes *int   `json:"minutes"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.Minutes == nil || *req.Minutes < 0 || time.Duration(*req.Minutes)*time.Minute > maxIncidentSnooze {
		writeError(w, http.StatusBadRequest, fmt.Errorf("minutes must be 0 (end the snooze) to %d", int(maxIncidentSnooze/time.Minute)))
		return
	}
	if _, ok := s.incidentActionTarget(w, p, req.ID, "incident.snooze"); !ok {
		return
	}
	now := s.now()
	s.incidentMu.Lock()
	inc, ok := s.store.Incident(req.ID)
	if !ok || !inc.Active() {
		s.incidentMu.Unlock()
		writeError(w, http.StatusConflict, errors.New("only an open incident can be snoozed"))
		return
	}
	if *req.Minutes == 0 {
		inc.SnoozedUntil, inc.SnoozedBy = time.Time{}, ""
	} else {
		inc.SnoozedUntil = now.Add(time.Duration(*req.Minutes) * time.Minute)
		inc.SnoozedBy = principalLabel(p)
	}
	inc.UpdatedAt = now
	if err := s.store.PutIncidents(inc); err != nil {
		s.logger.Printf("incidents: record snooze %s: %v", inc.ID, err)
	}
	s.incidentMu.Unlock()
	meta := map[string]string{"incident_id": inc.ID, "kind": inc.Kind, "minutes": strconv.Itoa(*req.Minutes)}
	if !inc.SnoozedUntil.IsZero() {
		meta["until"] = stamp(inc.SnoozedUntil)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: inc.NodeID, Action: "incident.snooze", Scope: "monitor:admin", Metadata: meta})
	writeJSON(w, http.StatusOK, s.toIncidentView(inc, now, s.maintenanceCoverAt(now), s.nodeNames()))
}

// maintenanceWindowVisible: an unrestricted reader sees every window; a
// node-confined one sees node windows that cover at least one of its nodes.
func maintenanceWindowVisible(p principal, mw store.MaintenanceWindow) bool {
	if !principalHasNodeRestriction(p) {
		return rbac.Allows(p.Principal, "monitor:read", "")
	}
	if len(mw.GroupIDs) > 0 {
		return false
	}
	for _, nodeID := range mw.NodeIDs {
		if rbac.Allows(p.Principal, "monitor:read", nodeID) {
			return true
		}
	}
	return false
}

// maintenanceWindowFor is a visible window as p may read it: a node-confined
// reader sees only the nodes it can read in node_ids, not the ids of the
// others. It cannot edit such a window either way, since a change needs
// monitor:admin on every node the window already covers.
func maintenanceWindowFor(p principal, mw store.MaintenanceWindow) store.MaintenanceWindow {
	if !principalHasNodeRestriction(p) {
		return mw
	}
	nodeIDs := make([]string, 0, len(mw.NodeIDs))
	for _, nodeID := range mw.NodeIDs {
		if rbac.Allows(p.Principal, "monitor:read", nodeID) {
			nodeIDs = append(nodeIDs, nodeID)
		}
	}
	mw.NodeIDs = nodeIDs
	return mw
}

// authorizeMaintenanceWindow checks the caller may set a window over these
// nodes and groups: monitor:admin on every node, and an unrestricted token
// for any group.
func (s *Server) authorizeMaintenanceWindow(w http.ResponseWriter, p principal, action string, nodeIDs, groupIDs []string) bool {
	if !s.requireScope(w, p, "monitor:admin") {
		return false
	}
	if len(groupIDs) > 0 && s.refuseConfinedFleetWrite(w, p, action, "monitor:admin") {
		return false
	}
	for _, nodeID := range nodeIDs {
		if !s.requireNodeScope(w, p, "monitor:admin", nodeID) {
			return false
		}
	}
	return true
}

func (s *Server) handleMaintenanceWindows(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "monitor:read") {
			return
		}
		out := []store.MaintenanceWindow{}
		for _, mw := range s.store.MaintenanceWindows() {
			if maintenanceWindowVisible(p, mw) {
				out = append(out, maintenanceWindowFor(p, mw))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"windows": out, "now": s.now()})
	case http.MethodPost:
		s.upsertMaintenanceWindow(w, r, p)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// upsertMaintenanceWindow creates a window, or changes one when id names it.
// A window covers at least one node or group, ends after it starts, spans at
// most 30 days, and a new one must not have ended already. Setting ends_at to
// now ends a running window early.
func (s *Server) upsertMaintenanceWindow(w http.ResponseWriter, r *http.Request, p principal) {
	var req struct {
		ID       string    `json:"id"`
		Name     string    `json:"name"`
		Reason   string    `json:"reason"`
		NodeIDs  []string  `json:"node_ids"`
		GroupIDs []string  `json:"group_ids"`
		StartsAt time.Time `json:"starts_at"`
		EndsAt   time.Time `json:"ends_at"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	now := s.now()
	mw := store.MaintenanceWindow{
		ID: strings.TrimSpace(req.ID), Name: strings.TrimSpace(req.Name), Reason: strings.TrimSpace(req.Reason),
		StartsAt: req.StartsAt.UTC(), EndsAt: req.EndsAt.UTC(),
	}
	mw.NodeIDs = cleanIDList(req.NodeIDs)
	mw.GroupIDs = cleanIDList(req.GroupIDs)
	var existing store.MaintenanceWindow
	exists := false
	if mw.ID != "" {
		existing, exists = s.store.MaintenanceWindow(mw.ID)
		if !exists || !maintenanceWindowVisible(p, existing) {
			writeError(w, http.StatusNotFound, errors.New("maintenance window not found"))
			return
		}
	}
	if mw.StartsAt.IsZero() {
		mw.StartsAt = now
		if exists {
			mw.StartsAt = existing.StartsAt
		}
	}
	switch {
	case mw.Name == "" || len(mw.Name) > maxMaintenanceNameLen:
		writeError(w, http.StatusBadRequest, fmt.Errorf("name is required, at most %d characters", maxMaintenanceNameLen))
		return
	case len(mw.Reason) > maxMaintenanceReasonLen:
		writeError(w, http.StatusBadRequest, fmt.Errorf("reason is at most %d characters", maxMaintenanceReasonLen))
		return
	case len(mw.NodeIDs) == 0 && len(mw.GroupIDs) == 0:
		writeError(w, http.StatusBadRequest, errors.New("a maintenance window covers at least one node or group"))
		return
	case mw.EndsAt.IsZero() || !mw.EndsAt.After(mw.StartsAt):
		writeError(w, http.StatusBadRequest, errors.New("ends_at must be after starts_at"))
		return
	case mw.EndsAt.Sub(mw.StartsAt) > maxMaintenanceWindowSpan:
		writeError(w, http.StatusBadRequest, fmt.Errorf("a maintenance window spans at most %s", livenessSpan(maxMaintenanceWindowSpan)))
		return
	case !exists && !mw.EndsAt.After(now):
		writeError(w, http.StatusBadRequest, errors.New("a new maintenance window must end in the future"))
		return
	}
	for _, nodeID := range mw.NodeIDs {
		if _, ok := s.store.Node(nodeID); !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("node %q does not exist", nodeID))
			return
		}
	}
	for _, groupID := range mw.GroupIDs {
		if _, ok := s.store.Group(groupID); !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("group %q does not exist", groupID))
			return
		}
	}
	if !s.authorizeMaintenanceWindow(w, p, "maintenance.upsert", mw.NodeIDs, mw.GroupIDs) {
		return
	}
	if exists && !s.authorizeMaintenanceWindow(w, p, "maintenance.upsert", existing.NodeIDs, existing.GroupIDs) {
		return
	}
	if exists {
		mw.CreatedBy, mw.CreatedAt = existing.CreatedBy, existing.CreatedAt
	} else {
		mw.ID = id.New("mw")
		mw.CreatedBy, mw.CreatedAt = principalLabel(p), now
	}
	mw.UpdatedAt = now
	if err := s.store.PutMaintenanceWindow(mw, now); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "maintenance.upsert", Scope: "monitor:admin", Metadata: maintenanceAuditMeta(mw)})
	writeJSON(w, http.StatusOK, mw)
}

func (s *Server) handleDeleteMaintenanceWindow(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	mw, ok := s.store.MaintenanceWindow(strings.TrimSpace(req.ID))
	if !ok || !maintenanceWindowVisible(p, mw) {
		writeError(w, http.StatusNotFound, errors.New("maintenance window not found"))
		return
	}
	if !s.authorizeMaintenanceWindow(w, p, "maintenance.delete", mw.NodeIDs, mw.GroupIDs) {
		return
	}
	if err := s.store.DeleteMaintenanceWindow(mw.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "maintenance.delete", Scope: "monitor:admin", Metadata: maintenanceAuditMeta(mw)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func maintenanceAuditMeta(mw store.MaintenanceWindow) map[string]string {
	return map[string]string{
		"window_id": mw.ID, "name": mw.Name,
		"node_ids": strings.Join(mw.NodeIDs, ","), "group_ids": strings.Join(mw.GroupIDs, ","),
		"starts_at": stamp(mw.StartsAt), "ends_at": stamp(mw.EndsAt),
	}
}

// cleanIDList trims, drops empties and duplicates, and sorts.
func cleanIDList(in []string) []string {
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
