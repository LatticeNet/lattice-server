package server

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The check definition API (design 32 D1), in the action-route style of
// the monitor routes:
//
//	GET  /api/monitors/definitions          every definition the caller may read, and Fleet mesh
//	GET  /api/monitors/definitions?id=      one definition with its expanded monitors
//	POST /api/monitors/definitions          create
//	POST /api/monitors/definitions/update   edit, naming the version read
//	POST /api/monitors/definitions/preview  dry run of a create or an edit
//	POST /api/monitors/definitions/delete   delete with every monitor and its history
//	POST /api/monitors/definitions/forget   delete paused targets with their history

// checkDefinitionVisible reports whether p may read def. A principal with
// no node allowlist reads every definition; a restricted one reads only a
// definition that names its nodes explicitly, every one of them a node it
// may read, since a group or whole-fleet selector would tell it about nodes
// outside its scope.
func checkDefinitionVisible(p principal, def model.CheckDefinition) bool {
	if !principalHasNodeRestriction(p) {
		return rbac.Allows(p.Principal, "monitor:read", "")
	}
	if def.Type == model.MonitorTypeTLS || checkSelectorBroad(def.Sources) || checkSelectorBroad(def.Targets) {
		return false
	}
	for _, list := range [][]string{def.Sources.Nodes, def.Sources.Exclude, def.Targets.Nodes, def.Targets.Exclude} {
		for _, nodeID := range list {
			if !latencyNodeVisible(p, nodeID) {
				return false
			}
		}
	}
	return true
}

// checkDefinitionManageable reports whether p may edit, delete or forget
// def: what creating it would need now.
func checkDefinitionManageable(p principal, def model.CheckDefinition) bool {
	if !principalHasNodeRestriction(p) {
		return rbac.Allows(p.Principal, "monitor:admin", "")
	}
	if !checkDefinitionVisible(p, def) {
		return false
	}
	for _, nodeID := range def.Sources.Nodes {
		if !rbac.Allows(p.Principal, "monitor:admin", nodeID) {
			return false
		}
	}
	return true
}

// checkMonitorRuns counts the results each monitor stores over every
// source, from the latest records the hot store keeps per pair.
func (s *Server) checkMonitorRuns() map[string]int {
	latest, err := s.store.LatestMonitorResults()
	if err != nil {
		return map[string]int{}
	}
	out := make(map[string]int, len(latest))
	for monitorID, pairs := range latest {
		for _, pair := range pairs {
			out[monitorID] += pair.Held
		}
	}
	return out
}

// checkDefinitionView is def as the API reads it: secret values removed,
// counted against what is stored now, with its monitors when asked.
func (s *Server) checkDefinitionView(def model.CheckDefinition, plan checkDefinitionPlan, monitors []model.Monitor, runs map[string]int, withMonitors bool) model.CheckDefinitionView {
	view := model.CheckDefinitionView{CheckDefinition: def}
	view.Headers = redactMonitorHeaders(def.Headers)
	inSet := map[string]bool{}
	for _, e := range plan.entries {
		inSet[e.monitorID] = true
	}
	owner := store.CheckDefinitionOwner(def.ID)
	for _, mon := range monitors {
		if mon.ManagedBy != owner {
			continue
		}
		view.Summary.Monitors++
		if inSet[mon.ID] {
			if mon.Type == model.MonitorTypeTLS {
				view.Summary.Paths++
			} else {
				view.Summary.Paths += len(mon.NodeIDs)
			}
		} else {
			view.Summary.PausedTargets++
			view.Summary.PausedRuns += runs[mon.ID]
		}
		if withMonitors {
			sources := slices.Clone(mon.NodeIDs)
			if sources == nil {
				sources = []string{}
			}
			view.Monitors = append(view.Monitors, model.CheckDefinitionMonitor{
				MonitorID: mon.ID, Method: mon.Type, Target: mon.Target, TargetNode: mon.TargetNode,
				InSet: inSet[mon.ID], Enabled: mon.Enabled, Sources: sources, Runs: runs[mon.ID],
			})
		}
	}
	if withMonitors && view.Monitors == nil {
		view.Monitors = []model.CheckDefinitionMonitor{}
	}
	return view
}

// checkFleetMesh is the path set as the built-in check named Fleet mesh,
// counted against the fleet now and narrowed to what p may read.
func (s *Server) checkFleetMesh(p principal, now time.Time) model.CheckFleetMesh {
	plan := latencyPlanForPrincipal(s.pathPlanned(now).plan, p)
	out := model.CheckFleetMesh{
		Name:    model.CheckFleetMeshName,
		Enabled: plan.Config.Enabled,
		Stored:  plan.Stored,
		Version: plan.Config.Version,
		Method:  plan.Config.Method,
	}
	if out.Method == "" {
		out.Method = model.LatencyMethodTCP
	}
	for _, n := range plan.Nodes {
		if n.Source {
			out.Sources++
		}
		switch {
		case n.Target == model.LatencyTargetProbed:
			out.Targets++
		case n.Target == model.LatencyTargetPaused:
			out.PausedTargets++
		case n.Target == model.LatencyTargetNone && (n.MonitorID != "" || n.ICMPMonitorID != "" || n.BeaconMonitorID != ""):
			out.PausedTargets++
		}
	}
	for _, pair := range plan.Pairs {
		if pair.Active {
			out.Paths++
		}
	}
	return out
}

// handleCheckDefinitions reads definitions (GET, monitor:read) or creates
// one (POST, monitor:admin).
func (s *Server) handleCheckDefinitions(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "monitor:read") {
			return
		}
		now := s.now()
		c := s.checkPlanContextAt(now)
		plans := c.planAll(s.store.CheckDefinitions(), nil)
		monitors := s.store.Monitors()
		runs := s.checkMonitorRuns()
		if wanted := strings.TrimSpace(r.URL.Query().Get("id")); wanted != "" {
			for _, plan := range plans {
				if plan.def.ID == wanted && checkDefinitionVisible(p, plan.def) {
					writeJSON(w, http.StatusOK, s.checkDefinitionView(plan.def, plan, monitors, runs, true))
					return
				}
			}
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
			return
		}
		list := model.CheckDefinitionList{Definitions: []model.CheckDefinitionView{}, FleetMesh: s.checkFleetMesh(p, now)}
		for _, plan := range plans {
			if checkDefinitionVisible(p, plan.def) {
				list.Definitions = append(list.Definitions, s.checkDefinitionView(plan.def, plan, monitors, runs, false))
			}
		}
		slices.SortStableFunc(list.Definitions, func(a, b model.CheckDefinitionView) int {
			if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
				return c
			}
			return strings.Compare(a.ID, b.ID)
		})
		writeJSON(w, http.StatusOK, list)
	case http.MethodPost:
		if !s.requireScope(w, p, "monitor:admin") {
			return
		}
		var req model.CheckDefinitionSave
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if strings.TrimSpace(req.ID) != "" {
			writeError(w, http.StatusBadRequest, errors.New("a create carries no id; edit a definition through /api/monitors/definitions/update"))
			return
		}
		s.saveCheckDefinition(w, p, req)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// handleCheckDefinitionUpdate answers POST /api/monitors/definitions/update.
func (s *Server) handleCheckDefinitionUpdate(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req model.CheckDefinitionSave
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	s.saveCheckDefinition(w, p, req)
}

// checkPairCount is how many paths a plan measures: its sources times its
// targets, less a node probing itself, and one per tls target.
func checkPairCount(plan checkDefinitionPlan) int {
	n := 0
	for _, e := range plan.entries {
		if plan.def.Type == model.MonitorTypeTLS {
			n++
			continue
		}
		for _, sourceID := range plan.sources {
			if sourceID != e.targetNode {
				n++
			}
		}
	}
	return n
}

// saveCheckDefinition creates (req.ID empty) or edits a definition and, in
// the same store write, brings every definition's monitors in line with the
// fleet: an edit can free or take packet budget another definition shares.
func (s *Server) saveCheckDefinition(w http.ResponseWriter, p principal, req model.CheckDefinitionSave) {
	s.monitorSaves.Lock()
	defer s.monitorSaves.Unlock()
	s.checkDefSync.Lock()
	defer s.checkDefSync.Unlock()
	var prior *model.CheckDefinition
	if req.ID != "" {
		stored, ok := s.store.CheckDefinition(req.ID)
		if !ok || !checkDefinitionVisible(p, stored) {
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
			return
		}
		if !checkDefinitionManageable(p, stored) {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
			return
		}
		prior = &stored
	}
	def, failure := s.normalizeCheckDefinition(p, req, prior)
	if failure != nil {
		writeError(w, failure.status, failure.err)
		return
	}
	expected := req.Version
	if prior == nil {
		def.ID = id.New(strings.TrimSuffix(model.CheckDefinitionIDPrefix, "_"))
		expected = 0
	} else {
		def.CreatedAt = prior.CreatedAt
	}
	now := s.now()
	c := s.checkPlanContextAt(now)
	plans := c.planAll(s.store.CheckDefinitions(), &def)
	for _, plan := range plans {
		if plan.def.ID == def.ID {
			if n := checkPairCount(plan); n > model.CheckDefinitionPairsMax {
				writeError(w, http.StatusBadRequest, errors.New("the check would measure "+strconv.Itoa(n)+" paths, at most "+strconv.Itoa(model.CheckDefinitionPairsMax)+": narrow its sources or targets"))
				return
			}
		}
	}
	stored, changes, err := s.store.SaveCheckDefinition(def, expected, p.ActorID, c.sets(plans), now)
	switch {
	case errors.Is(err, store.ErrCheckDefinitionVersion):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	action := "monitor.check.create"
	meta := checkDefinitionAuditMeta(stored)
	if prior != nil {
		action = "monitor.check.update"
		meta["changed"] = strings.Join(checkDefinitionChanged(*prior, stored), ",")
	}
	own := changes[store.CheckDefinitionOwner(stored.ID)]
	meta["created"] = latencyIDList(own.Created)
	meta["updated"] = latencyIDList(own.Updated)
	meta["deleted"] = latencyIDList(own.Deleted)
	var others []string
	for owner, ch := range changes {
		if owner != store.CheckDefinitionOwner(stored.ID) && ch.Changed() {
			others = append(others, strings.TrimPrefix(owner, store.MonitorManagedCheckPrefix))
		}
	}
	if len(others) > 0 {
		slices.Sort(others)
		meta["also_resynced"] = latencyIDList(others)
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), At: now.UTC(), Action: action, Scope: "monitor:admin", Decision: "allow", Metadata: meta})
	var plan checkDefinitionPlan
	for _, candidate := range plans {
		if candidate.def.ID == stored.ID {
			plan = candidate
		}
	}
	writeJSON(w, http.StatusOK, s.checkDefinitionView(stored, plan, s.store.Monitors(), s.checkMonitorRuns(), true))
}

// handleCheckDefinitionPreview answers POST /api/monitors/definitions/preview:
// what a create (no id) or an edit (with the id) of the same body would
// write and measure, judged exactly as the save judges it. Nothing is
// written. A create has no id yet, so its monitor ids carry a stand-in.
func (s *Server) handleCheckDefinitionPreview(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req model.CheckDefinitionSave
	if !decodeClientJSON(w, r, &req) {
		return
	}
	s.checkDefSync.Lock()
	defer s.checkDefSync.Unlock()
	req.ID = strings.TrimSpace(req.ID)
	var prior *model.CheckDefinition
	if req.ID != "" {
		stored, ok := s.store.CheckDefinition(req.ID)
		if !ok || !checkDefinitionVisible(p, stored) {
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
			return
		}
		if !checkDefinitionManageable(p, stored) {
			writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
			return
		}
		prior = &stored
	}
	def, failure := s.normalizeCheckDefinition(p, req, prior)
	if failure != nil {
		writeError(w, failure.status, failure.err)
		return
	}
	if prior == nil {
		def.ID = checkDefinitionPreviewID
	} else {
		def.CreatedAt = prior.CreatedAt
	}
	c := s.checkPlanContextAt(s.now())
	for _, plan := range c.planAll(s.store.CheckDefinitions(), &def) {
		if plan.def.ID == def.ID {
			if n := checkPairCount(plan); n > model.CheckDefinitionPairsMax {
				writeError(w, http.StatusBadRequest, errors.New("the check would measure "+strconv.Itoa(n)+" paths, at most "+strconv.Itoa(model.CheckDefinitionPairsMax)+": narrow its sources or targets"))
				return
			}
			writeJSON(w, http.StatusOK, s.checkPreview(c, plan))
			return
		}
	}
	writeError(w, http.StatusInternalServerError, errors.New("the dry run lost its definition"))
}

// handleCheckDefinitionDelete answers POST /api/monitors/definitions/delete.
// The body names the monitors the operator confirmed, which must be exactly
// the definition's monitors now; every one goes with its history.
func (s *Server) handleCheckDefinitionDelete(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req model.CheckDefinitionDelete
	if !decodeClientJSON(w, r, &req) {
		return
	}
	s.checkDefSync.Lock()
	defer s.checkDefSync.Unlock()
	def, ok := s.store.CheckDefinition(strings.TrimSpace(req.ID))
	if !ok || !checkDefinitionVisible(p, def) {
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
		return
	}
	if !checkDefinitionManageable(p, def) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return
	}
	runs := s.checkMonitorRuns()
	deleted, err := s.store.DeleteCheckDefinition(def.ID, req.Version, req.MonitorIDs)
	switch {
	case errors.Is(err, store.ErrCheckDefinitionNotFound):
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
		return
	case errors.Is(err, store.ErrCheckDefinitionVersion), errors.Is(err, store.ErrCheckDefinitionMonitors):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil && deleted == nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	total := 0
	for _, monitorID := range deleted {
		total += runs[monitorID]
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "monitor.check.delete", Scope: "monitor:admin", Decision: "allow",
		Metadata: map[string]string{
			"definition_id": def.ID,
			"name":          def.Name,
			"version":       strconv.FormatInt(def.Version, 10),
			"monitors":      latencyIDList(deleted),
			"runs":          strconv.Itoa(total),
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": emptyIfNil(deleted), "runs": total})
}

// handleCheckDefinitionForget answers POST /api/monitors/definitions/forget:
// the named monitors, each a paused target of the definition (its target
// left the set), go with their history.
func (s *Server) handleCheckDefinitionForget(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req model.CheckDefinitionForget
	if !decodeClientJSON(w, r, &req) {
		return
	}
	s.checkDefSync.Lock()
	defer s.checkDefSync.Unlock()
	def, ok := s.store.CheckDefinition(strings.TrimSpace(req.ID))
	if !ok || !checkDefinitionVisible(p, def) {
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
		return
	}
	if !checkDefinitionManageable(p, def) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return
	}
	c := s.checkPlanContextAt(s.now())
	inSet := map[string]bool{}
	for _, plan := range c.planAll(s.store.CheckDefinitions(), nil) {
		if plan.def.ID != def.ID {
			continue
		}
		for _, e := range plan.entries {
			inSet[e.monitorID] = true
		}
	}
	for _, monitorID := range req.MonitorIDs {
		if inSet[monitorID] {
			writeError(w, http.StatusConflict, errors.New("monitor "+monitorID+" measures a target still in the set; only paused targets can be forgotten"))
			return
		}
	}
	runs := s.checkMonitorRuns()
	forgotten, err := s.store.ForgetCheckMonitors(def.ID, req.MonitorIDs)
	switch {
	case errors.Is(err, store.ErrCheckDefinitionNotFound):
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
		return
	case errors.Is(err, store.ErrCheckDefinitionMonitors):
		writeError(w, http.StatusConflict, err)
		return
	case err != nil && forgotten == nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	total := 0
	for _, monitorID := range forgotten {
		total += runs[monitorID]
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), Action: "monitor.check.forget", Scope: "monitor:admin", Decision: "allow",
		Metadata: map[string]string{
			"definition_id": def.ID,
			"monitors":      latencyIDList(forgotten),
			"runs":          strconv.Itoa(total),
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "forgotten": emptyIfNil(forgotten), "runs": total})
}

// checkSelectorSummary is a selector for an audit field, each list bounded.
func checkSelectorSummary(sel model.TargetSelector) string {
	var parts []string
	if sel.All {
		parts = append(parts, "all")
	}
	if len(sel.Nodes) > 0 {
		parts = append(parts, "nodes="+latencyIDList(sel.Nodes))
	}
	if len(sel.Groups) > 0 {
		parts = append(parts, "groups="+latencyIDList(sel.Groups))
	}
	if len(sel.Exclude) > 0 {
		parts = append(parts, "exclude="+latencyIDList(sel.Exclude))
	}
	return strings.Join(parts, ";")
}

// checkDefinitionAuditMeta is a stored definition for its save's audit
// record: header names and secrecy, never a value.
func checkDefinitionAuditMeta(def model.CheckDefinition) map[string]string {
	meta := map[string]string{
		"definition_id": def.ID,
		"name":          def.Name,
		"type":          def.Type,
		"version":       strconv.FormatInt(def.Version, 10),
		"enabled":       strconv.FormatBool(def.Enabled),
		"sources":       checkSelectorSummary(def.Sources),
		"targets":       checkSelectorSummary(def.Targets),
		"addresses":     strconv.Itoa(len(def.Addresses)),
		"interval_sec":  strconv.Itoa(def.IntervalSec),
		"alert":         def.Alert,
	}
	if len(def.Headers) > 0 {
		meta["headers"] = monitorHeaderNames(def.Headers)
	}
	if def.Degraded != nil {
		meta["degraded"] = degradedRuleSummary(def.Degraded)
	}
	return meta
}

// checkDefinitionChanged names the fields an edit changed.
func checkDefinitionChanged(prior, next model.CheckDefinition) []string {
	var out []string
	note := func(field string, differs bool) {
		if differs {
			out = append(out, field)
		}
	}
	selectorEqual := func(a, b model.TargetSelector) bool {
		return a.All == b.All && slices.Equal(a.Nodes, b.Nodes) && slices.Equal(a.Groups, b.Groups) && slices.Equal(a.Exclude, b.Exclude)
	}
	note("name", prior.Name != next.Name)
	note("type", prior.Type != next.Type)
	note("sources", !selectorEqual(prior.Sources, next.Sources))
	note("targets", !selectorEqual(prior.Targets, next.Targets))
	note("addresses", !slices.Equal(prior.Addresses, next.Addresses))
	note("interval_sec", prior.IntervalSec != next.IntervalSec)
	note("timeout_sec", prior.TimeoutSec != next.TimeoutSec)
	note("packets", prior.Packets != next.Packets)
	note("threshold_days", prior.ThresholdDays != next.ThresholdDays)
	note("expect_status", prior.ExpectStatus != next.ExpectStatus)
	note("headers", !monitorHeadersEqual(prior.Headers, next.Headers))
	note("alert", prior.Alert != next.Alert)
	note("alert_after", prior.AlertAfter != next.AlertAfter)
	note("degraded", !degradedRulesEqual(prior.Degraded, next.Degraded))
	note("enabled", prior.Enabled != next.Enabled)
	return out
}
