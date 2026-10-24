package server

import (
	"errors"
	"fmt"
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
// source, from the latest records the hot store keeps per pair. A failed
// read is logged and counts nothing, so a confirmation never stalls on it.
func (s *Server) checkMonitorRuns() map[string]int {
	latest, err := s.store.LatestMonitorResults()
	if err != nil {
		s.logger.Printf("check definitions: run counts unread: %v", err)
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

// checkMonitorReadable is whether p may read everything a definition's
// monitor names: the check as an operator's check is read, and every source
// it holds. A monitor of a target that left the set keeps the sources and
// the address it had, which can name nodes the definition no longer does.
func checkMonitorReadable(p principal, mon model.Monitor) bool {
	if !monitorVisibleToPrincipal(p, "monitor:read", mon) {
		return false
	}
	for _, nodeID := range mon.NodeIDs {
		if !latencyNodeVisible(p, nodeID) {
			return false
		}
	}
	return true
}

// narrowDefinitionMonitorViews narrows, for a principal with a node
// allowlist, the monitors a check definition expanded into: a definition's
// monitor runs from many sources, and one the principal may read through any
// of them must not list the others, nor name a definition the principal may
// not read.
func (s *Server) narrowDefinitionMonitorViews(p principal, monitors []model.Monitor, views []monitorView) {
	if !principalHasNodeRestriction(p) {
		return
	}
	visibleDefs := map[string]bool{}
	readable := func(list []string) []string {
		var out []string
		for _, nodeID := range list {
			if latencyNodeVisible(p, nodeID) {
				out = append(out, nodeID)
			}
		}
		return out
	}
	for i, mon := range monitors {
		definitionID, ok := store.MonitorDefinitionID(mon)
		if !ok {
			continue
		}
		views[i].NodeIDs = readable(mon.NodeIDs)
		views[i].PausedNodeIDs = readable(mon.PausedNodeIDs)
		seen, known := visibleDefs[definitionID]
		if !known {
			def, exists := s.store.CheckDefinition(definitionID)
			seen = exists && checkDefinitionVisible(p, def)
			visibleDefs[definitionID] = seen
		}
		if !seen {
			views[i].CheckDefinitionID = ""
		}
	}
}

// checkDefinitionView is def as p reads it: secret values removed, counted
// against what is stored now, with its monitors when asked, less any
// monitor that names a node p may not read.
func (s *Server) checkDefinitionView(p principal, def model.CheckDefinition, plan checkDefinitionPlan, monitors []model.Monitor, runs map[string]int, withMonitors bool) model.CheckDefinitionView {
	view := model.CheckDefinitionView{CheckDefinition: def}
	view.Headers = redactMonitorHeaders(def.Headers)
	// measuring are the monitors that measure now; a monitor of a target
	// still in the set that is not one of them holds an auto definition's
	// earlier method, which is the pair's history, not a paused target.
	measuring := map[string]bool{}
	for _, e := range plan.entries {
		measuring[e.monitorID] = true
	}
	inSet := plan.targetKeys()
	owner := store.CheckDefinitionOwner(def.ID)
	restricted := principalHasNodeRestriction(p)
	for _, mon := range monitors {
		if store.MonitorOwnerKey(mon) != owner || (restricted && !checkMonitorReadable(p, mon)) {
			continue
		}
		view.Summary.Monitors++
		switch {
		case measuring[mon.ID] && mon.Type == model.MonitorTypeTLS:
			view.Summary.Paths++
		case measuring[mon.ID]:
			view.Summary.Paths += len(mon.NodeIDs)
		case !inSet[checkMonitorKey(mon)]:
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
				InSet: inSet[checkMonitorKey(mon)], Enabled: mon.Enabled, Sources: sources, Runs: runs[mon.ID],
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
					writeJSON(w, http.StatusOK, s.checkDefinitionView(p, plan.def, plan, monitors, runs, true))
					return
				}
			}
			writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
			return
		}
		list := model.CheckDefinitionList{Definitions: []model.CheckDefinitionView{}, FleetMesh: s.checkFleetMesh(p, now)}
		for _, plan := range plans {
			if checkDefinitionVisible(p, plan.def) {
				list.Definitions = append(list.Definitions, s.checkDefinitionView(p, plan.def, plan, monitors, runs, false))
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

// managedDefinition loads the definition id names for an edit, a dry run,
// a delete or a forget: 404 when it does not exist or p may not read it,
// 403 when p may read it but not manage it. false means the answer is
// written.
func (s *Server) managedDefinition(w http.ResponseWriter, p principal, id string) (model.CheckDefinition, bool) {
	def, ok := s.store.CheckDefinition(strings.TrimSpace(id))
	if !ok || !checkDefinitionVisible(p, def) {
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
		return model.CheckDefinition{}, false
	}
	if !checkDefinitionManageable(p, def) {
		writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden"))
		return model.CheckDefinition{}, false
	}
	return def, true
}

// checkPlanBounds refuses a plan past the bounds a save may leave: more
// paths than CheckDefinitionPairsMax, or more paused targets than
// CheckDefinitionPausedMax (a token that churns addresses would otherwise
// grow the state without limit; the operator forgets paused targets first).
func checkPlanBounds(plan checkDefinitionPlan) error {
	if n := checkPairCount(plan); n > model.CheckDefinitionPairsMax {
		return fmt.Errorf("the check would measure %d paths, at most %d: narrow its sources or targets", n, model.CheckDefinitionPairsMax)
	}
	inSet := plan.targetKeys()
	paused := 0
	for _, mon := range plan.desired {
		if !inSet[checkMonitorKey(mon)] {
			paused++
		}
	}
	if paused > model.CheckDefinitionPausedMax {
		return fmt.Errorf("the check would keep %d paused targets, at most %d: forget some of them first", paused, model.CheckDefinitionPausedMax)
	}
	return nil
}

// checkPairCount is how many paths a plan measures: each entry's sources
// (the definition's sources less a node probing itself and the excluded
// pairs, split by method for auto), and one per tls target.
func checkPairCount(plan checkDefinitionPlan) int {
	n := 0
	for _, e := range plan.entries {
		if plan.def.Type == model.MonitorTypeTLS {
			n++
			continue
		}
		n += len(e.sources)
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
		stored, ok := s.managedDefinition(w, p, req.ID)
		if !ok {
			return
		}
		prior = &stored
	} else if s.store.CheckDefinitionCount() >= model.CheckDefinitionsMax {
		writeError(w, http.StatusBadRequest, fmt.Errorf("the control plane keeps at most %d check definitions; delete one first", model.CheckDefinitionsMax))
		return
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
			if err := checkPlanBounds(plan); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
	}
	stored, changes, err := s.store.SaveCheckDefinition(def, expected, p.ActorID, c.sets(plans), now)
	switch {
	case errors.Is(err, store.ErrCheckDefinitionVersion):
		writeError(w, http.StatusConflict, versionConflict(err))
		return
	case err != nil && stored.ID == "":
		writeError(w, http.StatusInternalServerError, err)
		return
	case err != nil:
		// On disk, not yet durable: the save stands.
		s.logger.Printf("check definition %s saved; the state write is not durable yet: %v", stored.ID, err)
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
	writeJSON(w, http.StatusOK, s.checkDefinitionView(p, stored, plan, s.store.Monitors(), s.checkMonitorRuns(), true))
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
		stored, ok := s.managedDefinition(w, p, req.ID)
		if !ok {
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
	plans := c.planAll(s.store.CheckDefinitions(), &def)
	for _, plan := range plans {
		if plan.def.ID == def.ID {
			if err := checkPlanBounds(plan); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			preview, err := s.checkPreview(c, plans, plan)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, preview)
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
	def, ok := s.managedDefinition(w, p, req.ID)
	if !ok {
		return
	}
	runs := s.checkMonitorRuns()
	deleted, err := s.store.DeleteCheckDefinition(def.ID, req.Version, req.MonitorIDs)
	switch {
	case errors.Is(err, store.ErrCheckDefinitionNotFound):
		writeError(w, http.StatusNotFound, apiError(model.APIErrorNotFound, "check definition not found"))
		return
	case errors.Is(err, store.ErrCheckDefinitionVersion):
		writeError(w, http.StatusConflict, versionConflict(err))
		return
	case errors.Is(err, store.ErrCheckDefinitionMonitors):
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
	def, ok := s.managedDefinition(w, p, req.ID)
	if !ok {
		return
	}
	c := s.checkPlanContextAt(s.now())
	inSet := map[string]bool{}
	for _, plan := range c.planAll(s.store.CheckDefinitions(), nil) {
		if plan.def.ID == def.ID {
			inSet = plan.targetKeys()
		}
	}
	for _, monitorID := range req.MonitorIDs {
		if mon, ok := s.store.Monitor(monitorID); ok && inSet[checkMonitorKey(mon)] {
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
