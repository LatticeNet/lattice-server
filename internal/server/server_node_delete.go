package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// nodeDeleteSummary is the wire DTO for the node hard-delete plan/delete
// endpoints. It mirrors store.NodeCascadeReport and adds the server-layer
// cleanup counts (terminal sessions, proxy-drift cache, cross-store log purge).
// Mutated distinguishes a dry-run plan (false) from an applied delete (true).
type nodeDeleteSummary struct {
	NodeID                   string `json:"node_id"`
	NodeName                 string `json:"node_name"`
	Found                    bool   `json:"found"`
	Mutated                  bool   `json:"mutated"` // false=plan, true=delete
	TasksStripped            int    `json:"tasks_stripped"`
	TasksDeleted             int    `json:"tasks_deleted"`
	TaskResults              int    `json:"task_results"`
	DDNSProfiles             int    `json:"ddns_profiles"`
	MachineProfiles          int    `json:"machine_profiles"`
	NFTInputs                int    `json:"nft_inputs"`
	DNSDeployments           int    `json:"dns_deployments"`
	NetPolicies              int    `json:"net_policies"`
	NetPeerRulesStripped     int    `json:"net_peer_rules_stripped"`
	GroupPolicyRulesStripped int    `json:"group_policy_rules_stripped"`
	GeoRoutingStripped       int    `json:"geo_routing_stripped"`
	GeoRoutingDeleted        int    `json:"geo_routing_deleted"`
	AgentUpdatePolicies      int    `json:"agent_update_policies"`
	ProxyNodeProfiles        int    `json:"proxy_node_profiles"`
	ProxyUsageSnapshots      int    `json:"proxy_usage_snapshots"`
	MonitorsStripped         int    `json:"monitors_stripped"`
	MonitorResults           int    `json:"monitor_results"`
	LogSources               int    `json:"log_sources"`
	Groups                   int    `json:"groups"`
	Approvals                int    `json:"approvals"`
	Tunnels                  int    `json:"tunnels"`
	TerminalSessions         int    `json:"terminal_sessions"`    // closed (delete) / active (plan)
	ProxyDriftCleared        int    `json:"proxy_drift_cleared"`  // 0/1
	LogStorePurged           int    `json:"log_store_purged"`     // delete only
	LogStorePurgeErrs        int    `json:"log_store_purge_errs"` // surfaced, not swallowed
}

func newNodeDeleteSummary(nodeID, name string, mutated bool, r store.NodeCascadeReport) nodeDeleteSummary {
	return nodeDeleteSummary{
		NodeID: nodeID, NodeName: name, Found: true, Mutated: mutated,
		TasksStripped: r.TasksStripped, TasksDeleted: r.TasksDeleted, TaskResults: r.TaskResults,
		DDNSProfiles: r.DDNSProfiles, MachineProfiles: r.MachineProfiles, NFTInputs: r.NFTInputs,
		DNSDeployments: r.DNSDeployments, NetPolicies: r.NetPolicies,
		NetPeerRulesStripped: r.NetPeerRulesStripped, GroupPolicyRulesStripped: r.GroupPolicyRulesStripped,
		GeoRoutingStripped: r.GeoRoutingStripped, GeoRoutingDeleted: r.GeoRoutingDeleted,
		AgentUpdatePolicies: r.AgentUpdatePolicies, ProxyNodeProfiles: r.ProxyNodeProfiles,
		ProxyUsageSnapshots: r.ProxyUsageSnapshots, MonitorsStripped: r.MonitorsStripped,
		MonitorResults: r.MonitorResults, LogSources: r.LogSources, Groups: r.Groups,
		Approvals: r.Approvals, Tunnels: r.Tunnels,
	}
}

type nodeDeleteRequest struct {
	NodeID string `json:"node_id"`
}

// handleDeleteNodePlan returns a non-mutating dry run of the cascade a delete
// would perform. It records NO success audit (consistent with the other /plan
// endpoints); only an authz deny is audited.
func (s *Server) handleDeleteNodePlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req nodeDeleteRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	// node_id rides in the POST body, so withAuth's ?node_id allowlist check is
	// best-effort; re-gate here on the real id. requireNodeScope denies+audits a
	// restricted token whose allowlist excludes this node.
	if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
		return
	}
	node, found := s.store.Node(req.NodeID)
	if !found {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	report, ok := s.store.PlanDeleteNode(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	summary := newNodeDeleteSummary(req.NodeID, node.Name, false, report)
	// Plan-side server cleanups are counted, not applied.
	summary.TerminalSessions = s.terminalBroker.activeSessionsForNode(req.NodeID)
	s.proxyDriftMu.RLock()
	if _, present := s.proxyDrift[req.NodeID]; present {
		summary.ProxyDriftCleared = 1
	}
	s.proxyDriftMu.RUnlock()
	writeJSON(w, http.StatusOK, summary)
}

// handleDeleteNode hard-deletes a node and cascades the removal across the
// store, then performs the server-layer cleanups (cross-store log purge,
// in-memory terminal sessions, proxy-drift cache) and records exactly one
// node.delete audit event with the final removed-counts as metadata.
func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req nodeDeleteRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
		return
	}
	// Capture the name before deletion; after DeleteNode the record is gone.
	node, found := s.store.Node(req.NodeID)
	if !found {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	name := node.Name

	report, ok, err := s.store.DeleteNode(req.NodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	summary := newNodeDeleteSummary(req.NodeID, name, true, report)

	now := s.now()

	// Step 19: purge the per-source log lines from the separate logstore bbolt.
	// The node is already gone, so a purge failure must NOT fail the request; it
	// is surfaced via log_store_purge_errs and logged.
	if s.logStore != nil {
		for _, sid := range report.RemovedLogSourceIDs {
			if err := s.logStore.PurgeSource(sid); err != nil {
				summary.LogStorePurgeErrs++
				if s.logger != nil {
					s.logger.Printf("node.delete: purge log source %q for node %q: %v", sid, req.NodeID, err)
				}
			} else {
				summary.LogStorePurged++
			}
		}
	} else if len(report.RemovedLogSourceIDs) > 0 {
		// No logstore wired but records existed; surface so the gap is legible.
		summary.LogStorePurgeErrs += len(report.RemovedLogSourceIDs)
	}

	// Step 20: close any active in-memory terminal sessions for the node.
	summary.TerminalSessions = s.terminalBroker.closeForNode(req.NodeID, now)

	// Step 21: drop the in-memory proxy-drift cache entry to avoid a stale row.
	s.proxyDriftMu.Lock()
	if _, present := s.proxyDrift[req.NodeID]; present {
		delete(s.proxyDrift, req.NodeID)
		summary.ProxyDriftCleared = 1
	}
	s.proxyDriftMu.Unlock()

	// Exactly one node.delete audit event, AFTER all cleanups so counts are
	// final. Audit rows are append-only and never deleted.
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: req.NodeID,
		Action: "node.delete",
		Scope:  "node:admin",
		Metadata: map[string]string{
			"node_name":           name,
			"tasks_stripped":      strconv.Itoa(summary.TasksStripped),
			"tasks_deleted":       strconv.Itoa(summary.TasksDeleted),
			"task_results":        strconv.Itoa(summary.TaskResults),
			"ddns":                strconv.Itoa(summary.DDNSProfiles),
			"machine_profiles":    strconv.Itoa(summary.MachineProfiles),
			"nft":                 strconv.Itoa(summary.NFTInputs),
			"dns_deployments":     strconv.Itoa(summary.DNSDeployments),
			"net_policies":        strconv.Itoa(summary.NetPolicies),
			"net_peer_rules":      strconv.Itoa(summary.NetPeerRulesStripped),
			"group_policy_rules":  strconv.Itoa(summary.GroupPolicyRulesStripped),
			"geo_stripped":        strconv.Itoa(summary.GeoRoutingStripped),
			"geo_deleted":         strconv.Itoa(summary.GeoRoutingDeleted),
			"agent_updates":       strconv.Itoa(summary.AgentUpdatePolicies),
			"proxy_profiles":      strconv.Itoa(summary.ProxyNodeProfiles),
			"proxy_usage":         strconv.Itoa(summary.ProxyUsageSnapshots),
			"monitors_stripped":   strconv.Itoa(summary.MonitorsStripped),
			"monitor_results":     strconv.Itoa(summary.MonitorResults),
			"log_sources":         strconv.Itoa(summary.LogSources),
			"groups":              strconv.Itoa(summary.Groups),
			"approvals":           strconv.Itoa(summary.Approvals),
			"tunnels":             strconv.Itoa(summary.Tunnels),
			"terminal_sessions":   strconv.Itoa(summary.TerminalSessions),
			"proxy_drift_cleared": strconv.Itoa(summary.ProxyDriftCleared),
			"log_purge_errors":    strconv.Itoa(summary.LogStorePurgeErrs),
		},
	})

	writeJSON(w, http.StatusOK, summary)
}
