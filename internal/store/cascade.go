package store

import "github.com/LatticeNet/lattice-sdk/model"

// NodeCascadeReport tallies what a node hard-delete removed (or, in plan mode,
// would remove) from the JSON store. It is a server-LOCAL plain report: the
// store cannot import internal/server (that would be an import cycle), so it
// returns this struct and the server layer maps it onto the wire DTO.
//
// SHARED resources (GeoRouting, Monitors, Groups) are stripped of the gone node
// rather than deleted, because deleting them would also affect other still-live
// nodes. Node-owned resources are deleted outright.
type NodeCascadeReport struct {
	NodeID          string `json:"node_id"`
	TasksStripped   int    `json:"tasks_stripped"` // nodeID removed from Targets, task kept
	TasksDeleted    int    `json:"tasks_deleted"`  // task deleted (sole target)
	TaskResults     int    `json:"task_results"`
	DDNSProfiles    int    `json:"ddns_profiles"`
	MachineProfiles int    `json:"machine_profiles"`
	NFTInputs       int    `json:"nft_inputs"`
	DNSDeployments  int    `json:"dns_deployments"`
	NetPolicies     int    `json:"net_policies"`
	// NetPeerRulesStripped / GroupPolicyRulesStripped count node-reference rules
	// removed from OTHER nodes' net policies and from group policies (SHARED:
	// strip the dangling Remote.NodeID rule, keep the owner's policy).
	NetPeerRulesStripped     int `json:"net_peer_rules_stripped"`
	GroupPolicyRulesStripped int `json:"group_policy_rules_stripped"`
	GeoRoutingStripped       int `json:"geo_routing_stripped"` // SHARED: stripped, kept
	GeoRoutingDeleted        int `json:"geo_routing_deleted"`  // became empty -> deleted
	AgentUpdatePolicies      int `json:"agent_update_policies"`
	ProxyNodeProfiles        int `json:"proxy_node_profiles"`
	ProxyUsageSnapshots      int `json:"proxy_usage_snapshots"`
	MonitorsStripped         int `json:"monitors_stripped"` // SHARED: stripped from Monitor.NodeIDs
	MonitorResults           int `json:"monitor_results"`
	LogSources               int `json:"log_sources"`
	Groups                   int `json:"groups"`    // Members/LeaderID edited
	Approvals                int `json:"approvals"` // NO existing primitive
	Tunnels                  int `json:"tunnels"`
	// RemovedLogSourceIDs lists the log-source IDs whose records this delete
	// removed from the JSON store. The SERVER must call logStore.PurgeSource on
	// each (the log lines live in a separate bbolt db the store cannot reach).
	RemovedLogSourceIDs []string `json:"-"`
}

// cloneGeoRouting deep-copies a geo-routing record's mutable node-id slices so a
// strip-edit never mutates the caller's (or the persisted state's) backing
// arrays. Mirrors cloneGroup's contract.
func cloneGeoRouting(gr model.GeoRouting) model.GeoRouting {
	gr.NodeIDs = append([]string(nil), gr.NodeIDs...)
	gr.DNSNodeIDs = append([]string(nil), gr.DNSNodeIDs...)
	return gr
}

// cloneMonitor deep-copies a monitor's NodeIDs assignment slice so a strip-edit
// never shares a backing array with persisted state.
func cloneMonitor(m model.Monitor) model.Monitor {
	m.NodeIDs = append([]string(nil), m.NodeIDs...)
	return m
}

// withoutString returns a new slice with every occurrence of value removed. A
// nil input yields nil so JSON omitempty round-trips unchanged.
func withoutString(values []string, value string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != value {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DeleteNode hard-deletes a node and cascades the removal across every
// node-owned and node-referencing resource in a SINGLE critical section, then
// performs exactly one whole-snapshot Save. The bool is false (and no Save runs)
// when the node does not exist, so the operation is idempotent. Audit rows are
// never touched: deletion would break the append-only hash-chained WAL, and the
// SERVER records one node.delete audit event afterwards.
//
// CRITICAL: every step is INLINE raw s.state mutation. The *ForNode / Delete* /
// Upsert* helpers each take s.mu themselves, and sync.Mutex is non-reentrant, so
// calling any of them here would self-deadlock.
func (s *Store) DeleteNode(nodeID string) (NodeCascadeReport, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	report, ok := s.buildNodeCascadeLocked(nodeID, true)
	if !ok {
		return report, false, nil
	}
	return report, true, s.Save()
}

// PlanDeleteNode computes the same cascade report DeleteNode would produce
// without mutating or persisting anything (a dry run). The bool is false when
// the node does not exist.
func (s *Store) PlanDeleteNode(nodeID string) (NodeCascadeReport, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buildNodeCascadeLocked(nodeID, false)
}

// buildNodeCascadeLocked is the shared engine for DeleteNode (mutate=true) and
// PlanDeleteNode (mutate=false). The caller MUST already hold s.mu. When
// mutate is false the function only counts; the counts are identical to what a
// real delete would apply, so the plan is an exact preview. It never calls
// Save (DeleteNode owns the single persist).
func (s *Store) buildNodeCascadeLocked(nodeID string, mutate bool) (NodeCascadeReport, bool) {
	report := NodeCascadeReport{NodeID: nodeID}
	if _, ok := s.state.Nodes[nodeID]; !ok {
		return report, false
	}

	// Step 1: Tasks (multi-target). Strip nodeID from Targets; delete the task
	// only when it was the sole target. Track deleted task IDs so step 2 prunes
	// their results consistently in both plan and delete modes.
	deletedTasks := map[string]bool{}
	for tid, t := range s.state.Tasks {
		if !contains(t.Targets, nodeID) {
			continue
		}
		remaining := withoutString(t.Targets, nodeID)
		if len(remaining) == 0 {
			report.TasksDeleted++
			deletedTasks[tid] = true
			if mutate {
				delete(s.state.Tasks, tid)
			}
		} else {
			report.TasksStripped++
			if mutate {
				t.Targets = remaining
				s.state.Tasks[tid] = t
			}
		}
	}

	// Step 2: TaskResult (per-node). Remove this node's results AND the results
	// of tasks deleted in step 1. taskGone is consistent across modes because it
	// consults deletedTasks (plan mode leaves the Tasks map intact).
	taskGone := func(taskID string) bool {
		if deletedTasks[taskID] {
			return true
		}
		_, ok := s.state.Tasks[taskID]
		return !ok
	}
	if mutate {
		kept := s.state.Results[:0]
		for _, r := range s.state.Results {
			if r.NodeID != nodeID && !taskGone(r.TaskID) {
				kept = append(kept, r)
			} else {
				report.TaskResults++
			}
		}
		s.state.Results = kept
	} else {
		for _, r := range s.state.Results {
			if r.NodeID == nodeID || taskGone(r.TaskID) {
				report.TaskResults++
			}
		}
	}

	// Step 3: DDNSProfile (node-owned, CFAPIToken secret dropped).
	for id, p := range s.state.DDNS {
		if p.NodeID == nodeID {
			report.DDNSProfiles++
			if mutate {
				delete(s.state.DDNS, id)
			}
		}
	}

	// Step 4: MachineProfile (at most one per node).
	for id, mp := range s.state.MachineProfiles {
		if mp.NodeID == nodeID {
			report.MachineProfiles++
			if mutate {
				delete(s.state.MachineProfiles, id)
			}
		}
	}

	// Step 5: NFTInputs (keyed by nodeID).
	if _, ok := s.state.NFTInputs[nodeID]; ok {
		report.NFTInputs = 1
		if mutate {
			delete(s.state.NFTInputs, nodeID)
		}
	}

	// Step 6: DNSDeployment (node-owned, CFAPIToken secret dropped).
	for id, d := range s.state.DNSDeployments {
		if d.NodeID == nodeID {
			report.DNSDeployments++
			if mutate {
				delete(s.state.DNSDeployments, id)
			}
		}
	}

	// Step 7: NetPolicy keyed by this node (its own per-node policy, whether
	// manually authored or group-derived, is removed wholesale).
	if _, ok := s.state.NetPolicies[nodeID]; ok {
		report.NetPolicies = 1
		if mutate {
			delete(s.state.NetPolicies, nodeID)
		}
	}

	// Step 7b: peer node-references inside OTHER resources' rules. A NetRule /
	// GroupNetRule Remote endpoint can point at the gone node (Remote.Kind ==
	// NetRefNode, Remote.NodeID == nodeID). Left behind these are orphaned config
	// AND break the surviving owner's nft compile ("remote node ... not found"),
	// so strip every such rule. The container policy is KEPT — it belongs to a
	// live node/group. Group-derived NetPolicies live in NetPolicies too, so this
	// also prunes materialized rules; stripping the authored GroupPolicy stops the
	// gone node from being re-materialized on the next ExpandGroupPolicies run.
	for key, np := range s.state.NetPolicies {
		if key == nodeID {
			continue // this node's own policy is removed wholesale in step 7
		}
		stripped := 0
		for _, rule := range np.Rules {
			if rule.Remote.Kind == model.NetRefNode && rule.Remote.NodeID == nodeID {
				stripped++
			}
		}
		if stripped == 0 {
			continue
		}
		report.NetPeerRulesStripped += stripped
		if mutate {
			kept := make([]model.NetRule, 0, len(np.Rules)-stripped)
			for _, rule := range np.Rules {
				if rule.Remote.Kind == model.NetRefNode && rule.Remote.NodeID == nodeID {
					continue
				}
				kept = append(kept, rule)
			}
			np.Rules = kept
			s.state.NetPolicies[key] = np
		}
	}
	for key, gp := range s.state.GroupPolicies {
		stripped := 0
		for _, rule := range gp.Rules {
			if rule.Remote.Kind == model.NetRefNode && rule.Remote.NodeID == nodeID {
				stripped++
			}
		}
		if stripped == 0 {
			continue
		}
		report.GroupPolicyRulesStripped += stripped
		if mutate {
			kept := make([]model.GroupNetRule, 0, len(gp.Rules)-stripped)
			for _, rule := range gp.Rules {
				if rule.Remote.Kind == model.NetRefNode && rule.Remote.NodeID == nodeID {
					continue
				}
				kept = append(kept, rule)
			}
			gp.Rules = kept
			s.state.GroupPolicies[key] = gp
		}
	}

	// Step 8: GeoRouting (SHARED - strip, never DeleteGeoRouting).
	for id, gr := range s.state.GeoRouting {
		if !contains(gr.NodeIDs, nodeID) && !contains(gr.DNSNodeIDs, nodeID) {
			continue
		}
		clone := cloneGeoRouting(gr)
		clone.NodeIDs = withoutString(clone.NodeIDs, nodeID)
		clone.DNSNodeIDs = withoutString(clone.DNSNodeIDs, nodeID)
		if len(clone.NodeIDs) == 0 && len(clone.DNSNodeIDs) == 0 {
			report.GeoRoutingDeleted++
			if mutate {
				delete(s.state.GeoRouting, id)
			}
		} else {
			report.GeoRoutingStripped++
			if mutate {
				s.state.GeoRouting[id] = clone
			}
		}
	}

	// Step 9: AgentUpdatePolicy (keyed by nodeID).
	if _, ok := s.state.AgentUpdates[nodeID]; ok {
		report.AgentUpdatePolicies = 1
		if mutate {
			delete(s.state.AgentUpdates, nodeID)
		}
	}

	// Step 10: ProxyNodeProfile (keyed by nodeID; central ProxyUser/ProxyInbound
	// left intact).
	if _, ok := s.state.ProxyProfiles[nodeID]; ok {
		report.ProxyNodeProfiles = 1
		if mutate {
			delete(s.state.ProxyProfiles, nodeID)
		}
	}

	// Step 11: ProxyUsageSnapshot (keyed by nodeID; global usage accounting
	// unaffected).
	if _, ok := s.state.ProxyUsage[nodeID]; ok {
		report.ProxyUsageSnapshots = 1
		if mutate {
			delete(s.state.ProxyUsage, nodeID)
		}
	}

	// Step 12: Monitor ASSIGNMENT (SHARED - strip; AssignAll monitors unchanged)
	// + MonitorResult (per-node).
	for id, m := range s.state.Monitors {
		if m.AssignAll || !contains(m.NodeIDs, nodeID) {
			continue
		}
		report.MonitorsStripped++
		if mutate {
			clone := cloneMonitor(m)
			clone.NodeIDs = withoutString(clone.NodeIDs, nodeID)
			s.state.Monitors[id] = clone
		}
	}
	for mid, series := range s.state.MonResults {
		removed := 0
		for _, mr := range series {
			if mr.NodeID == nodeID {
				removed++
			}
		}
		if removed == 0 {
			continue
		}
		report.MonitorResults += removed
		if mutate {
			kept := series[:0]
			for _, mr := range series {
				if mr.NodeID != nodeID {
					kept = append(kept, mr)
				}
			}
			s.state.MonResults[mid] = kept
			delete(s.monitorPersistedAt, monitorResultPersistenceKey(mid, nodeID))
		}
	}

	// Step 13: LogSource (node-owned). The store removes the record; the SERVER
	// must logStore.PurgeSource each collected ID (separate bbolt db).
	for id, ls := range s.state.LogSources {
		if ls.NodeID == nodeID {
			report.LogSources++
			report.RemovedLogSourceIDs = append(report.RemovedLogSourceIDs, id)
			if mutate {
				delete(s.state.LogSources, id)
			}
		}
	}

	// Step 14: Group MEMBERSHIP + LeaderID (edit, never DeleteGroup).
	for id, g := range s.state.Groups {
		if !contains(g.Members, nodeID) && g.LeaderID != nodeID {
			continue
		}
		report.Groups++
		if mutate {
			clone := cloneGroup(g)
			clone.Members = withoutString(clone.Members, nodeID)
			if clone.LeaderID == nodeID {
				clone.LeaderID = ""
			}
			s.state.Groups[id] = clone
		}
	}

	// Step 15: Approval (no DeleteApproval primitive exists).
	for id, a := range s.state.Approvals {
		if a.NodeID == nodeID {
			report.Approvals++
			if mutate {
				delete(s.state.Approvals, id)
			}
		}
	}

	// Step 16: TunnelProfile (node-scoped; no node-indexed query helper).
	for id, t := range s.state.Tunnels {
		if t.NodeID == nodeID {
			report.Tunnels++
			if mutate {
				delete(s.state.Tunnels, id)
			}
		}
	}

	// Step 17: the node itself (embedded TokenHash/Metrics/HostFacts/Geo/etc all
	// purged with the record).
	if mutate {
		delete(s.state.Nodes, nodeID)
		delete(s.metricsPersistedAt, nodeID)
	}

	return report, true
}
