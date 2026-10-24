package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/netguard"
	"github.com/LatticeNet/lattice-server/internal/network"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// node.beacon plans (design 29 D3, D12). Enabling, disabling or changing a
// beacon opens or closes a port, so it is a reviewed plan whose approval
// hashes the document the operator was shown: the settings, the source set,
// the limits and, when NetGuard manages the node, the whole ruleset the
// companion rule set produces. The document is rendered again from live
// state when the approval is decided, and refused as stale when the bytes
// differ.

var errBeaconNotEnabled = errors.New("the node has no enabled beacon")

func isBeaconApproval(approval model.Approval) bool {
	return approval.Plugin == model.BeaconApprovalPlugin && approval.Action == model.BeaconPlanKind
}

// beaconPlanError carries the status a plan refusal answers with.
type beaconPlanError struct {
	status   int
	err      error
	findings []model.BeaconFinding
}

func (e *beaconPlanError) Error() string { return e.err.Error() }

func beaconBadRequest(format string, args ...any) error {
	return &beaconPlanError{status: http.StatusBadRequest, err: fmt.Errorf(format, args...)}
}

// beaconDefaultBind is where a node's beacon binds unless the operator
// says otherwise: its primary interface address (its private address on a
// NAT node, where the public one is not on the host), else its public IPv4.
func beaconDefaultBind(n model.Node) string {
	for _, raw := range []string{n.InternalIP, n.PublicIP} {
		if addr, err := beacon.ParseIPv4(strings.TrimSpace(raw)); err == nil {
			return addr.String()
		}
	}
	return ""
}

// beaconSettingsFor turns a request into the settings it asks for, against
// the node's stored beacon.
func (s *Server) beaconSettingsFor(req model.BeaconPlanRequest, node model.Node, t store.BeaconTarget, exists bool) (model.BeaconSettings, error) {
	current := t.Settings
	switch req.Action {
	case model.BeaconActionDisable:
		if !exists || !current.Enabled {
			return model.BeaconSettings{}, &beaconPlanError{status: http.StatusConflict, err: errBeaconNotEnabled}
		}
		if req.Port != 0 || req.Bind != "" || req.Endpoint != "" {
			return model.BeaconSettings{}, beaconBadRequest("a disable takes no port, bind or endpoint")
		}
		out := current
		out.Enabled = false
		return out, nil
	case model.BeaconActionEnable, model.BeaconActionChange:
	default:
		return model.BeaconSettings{}, beaconBadRequest("action must be %q, %q or %q", model.BeaconActionEnable, model.BeaconActionDisable, model.BeaconActionChange)
	}
	if req.Action == model.BeaconActionChange && (!exists || !current.Enabled) {
		return model.BeaconSettings{}, &beaconPlanError{status: http.StatusConflict, err: errors.New("the node has no enabled beacon to change; enable it first")}
	}
	if req.Action == model.BeaconActionEnable && exists && current.Enabled {
		return model.BeaconSettings{}, &beaconPlanError{status: http.StatusConflict, err: errors.New("the node's beacon is already enabled; plan a change instead")}
	}
	out := model.BeaconSettings{Enabled: true, Limits: model.DefaultBeaconLimits()}
	if req.Action == model.BeaconActionChange {
		out.Port, out.Bind, out.Endpoint = current.Port, current.Bind, current.Endpoint
	}
	portChanged := false
	switch {
	case req.Port != 0:
		if !beacon.ValidListenPort(req.Port) {
			return model.BeaconSettings{}, beaconBadRequest("port must be %d to 65535", beacon.PortOverrideMin)
		}
		portChanged = req.Port != out.Port
		out.Port = req.Port
	case out.Port == 0:
		port, err := s.beaconSuggestedPort(node.ID)
		if err != nil {
			return model.BeaconSettings{}, err
		}
		out.Port = port
		portChanged = true
	}
	switch bind := strings.TrimSpace(req.Bind); {
	case bind != "":
		addr, err := beacon.ParseIPv4(bind)
		if err != nil {
			return model.BeaconSettings{}, beaconBadRequest("bind: %v", err)
		}
		out.Bind = addr.String()
	case out.Bind == "":
		out.Bind = beaconDefaultBind(node)
		if out.Bind == "" {
			return model.BeaconSettings{}, beaconBadRequest("the node reports no IPv4 address to bind; name one with bind")
		}
	}
	switch endpoint := strings.TrimSpace(req.Endpoint); {
	case endpoint != "":
		ap, err := beacon.ParseEndpoint(endpoint)
		if err != nil {
			return model.BeaconSettings{}, beaconBadRequest("endpoint: %v", err)
		}
		out.Endpoint = ap.String()
	case out.Endpoint == "" || (portChanged && out.Endpoint == net.JoinHostPort(strings.TrimSpace(node.PublicIP), strconv.Itoa(current.Port))):
		ip, ok := latencyPublicIPv4(node.PublicIP)
		if !ok {
			return model.BeaconSettings{}, beaconBadRequest("the node has no public IPv4 to advertise; name the endpoint (address:port)")
		}
		ap, err := beacon.ParseEndpoint(net.JoinHostPort(ip, strconv.Itoa(out.Port)))
		if err != nil {
			return model.BeaconSettings{}, beaconBadRequest("endpoint: %v", err)
		}
		out.Endpoint = ap.String()
	}
	return out, nil
}

// buildBeaconPlan renders the plan document for settings from live state.
// It reads and never writes, so the decision can render it again and
// compare bytes. compile builds the node's NetGuard compile input.
func (s *Server) buildBeaconPlan(node model.Node, action string, settings model.BeaconSettings, t store.BeaconTarget, now time.Time, compile func(nodeID string) (netguard.CompileInput, error)) (model.BeaconPlan, string, error) {
	plan := model.BeaconPlan{
		Kind:        model.BeaconPlanKind,
		NodeID:      node.ID,
		NodeName:    node.Name,
		Action:      action,
		Beacon:      settings,
		Sources:     []model.BeaconPlanSource{},
		Exposure:    model.BeaconExposureInternet,
		BaseVersion: t.Version,
	}
	if t.Version > 0 || t.Settings.Enabled {
		prev := t.Settings
		plan.Previous = &prev
	}
	if settings.Enabled {
		// The endpoint must be one of the node's own addresses (its public
		// or primary interface address, or a provider edge its lines name),
		// so no plan can point the sources at a third party. Judged at every
		// render, so a node that moved before the decision is refused.
		if !beaconEndpointCurrent(node, settings.Endpoint, s.pathPlanned(now).endpoints) {
			return plan, "", &beaconPlanError{status: http.StatusBadRequest, err: fmt.Errorf(
				"endpoint %s is not one of the node's addresses (its public IPv4, its primary interface address or a provider edge its lines declare)", settings.Endpoint)}
		}
		if _, err := beacon.ParseIPv4(settings.Bind); err != nil {
			return plan, "", &beaconPlanError{status: http.StatusBadRequest, err: fmt.Errorf("bind: %w", err)}
		}
	}
	binding, hasBinding := s.store.NodeGuardBinding(node.ID)
	managed := hasBinding && binding.Managed
	if managed {
		plan.Exposure = model.BeaconExposureNetGuard
	}
	if settings.Enabled {
		nodes := map[string]model.Node{}
		for _, n := range s.store.Nodes() {
			nodes[n.ID] = n
		}
		current := s.beaconCurrentSources(node.ID, s.beaconPlanned(now, nodes), s.store.Monitors(), nodes)
		ids := s.store.BeaconSourceIDs()
		sourceIDs := make([]string, 0, len(current))
		for sourceID := range current {
			sourceIDs = append(sourceIDs, sourceID)
		}
		sort.Strings(sourceIDs)
		for _, sourceID := range sourceIDs {
			src := model.BeaconPlanSource{NodeID: sourceID, Name: nodes[sourceID].Name, SourceID: ids[sourceID]}
			if src.SourceID == 0 {
				return plan, "", fmt.Errorf("source %s has no beacon source id", sourceID)
			}
			if managed {
				src.Allow = s.beaconSourceAllow(nodes[sourceID])
			}
			plan.Sources = append(plan.Sources, src)
		}
	}
	if managed {
		input, err := compile(node.ID)
		if err != nil {
			return plan, "", err
		}
		allow := []string{}
		for _, src := range plan.Sources {
			allow = append(allow, src.Allow...)
		}
		slices.Sort(allow)
		allow = slices.Compact(allow)
		input.Beacon = nil
		if settings.Enabled {
			input.Beacon = &netguard.BeaconCompanion{Bind: settings.Bind, Port: settings.Port, Allow: allow}
		}
		compiled, err := netguard.Compile(input)
		if err != nil {
			return plan, "", err
		}
		ruleset, err := network.GenerateNFTPlan(compiled)
		if err != nil {
			return plan, "", err
		}
		sum := sha256.Sum256([]byte(ruleset))
		plan.NetGuard = &model.BeaconNetGuardPlan{
			Port:           settings.Port,
			Allow:          allow,
			Notrack:        settings.Enabled,
			BindingVersion: binding.Version,
			RulesetSHA256:  hex.EncodeToString(sum[:]),
			Ruleset:        ruleset,
		}
		if !settings.Enabled {
			plan.NetGuard.Allow = []string{}
		}
	}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return plan, "", err
	}
	return plan, string(raw), nil
}

// beaconSourceAllow is the /32s a source's datagrams may come from: its
// pinned public and WireGuard IPv4 addresses, and the egress address it was
// seen connecting from when that differs from both.
func (s *Server) beaconSourceAllow(n model.Node) []string {
	var out []string
	for _, raw := range []string{n.PublicIP, n.WireGuardIP, s.store.BeaconEgress(n.ID)} {
		addr, err := beacon.ParseIPv4(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		out = append(out, addr.String()+"/32")
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// beaconLint judges a plan's settings against what the node is known to
// listen on. Port conflicts block; the rest warn.
func (s *Server) beaconLint(node model.Node, plan model.BeaconPlan, now time.Time) []model.BeaconFinding {
	findings := []model.BeaconFinding{}
	if !plan.Beacon.Enabled {
		return findings
	}
	port := plan.Beacon.Port
	block := func(code, msg string) {
		findings = append(findings, model.BeaconFinding{Code: code, Severity: model.BeaconFindingBlock, Message: msg})
	}
	warn := func(code, msg string) {
		findings = append(findings, model.BeaconFinding{Code: code, Severity: model.BeaconFindingWarn, Message: msg})
	}
	for _, inv := range s.liveSingBoxInventories(now) {
		if inv.NodeID != node.ID {
			continue
		}
		for _, line := range inv.Nodes {
			if p, err := strconv.Atoi(strings.TrimSpace(line.Port)); err == nil && p == port {
				block(model.BeaconLintPortSingBox, fmt.Sprintf("sing-box inbound %q listens on port %d", line.Name, port))
			}
		}
	}
	if reality := s.guardRealityForLint(node.ID); reality != nil && reality.SSHD != nil && slices.Contains(reality.SSHD.Ports, port) {
		block(model.BeaconLintPortSSH, fmt.Sprintf("sshd listens on port %d", port))
	}
	if port == 22 {
		block(model.BeaconLintPortSSH, "port 22 is SSH")
	}
	knock := s.sshGuardKnockStateIn(node.ID, s.store.Approvals())
	if knock.SSHPort == port {
		block(model.BeaconLintPortSSH, fmt.Sprintf("SSH Guard moved sshd to port %d", port))
	}
	if slices.Contains(knock.Sequence.Ports, port) || slices.Contains(knock.Sequence.PreviousPorts, port) || slices.Contains(knock.GatedPorts, port) {
		block(model.BeaconLintPortKnock, fmt.Sprintf("port %d is in the node's knock sequence or behind its knock", port))
	}
	if node.WireGuardPort == port {
		block(model.BeaconLintPortWireGuard, fmt.Sprintf("WireGuard listens on port %d", port))
	}
	if wg := strings.TrimSpace(node.WireGuardIP); wg != "" {
		if host := strings.SplitN(wg, "/", 2)[0]; host == plan.Beacon.Bind {
			block(model.BeaconLintBindWireGuard, "the bind address is the node's WireGuard address; the beacon must not listen inside the overlay")
		}
	}
	if plan.Beacon.Bind != strings.TrimSpace(node.InternalIP) && plan.Beacon.Bind != strings.TrimSpace(node.PublicIP) {
		warn(model.BeaconLintBindNotLocal, "the bind address is neither the node's primary interface address nor its public IPv4; the agent reports a bind failure if it is not on the host")
	}
	if plan.Beacon.Endpoint != net.JoinHostPort(strings.TrimSpace(node.PublicIP), strconv.Itoa(port)) {
		warn(model.BeaconLintEndpointMapped, "the endpoint differs from the node's public IPv4 and listen port; sources will send to the mapping named here")
	}
	if len(plan.Sources) == 0 {
		warn(model.BeaconLintNoSources, "no source uses this node's beacon yet; sources added later need a change plan")
	}
	if plan.Exposure == model.BeaconExposureInternet {
		warn(model.BeaconLintOpenToInternet, "NetGuard does not manage this node: the port is open to the internet and protected only by the beacon's authentication")
	}
	return findings
}

func beaconFindingsBlock(findings []model.BeaconFinding) bool {
	for _, f := range findings {
		if f.Severity == model.BeaconFindingBlock {
			return true
		}
	}
	return false
}

// requireBeaconScopes is the gate on authoring and deciding: monitor:admin
// and node:admin on the node, and netguard:admin as well when the plan
// carries a NetGuard companion.
func beaconScopesAllow(p principal, nodeID string, companion bool) bool {
	if !rbac.Allows(p.Principal, "monitor:admin", nodeID) || !rbac.Allows(p.Principal, "node:admin", nodeID) {
		return false
	}
	return !companion || rbac.Allows(p.Principal, "netguard:admin", nodeID)
}

// handleBeaconPlan answers POST /api/nodes/beacon/plan.
func (s *Server) handleBeaconPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req model.BeaconPlanRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	for _, scope := range []string{"monitor:admin", "node:admin", "network:plan"} {
		if !s.requireNodeScope(w, p, scope, req.NodeID) {
			return
		}
	}
	node, ok := s.store.Node(req.NodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	if binding, ok := s.store.NodeGuardBinding(req.NodeID); ok && binding.Managed && !s.requireNodeScope(w, p, "netguard:admin", req.NodeID) {
		return
	}
	now := s.now()
	s.monitorSaves.Lock()
	defer s.monitorSaves.Unlock()
	t, exists := s.store.BeaconTarget(req.NodeID)
	settings, err := s.beaconSettingsFor(req, node, t, exists)
	if err != nil {
		writeBeaconPlanError(w, err)
		return
	}
	if t, exists = s.store.BeaconTarget(req.NodeID); !exists {
		t = store.BeaconTarget{NodeID: req.NodeID}
	}
	// Every current source needs its id before the document names it.
	if settings.Enabled {
		nodes := map[string]model.Node{}
		for _, n := range s.store.Nodes() {
			nodes[n.ID] = n
		}
		current := s.beaconCurrentSources(req.NodeID, s.beaconPlanned(now, nodes), s.store.Monitors(), nodes)
		sourceIDs := make([]string, 0, len(current))
		for sourceID := range current {
			// The plan names each source and its addresses.
			if !latencyNodeVisible(p, sourceID) {
				writeError(w, http.StatusForbidden, apiError(model.APIErrorCapabilityDenied, "forbidden: a source of this beacon is a node this token may not read"))
				return
			}
			sourceIDs = append(sourceIDs, sourceID)
		}
		if _, err := s.store.EnsureBeaconSourceIDs(sourceIDs); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	var refused *scopedNodeResolver
	plan, raw, err := s.buildBeaconPlan(node, req.Action, settings, t, now, func(nodeID string) (netguard.CompileInput, error) {
		input, resolver, err := s.compileInputFor(p, nodeID)
		refused = resolver
		return input, err
	})
	if refused != nil && s.writeRefusal(w, p, refused) {
		return
	}
	if err != nil {
		var pe *beaconPlanError
		if errors.As(err, &pe) {
			writeBeaconPlanError(w, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	findings := s.beaconLint(node, plan, now)
	if beaconFindingsBlock(findings) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "plan blocked by lint findings", "findings": findings})
		return
	}
	approval := model.Approval{
		ID:        id.New("approval"),
		NodeID:    req.NodeID,
		Plugin:    model.BeaconApprovalPlugin,
		Action:    model.BeaconPlanKind,
		Plan:      raw,
		Status:    model.ApprovalPending,
		ActorID:   p.ActorID,
		CreatedAt: now.UTC(),
	}
	approval, err = s.submitApproval(r.Context(), approval)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "beacon.plan", Scope: "monitor:admin,node:admin",
		Metadata: map[string]string{
			"approval_id": approval.ID,
			"action":      req.Action,
			"port":        strconv.Itoa(plan.Beacon.Port),
			"bind":        plan.Beacon.Bind,
			"endpoint":    plan.Beacon.Endpoint,
			"sources":     strconv.Itoa(len(plan.Sources)),
			"exposure":    plan.Exposure,
		},
	})
	writeJSON(w, http.StatusOK, model.BeaconPlanResponse{Approval: approval, Plan: plan, Findings: findings})
}

func writeBeaconPlanError(w http.ResponseWriter, err error) {
	var pe *beaconPlanError
	if errors.As(err, &pe) {
		if len(pe.findings) > 0 {
			writeJSON(w, pe.status, map[string]any{"error": pe.err.Error(), "findings": pe.findings})
			return
		}
		writeError(w, pe.status, pe.err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

// beaconPlanOf parses a node.beacon approval's document.
func beaconPlanOf(approval model.Approval) (model.BeaconPlan, error) {
	var plan model.BeaconPlan
	if err := json.Unmarshal([]byte(approval.Plan), &plan); err != nil {
		return plan, fmt.Errorf("beacon plan does not parse: %w", err)
	}
	if plan.Kind != model.BeaconPlanKind || plan.NodeID != approval.NodeID {
		return plan, errors.New("beacon plan names another kind or node")
	}
	return plan, nil
}

// currentBeaconPlan renders approval's document again from live state, the
// staleness check of the decision.
func (s *Server) currentBeaconPlan(approval model.Approval, now time.Time) (model.BeaconPlan, error) {
	plan, err := beaconPlanOf(approval)
	if err != nil {
		return plan, err
	}
	node, ok := s.store.Node(approval.NodeID)
	if !ok {
		return plan, errors.New("the node no longer exists")
	}
	t, exists := s.store.BeaconTarget(approval.NodeID)
	if !exists {
		t = store.BeaconTarget{NodeID: approval.NodeID}
	}
	_, raw, err := s.buildBeaconPlan(node, plan.Action, plan.Beacon, t, now, s.compileInputForSystem)
	if err != nil {
		return plan, fmt.Errorf("the plan cannot be rendered again: %w", err)
	}
	if raw != approval.Plan {
		return plan, errors.New("the beacon's settings, sources, addresses or the node's NetGuard intent changed since this plan was made; re-plan before approving")
	}
	return plan, nil
}

// beaconApprove decides a node.beacon approval: re-render and compare,
// check the decider's scopes, write the node's new beacon state and queue
// the NetGuard companion's apply task in one commit.
func (s *Server) beaconApprove(ctx context.Context, p principal, approval model.Approval, queueApply bool) (model.Approval, error) {
	now := s.now()
	plan, err := s.currentBeaconPlan(approval, now)
	if err != nil {
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale, err.Error())}
	}
	companion := plan.NetGuard != nil
	node, _ := s.store.Node(approval.NodeID)
	// A listener that took the port since the plan was made blocks it now:
	// the lint's inputs (sing-box inventory, sshd, knock state) are not in
	// the document, so the decision judges them again.
	if findings := s.beaconLint(node, plan, now); beaconFindingsBlock(findings) {
		var codes []string
		for _, f := range findings {
			if f.Severity == model.BeaconFindingBlock {
				codes = append(codes, f.Code)
			}
		}
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale,
			"the plan is blocked by lint findings now ("+strings.Join(codes, ", ")+"); re-plan before approving")}
	}
	if !beaconScopesAllow(p, approval.NodeID, companion) {
		return approval, &approvalDecisionError{status: http.StatusForbidden, err: apiError(model.APIErrorCapabilityDenied, "deciding a node.beacon plan needs monitor:admin and node:admin on the node, and netguard:admin when it carries NetGuard rules")}
	}
	if companion && !queueApply {
		return approval, &approvalDecisionError{status: http.StatusBadRequest, err: apiError(model.APIErrorBadRequest,
			"a node.beacon plan with NetGuard rules must queue its apply task: approve with queue_apply")}
	}
	if companion && s.taskExecutionDisabled {
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(apiErrorTaskExecutionDisabled, errTaskExecutionDisabled.Error()), taskExecutionDisabled: true}
	}
	if companion && !s.agentHasCapability(approval.NodeID, netGuardManagedSHACapability) {
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorBadRequest,
			"node agent has not advertised netguard-managed-sha-v1; update or reconnect the agent before applying")}
	}
	stored, _ := s.store.BeaconTarget(approval.NodeID)
	if stored.Version != plan.BaseVersion {
		return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale,
			"another node.beacon plan applied since this one was made; re-plan before approving")}
	}
	next := stored
	next.NodeID = approval.NodeID
	next.Version = plan.BaseVersion + 1
	next.Settings = plan.Beacon
	next.Approved = plan.Sources
	next.Exposure = plan.Exposure
	next.Companion = nil
	if companion && plan.Beacon.Enabled {
		next.Companion = &store.BeaconCompanion{Bind: plan.Beacon.Bind, Port: plan.NetGuard.Port, Allow: slices.Clone(plan.NetGuard.Allow)}
	}
	// Until the companion applies, no source probes the beacon: the port is
	// closed to it, and a reachability check would read filtered.
	next.CompanionPending = companion && plan.Beacon.Enabled
	next.AppliedApprovalID = approval.ID
	next.AppliedAt = now.UTC()
	next.AppliedBy = p.ActorID
	rotated := false
	switch {
	case !plan.Beacon.Enabled:
		next.Key, next.PrevEpoch, next.AckedAt = "", 0, time.Time{}
		next.TableSources = nil
		next.ReachArmed = false
		next.Reach = model.BeaconReachability{}
	case next.Key == "":
		key, err := newBeaconTargetKey()
		if err != nil {
			return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
		}
		next.Key = key
		next.Epoch++
		next.PrevEpoch, next.AckedAt, next.RotatedAt = 0, time.Time{}, now.UTC()
		next.TableSources = nil
	default:
		// A change that approves fewer sources ends the removed ones' keys.
		for _, prior := range stored.Approved {
			if !slices.ContainsFunc(plan.Sources, func(src model.BeaconPlanSource) bool { return src.NodeID == prior.NodeID }) {
				rotateBeaconEpoch(&next, now)
				rotated = true
				break
			}
		}
	}
	if plan.Beacon.Enabled {
		next.ReachArmed = true
		next.Reach = model.BeaconReachability{State: model.BeaconReachPending}
	}
	approval.ApprovedBy = p.ActorID
	var task *model.Task
	ruleset := ""
	var bindingVersion int64
	if companion {
		approval.Status = model.ApprovalApproved
		ruleset = plan.NetGuard.Ruleset
		bindingVersion = plan.NetGuard.BindingVersion
		task = &model.Task{
			ID:          id.New("task"),
			ApprovalID:  approval.ID,
			ActorID:     p.ActorID,
			TokenID:     p.TokenID,
			Targets:     []string{approval.NodeID},
			Interpreter: "sh",
			Script:      netGuardApplyScript(ruleset, s.publicURL),
			TimeoutSec:  networkApplyTaskTimeoutSec,
			OutputLimit: 65536,
			Status:      model.TaskQueued,
			CreatedAt:   now.UTC(),
		}
	} else {
		// Nothing runs on the node: the plan takes effect through the config
		// pull, so the approval is applied as it is decided.
		approval.Status = model.ApprovalApplied
	}
	committed, err := s.store.ApplyBeaconApproval(approval, next, task, ruleset, bindingVersion)
	if !committed {
		if errors.Is(err, store.ErrBeaconVersion) || errors.Is(err, store.ErrGuardVersionConflict) || errors.Is(err, store.ErrTaskTransitionConflict) {
			return approval, &approvalDecisionError{status: http.StatusConflict, err: apiError(model.APIErrorApprovalStale, "the beacon or the node's NetGuard binding changed while deciding; re-plan before approving")}
		}
		return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	if err != nil {
		s.logger.Printf("beacon approval committed with degraded durability: %v", err)
		return approval, &approvalDecisionError{status: http.StatusInternalServerError, err: err}
	}
	meta := map[string]string{
		"approval_id": approval.ID,
		"action":      plan.Action,
		"enabled":     strconv.FormatBool(plan.Beacon.Enabled),
		"port":        strconv.Itoa(plan.Beacon.Port),
		"endpoint":    plan.Beacon.Endpoint,
		"sources":     strconv.Itoa(len(plan.Sources)),
		"exposure":    plan.Exposure,
		"epoch":       strconv.FormatUint(uint64(next.Epoch), 10),
	}
	if rotated {
		meta["rotated"] = "true"
	}
	if task != nil {
		meta["task_id"] = task.ID
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: approval.NodeID, Action: "beacon.approve", Scope: approvalDecisionAuditScope(approval), Metadata: meta,
	})
	if _, _, err := s.syncLatencyProbes(now); err != nil {
		s.logger.Printf("latency probes not synced after beacon approval %s: %v", approval.ID, err)
	}
	if _, err := s.syncCheckDefinitions(now, "beacon"); err != nil {
		s.logger.Printf("check definitions not synced after beacon approval %s: %v", approval.ID, err)
	}
	s.syncBeaconReach(now)
	if fresh, ok := s.store.Approval(approval.ID); ok {
		approval = fresh
	}
	_ = ctx
	return approval, nil
}

// handleBeaconTaskResult records how a node.beacon plan's NetGuard
// companion applied.
func (s *Server) handleBeaconTaskResult(r *http.Request, approval model.Approval, task model.Task, result model.TaskResult) error {
	plan, err := beaconPlanOf(approval)
	if err != nil || plan.NetGuard == nil {
		return store.ErrTaskNotFound
	}
	reason := ""
	managedSHA := ""
	if result.Error != "" || result.ExitCode != 0 {
		reason = taskFailureSummary(result)
		if strings.TrimSpace(reason) == "" {
			reason = "beacon NetGuard apply failed"
		}
	} else if managedSHA, err = netGuardManagedSHAFromTaskResult(result.Stdout); err != nil {
		reason = err.Error()
	}
	finished := result.FinishedAt
	if finished.IsZero() {
		finished = s.now().UTC()
	}
	if err := s.store.CompleteBeaconCompanionTask(approval.ID, plan.NetGuard.RulesetSHA256, managedSHA, reason, finished); err != nil {
		return err
	}
	action, decision := "beacon.netguard.applied", "allow"
	if reason != "" {
		action, decision = "beacon.netguard.failed", "deny"
	}
	s.recordRequestAudit(r, model.AuditEvent{
		ID: id.New("audit"), NodeID: approval.NodeID, Action: action, Decision: decision, Reason: reason,
		Metadata: map[string]string{"approval_id": approval.ID, "task_id": task.ID, "managed_sha": managedSHA},
	})
	return nil
}

// handleBeaconRotate answers POST /api/nodes/beacon/rotate.
func (s *Server) handleBeaconRotate(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req model.BeaconRotateRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "monitor:admin", req.NodeID) || !s.requireNodeScope(w, p, "node:admin", req.NodeID) {
		return
	}
	t, err := s.beaconRotate(req.NodeID, s.now())
	if errors.Is(err, errBeaconNotEnabled) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: req.NodeID, Action: "beacon.rotate", Scope: "monitor:admin,node:admin",
		Metadata: map[string]string{"node_id": req.NodeID, "epoch": strconv.FormatUint(uint64(t.Epoch), 10)},
	})
	writeJSON(w, http.StatusOK, model.BeaconRotateResponse{NodeID: req.NodeID, Epoch: t.Epoch})
}

// handleNodeBeacon answers GET /api/nodes/beacon?node_id=.
func (s *Server) handleNodeBeacon(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, errors.New("node_id is required"))
		return
	}
	if !s.requireNodeScope(w, p, "monitor:read", nodeID) {
		return
	}
	node, ok := s.store.Node(nodeID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("node not found"))
		return
	}
	writeJSON(w, http.StatusOK, s.beaconView(p, node, s.now()))
}

// beaconView is a node's beacon as the console reads it. It never carries a
// key.
func (s *Server) beaconView(p principal, node model.Node, now time.Time) model.BeaconView {
	t, exists := s.store.BeaconTarget(node.ID)
	facts := s.beaconFactsOf(node)
	view := model.BeaconView{NodeID: node.ID, State: model.BeaconStateOff, Sources: []model.BeaconSourceView{}, Agent: facts}
	if exists {
		view.Version = t.Version
		view.SuggestedPort = t.SuggestedPort
		view.Reachability = t.Reach
		view.Exposure = t.Exposure
		if t.Version > 0 {
			settings := t.Settings
			view.Applied = &settings
			view.AppliedApprovalID = t.AppliedApprovalID
			view.AppliedAt = t.AppliedAt
		}
		if t.Settings.Enabled {
			view.Epoch = t.Epoch
			view.RotatedAt = t.RotatedAt
		}
	}
	if facts != nil {
		view.LastAuthAt = facts.LastAuthAt
	}
	if exists && t.Settings.Enabled {
		switch {
		case facts != nil && facts.Refusal != "":
			view.State, view.Reason = model.BeaconStateRefusedByNode, model.PathReasonRefusedByNode
		case facts == nil || !facts.Responder:
			view.State, view.Reason = model.BeaconStateAgentTooOld, model.PathReasonAgentTooOld
		case beaconListening(facts, t):
			view.State = model.BeaconStateListening
		case facts.State == model.BeaconAgentBindFailed || facts.State == model.BeaconAgentCircuitOpen:
			view.State, view.Reason = model.BeaconStateNotListening, model.PathReasonBeaconNotListening
		default:
			view.State = model.BeaconStatePending
		}
	}
	// The suggested port is assigned by the first plan, never by a read.
	nodes := map[string]model.Node{}
	for _, n := range s.store.Nodes() {
		nodes[n.ID] = n
	}
	current := s.beaconCurrentSources(node.ID, s.beaconPlanned(now, nodes), s.store.Monitors(), nodes)
	ids := s.store.BeaconSourceIDs()
	seen := map[string]bool{}
	add := func(sourceID string, approved bool) {
		if seen[sourceID] || !latencyNodeVisible(p, sourceID) {
			return
		}
		seen[sourceID] = true
		sv := model.BeaconSourceView{NodeID: sourceID, Name: nodes[sourceID].Name, SourceID: ids[sourceID], Approved: approved, Current: current[sourceID]}
		if sv.Current && !sv.Approved && exists && t.Settings.Enabled {
			sv.Reason = beaconSourceGate(t, sourceID)
		}
		view.Sources = append(view.Sources, sv)
	}
	if exists && t.Settings.Enabled {
		for _, src := range t.Approved {
			add(src.NodeID, true)
		}
	}
	extra := make([]string, 0, len(current))
	for sourceID := range current {
		extra = append(extra, sourceID)
	}
	sort.Strings(extra)
	for _, sourceID := range extra {
		add(sourceID, false)
	}
	sort.Slice(view.Sources, func(i, j int) bool { return view.Sources[i].NodeID < view.Sources[j].NodeID })
	if exists && t.Settings.Enabled && t.CompanionPending {
		view.FirewallPending = true
	}
	if exists && t.Settings.Enabled && t.Exposure == model.BeaconExposureNetGuard && !view.FirewallPending {
		approvedSet := map[string]bool{}
		for _, src := range t.Approved {
			approvedSet[src.NodeID] = true
		}
		if len(approvedSet) != len(current) {
			view.FirewallPending = true
		} else {
			for sourceID := range current {
				if !approvedSet[sourceID] {
					view.FirewallPending = true
					break
				}
			}
		}
	}
	for _, a := range s.store.Approvals() {
		if a.NodeID == node.ID && isBeaconApproval(a) && a.Status == model.ApprovalPending {
			view.PendingApprovalID = a.ID
		}
	}
	if exists {
		view.Replan = beaconReplanFor(node, t, current, view.PendingApprovalID, func(nodeID string) bool { return latencyNodeVisible(p, nodeID) })
	}
	return view
}

// beaconReplanFor is the change plan node's beacon needs, nil when it needs
// none: a source that uses the beacon now (current) and that the applied
// plan did not approve, or, when NetGuard manages the node, an approved
// source that no longer uses it, whose addresses the allow set still
// admits. Without NetGuard a source that left drops out of the table at the
// target's next config pull, so it needs no plan. Whether a plan is needed
// is judged on every source; visible narrows the ids listed to the ones the
// caller may read. Nothing is filed or applied here: the request is for the
// operator to send, and its approval decides.
func beaconReplanFor(node model.Node, t store.BeaconTarget, current map[string]bool, pendingApprovalID string, visible func(string) bool) *model.BeaconReplan {
	if !t.Settings.Enabled || t.Version == 0 {
		return nil
	}
	approved := make(map[string]bool, len(t.Approved))
	for _, src := range t.Approved {
		approved[src.NodeID] = true
	}
	netguard := t.Exposure == model.BeaconExposureNetGuard
	var added, removed []string
	for sourceID := range current {
		if !approved[sourceID] {
			added = append(added, sourceID)
		}
	}
	if netguard {
		for sourceID := range approved {
			if !current[sourceID] {
				removed = append(removed, sourceID)
			}
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	listed := func(ids []string) []string {
		out := []string{}
		for _, nodeID := range ids {
			if visible(nodeID) {
				out = append(out, nodeID)
			}
		}
		sort.Strings(out)
		return out
	}
	reason := model.PathReasonBeaconSourcePending
	if netguard {
		reason = model.PathReasonFirewallPending
	}
	return &model.BeaconReplan{
		NodeID:            node.ID,
		Name:              latencyNodeLabel(node),
		Reason:            reason,
		Added:             listed(added),
		Removed:           listed(removed),
		PendingApprovalID: pendingApprovalID,
		// A change with no port, bind or endpoint keeps all three and
		// re-plans the sources current when it is filed.
		Request: model.BeaconPlanRequest{NodeID: node.ID, Action: model.BeaconActionChange},
	}
}

// beaconReplans lists every node the principal may read whose beacon needs
// a change plan (beaconReplanFor), by node id. The open approvals are read
// only when some node needs one.
func (s *Server) beaconReplans(p principal, nodes map[string]model.Node, now time.Time) []model.BeaconReplan {
	out := []model.BeaconReplan{}
	targets := s.store.BeaconTargets()
	ids := make([]string, 0, len(targets))
	for nodeID, t := range targets {
		if _, ok := nodes[nodeID]; ok && t.Settings.Enabled && latencyNodeVisible(p, nodeID) {
			ids = append(ids, nodeID)
		}
	}
	if len(ids) == 0 {
		return out
	}
	sort.Strings(ids)
	planned := s.beaconPlanned(now, nodes)
	monitors := s.store.Monitors()
	visible := func(nodeID string) bool { return latencyNodeVisible(p, nodeID) }
	for _, nodeID := range ids {
		current := s.beaconCurrentSources(nodeID, planned, monitors, nodes)
		if r := beaconReplanFor(nodes[nodeID], targets[nodeID], current, "", visible); r != nil {
			out = append(out, *r)
		}
	}
	if len(out) == 0 {
		return out
	}
	pending := map[string]string{}
	for _, a := range s.store.Approvals() {
		if isBeaconApproval(a) && a.Status == model.ApprovalPending {
			pending[a.NodeID] = a.ID
		}
	}
	for i := range out {
		out[i].PendingApprovalID = pending[out[i].NodeID]
	}
	return out
}
