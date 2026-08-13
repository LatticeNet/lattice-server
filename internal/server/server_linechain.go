package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	lineChainPlugin             = "singbox-linechain"
	lineChainService            = "network/lines"
	lineChainSetMethod          = "chain_set_apply"
	lineChainRemoveMethod       = "chain_remove_apply"
	lineChainActionPrefix       = "apply-line-chain:"
	lineChainDurableCapability  = "durable-task-result-v1"
	lineChainFragmentPathPrefix = "/etc/sing-box/conf.d/lattice-linechain-"
)

type lineChainCompileRequest struct {
	SourceLineUUID string `json:"source_line_uuid"`
	TargetLineUUID string `json:"target_line_uuid,omitempty"`
}

type lineChainPlan struct {
	Operation              string   `json:"operation"`
	SourceLineUUID         string   `json:"source_line_uuid"`
	TargetLineUUID         string   `json:"target_line_uuid,omitempty"`
	SourceNodeID           string   `json:"source_node_id"`
	TargetNodeID           string   `json:"target_node_id,omitempty"`
	SourceLabel            string   `json:"source_label"`
	TargetLabel            string   `json:"target_label,omitempty"`
	SourceInboundTag       string   `json:"source_inbound_tag"`
	OutboundTag            string   `json:"outbound_tag"`
	FragmentPath           string   `json:"fragment_path"`
	TargetHost             string   `json:"target_host,omitempty"`
	TargetPort             int      `json:"target_port,omitempty"`
	Protocol               string   `json:"protocol,omitempty"`
	SNI                    string   `json:"sni,omitempty"`
	PublicKeyFingerprint   string   `json:"public_key_fingerprint,omitempty"`
	ShortIDFingerprint     string   `json:"short_id_fingerprint,omitempty"`
	FragmentSHA256         string   `json:"fragment_sha256"`
	SidecarSHA256          string   `json:"sidecar_sha256"`
	ArtifactSHA256         string   `json:"artifact_sha256"`
	RequestSHA256          string   `json:"request_sha256"`
	PreviousTargetLineUUID string   `json:"previous_target_line_uuid,omitempty"`
	PreviousArtifactSHA256 string   `json:"previous_artifact_sha256,omitempty"`
	PreflightChecks        []string `json:"preflight_checks"`
	Summary                string   `json:"summary"`
}

type lineChainCompiledArtifact struct {
	Plan                 lineChainPlan
	FragmentJSON         string
	SidecarJSON          string
	TargetCredentialUUID string
	TargetPublicKey      string
	TargetShortID        string
	TargetDefinition     managedLineDef
}

// lineChainCompileSnapshot freezes every resolved compiler input before any
// validation or rendering. Compiler code below must not reach back into live
// server/store state after this boundary.
type lineChainCompileSnapshot struct {
	Lines        map[string][]Line
	Definitions  map[string]managedLineDef
	Users        map[string]VpnUser
	Nodes        map[string]model.Node
	Chains       store.LineChainSnapshot
	Capabilities map[string]bool
}

func (s *Server) captureLineChainCompileSnapshot() (lineChainCompileSnapshot, error) {
	snapshot := lineChainCompileSnapshot{
		Lines: make(map[string][]Line), Definitions: make(map[string]managedLineDef),
		Users: make(map[string]VpnUser), Nodes: make(map[string]model.Node),
		Chains: s.store.LineChainSnapshot(), Capabilities: make(map[string]bool),
	}
	for _, group := range s.buildLineGroups() {
		for _, line := range group.Lines {
			if line.LineUUID != "" {
				uuid := strings.ToLower(line.LineUUID)
				snapshot.Lines[uuid] = append(snapshot.Lines[uuid], line)
			}
		}
	}
	definitions, err := s.managedLineDefs()
	if err != nil {
		return lineChainCompileSnapshot{}, err
	}
	for _, definition := range definitions {
		snapshot.Definitions[strings.ToLower(definition.LineUUID)] = definition
	}
	for _, user := range s.listVpnUsers() {
		snapshot.Users[user.ID] = user
	}
	for _, node := range s.store.Nodes() {
		snapshot.Nodes[node.ID] = node
	}
	s.agentCapabilitiesMu.RLock()
	for nodeID, capabilities := range s.agentCapabilities {
		_, snapshot.Capabilities[nodeID] = capabilities[lineChainDurableCapability]
	}
	s.agentCapabilitiesMu.RUnlock()
	return snapshot, nil
}

func deterministicLineChainTag(sourceUUID, targetUUID string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(sourceUUID) + "\x00" + strings.ToLower(targetUUID)))
	return "lattice-chain-" + hex.EncodeToString(sum[:])[:20]
}

func lineChainFragmentPath(sourceUUID string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(sourceUUID)))
	return lineChainFragmentPathPrefix + hex.EncodeToString(sum[:])[:20] + ".json"
}

func digestText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func shortFingerprint(value string) string {
	digest := digestText(value)
	return digest[:16]
}

func (s *Server) compileLineChain(req lineChainCompileRequest) (lineChainCompiledArtifact, error) {
	snapshot, err := s.captureLineChainCompileSnapshot()
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	return s.compileLineChainSnapshot(snapshot, req)
}

func (s *Server) compileLineChainSnapshot(snapshot lineChainCompileSnapshot, req lineChainCompileRequest) (lineChainCompiledArtifact, error) {
	req.SourceLineUUID = strings.ToLower(strings.TrimSpace(req.SourceLineUUID))
	req.TargetLineUUID = strings.ToLower(strings.TrimSpace(req.TargetLineUUID))
	if !validLineUUIDv4(req.SourceLineUUID) || !validLineUUIDv4(req.TargetLineUUID) {
		return lineChainCompiledArtifact{}, errors.New("source_line_uuid and target_line_uuid must be UUIDv4")
	}
	if req.SourceLineUUID == req.TargetLineUUID {
		return lineChainCompiledArtifact{}, errors.New("source and target line must differ")
	}
	resolve := func(uuid string) (Line, error) {
		matches := snapshot.Lines[uuid]
		if len(matches) != 1 {
			return Line{}, fmt.Errorf("line_uuid %s resolves to %d lines", uuid, len(matches))
		}
		return matches[0], nil
	}
	source, err := resolve(req.SourceLineUUID)
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	target, err := resolve(req.TargetLineUUID)
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	if source.NodeID == target.NodeID {
		return lineChainCompiledArtifact{}, errors.New("source and target must be on distinct nodes")
	}
	if source.Core != model.ProxyCoreSingbox || source.Tag == "" || source.Status != "ok" {
		return lineChainCompiledArtifact{}, errors.New("source must be a healthy sing-box line with a stable inbound tag")
	}
	if target.Core != model.ProxyCoreSingbox || target.Type != model.ProxyProtocolVLESS ||
		target.Security != model.ProxySecurityReality || target.Transport != model.ProxyTransportTCP {
		return lineChainCompiledArtifact{}, errors.New("target must be sing-box VLESS+REALITY+TCP")
	}
	if !target.Overlay || target.OverlayStatus != managedLineStatusApplied || target.Status != "ok" {
		return lineChainCompiledArtifact{}, errors.New("target must be a healthy applied managed-line overlay")
	}
	chainSnapshot := snapshot.Chains
	if store.WouldCreateLineChainCycle(chainSnapshot, source.LineUUID, target.LineUUID) {
		return lineChainCompiledArtifact{}, errors.New("candidate would create a line chain cycle")
	}
	if !snapshot.Capabilities[source.NodeID] {
		return lineChainCompiledArtifact{}, errors.New("source node does not advertise durable-task-result-v1")
	}
	definition, ok := snapshot.Definitions[strings.ToLower(target.LineUUID)]
	if !ok || definition.Status != managedLineStatusApplied || definition.Port < 1 || definition.SNI == "" ||
		definition.RealityPublicKey == "" || definition.ShortID == "" || definition.UserID == "" {
		return lineChainCompiledArtifact{}, errors.New("target managed-line descriptor is incomplete")
	}
	user, ok := snapshot.Users[definition.UserID]
	if !ok || !user.Enabled {
		return lineChainCompiledArtifact{}, errors.New("target managed-line user is unavailable")
	}
	credential, ok := vpnCredentialForProtocol(user.Credentials, model.ProxyProtocolVLESS)
	if !ok || strings.TrimSpace(credential.UUID) == "" {
		return lineChainCompiledArtifact{}, errors.New("target managed-line VLESS credential is unavailable")
	}
	targetHost := firstNonEmpty(target.PublicHost, strings.TrimSpace(snapshot.Nodes[target.NodeID].PublicIP))
	if targetHost == "" {
		return lineChainCompiledArtifact{}, errors.New("target public host is unavailable")
	}
	outboundTag := deterministicLineChainTag(source.LineUUID, target.LineUUID)
	fragment, err := proxycore.RenderLineChainFragment(proxycore.LineChainOutboundOptions{
		Tag: outboundTag, SourceInboundTag: source.Tag, Server: targetHost, ServerPort: definition.Port,
		UUID: credential.UUID, Flow: firstNonEmpty(credential.Flow, "xtls-rprx-vision"), SNI: definition.SNI,
		RealityPublicKey: definition.RealityPublicKey, RealityShortID: definition.ShortID,
	})
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	sidecar, err := s.renderLineChainSidecarSnapshot(snapshot, source.NodeID, source.LineUUID, target.LineUUID)
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	sidecarSHA := digestText(string(sidecar))
	combined := digestText(fragment.JSON + "\x00" + string(sidecar))
	requestBinding, _ := json.Marshal(struct {
		Request          lineChainCompileRequest `json:"request"`
		SourceLineHashID string                  `json:"source_line_hash_id"`
		TargetDefinition string                  `json:"target_definition_digest"`
		TargetCredential string                  `json:"target_credential_digest"`
		Artifact         string                  `json:"artifact_sha256"`
	}{req, source.LineHashID, digestManagedLineDefinition(definition), digestText(credential.UUID), combined})
	plan := lineChainPlan{
		Operation: "set", SourceLineUUID: source.LineUUID, TargetLineUUID: target.LineUUID,
		SourceNodeID: source.NodeID, TargetNodeID: target.NodeID, SourceLabel: source.Name, TargetLabel: target.Name,
		SourceInboundTag: source.Tag, OutboundTag: outboundTag, FragmentPath: lineChainFragmentPath(source.LineUUID),
		TargetHost: targetHost, TargetPort: definition.Port, Protocol: model.ProxyProtocolVLESS, SNI: definition.SNI,
		PublicKeyFingerprint: shortFingerprint(definition.RealityPublicKey), ShortIDFingerprint: shortFingerprint(definition.ShortID),
		FragmentSHA256: fragment.SHA256, SidecarSHA256: sidecarSHA, ArtifactSHA256: combined,
		RequestSHA256:   digestText(string(requestBinding)),
		PreflightChecks: []string{"source_identity", "target_managed_applied", "target_credential", "consumer_capability", "distinct_nodes"},
		Summary:         fmt.Sprintf("Route %s on %s through managed target %s", source.Name, s.nodeDisplayName(source.NodeID), target.Name),
	}
	if current, ok := chainSnapshot.Definitions[source.LineUUID]; ok {
		plan.PreviousTargetLineUUID = current.TargetLineUUID
		plan.PreviousArtifactSHA256 = current.ArtifactSHA256
	}
	return lineChainCompiledArtifact{
		Plan: plan, FragmentJSON: fragment.JSON, SidecarJSON: string(sidecar), TargetCredentialUUID: credential.UUID,
		TargetPublicKey: definition.RealityPublicKey, TargetShortID: definition.ShortID, TargetDefinition: definition,
	}, nil
}

func (s *Server) renderLineChainSidecarSnapshot(snapshot lineChainCompileSnapshot, nodeID, sourceUUID, targetUUID string) ([]byte, error) {
	inbounds := make([]lineMetadataInboundV2, 0)
	found := false
	for _, matches := range snapshot.Lines {
		for _, line := range matches {
			if line.NodeID != nodeID {
				continue
			}
			if line.Tag == "" || !validLineUUIDv4(line.LineUUID) {
				return nil, fmt.Errorf("line %s is missing stable sidecar identity", line.LineHashID)
			}
			inbound := lineMetadataInboundV2{Tag: line.Tag, LineUUID: line.LineUUID, LineHashID: line.LineHashID}
			downstream := strings.TrimSpace(line.DownstreamLineUUID)
			if strings.EqualFold(line.LineUUID, sourceUUID) {
				downstream = targetUUID
				found = true
			}
			if downstream != "" {
				target := downstream
				inbound.Chain = &lineMetadataChainV2{DownstreamLineUUID: &target}
				if targetLines := snapshot.Lines[strings.ToLower(downstream)]; len(targetLines) == 1 {
					targetNode := snapshot.Nodes[targetLines[0].NodeID]
					inbound.Chain.DownstreamNode = firstNonEmpty(strings.TrimSpace(targetNode.Name), targetLines[0].NodeID)
				}
			}
			inbounds = append(inbounds, inbound)
		}
	}
	if !found {
		return nil, errors.New("source line is absent from its node sidecar")
	}
	sort.Slice(inbounds, func(i, j int) bool { return inbounds[i].Tag < inbounds[j].Tag })
	node := snapshot.Nodes[nodeID]
	doc := lineMetadataDocV2{
		Schema: lineMetadataSchemaV2, NodeID: nodeID, NodeUUID: strings.TrimSpace(node.LatticeIdentityUUID),
		UpdatedAt: s.now().UTC().Format(time.RFC3339), Writer: lineMetadataWriter, Inbounds: inbounds,
		Reserved: lineMetadataReservedV2{InConfigKey: "_lattice", Fields: lineMetadataReservedFields{LineUUID: "string", NodeUUID: "string", LineHashID: "string"}},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func digestManagedLineDefinition(definition managedLineDef) string {
	public, private := splitManagedLineRecord(definition)
	raw, _ := json.Marshal(struct {
		Public  any `json:"public"`
		Private any `json:"private"`
	}{public, private})
	return digestText(string(raw))
}

func (s *Server) renderLineChainSidecar(nodeID, sourceUUID, targetUUID string) ([]byte, error) {
	raw, err := s.renderLineMetadataJSON(nodeID)
	if err != nil {
		return nil, err
	}
	var doc lineMetadataDocV2
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	found := false
	for i := range doc.Inbounds {
		if strings.EqualFold(doc.Inbounds[i].LineUUID, sourceUUID) {
			if targetUUID == "" {
				doc.Inbounds[i].Chain = nil
			} else {
				target := targetUUID
				doc.Inbounds[i].Chain = &lineMetadataChainV2{DownstreamLineUUID: &target, DownstreamNode: ""}
			}
			found = true
		}
	}
	if !found {
		return nil, errors.New("source line is absent from its node sidecar")
	}
	sort.Slice(doc.Inbounds, func(i, j int) bool { return doc.Inbounds[i].Tag < doc.Inbounds[j].Tag })
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func (s *Server) compileLineChainRemove(sourceUUID string) (lineChainCompiledArtifact, error) {
	sourceUUID = strings.ToLower(strings.TrimSpace(sourceUUID))
	if !validLineUUIDv4(sourceUUID) {
		return lineChainCompiledArtifact{}, errors.New("source_line_uuid must be UUIDv4")
	}
	snapshot := s.store.LineChainSnapshot()
	current, ok := snapshot.Definitions[sourceUUID]
	if !ok || current.TargetLineUUID == "" {
		return lineChainCompiledArtifact{}, errors.New("source has no committed chain to remove")
	}
	var source Line
	found := false
	for _, group := range s.buildLineGroups() {
		for _, line := range group.Lines {
			if strings.EqualFold(line.LineUUID, sourceUUID) {
				if found {
					return lineChainCompiledArtifact{}, errors.New("source line identity is ambiguous")
				}
				source, found = line, true
			}
		}
	}
	if !found || source.NodeID != current.SourceNodeID || source.Tag == "" {
		return lineChainCompiledArtifact{}, errors.New("committed source line is unavailable")
	}
	if !s.agentHasCapability(source.NodeID, lineChainDurableCapability) {
		return lineChainCompiledArtifact{}, errors.New("source node does not advertise durable-task-result-v1")
	}
	sidecar, err := s.renderLineChainSidecar(source.NodeID, sourceUUID, "")
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	artifactSHA := digestText("\x00" + string(sidecar))
	requestSHA := digestText("remove\x00" + sourceUUID + "\x00" + current.ArtifactSHA256 + "\x00" + artifactSHA)
	return lineChainCompiledArtifact{Plan: lineChainPlan{
		Operation: "remove", SourceLineUUID: sourceUUID, SourceNodeID: source.NodeID, SourceLabel: source.Name,
		SourceInboundTag: source.Tag, OutboundTag: current.OutboundTag, FragmentPath: current.FragmentPath,
		SidecarSHA256: digestText(string(sidecar)), ArtifactSHA256: artifactSHA, RequestSHA256: requestSHA,
		PreviousTargetLineUUID: current.TargetLineUUID, PreviousArtifactSHA256: current.ArtifactSHA256,
		PreflightChecks: []string{"source_identity", "committed_baseline", "consumer_capability"},
		Summary:         fmt.Sprintf("Remove managed downstream from %s on %s", source.Name, s.nodeDisplayName(source.NodeID)),
	}, SidecarJSON: string(sidecar)}, nil
}

func (s *Server) persistLineChainPlan(p principal, compiled lineChainCompiledArtifact) (model.Approval, error) {
	planJSON, err := json.Marshal(compiled.Plan)
	if err != nil {
		return model.Approval{}, err
	}
	method := lineChainSetMethod
	operation := store.LineChainOperationSet
	if compiled.Plan.Operation == "remove" {
		method = lineChainRemoveMethod
		operation = store.LineChainOperationRemove
	}
	approval := model.Approval{
		ID: id.New("approval"), NodeID: compiled.Plan.SourceNodeID, Plugin: lineChainPlugin,
		PluginVersion: "design-18-e3-v1", Service: lineChainService, Method: method,
		Action: lineChainActionPrefix + compiled.Plan.ArtifactSHA256, ArtifactDigest: compiled.Plan.ArtifactSHA256,
		RequestSHA256: compiled.Plan.RequestSHA256, Targets: []string{compiled.Plan.SourceNodeID},
		Plan: string(planJSON), Status: model.ApprovalPending, ActorID: p.ActorID,
		CreatedAt: s.now(), UpdatedAt: s.now(),
	}
	current := s.store.LineChainSnapshot().Definitions[compiled.Plan.SourceLineUUID]
	attempt := store.LineChainAttempt{
		ApprovalID: approval.ID, Operation: operation, SourceLineUUID: compiled.Plan.SourceLineUUID,
		SourceNodeID: compiled.Plan.SourceNodeID, CandidateTargetLineUUID: compiled.Plan.TargetLineUUID,
		CandidateTargetNodeID: compiled.Plan.TargetNodeID, BaseGeneration: current.Generation,
		BaseArtifactSHA256: current.ArtifactSHA256, CandidateArtifactSHA256: compiled.Plan.ArtifactSHA256,
		RequestSHA256: compiled.Plan.RequestSHA256,
	}
	planned, deduped, err := s.store.PlanLineChainApproval(attempt, approval)
	if err != nil {
		return model.Approval{}, err
	}
	if deduped {
		existing, ok := s.store.Approval(planned.ApprovalID)
		if !ok {
			return model.Approval{}, errors.New("deduplicated line chain approval is missing")
		}
		return existing, nil
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID: id.New("audit"), NodeID: approval.NodeID, Action: "linechain.plan", Scope: "network:plan",
		Metadata: map[string]string{"approval_id": approval.ID, "source_line_uuid": compiled.Plan.SourceLineUUID, "target_line_uuid": compiled.Plan.TargetLineUUID, "artifact_sha256": compiled.Plan.ArtifactSHA256},
	})
	return approval, nil
}

func (s *Server) handleLineChainPlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req lineChainCompileRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	compiled, err := s.compileLineChain(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval, err := s.persistLineChainPlan(p, compiled)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approval": toApprovalView(approval), "preview": compiled.Plan})
}

func (s *Server) handleLineChainRemovePlan(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		SourceLineUUID string `json:"source_line_uuid"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	compiled, err := s.compileLineChainRemove(req.SourceLineUUID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	approval, err := s.persistLineChainPlan(p, compiled)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approval": toApprovalView(approval), "preview": compiled.Plan})
}

func (s *Server) handleLineChains(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, s.lineChainViews())
}

func (s *Server) lineChainViews() map[string]any {
	snapshot := s.store.LineChainSnapshot()
	return map[string]any{"definitions": snapshot.Definitions, "attempts": snapshot.Attempts, "graph_revision": snapshot.Revision}
}

func (s *Server) vpnCoreLineChainsRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "chains":
		return json.Marshal(s.lineChainViews())
	case "plan_chain":
		p, err := pluginOperatorPrincipal(ctx)
		if err != nil {
			return nil, err
		}
		var req lineChainCompileRequest
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, err
		}
		compiled, err := s.compileLineChain(req)
		if err != nil {
			return nil, err
		}
		approval, err := s.persistLineChainPlan(p, compiled)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"approval": toApprovalView(approval), "preview": compiled.Plan})
	case "plan_remove_chain":
		p, err := pluginOperatorPrincipal(ctx)
		if err != nil {
			return nil, err
		}
		var req struct {
			SourceLineUUID string `json:"source_line_uuid"`
		}
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, err
		}
		compiled, err := s.compileLineChainRemove(req.SourceLineUUID)
		if err != nil {
			return nil, err
		}
		approval, err := s.persistLineChainPlan(p, compiled)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"approval": toApprovalView(approval), "preview": compiled.Plan})
	default:
		return nil, fmt.Errorf("vpn-core/lines chain method %q is unknown", method)
	}
}
