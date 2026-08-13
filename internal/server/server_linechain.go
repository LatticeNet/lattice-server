package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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
	lineChainFragmentPathPrefix = "lattice-linechain-"
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
	SidecarPatchSHA256     string   `json:"sidecar_patch_sha256"`
	ArtifactSHA256         string   `json:"artifact_sha256"`
	RequestSHA256          string   `json:"request_sha256"`
	PreviousTargetLineUUID string   `json:"previous_target_line_uuid,omitempty"`
	PreviousArtifactSHA256 string   `json:"previous_artifact_sha256,omitempty"`
	PreflightChecks        []string `json:"preflight_checks"`
	Summary                string   `json:"summary"`
}

type lineChainCompiledArtifact struct {
	Plan                   lineChainPlan
	FragmentJSON           string
	SidecarPatchJSON       string
	TargetCredentialUUID   string
	TargetPublicKey        string
	TargetShortID          string
	TargetDefinition       managedLineDef
	BaseGeneration         uint64
	PlanGraphRevision      uint64
	PreviousFragmentSHA256 string
	CandidateDefinition    store.LineChainDefinition
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
	EvidenceAt   time.Time
}

const (
	lineChainDurableProtocol = "linechain-e3-v2"
	lineChainPatchSchema     = "lattice.singbox-linechain-sidecar-patch.v1"
	lineChainArtifactSchema  = "lattice.singbox-linechain-artifact.v2"
)

type lineChainSidecarPatch struct {
	Schema                     string  `json:"schema"`
	SourceLineUUID             string  `json:"source_line_uuid"`
	SourceInboundTag           string  `json:"source_inbound_tag"`
	ExpectedDownstreamLineUUID *string `json:"expected_downstream_line_uuid"`
	DesiredDownstreamLineUUID  *string `json:"desired_downstream_line_uuid"`
}

type lineChainArtifactBindingV2 struct {
	Schema                 string  `json:"schema"`
	Operation              string  `json:"operation"`
	FragmentBasename       string  `json:"fragment_basename"`
	PreviousFragmentSHA256 *string `json:"previous_fragment_sha256"`
	FragmentSHA256         *string `json:"fragment_sha256"`
	SidecarPatchSHA256     string  `json:"sidecar_patch_sha256"`
}

func canonicalLineChainSidecarPatch(sourceUUID, sourceTag, expected, desired string) (lineChainSidecarPatch, string, string, error) {
	sourceUUID = strings.ToLower(strings.TrimSpace(sourceUUID))
	if !validLineUUIDv4(sourceUUID) || sourceTag == "" || sourceTag != strings.TrimSpace(sourceTag) {
		return lineChainSidecarPatch{}, "", "", errors.New("sidecar patch source identity is invalid")
	}
	normalizeNullableUUID := func(value string) (*string, error) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return nil, nil
		}
		if !validLineUUIDv4(value) {
			return nil, fmt.Errorf("invalid downstream line_uuid %q", value)
		}
		return &value, nil
	}
	expectedUUID, err := normalizeNullableUUID(expected)
	if err != nil {
		return lineChainSidecarPatch{}, "", "", err
	}
	desiredUUID, err := normalizeNullableUUID(desired)
	if err != nil {
		return lineChainSidecarPatch{}, "", "", err
	}
	patch := lineChainSidecarPatch{Schema: lineChainPatchSchema, SourceLineUUID: sourceUUID, SourceInboundTag: sourceTag,
		ExpectedDownstreamLineUUID: expectedUUID, DesiredDownstreamLineUUID: desiredUUID}
	raw, err := json.Marshal(patch)
	if err != nil {
		return lineChainSidecarPatch{}, "", "", err
	}
	return patch, string(raw), digestText(string(raw)), nil
}

func canonicalLineChainArtifact(operation, fragmentBasename, previousFragmentSHA, fragmentSHA, patchSHA string) (string, error) {
	_, digest, err := canonicalLineChainArtifactJSON(operation, fragmentBasename, previousFragmentSHA, fragmentSHA, patchSHA)
	return digest, err
}

func canonicalLineChainArtifactJSON(operation, fragmentBasename, previousFragmentSHA, fragmentSHA, patchSHA string) (string, string, error) {
	nullableSHA := func(value string) (*string, error) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return nil, nil
		}
		if len(value) != sha256.Size*2 {
			return nil, errors.New("artifact binding contains invalid sha256")
		}
		if _, err := hex.DecodeString(value); err != nil {
			return nil, errors.New("artifact binding contains invalid sha256")
		}
		return &value, nil
	}
	previous, err := nullableSHA(previousFragmentSHA)
	if err != nil {
		return "", "", err
	}
	fragment, err := nullableSHA(fragmentSHA)
	if err != nil {
		return "", "", err
	}
	patchSHA = strings.ToLower(strings.TrimSpace(patchSHA))
	if _, err := nullableSHA(patchSHA); err != nil || patchSHA == "" {
		return "", "", errors.New("artifact binding contains invalid sidecar patch sha256")
	}
	switch operation {
	case "create":
		if previous != nil || fragment == nil {
			return "", "", errors.New("create artifact requires previous fragment null and fragment sha256 present")
		}
	case "replace":
		if previous == nil || fragment == nil {
			return "", "", errors.New("replace artifact requires previous and desired fragment sha256")
		}
	case "remove":
		if previous == nil || fragment != nil {
			return "", "", errors.New("remove artifact requires previous fragment sha256 and desired fragment null")
		}
	default:
		return "", "", fmt.Errorf("unsupported line-chain artifact operation %q", operation)
	}
	binding := lineChainArtifactBindingV2{Schema: lineChainArtifactSchema, Operation: operation, FragmentBasename: fragmentBasename,
		PreviousFragmentSHA256: previous, FragmentSHA256: fragment, SidecarPatchSHA256: patchSHA}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", "", err
	}
	return string(raw), digestText(string(raw)), nil
}

func (s *Server) captureLineChainCompileSnapshot() (lineChainCompileSnapshot, error) {
	return s.captureLineChainCompileSnapshotFromState(s.store.LineChainCompileStateSnapshot())
}

func (s *Server) captureLineChainCompileSnapshotFromState(persistent store.LineChainCompileStateSnapshot) (lineChainCompileSnapshot, error) {
	s.singboxInvMu.RLock()
	s.agentCapabilitiesMu.RLock()
	defer s.agentCapabilitiesMu.RUnlock()
	defer s.singboxInvMu.RUnlock()
	return s.captureLineChainCompileSnapshotFromStateLocked(persistent)
}

// captureLineChainCompileSnapshotFromStateLocked requires both live-input read
// locks. Result promotion uses it while retaining those locks through commit.
func (s *Server) captureLineChainCompileSnapshotFromStateLocked(persistent store.LineChainCompileStateSnapshot) (lineChainCompileSnapshot, error) {
	snapshot := lineChainCompileSnapshot{
		Lines: make(map[string][]Line), Definitions: make(map[string]managedLineDef),
		Users: make(map[string]VpnUser), Nodes: make(map[string]model.Node),
		Capabilities: make(map[string]bool),
	}
	// Fixed live-input lock order. The supplied persistent snapshot was copied
	// under one Store lock; this helper never re-enters Store.
	inventories := make([]model.SingBoxInventory, 0, len(s.singboxInv))
	for _, inventory := range s.singboxInv {
		copyInventory := inventory
		copyInventory.Nodes = append([]model.SingBoxNode(nil), inventory.Nodes...)
		inventories = append(inventories, copyInventory)
	}
	for nodeID, capabilities := range s.agentCapabilities {
		_, snapshot.Capabilities[nodeID] = capabilities[lineChainDurableCapability]
	}
	snapshot.Nodes = persistent.Nodes
	snapshot.Chains = persistent.Chains
	for uuid, public := range persistent.ManagedLines {
		private, ok := persistent.ManagedLineSecrets[uuid]
		if ok {
			snapshot.Definitions[strings.ToLower(uuid)] = joinManagedLineRecord(public, private)
		}
	}
	for id, public := range persistent.VpnUsers {
		private, ok := persistent.VpnUserSecrets[id]
		if ok {
			snapshot.Users[id] = joinVpnUserRecord(public, private)
		}
	}
	now := s.now()
	for _, inventory := range inventories {
		if inventory.At.After(snapshot.EvidenceAt) {
			snapshot.EvidenceAt = inventory.At
		}
		if _, ok := persistent.Nodes[inventory.NodeID]; !ok || inventory.Status != "ok" || (!inventory.At.IsZero() && now.Sub(inventory.At) > nodeOfflineThreshold) {
			continue
		}
		for _, discovered := range inventory.Nodes {
			port := atoiSafe(discovered.Port)
			hashID := stableLineHandle(discovered.LineID)
			if hashID == "" {
				hashID = lineHash(inventory.NodeID, model.ProxyCoreSingbox, discovered.Protocol, discovered.ListenHost, port, discovered.Name, discovered.OutboundRef)
			}
			uuid := strings.ToLower(strings.TrimSpace(persistent.LineUUIDByHash[hashID]))
			if uuid == "" || !validLineUUIDv4(uuid) {
				continue
			}
			line := Line{ID: hashID, LineHashID: hashID, LineID: discovered.LineID, LineUUID: uuid,
				NodeID: inventory.NodeID, NodeIdentityUUID: discovered.NodeIdentityUUID, Core: model.ProxyCoreSingbox,
				Source: "discovered", Name: discovered.Name, Tag: discovered.Name, Type: discovered.Protocol,
				Transport: discovered.Network, ListenHost: discovered.ListenHost, ListenPort: port,
				PublicHost: discovered.Address, Domain: firstNonEmpty(discovered.SNI, discovered.Host),
				OutboundRef: discovered.OutboundRef, OutboundServer: discovered.OutboundServer, OutboundPort: atoiSafe(discovered.OutboundPort),
				DownstreamLineUUID: strings.TrimSpace(discovered.DownstreamLineUUID), Status: "ok", Metadata: discovered.Metadata}
			if definition, ok := snapshot.Definitions[uuid]; ok && definition.LineHashID == hashID {
				line.Overlay, line.OverlayStatus, line.OverlayUser, line.Security = true, definition.Status, definition.UserID, model.ProxySecurityReality
			}
			snapshot.Lines[uuid] = append(snapshot.Lines[uuid], line)
		}
	}
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

func lineChainAuditID(kind, approvalID, suffix string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + approvalID + "\x00" + suffix))
	return "audit_linechain_" + hex.EncodeToString(digest[:16])
}

func (s *Server) appendRequiredLineChainAudit(event model.AuditEvent) error {
	_, err := s.store.AppendAuditIdempotent(event)
	return err
}

func lineChainAuditMetadata(approval model.Approval, taskID string) map[string]string {
	metadata := map[string]string{"approval_id": approval.ID, "artifact_sha256": approval.ArtifactDigest}
	if taskID != "" {
		metadata["task_id"] = taskID
	}
	var plan lineChainPlan
	if json.Unmarshal([]byte(approval.Plan), &plan) == nil {
		metadata["source_line_uuid"] = plan.SourceLineUUID
		target := firstNonEmpty(plan.TargetLineUUID, plan.PreviousTargetLineUUID)
		if target != "" {
			metadata["target_line_uuid"] = target
		}
	}
	return metadata
}

func lineChainPlanAudit(p principal, approval model.Approval) model.AuditEvent {
	return model.AuditEvent{ID: lineChainAuditID("plan", approval.ID, ""), At: approval.CreatedAt, ActorID: p.ActorID, TokenID: p.TokenID,
		NodeID: approval.NodeID, Action: "linechain.plan", Scope: "network:plan", Decision: "allow", CorrelationID: p.CorrelationID,
		Metadata: lineChainAuditMetadata(approval, "")}
}

func lineChainApproveAudit(p principal, approval model.Approval, taskID string) model.AuditEvent {
	return model.AuditEvent{ID: lineChainAuditID("approve", approval.ID, taskID), At: approval.UpdatedAt, ActorID: p.ActorID, TokenID: p.TokenID,
		NodeID: approval.NodeID, Action: "linechain.approve", Scope: approvalDecisionAuditScope(approval), Decision: "allow", CorrelationID: p.CorrelationID,
		Metadata: lineChainAuditMetadata(approval, taskID)}
}

func lineChainFailedAudit(p principal, approval model.Approval, taskID, code, reason string) model.AuditEvent {
	metadata := lineChainAuditMetadata(approval, taskID)
	metadata["error_code"] = code
	return model.AuditEvent{ID: lineChainAuditID("failed", approval.ID, taskID+"\x00"+code), At: time.Now().UTC(), ActorID: p.ActorID, TokenID: p.TokenID,
		NodeID: approval.NodeID, Action: "linechain.failed", Scope: approvalDecisionAuditScope(approval), Decision: "deny", Reason: reason,
		CorrelationID: p.CorrelationID, Metadata: metadata}
}

func (s *Server) lineChainTerminalAudit(approval model.Approval, task model.Task, result model.TaskResult, status, driftCode string) model.AuditEvent {
	auditID := lineChainAuditID("terminal", approval.ID, task.ID+"\x00"+result.NodeID)
	action, decision, reason := "linechain.apply", "allow", ""
	if result.ExitCode != 0 || result.Error != "" {
		action, decision, reason = "linechain.failed", "deny", "host apply failed"
	} else if approval.Method == lineChainRemoveMethod {
		action = "linechain.remove"
	} else if status == store.LineChainStatusDrifted {
		action, reason = "linechain.drift", driftCode
	}
	return model.AuditEvent{ID: auditID, At: result.FinishedAt, ActorID: task.ActorID, TokenID: task.TokenID, NodeID: approval.NodeID,
		Action: action, Scope: "network:apply", Decision: decision, Reason: reason, Metadata: lineChainAuditMetadata(approval, task.ID)}
}

func (s *Server) ensureLineChainTerminalAudit(approval model.Approval, task model.Task, result model.TaskResult) error {
	auditID := lineChainAuditID("terminal", approval.ID, task.ID+"\x00"+result.NodeID)
	event, ok := s.store.AuditEventByID(auditID)
	if !ok {
		return errors.New("committed line chain terminal audit is missing")
	}
	return s.appendRequiredLineChainAudit(event)
}

func (s *Server) ensureLineChainReconciliationAudits(nodeID string) error {
	for _, definition := range s.store.LineChainSnapshot().Definitions {
		if definition.SourceNodeID != nodeID || (definition.Status != store.LineChainStatusConverged && definition.Status != store.LineChainStatusDrifted) {
			continue
		}
		event := lineChainReconciliationAudit(definition)
		if err := s.appendRequiredLineChainAudit(event); err != nil {
			return err
		}
	}
	return nil
}

func lineChainReconciliationAudit(definition store.LineChainDefinition) model.AuditEvent {
	action, decision := "linechain.apply", "allow"
	if definition.TargetLineUUID == "" {
		action = "linechain.remove"
	}
	if definition.Status == store.LineChainStatusDrifted {
		action, decision = "linechain.drift", "deny"
	}
	metadata := map[string]string{"approval_id": definition.ApprovalID, "task_id": definition.TaskID, "artifact_sha256": definition.ArtifactSHA256,
		"source_line_uuid": definition.SourceLineUUID}
	if definition.AuditTargetLineUUID != "" {
		metadata["target_line_uuid"] = definition.AuditTargetLineUUID
	}
	return model.AuditEvent{ID: lineChainAuditID("observe", definition.ApprovalID, definition.Status+"\x00"+definition.DriftCode), At: definition.UpdatedAt,
		ActorID: definition.ActorID, TokenID: definition.TokenID, NodeID: definition.SourceNodeID, Action: action, Scope: "network:apply", Decision: decision,
		Reason: definition.DriftCode, Metadata: metadata}
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
	current := chainSnapshot.Definitions[source.LineUUID]
	expectedDownstream := ""
	if current.TargetLineUUID != "" {
		observed := strings.ToLower(strings.TrimSpace(source.DownstreamLineUUID))
		if observed != "" && observed != strings.ToLower(current.TargetLineUUID) {
			return lineChainCompiledArtifact{}, errors.New("observed source chain conflicts with committed baseline")
		}
		expectedDownstream = current.TargetLineUUID
	} else if strings.TrimSpace(source.DownstreamLineUUID) != "" {
		return lineChainCompiledArtifact{}, errors.New("true create requires an unclaimed source chain declaration")
	}
	_, sidecarPatch, sidecarPatchSHA, err := canonicalLineChainSidecarPatch(source.LineUUID, source.Tag, expectedDownstream, target.LineUUID)
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	agentOperation := "create"
	if current.FragmentSHA256 != "" {
		agentOperation = "replace"
	}
	combined, err := canonicalLineChainArtifact(agentOperation, lineChainFragmentPath(source.LineUUID), current.FragmentSHA256, fragment.SHA256, sidecarPatchSHA)
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	requestBinding, _ := json.Marshal(struct {
		Request          lineChainCompileRequest `json:"request"`
		SourceLineHashID string                  `json:"source_line_hash_id"`
		TargetDefinition string                  `json:"target_definition_digest"`
		TargetCredential string                  `json:"target_credential_digest"`
		Artifact         string                  `json:"artifact_sha256"`
	}{req, source.LineHashID, digestManagedLineDefinition(definition), digestText(credential.UUID), combined})
	sourceNodeLabel := firstNonEmpty(strings.TrimSpace(snapshot.Nodes[source.NodeID].Name), source.NodeID)
	plan := lineChainPlan{
		Operation: "set", SourceLineUUID: source.LineUUID, TargetLineUUID: target.LineUUID,
		SourceNodeID: source.NodeID, TargetNodeID: target.NodeID, SourceLabel: source.Name, TargetLabel: target.Name,
		SourceInboundTag: source.Tag, OutboundTag: outboundTag, FragmentPath: lineChainFragmentPath(source.LineUUID),
		TargetHost: targetHost, TargetPort: definition.Port, Protocol: model.ProxyProtocolVLESS, SNI: definition.SNI,
		PublicKeyFingerprint: shortFingerprint(definition.RealityPublicKey), ShortIDFingerprint: shortFingerprint(definition.ShortID),
		FragmentSHA256: fragment.SHA256, SidecarPatchSHA256: sidecarPatchSHA, ArtifactSHA256: combined,
		RequestSHA256:   digestText(string(requestBinding)),
		PreflightChecks: []string{"source_identity", "target_managed_applied", "target_credential", "consumer_capability", "distinct_nodes"},
		Summary:         fmt.Sprintf("Route %s on %s through managed target %s", source.Name, sourceNodeLabel, target.Name),
	}
	if current.SourceLineUUID != "" {
		plan.PreviousTargetLineUUID = current.TargetLineUUID
		plan.PreviousArtifactSHA256 = current.ArtifactSHA256
	}
	candidateDefinition := store.LineChainDefinition{SourceLineUUID: source.LineUUID, SourceNodeID: source.NodeID, SourceLineHashID: source.LineHashID,
		SourceInboundTag: source.Tag, TargetLineUUID: target.LineUUID, TargetNodeID: target.NodeID,
		TargetDefinitionDigest: digestManagedLineDefinition(definition), TargetPublicMaterialDigest: digestText(definition.RealityPublicKey + "\x00" + definition.ShortID),
		TargetCredentialDigest: digestText(credential.UUID), OutboundTag: outboundTag, FragmentPath: lineChainFragmentPath(source.LineUUID),
		FragmentSHA256: fragment.SHA256, SidecarPatchSHA256: sidecarPatchSHA, ArtifactSHA256: combined}
	return lineChainCompiledArtifact{
		Plan: plan, FragmentJSON: fragment.JSON, SidecarPatchJSON: sidecarPatch, TargetCredentialUUID: credential.UUID,
		TargetPublicKey: definition.RealityPublicKey, TargetShortID: definition.ShortID, TargetDefinition: definition,
		BaseGeneration: current.Generation, PlanGraphRevision: chainSnapshot.Revision, PreviousFragmentSHA256: current.FragmentSHA256,
		CandidateDefinition: candidateDefinition,
	}, nil
}

func digestManagedLineDefinition(definition managedLineDef) string {
	public, private := splitManagedLineRecord(definition)
	raw, _ := json.Marshal(struct {
		Public  any `json:"public"`
		Private any `json:"private"`
	}{public, private})
	return digestText(string(raw))
}

func (s *Server) compileLineChainRemove(sourceUUID string) (lineChainCompiledArtifact, error) {
	snapshot, err := s.captureLineChainCompileSnapshot()
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	return s.compileLineChainRemoveSnapshot(snapshot, sourceUUID)
}

func (s *Server) compileLineChainRemoveSnapshot(snapshot lineChainCompileSnapshot, sourceUUID string) (lineChainCompiledArtifact, error) {
	sourceUUID = strings.ToLower(strings.TrimSpace(sourceUUID))
	if !validLineUUIDv4(sourceUUID) {
		return lineChainCompiledArtifact{}, errors.New("source_line_uuid must be UUIDv4")
	}
	current, ok := snapshot.Chains.Definitions[sourceUUID]
	if !ok || current.TargetLineUUID == "" {
		return lineChainCompiledArtifact{}, errors.New("source has no committed chain to remove")
	}
	matches := snapshot.Lines[sourceUUID]
	if len(matches) != 1 || matches[0].NodeID != current.SourceNodeID || matches[0].Tag == "" {
		return lineChainCompiledArtifact{}, errors.New("committed source line is unavailable")
	}
	source := matches[0]
	if !snapshot.Capabilities[source.NodeID] {
		return lineChainCompiledArtifact{}, errors.New("source node does not advertise durable-task-result-v1")
	}
	observed := strings.ToLower(strings.TrimSpace(source.DownstreamLineUUID))
	if observed != "" && observed != strings.ToLower(current.TargetLineUUID) {
		return lineChainCompiledArtifact{}, errors.New("observed source chain conflicts with committed baseline")
	}
	_, sidecarPatch, sidecarPatchSHA, err := canonicalLineChainSidecarPatch(sourceUUID, source.Tag, current.TargetLineUUID, "")
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	artifactSHA, err := canonicalLineChainArtifact("remove", current.FragmentPath, current.FragmentSHA256, "", sidecarPatchSHA)
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	requestSHA := digestText("remove\x00" + sourceUUID + "\x00" + current.ArtifactSHA256 + "\x00" + artifactSHA)
	return lineChainCompiledArtifact{Plan: lineChainPlan{
		Operation: "remove", SourceLineUUID: sourceUUID, SourceNodeID: source.NodeID, SourceLabel: source.Name,
		SourceInboundTag: source.Tag, OutboundTag: current.OutboundTag, FragmentPath: current.FragmentPath,
		SidecarPatchSHA256: sidecarPatchSHA, ArtifactSHA256: artifactSHA, RequestSHA256: requestSHA,
		PreviousTargetLineUUID: current.TargetLineUUID, PreviousArtifactSHA256: current.ArtifactSHA256,
		PreflightChecks: []string{"source_identity", "committed_baseline", "consumer_capability"},
		Summary: fmt.Sprintf("Remove managed downstream from %s on %s", source.Name,
			firstNonEmpty(strings.TrimSpace(snapshot.Nodes[source.NodeID].Name), source.NodeID)),
	}, SidecarPatchJSON: sidecarPatch, BaseGeneration: current.Generation, PlanGraphRevision: snapshot.Chains.Revision,
		PreviousFragmentSHA256: current.FragmentSHA256, CandidateDefinition: store.LineChainDefinition{
			SourceLineUUID: sourceUUID, SourceNodeID: source.NodeID, SourceLineHashID: source.LineHashID, SourceInboundTag: source.Tag,
			OutboundTag: current.OutboundTag, FragmentPath: current.FragmentPath, SidecarPatchSHA256: sidecarPatchSHA, ArtifactSHA256: artifactSHA,
		}}, nil
}

type lineChainAgentDocumentV2 struct {
	Version                int                   `json:"version"`
	DurableProtocol        string                `json:"durable_protocol"`
	Operation              string                `json:"operation"`
	FragmentBasename       string                `json:"fragment_basename"`
	Fragment               *string               `json:"fragment"`
	SidecarPatch           lineChainSidecarPatch `json:"sidecar_patch"`
	PreviousFragmentSHA256 *string               `json:"previous_fragment_sha256"`
	FragmentSHA256         *string               `json:"fragment_sha256"`
	SidecarPatchSHA256     string                `json:"sidecar_patch_sha256"`
	ArtifactSHA256         string                `json:"artifact_sha256"`
}

type lineChainCrossContractFixtureV2 struct {
	Schema                 string                   `json:"schema"`
	ApprovalArtifactSHA256 string                   `json:"approval_artifact_sha256"`
	RequestSHA256          string                   `json:"request_sha256"`
	TaskScriptSHA256       string                   `json:"task_script_sha256"`
	TaskID                 string                   `json:"task_id"`
	LeaseID                string                   `json:"lease_id"`
	Document               lineChainAgentDocumentV2 `json:"document"`
}

func lineChainApplyScript(compiled lineChainCompiledArtifact) (string, error) {
	operation := "create"
	var fragment *string
	var fragmentSHA *string
	var previousFragmentSHA *string
	if compiled.Plan.Operation == store.LineChainOperationRemove {
		operation = "remove"
	} else {
		fragment = &compiled.FragmentJSON
		fragmentSHA = &compiled.Plan.FragmentSHA256
		if compiled.PreviousFragmentSHA256 != "" {
			operation = "replace"
		}
	}
	if compiled.PreviousFragmentSHA256 != "" {
		previousFragmentSHA = &compiled.PreviousFragmentSHA256
	}
	var patch lineChainSidecarPatch
	if err := json.Unmarshal([]byte(compiled.SidecarPatchJSON), &patch); err != nil {
		return "", fmt.Errorf("decode canonical sidecar patch: %w", err)
	}
	doc := lineChainAgentDocumentV2{Version: 2, DurableProtocol: lineChainDurableProtocol, Operation: operation, FragmentBasename: compiled.Plan.FragmentPath,
		Fragment: fragment, SidecarPatch: patch, PreviousFragmentSHA256: previousFragmentSHA,
		FragmentSHA256: fragmentSHA, SidecarPatchSHA256: compiled.Plan.SidecarPatchSHA256, ArtifactSHA256: compiled.Plan.ArtifactSHA256}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	script := "# lattice-linechain-e3-v2\nset -eu\n: \"${LATTICE_AGENT_BIN:?}\" \"${LATTICE_LINECHAIN_TXN_DIR:?}\"\nprintf '%s' '" + encoded + "' | base64 -d | \"$LATTICE_AGENT_BIN\" -linechain-apply\n"
	if fixturePath := strings.TrimSpace(os.Getenv("LATTICE_LINECHAIN_FIXTURE_OUT")); fixturePath != "" {
		fixture := lineChainCrossContractFixtureV2{
			Schema: "lattice.linechain.cross-contract-fixture.v2", ApprovalArtifactSHA256: compiled.Plan.ArtifactSHA256,
			RequestSHA256: compiled.Plan.RequestSHA256, TaskScriptSHA256: digestText(script),
			TaskID: "task-linechain-cross-contract-v2", LeaseID: "lease-linechain-cross-contract-v2", Document: doc,
		}
		fixtureRaw, err := json.Marshal(fixture)
		if err != nil {
			return "", fmt.Errorf("encode line-chain fixture: %w", err)
		}
		if err := os.WriteFile(fixturePath, append(fixtureRaw, '\n'), 0o600); err != nil {
			return "", fmt.Errorf("write line-chain fixture: %w", err)
		}
	}
	return script, nil
}

func isLineChainApproval(approval model.Approval) bool {
	return approval.Plugin == lineChainPlugin && approval.Service == lineChainService &&
		(approval.Method == lineChainSetMethod || approval.Method == lineChainRemoveMethod) && strings.HasPrefix(approval.Action, lineChainActionPrefix)
}

func (s *Server) validateLineChainApprovalForQueue(approval model.Approval) (lineChainCompiledArtifact, string, error) {
	var reviewed lineChainPlan
	if err := json.Unmarshal([]byte(approval.Plan), &reviewed); err != nil {
		return lineChainCompiledArtifact{}, "", err
	}
	var compiled lineChainCompiledArtifact
	var err error
	if reviewed.Operation == store.LineChainOperationRemove {
		compiled, err = s.compileLineChainRemove(reviewed.SourceLineUUID)
	} else {
		compiled, err = s.compileLineChain(lineChainCompileRequest{SourceLineUUID: reviewed.SourceLineUUID, TargetLineUUID: reviewed.TargetLineUUID})
	}
	if err != nil {
		return lineChainCompiledArtifact{}, "", err
	}
	if compiled.Plan.ArtifactSHA256 != approval.ArtifactDigest || compiled.Plan.RequestSHA256 != approval.RequestSHA256 ||
		approval.Action != lineChainActionPrefix+compiled.Plan.ArtifactSHA256 {
		return lineChainCompiledArtifact{}, "", errors.New("line chain inputs changed after review")
	}
	script, err := lineChainApplyScript(compiled)
	return compiled, script, err
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
	attempt := store.LineChainAttempt{
		ApprovalID: approval.ID, Operation: operation, SourceLineUUID: compiled.Plan.SourceLineUUID,
		SourceNodeID: compiled.Plan.SourceNodeID, CandidateTargetLineUUID: compiled.Plan.TargetLineUUID,
		CandidateTargetNodeID: compiled.Plan.TargetNodeID, BaseGeneration: compiled.BaseGeneration,
		BaseArtifactSHA256: compiled.Plan.PreviousArtifactSHA256, CandidateArtifactSHA256: compiled.Plan.ArtifactSHA256,
		RequestSHA256: compiled.Plan.RequestSHA256, PlanGraphRevision: compiled.PlanGraphRevision, CandidateDefinition: compiled.CandidateDefinition,
	}
	planAudit := lineChainPlanAudit(p, approval)
	planned, deduped, err := s.store.PlanLineChainApproval(attempt, approval, planAudit)
	if err != nil {
		return model.Approval{}, err
	}
	if deduped {
		existing, ok := s.store.Approval(planned.ApprovalID)
		if !ok {
			return model.Approval{}, errors.New("deduplicated line chain approval is missing")
		}
		storedAudit, ok := s.store.AuditEventByID(lineChainAuditID("plan", existing.ID, ""))
		if !ok {
			return existing, errors.New("deduplicated line chain plan audit is missing")
		}
		if err := s.appendRequiredLineChainAudit(storedAudit); err != nil {
			return existing, err
		}
		return existing, nil
	}
	if err := s.appendRequiredLineChainAudit(planAudit); err != nil {
		return approval, err
	}
	return approval, nil
}

func (s *Server) validateLineChainFirstLease(persistent store.LineChainCompileStateSnapshot, approval model.Approval, attempt store.LineChainAttempt, task model.Task) error {
	snapshot, err := s.captureLineChainCompileSnapshotFromState(persistent)
	if err != nil {
		return err
	}
	var reviewed lineChainPlan
	if err := json.Unmarshal([]byte(approval.Plan), &reviewed); err != nil {
		return fmt.Errorf("decode reviewed line chain plan: %w", err)
	}
	var compiled lineChainCompiledArtifact
	if attempt.Operation == store.LineChainOperationRemove {
		compiled, err = s.compileLineChainRemoveSnapshot(snapshot, attempt.SourceLineUUID)
	} else {
		compiled, err = s.compileLineChainSnapshot(snapshot, lineChainCompileRequest{SourceLineUUID: attempt.SourceLineUUID, TargetLineUUID: attempt.CandidateTargetLineUUID})
	}
	if err != nil {
		return err
	}
	if compiled.Plan.ArtifactSHA256 != approval.ArtifactDigest || compiled.Plan.RequestSHA256 != approval.RequestSHA256 ||
		approval.Action != lineChainActionPrefix+compiled.Plan.ArtifactSHA256 || compiled.Plan.ArtifactSHA256 != attempt.CandidateArtifactSHA256 ||
		compiled.BaseGeneration != attempt.BaseGeneration || compiled.PlanGraphRevision != persistent.Chains.Revision || reviewed.ArtifactSHA256 != compiled.Plan.ArtifactSHA256 {
		return errors.New("reviewed line chain artifact no longer matches live inputs")
	}
	if task.ApprovalID != approval.ID || len(task.Targets) != 1 || task.Targets[0] != attempt.SourceNodeID {
		return errors.New("line chain task binding changed")
	}
	expectedScript, err := lineChainApplyScript(compiled)
	if err != nil || task.Script != expectedScript {
		return errors.New("line chain task script no longer matches live artifact")
	}
	return nil
}

func (s *Server) handleLineChainTaskResult(approval model.Approval, task model.Task, result model.TaskResult) error {
	terminalError := result.Error
	if terminalError == "" && result.ExitCode != 0 {
		terminalError = fmt.Sprintf("line chain task exited %d", result.ExitCode)
	}
	committed, err := s.store.CompleteLineChainTaskResultClassified(result, approval, terminalError,
		func(persistent store.LineChainCompileStateSnapshot, _ store.LineChainAttempt) (string, string, func(), error) {
			s.singboxInvMu.RLock()
			s.agentCapabilitiesMu.RLock()
			release := func() {
				s.agentCapabilitiesMu.RUnlock()
				s.singboxInvMu.RUnlock()
			}
			snapshot, err := s.captureLineChainCompileSnapshotFromStateLocked(persistent)
			if err != nil {
				return store.LineChainStatusDrifted, "inputs_changed", release, nil
			}
			status, code, err := s.classifyLineChainTerminalCompiledSnapshot(snapshot, approval.ID)
			return status, code, release, err
		},
		func(status, code string) model.AuditEvent {
			return s.lineChainTerminalAudit(approval, task, result, status, code)
		})
	if committed && err != nil {
		s.logger.Printf("line chain terminal result committed with degraded durability: %v", err)
	}
	if err != nil {
		return err
	}
	return s.ensureLineChainTerminalAudit(approval, task, result)
}

func (s *Server) classifyLineChainTerminal(approvalID string) (string, string, error) {
	return s.classifyLineChainTerminalSnapshot(s.store.LineChainCompileStateSnapshot(), approvalID)
}

func (s *Server) classifyLineChainTerminalSnapshot(persistent store.LineChainCompileStateSnapshot, approvalID string) (string, string, error) {
	snapshot, err := s.captureLineChainCompileSnapshotFromState(persistent)
	if err != nil {
		return store.LineChainStatusDrifted, "inputs_changed", nil
	}
	return s.classifyLineChainTerminalCompiledSnapshot(snapshot, approvalID)
}

func (s *Server) classifyLineChainTerminalCompiledSnapshot(snapshot lineChainCompileSnapshot, approvalID string) (string, string, error) {
	attempt, ok := snapshot.Chains.Attempts[approvalID]
	if !ok {
		return "", "", store.ErrLineChainAttemptNotFound
	}
	frozen := attempt.CandidateDefinition
	source := snapshot.Lines[attempt.SourceLineUUID]
	if len(source) != 1 {
		return store.LineChainStatusDrifted, "source_missing", nil
	}
	if source[0].NodeID != frozen.SourceNodeID || source[0].LineHashID != frozen.SourceLineHashID || source[0].Tag != frozen.SourceInboundTag {
		return store.LineChainStatusDrifted, "inputs_changed", nil
	}
	if attempt.Operation == store.LineChainOperationRemove {
		base := snapshot.Chains.Definitions[attempt.SourceLineUUID]
		if base.Generation != attempt.BaseGeneration || base.ArtifactSHA256 != attempt.BaseArtifactSHA256 {
			return store.LineChainStatusDrifted, "inputs_changed", nil
		}
		return store.LineChainStatusAppliedUnobserved, "", nil
	}
	if _, ok := snapshot.Nodes[frozen.TargetNodeID]; !ok || len(snapshot.Lines[frozen.TargetLineUUID]) != 1 {
		return store.LineChainStatusDrifted, "target_missing", nil
	}
	if _, ok := snapshot.Definitions[frozen.TargetLineUUID]; !ok {
		return store.LineChainStatusDrifted, "inputs_changed", nil
	}
	compiled, err := s.compileLineChainSnapshot(snapshot, lineChainCompileRequest{SourceLineUUID: attempt.SourceLineUUID, TargetLineUUID: attempt.CandidateTargetLineUUID})
	if err != nil || !sameLineChainCandidate(compiled.CandidateDefinition, frozen) {
		return store.LineChainStatusDrifted, "inputs_changed", nil
	}
	return store.LineChainStatusAppliedUnobserved, "", nil
}

func sameLineChainCandidate(a, b store.LineChainDefinition) bool {
	return a.SourceLineUUID == b.SourceLineUUID && a.SourceNodeID == b.SourceNodeID && a.SourceLineHashID == b.SourceLineHashID &&
		a.SourceInboundTag == b.SourceInboundTag && a.TargetLineUUID == b.TargetLineUUID && a.TargetNodeID == b.TargetNodeID &&
		a.TargetDefinitionDigest == b.TargetDefinitionDigest && a.TargetPublicMaterialDigest == b.TargetPublicMaterialDigest &&
		a.TargetCredentialDigest == b.TargetCredentialDigest && a.OutboundTag == b.OutboundTag && a.FragmentPath == b.FragmentPath &&
		a.FragmentSHA256 == b.FragmentSHA256 && a.SidecarPatchSHA256 == b.SidecarPatchSHA256 && a.ArtifactSHA256 == b.ArtifactSHA256
}

func (s *Server) reconcileLineChainsForNode(nodeID string) error {
	snapshot, err := s.captureLineChainCompileSnapshot()
	if err != nil {
		return err
	}
	observations := make(map[string]store.LineChainObservation)
	for sourceUUID, definition := range snapshot.Chains.Definitions {
		if definition.SourceNodeID != nodeID {
			continue
		}
		observation := store.LineChainObservation{}
		if lines := snapshot.Lines[sourceUUID]; len(lines) == 1 {
			observation.OutboundTag = strings.TrimSpace(lines[0].OutboundRef)
			observation.DownstreamLineUUID = strings.TrimSpace(lines[0].DownstreamLineUUID)
		}
		observations[sourceUUID] = observation
	}
	_, err = s.store.ReconcileLineChainsWithAudits(observations, func(definition store.LineChainDefinition) (model.AuditEvent, bool) {
		if definition.ApprovalID == "" || definition.TaskID == "" {
			return model.AuditEvent{}, false
		}
		return lineChainReconciliationAudit(definition), true
	})
	if err != nil {
		return err
	}
	return s.ensureLineChainReconciliationAudits(nodeID)
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
	view, err := s.lineChainViews()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type lineChainCurrentView struct {
	TargetLineUUID string `json:"target_line_uuid,omitempty"`
	TargetNodeID   string `json:"target_node_id,omitempty"`
	ArtifactDigest string `json:"artifact_digest"`
	Status         string `json:"status"`
}

type lineChainAttemptView struct {
	Operation               string `json:"operation"`
	CandidateTargetLineUUID string `json:"candidate_target_line_uuid,omitempty"`
	ApprovalID              string `json:"approval_id"`
	CandidateArtifactDigest string `json:"candidate_artifact_digest,omitempty"`
	Status                  string `json:"status"`
	ErrorCode               string `json:"error_code,omitempty"`
	Error                   string `json:"error,omitempty"`
}

type lineChainView struct {
	SourceLineUUID             string                `json:"source_line_uuid"`
	SourceNodeID               string                `json:"source_node_id"`
	Status                     string                `json:"status"`
	Current                    *lineChainCurrentView `json:"current"`
	Attempt                    *lineChainAttemptView `json:"attempt"`
	ObservedOutboundTag        string                `json:"observed_outbound_tag,omitempty"`
	ObservedDownstreamLineUUID string                `json:"observed_downstream_line_uuid,omitempty"`
	LastError                  string                `json:"last_error,omitempty"`
}

type lineChainListView struct {
	Chains []lineChainView `json:"chains"`
}

func (s *Server) lineChainViews() (lineChainListView, error) {
	snapshot, err := s.captureLineChainCompileSnapshot()
	if err != nil {
		return lineChainListView{}, err
	}
	bySource := make(map[string]lineChainView)
	for source, definition := range snapshot.Chains.Definitions {
		row := bySource[source]
		row.SourceLineUUID, row.SourceNodeID, row.Status = source, definition.SourceNodeID, definition.Status
		row.Current = &lineChainCurrentView{TargetLineUUID: definition.TargetLineUUID, TargetNodeID: definition.TargetNodeID, ArtifactDigest: definition.ArtifactSHA256, Status: definition.Status}
		row.LastError = definition.DriftCode
		bySource[source] = row
	}
	for _, attempt := range snapshot.Chains.Attempts {
		row := bySource[attempt.SourceLineUUID]
		row.SourceLineUUID, row.SourceNodeID, row.Status = attempt.SourceLineUUID, attempt.SourceNodeID, attempt.Status
		operation := publicLineChainOperation(attempt)
		publicError := redactLineChainError(attempt.LastError, snapshot)
		row.Attempt = &lineChainAttemptView{Operation: operation, CandidateTargetLineUUID: attempt.CandidateTargetLineUUID,
			ApprovalID: attempt.ApprovalID, CandidateArtifactDigest: attempt.CandidateArtifactSHA256, Status: attempt.Status,
			ErrorCode: attempt.LastErrorCode, Error: publicError}
		if publicError != "" {
			row.LastError = publicError
		}
		bySource[attempt.SourceLineUUID] = row
	}
	chains := make([]lineChainView, 0, len(bySource))
	for source, row := range bySource {
		if lines := snapshot.Lines[source]; len(lines) == 1 {
			row.ObservedOutboundTag = lines[0].OutboundRef
			row.ObservedDownstreamLineUUID = lines[0].DownstreamLineUUID
		}
		chains = append(chains, row)
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].SourceLineUUID < chains[j].SourceLineUUID })
	return lineChainListView{Chains: chains}, nil
}

func publicLineChainOperation(attempt store.LineChainAttempt) string {
	if attempt.Operation == store.LineChainOperationSet && attempt.BaseGeneration > 0 {
		return "replace"
	}
	return attempt.Operation
}

func redactLineChainError(message string, snapshot lineChainCompileSnapshot) string {
	if len(message) > 512 {
		message = message[:512]
	}
	secrets := make([]string, 0)
	for _, user := range snapshot.Users {
		secrets = append(secrets, user.SubID)
		for _, credential := range user.Credentials {
			secrets = append(secrets, credential.UUID, credential.Password)
		}
	}
	for _, definition := range snapshot.Definitions {
		secrets = append(secrets, definition.RealityPrivateKey)
	}
	for _, secret := range secrets {
		if strings.TrimSpace(secret) != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return message
}

func (s *Server) vpnCoreLineChainsRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "chains":
		view, err := s.lineChainViews()
		if err != nil {
			return nil, err
		}
		return json.Marshal(view)
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
