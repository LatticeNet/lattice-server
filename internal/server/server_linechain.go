package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
)

const (
	lineChainPlugin             = "singbox-linechain"
	lineChainService            = "network/lines"
	lineChainSetMethod          = "chain_set_apply"
	lineChainRemoveMethod       = "chain_remove_apply"
	lineChainActionPrefix       = "apply-line-chain:"
	lineChainDurableCapability  = "durable-task-result-v1"
	lineChainFragmentPathPrefix = "/etc/sing-box/conf.d/lattice-chain-"
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
	req.SourceLineUUID = strings.ToLower(strings.TrimSpace(req.SourceLineUUID))
	req.TargetLineUUID = strings.ToLower(strings.TrimSpace(req.TargetLineUUID))
	if !validLineUUIDv4(req.SourceLineUUID) || !validLineUUIDv4(req.TargetLineUUID) {
		return lineChainCompiledArtifact{}, errors.New("source_line_uuid and target_line_uuid must be UUIDv4")
	}
	if req.SourceLineUUID == req.TargetLineUUID {
		return lineChainCompiledArtifact{}, errors.New("source and target line must differ")
	}
	byUUID := make(map[string][]Line)
	for _, group := range s.buildLineGroups() {
		for _, line := range group.Lines {
			if line.LineUUID != "" {
				byUUID[strings.ToLower(line.LineUUID)] = append(byUUID[strings.ToLower(line.LineUUID)], line)
			}
		}
	}
	resolve := func(uuid string) (Line, error) {
		matches := byUUID[uuid]
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
	if !target.Overlay || target.OverlayStatus != managedLineStatusApplied || target.Status != "ok" {
		return lineChainCompiledArtifact{}, errors.New("target must be a healthy applied managed-line overlay")
	}
	if !s.agentHasCapability(source.NodeID, lineChainDurableCapability) {
		return lineChainCompiledArtifact{}, errors.New("source node does not advertise durable-task-result-v1")
	}
	definition, ok, err := s.managedLineDefByUUID(target.LineUUID)
	if err != nil {
		return lineChainCompiledArtifact{}, err
	}
	if !ok || definition.Status != managedLineStatusApplied || definition.Port < 1 || definition.SNI == "" ||
		definition.RealityPublicKey == "" || definition.ShortID == "" || definition.UserID == "" {
		return lineChainCompiledArtifact{}, errors.New("target managed-line descriptor is incomplete")
	}
	user, ok := s.getVpnUser(definition.UserID)
	if !ok || !user.Enabled {
		return lineChainCompiledArtifact{}, errors.New("target managed-line user is unavailable")
	}
	credential, ok := vpnCredentialForProtocol(user.Credentials, model.ProxyProtocolVLESS)
	if !ok || strings.TrimSpace(credential.UUID) == "" {
		return lineChainCompiledArtifact{}, errors.New("target managed-line VLESS credential is unavailable")
	}
	targetHost := firstNonEmpty(target.PublicHost, s.nodePublicHost(target.NodeID))
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
	sidecar, err := s.renderLineChainSidecar(source.NodeID, source.LineUUID, target.LineUUID)
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
	if current, ok := s.store.LineChainSnapshot().Definitions[source.LineUUID]; ok {
		plan.PreviousTargetLineUUID = current.TargetLineUUID
		plan.PreviousArtifactSHA256 = current.ArtifactSHA256
	}
	return lineChainCompiledArtifact{
		Plan: plan, FragmentJSON: fragment.JSON, SidecarJSON: string(sidecar), TargetCredentialUUID: credential.UUID,
		TargetPublicKey: definition.RealityPublicKey, TargetShortID: definition.ShortID, TargetDefinition: definition,
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
			target := targetUUID
			doc.Inbounds[i].Chain = &lineMetadataChainV2{DownstreamLineUUID: &target, DownstreamNode: ""}
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
