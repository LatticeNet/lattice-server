package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func decodeStrictGraphSubscriptionRequest(raw []byte, out *graphSubscriptionRequest) error {
	if len(bytes.TrimSpace(raw)) == 0 || len(raw) > model.MaxSubscriptionResponseBytes {
		return errors.New("invalid request")
	}
	if err := scanUniqueJSONValue(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("invalid trailing JSON")
	}
	return nil
}

func scanUniqueJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate or invalid JSON field")
			}
			seen[key] = true
			if err := scanUniqueJSONValue(dec); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for dec.More() {
			if err := scanUniqueJSONValue(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token()
	return err
}

type graphSubscriptionRequest struct {
	SchemaVersion int      `json:"schema_version"`
	IdentityID    string   `json:"identity_id"`
	EntryRoots    []string `json:"entry_roots"`
}

type graphSubscriptionError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type graphSubscriptionResponse struct {
	SchemaVersion  int                     `json:"schema_version"`
	OK             bool                    `json:"ok"`
	SourceVersion  string                  `json:"source_version,omitempty"`
	SourceManifest json.RawMessage         `json:"source_manifest,omitempty"`
	Entries        []string                `json:"entries,omitempty"`
	Raw            string                  `json:"raw,omitempty"`
	Error          *graphSubscriptionError `json:"error,omitempty"`
}

type graphComposeFailure struct{ code string }

func (e graphComposeFailure) Error() string { return e.code }

func composeFailure(code string) error { return graphComposeFailure{code: code} }

func composeFailureView(err error) *graphSubscriptionError {
	var failure graphComposeFailure
	if !errors.As(err, &failure) {
		failure.code = "compose_failed"
	}
	messages := map[string]string{
		"invalid_request":      "The compose request is invalid.",
		"identity_unavailable": "The selected identity is unavailable.",
		"root_unavailable":     "A selected entry root is unavailable.",
		"graph_busy":           "A selected route has an active change.",
		"graph_not_converged":  "A selected route is not converged.",
		"graph_undeclared":     "A selected route is not fully declared.",
		"graph_drifted":        "Observed routing does not match the committed route.",
		"graph_cycle":          "The selected routes contain a cycle.",
		"unsupported_line":     "A selected route contains an unsupported line.",
		"bounds_exceeded":      "The composed subscription exceeds a safety limit.",
		"compose_failed":       "The subscription could not be composed.",
	}
	return &graphSubscriptionError{Code: failure.code, Message: messages[failure.code]}
}

func composeGraphSubscription(snapshot lineChainCompileSnapshot, req graphSubscriptionRequest, now time.Time) (graphSubscriptionResponse, error) {
	identityID := strings.TrimSpace(req.IdentityID)
	if req.SchemaVersion != 1 || identityID == "" || identityID != req.IdentityID || len(req.EntryRoots) == 0 {
		return graphSubscriptionResponse{}, composeFailure("invalid_request")
	}
	if len(req.EntryRoots) > model.MaxSubscriptionSourceRoots {
		return graphSubscriptionResponse{}, composeFailure("bounds_exceeded")
	}
	identity, ok := snapshot.Users[identityID]
	if !ok || !identity.Enabled || (!identity.ExpiresAt.IsZero() && !now.Before(identity.ExpiresAt)) || identity.SubscriptionGeneration == 0 {
		return graphSubscriptionResponse{}, composeFailure("identity_unavailable")
	}
	credential, ok := vpnCredentialForProtocol(identity.Credentials, "vless")
	if !ok || credential.UUID == "" {
		return graphSubscriptionResponse{}, composeFailure("identity_unavailable")
	}
	activeSources := make(map[string]bool)
	for _, attempt := range snapshot.Chains.Attempts {
		if attempt.Status == store.LineChainStatusPlanned || attempt.Status == store.LineChainStatusApplying {
			activeSources[strings.ToLower(attempt.SourceLineUUID)] = true
		}
	}
	bound := make(map[string]bool)
	for _, binding := range identity.Bindings {
		if binding.Enabled {
			bound[binding.LineHashID] = true
		}
	}
	seenRoots := make(map[string]bool, len(req.EntryRoots))
	totalTraversalVisits := 0
	manifest := model.SubscriptionSourceManifestV1{
		Schema: model.SubscriptionSourceManifestSchemaV1, Renderer: model.SubscriptionSourceRendererV1,
		Identity:   model.SubscriptionSourceManifestIdentity{ID: identityID, Generation: identity.SubscriptionGeneration},
		EntryRoots: make([]string, 0, len(req.EntryRoots)), Entries: make([]model.SubscriptionSourceManifestEntry, 0, len(req.EntryRoots)),
	}
	entries := make([]string, 0, len(req.EntryRoots))
	rawBytes := 0
	for _, requestedRoot := range req.EntryRoots {
		root := strings.TrimSpace(requestedRoot)
		if root != requestedRoot || root != strings.ToLower(root) || !validLineUUIDv4(root) || seenRoots[root] {
			return graphSubscriptionResponse{}, composeFailure("invalid_request")
		}
		if strings.EqualFold(root, credential.UUID) {
			return graphSubscriptionResponse{}, composeFailure("invalid_request")
		}
		seenRoots[root] = true
		manifest.EntryRoots = append(manifest.EntryRoots, root)
		rootLine, rootDefinition, err := composeLine(snapshot, root)
		if err != nil {
			return graphSubscriptionResponse{}, err
		}
		if !bound[rootLine.LineHashID] {
			return graphSubscriptionResponse{}, composeFailure("identity_unavailable")
		}
		host := firstNonEmpty(rootLine.PublicHost, strings.TrimSpace(snapshot.Nodes[rootLine.NodeID].PublicIP))
		endpoint, err := proxycore.NewVLESSRealityEndpoint(proxycore.VLESSRealityEndpointOptions{
			Label: rootLine.Name, Tag: rootLine.Tag, NodeID: rootLine.NodeID, InboundID: root,
			Server: host, ServerPort: rootDefinition.Port, UUID: credential.UUID, Flow: firstNonEmpty(credential.Flow, "xtls-rprx-vision"),
			SNI: rootDefinition.SNI, Fingerprint: "chrome", PublicKey: rootDefinition.RealityPublicKey, ShortID: rootDefinition.ShortID,
		})
		if err != nil {
			return graphSubscriptionResponse{}, composeFailure("unsupported_line")
		}
		uri := endpoint.Link()
		if len(uri) > model.MaxSubscriptionURIBytes {
			return graphSubscriptionResponse{}, composeFailure("bounds_exceeded")
		}
		rawBytes += len(uri)
		if len(entries) > 0 {
			rawBytes++
		}
		if rawBytes > model.MaxSubscriptionRawBytes {
			return graphSubscriptionResponse{}, composeFailure("bounds_exceeded")
		}
		path, terminal, err := composeDeclaredPath(snapshot, root, activeSources, &totalTraversalVisits)
		if err != nil {
			return graphSubscriptionResponse{}, err
		}
		entries = append(entries, uri)
		manifest.Entries = append(manifest.Entries, model.SubscriptionSourceManifestEntry{
			Root: root,
			Endpoint: model.SubscriptionSourceManifestEndpoint{LineUUID: root, NodeID: rootLine.NodeID, Label: rootLine.Name, Host: endpoint.Server, Port: endpoint.ServerPort,
				SNI: endpoint.SNI, Fingerprint: endpoint.Fingerprint, ALPN: append(make([]string, 0, len(endpoint.ALPN)), endpoint.ALPN...), PublicKey: endpoint.PublicKey, ShortID: endpoint.ShortID, Flow: endpoint.Flow},
			Path: path, Terminal: terminal,
		})
	}
	manifestRaw, sourceVersion, err := model.CanonicalSubscriptionSourceManifest(manifest)
	if err != nil {
		return graphSubscriptionResponse{}, composeFailure("bounds_exceeded")
	}
	return graphSubscriptionResponse{SchemaVersion: 1, OK: true, SourceVersion: sourceVersion,
		SourceManifest: manifestRaw, Entries: entries, Raw: strings.Join(entries, "\n")}, nil
}

func composeLine(snapshot lineChainCompileSnapshot, uuid string) (Line, managedLineDef, error) {
	lines := snapshot.Lines[uuid]
	definition, ok := snapshot.Definitions[uuid]
	if len(lines) != 1 || !ok {
		return Line{}, managedLineDef{}, composeFailure("root_unavailable")
	}
	line := lines[0]
	if line.Status != "ok" || line.Core != "sing-box" || line.Type != "vless" || (line.Transport != "tcp" && line.Transport != "reality") ||
		!line.Overlay || line.OverlayStatus != managedLineStatusApplied || definition.Status != managedLineStatusApplied ||
		definition.Port < 1 || definition.SNI == "" || definition.RealityPublicKey == "" || definition.ShortID == "" {
		return Line{}, managedLineDef{}, composeFailure("unsupported_line")
	}
	return line, definition, nil
}

func composeDeclaredPath(snapshot lineChainCompileSnapshot, root string, activeSources map[string]bool, totalTraversalVisits *int) ([]model.SubscriptionSourceManifestEdge, model.SubscriptionSourceManifestTerminal, error) {
	path := make([]model.SubscriptionSourceManifestEdge, 0)
	seen := make(map[string]bool)
	current := root
	for {
		*totalTraversalVisits++
		if *totalTraversalVisits > model.MaxSubscriptionSourceVisits {
			return nil, model.SubscriptionSourceManifestTerminal{}, composeFailure("bounds_exceeded")
		}
		if seen[current] {
			return nil, model.SubscriptionSourceManifestTerminal{}, composeFailure("graph_cycle")
		}
		seen[current] = true
		if activeSources[current] {
			return nil, model.SubscriptionSourceManifestTerminal{}, composeFailure("graph_busy")
		}
		line, _, err := composeLine(snapshot, current)
		if err != nil {
			return nil, model.SubscriptionSourceManifestTerminal{}, err
		}
		definition, ok := snapshot.Chains.Definitions[current]
		if !ok {
			return nil, model.SubscriptionSourceManifestTerminal{}, composeFailure("graph_undeclared")
		}
		if definition.Status != store.LineChainStatusConverged {
			return nil, model.SubscriptionSourceManifestTerminal{}, composeFailure("graph_not_converged")
		}
		observed := strings.ToLower(strings.TrimSpace(line.DownstreamLineUUID))
		target := strings.ToLower(strings.TrimSpace(definition.TargetLineUUID))
		if observed != target {
			return nil, model.SubscriptionSourceManifestTerminal{}, composeFailure("graph_drifted")
		}
		if target == "" {
			return path, model.SubscriptionSourceManifestTerminal{LineUUID: current, Generation: definition.Generation,
				ObservationRevision: definition.ObservationRevision, Status: definition.Status}, nil
		}
		path = append(path, model.SubscriptionSourceManifestEdge{Source: current, Target: target, Generation: definition.Generation,
			ObservationRevision: definition.ObservationRevision, Status: definition.Status})
		current = target
	}
}
