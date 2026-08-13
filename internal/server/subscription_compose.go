package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-server/internal/proxycore"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	graphSubscriptionRenderer         = "vpn-core-graph-v1"
	maxGraphSubscriptionRoots         = 2_048
	maxGraphSubscriptionVisited       = 10_000
	maxGraphSubscriptionURIBytes      = 4 << 10
	maxGraphSubscriptionRawBytes      = 1 << 20
	maxGraphSubscriptionManifestBytes = 1 << 20
)

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

type graphSubscriptionManifest struct {
	Schema     string                            `json:"schema"`
	Renderer   string                            `json:"renderer"`
	Identity   graphSubscriptionManifestIdentity `json:"identity"`
	EntryRoots []string                          `json:"entry_roots"`
	Entries    []graphSubscriptionManifestEntry  `json:"entries"`
}

type graphSubscriptionManifestIdentity struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
}

type graphSubscriptionManifestEntry struct {
	Root     string                            `json:"root"`
	Endpoint graphSubscriptionManifestEndpoint `json:"endpoint"`
	Path     []graphSubscriptionManifestEdge   `json:"path"`
	Terminal graphSubscriptionManifestTerminal `json:"terminal"`
}

type graphSubscriptionManifestEndpoint struct {
	LineUUID    string   `json:"line_uuid"`
	NodeID      string   `json:"node_id"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	SNI         string   `json:"sni"`
	Fingerprint string   `json:"fingerprint"`
	ALPN        []string `json:"alpn"`
	PublicKey   string   `json:"public_key"`
	ShortID     string   `json:"short_id"`
}

type graphSubscriptionManifestEdge struct {
	Source              string `json:"source"`
	Target              string `json:"target"`
	Generation          uint64 `json:"generation"`
	ObservationRevision uint64 `json:"observation_revision"`
	Status              string `json:"status"`
}

type graphSubscriptionManifestTerminal struct {
	LineUUID            string `json:"line_uuid"`
	Generation          uint64 `json:"generation"`
	ObservationRevision uint64 `json:"observation_revision"`
	Status              string `json:"status"`
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
	if req.SchemaVersion != 1 || identityID == "" || len(req.EntryRoots) == 0 || len(req.EntryRoots) > maxGraphSubscriptionRoots {
		return graphSubscriptionResponse{}, composeFailure("invalid_request")
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
	visitedAll := make(map[string]bool)
	manifest := graphSubscriptionManifest{
		Schema: "lattice.vpn-core-graph-manifest.v1", Renderer: graphSubscriptionRenderer,
		Identity:   graphSubscriptionManifestIdentity{ID: identityID, Generation: identity.SubscriptionGeneration},
		EntryRoots: make([]string, 0, len(req.EntryRoots)), Entries: make([]graphSubscriptionManifestEntry, 0, len(req.EntryRoots)),
	}
	entries := make([]string, 0, len(req.EntryRoots))
	rawBytes := 0
	for _, requestedRoot := range req.EntryRoots {
		root := strings.TrimSpace(requestedRoot)
		if root != strings.ToLower(root) || !validLineUUIDv4(root) || seenRoots[root] {
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
		if len(uri) > maxGraphSubscriptionURIBytes {
			return graphSubscriptionResponse{}, composeFailure("bounds_exceeded")
		}
		rawBytes += len(uri)
		if len(entries) > 0 {
			rawBytes++
		}
		if rawBytes > maxGraphSubscriptionRawBytes {
			return graphSubscriptionResponse{}, composeFailure("bounds_exceeded")
		}
		path, terminal, err := composeDeclaredPath(snapshot, root, activeSources, visitedAll)
		if err != nil {
			return graphSubscriptionResponse{}, err
		}
		entries = append(entries, uri)
		manifest.Entries = append(manifest.Entries, graphSubscriptionManifestEntry{
			Root: root,
			Endpoint: graphSubscriptionManifestEndpoint{LineUUID: root, NodeID: rootLine.NodeID, Host: endpoint.Server, Port: endpoint.ServerPort,
				SNI: endpoint.SNI, Fingerprint: endpoint.Fingerprint, ALPN: append([]string(nil), endpoint.ALPN...), PublicKey: endpoint.PublicKey, ShortID: endpoint.ShortID},
			Path: path, Terminal: terminal,
		})
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil || len(manifestRaw) > maxGraphSubscriptionManifestBytes {
		return graphSubscriptionResponse{}, composeFailure("bounds_exceeded")
	}
	digest := sha256.Sum256(manifestRaw)
	return graphSubscriptionResponse{SchemaVersion: 1, OK: true, SourceVersion: "sv1:" + hex.EncodeToString(digest[:]),
		SourceManifest: manifestRaw, Entries: entries, Raw: strings.Join(entries, "\n")}, nil
}

func composeLine(snapshot lineChainCompileSnapshot, uuid string) (Line, managedLineDef, error) {
	lines := snapshot.Lines[uuid]
	definition, ok := snapshot.Definitions[uuid]
	if len(lines) != 1 || !ok {
		return Line{}, managedLineDef{}, composeFailure("root_unavailable")
	}
	line := lines[0]
	if line.Status != "ok" || line.Core != "sing-box" || line.Type != "vless" || line.Transport != "tcp" ||
		!line.Overlay || line.OverlayStatus != managedLineStatusApplied || definition.Status != managedLineStatusApplied ||
		definition.Port < 1 || definition.SNI == "" || definition.RealityPublicKey == "" || definition.ShortID == "" {
		return Line{}, managedLineDef{}, composeFailure("unsupported_line")
	}
	return line, definition, nil
}

func composeDeclaredPath(snapshot lineChainCompileSnapshot, root string, activeSources, visitedAll map[string]bool) ([]graphSubscriptionManifestEdge, graphSubscriptionManifestTerminal, error) {
	path := make([]graphSubscriptionManifestEdge, 0)
	seen := make(map[string]bool)
	current := root
	for {
		if seen[current] {
			return nil, graphSubscriptionManifestTerminal{}, composeFailure("graph_cycle")
		}
		seen[current] = true
		if !visitedAll[current] {
			visitedAll[current] = true
			if len(visitedAll) > maxGraphSubscriptionVisited {
				return nil, graphSubscriptionManifestTerminal{}, composeFailure("bounds_exceeded")
			}
		}
		if activeSources[current] {
			return nil, graphSubscriptionManifestTerminal{}, composeFailure("graph_busy")
		}
		line, _, err := composeLine(snapshot, current)
		if err != nil {
			return nil, graphSubscriptionManifestTerminal{}, err
		}
		definition, ok := snapshot.Chains.Definitions[current]
		if !ok {
			return nil, graphSubscriptionManifestTerminal{}, composeFailure("graph_undeclared")
		}
		if definition.Status != store.LineChainStatusConverged {
			return nil, graphSubscriptionManifestTerminal{}, composeFailure("graph_not_converged")
		}
		observed := strings.ToLower(strings.TrimSpace(line.DownstreamLineUUID))
		target := strings.ToLower(strings.TrimSpace(definition.TargetLineUUID))
		if observed != target {
			return nil, graphSubscriptionManifestTerminal{}, composeFailure("graph_drifted")
		}
		if target == "" {
			return path, graphSubscriptionManifestTerminal{LineUUID: current, Generation: definition.Generation,
				ObservationRevision: definition.ObservationRevision, Status: definition.Status}, nil
		}
		path = append(path, graphSubscriptionManifestEdge{Source: current, Target: target, Generation: definition.Generation,
			ObservationRevision: definition.ObservationRevision, Status: definition.Status})
		current = target
	}
}
