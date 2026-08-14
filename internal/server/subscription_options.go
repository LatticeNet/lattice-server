package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type graphSubscriptionIdentityOption struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Selectable bool   `json:"selectable"`
}

type graphSubscriptionRootOption struct {
	LineUUID    string `json:"line_uuid"`
	Label       string `json:"label"`
	SourceNode  string `json:"source_node_id"`
	Source      string `json:"source"`
	TargetLabel string `json:"target_label,omitempty"`
	Status      string `json:"status"`
	PathSummary string `json:"path_summary"`
	Reason      string `json:"reason,omitempty"`
	Selectable  bool   `json:"selectable"`
}

type graphSubscriptionOptionsResponse struct {
	SchemaVersion  int                               `json:"schema_version"`
	OK             bool                              `json:"ok"`
	OptionsVersion string                            `json:"options_version,omitempty"`
	Identities     []graphSubscriptionIdentityOption `json:"identities,omitempty"`
	Roots          []graphSubscriptionRootOption     `json:"roots,omitempty"`
	Error          *graphSubscriptionError           `json:"error,omitempty"`
}

func (response graphSubscriptionOptionsResponse) Clone() graphSubscriptionOptionsResponse {
	response.Identities = append(make([]graphSubscriptionIdentityOption, 0, len(response.Identities)), response.Identities...)
	response.Roots = append(make([]graphSubscriptionRootOption, 0, len(response.Roots)), response.Roots...)
	if response.Error != nil {
		cloned := *response.Error
		response.Error = &cloned
	}
	return response
}

func decodeStrictGraphOptionsRequest(raw []byte) error {
	if len(bytes.TrimSpace(raw)) == 0 || len(raw) > model.MaxSubscriptionResponseBytes {
		return errors.New("invalid request")
	}
	if err := scanUniqueJSONValue(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var request map[string]json.RawMessage
	if err := dec.Decode(&request); err != nil || request == nil || len(request) != 0 {
		return errors.New("options request must be an empty object")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("invalid trailing JSON")
	}
	return nil
}

func graphSubscriptionOptionsFromCapture(capture func() (lineChainCompileSnapshot, error), now time.Time) (graphSubscriptionOptionsResponse, error) {
	snapshot, err := capture()
	if err != nil {
		return graphSubscriptionOptionsResponse{}, err
	}
	return graphSubscriptionOptions(snapshot, now)
}

func graphSubscriptionOptions(snapshot lineChainCompileSnapshot, now time.Time) (graphSubscriptionOptionsResponse, error) {
	identityIDs := make([]string, 0, len(snapshot.Users))
	for id := range snapshot.Users {
		identityIDs = append(identityIDs, id)
	}
	sort.Strings(identityIDs)
	if len(identityIDs) > model.MaxSubscriptionSourceVisits {
		return graphSubscriptionOptionsResponse{}, composeFailure("bounds_exceeded")
	}

	identities := make([]graphSubscriptionIdentityOption, 0, len(identityIDs))
	eligibleBindings := make(map[string]bool)
	for _, id := range identityIDs {
		identity := snapshot.Users[id]
		option := graphSubscriptionIdentityOption{ID: identity.ID, Label: safeGraphOptionLabel(firstNonEmpty(identity.Name, identity.Email, identity.ID)), Status: "eligible", Selectable: true}
		switch {
		case !identity.Enabled:
			option.Status, option.Reason, option.Selectable = "disabled", "identity_disabled", false
		case !identity.ExpiresAt.IsZero() && !now.Before(identity.ExpiresAt):
			option.Status, option.Reason, option.Selectable = "expired", "identity_expired", false
		case identity.SubscriptionGeneration == 0:
			option.Status, option.Reason, option.Selectable = "incomplete", "identity_unversioned", false
		default:
			credential, ok := vpnCredentialForProtocol(identity.Credentials, "vless")
			if !ok || credential.UUID == "" {
				option.Status, option.Reason, option.Selectable = "incomplete", "vless_credential_missing", false
			}
		}
		if option.Selectable {
			for _, binding := range identity.Bindings {
				if binding.Enabled {
					eligibleBindings[binding.LineHashID] = true
				}
			}
		}
		identities = append(identities, option)
	}

	activeSources := make(map[string]bool)
	for _, attempt := range snapshot.Chains.Attempts {
		if attempt.Status == store.LineChainStatusPlanned || attempt.Status == store.LineChainStatusApplying {
			activeSources[strings.ToLower(attempt.SourceLineUUID)] = true
		}
	}
	rootIDs := make([]string, 0, len(snapshot.Lines))
	for uuid := range snapshot.Lines {
		uuid = strings.ToLower(strings.TrimSpace(uuid))
		if validLineUUIDv4(uuid) {
			rootIDs = append(rootIDs, uuid)
		}
	}
	sort.Strings(rootIDs)
	if len(rootIDs) > model.MaxSubscriptionSourceRoots {
		return graphSubscriptionOptionsResponse{}, composeFailure("bounds_exceeded")
	}
	roots := make([]graphSubscriptionRootOption, 0, len(rootIDs))
	totalTraversalVisits := 0
	for _, uuid := range rootIDs {
		lines := snapshot.Lines[uuid]
		option := graphSubscriptionRootOption{LineUUID: uuid, Status: "unresolved", Reason: "root_unavailable"}
		if len(lines) == 1 {
			line := lines[0]
			option.Label = safeGraphOptionLabel(firstNonEmpty(line.Name, line.Tag, uuid))
			option.SourceNode = line.NodeID
			option.Source = line.Source
			option.PathSummary = option.Label
			if definition, ok := snapshot.Chains.Definitions[uuid]; ok {
				option.Status = definition.Status
				if targetLines := snapshot.Lines[strings.ToLower(definition.TargetLineUUID)]; len(targetLines) == 1 {
					option.TargetLabel = safeGraphOptionLabel(firstNonEmpty(targetLines[0].Name, targetLines[0].Tag, definition.TargetLineUUID))
				}
			}
			if _, _, err := composeLine(snapshot, uuid); err != nil {
				option.Reason = composeFailureView(err).Code
			} else if path, terminal, err := composeDeclaredPath(snapshot, uuid, activeSources, &totalTraversalVisits); err != nil {
				option.Reason = composeFailureView(err).Code
			} else if !eligibleBindings[line.LineHashID] {
				option.Reason = "identity_unavailable"
			} else {
				option.Selectable = true
				option.Reason = ""
				option.Status = store.LineChainStatusConverged
				terminalLabel := option.TargetLabel
				if terminalLines := snapshot.Lines[terminal.LineUUID]; len(terminalLines) == 1 {
					terminalLabel = safeGraphOptionLabel(firstNonEmpty(terminalLines[0].Name, terminalLines[0].Tag, terminal.LineUUID))
				}
				if terminalLabel != "" && terminalLabel != option.Label {
					option.PathSummary = option.Label + " → " + terminalLabel
				}
				if len(path) > 0 {
					option.PathSummary += " (" + graphOptionHopCount(len(path)) + ")"
				}
			}
		}
		if option.Label == "" {
			option.Label = "Unavailable line"
		}
		if option.PathSummary == "" {
			option.PathSummary = option.Label
		}
		roots = append(roots, option)
	}

	payload := struct {
		SchemaVersion int                               `json:"schema_version"`
		Identities    []graphSubscriptionIdentityOption `json:"identities"`
		Roots         []graphSubscriptionRootOption     `json:"roots"`
	}{SchemaVersion: 1, Identities: identities, Roots: roots}
	canonical, err := json.Marshal(payload)
	if err != nil || len(canonical) > model.MaxSubscriptionResponseBytes {
		return graphSubscriptionOptionsResponse{}, composeFailure("bounds_exceeded")
	}
	sum := sha256.Sum256(canonical)
	return graphSubscriptionOptionsResponse{SchemaVersion: 1, OK: true, OptionsVersion: "ov1:" + hex.EncodeToString(sum[:]), Identities: identities, Roots: roots}, nil
}

func safeGraphOptionLabel(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	if len(value) > 128 {
		for end := 128; end > 0; end-- {
			if value[end]&0xc0 != 0x80 {
				value = value[:end]
				break
			}
		}
	}
	return value
}

func graphOptionHopCount(count int) string {
	if count == 1 {
		return "1 hop"
	}
	return fmt.Sprintf("%d hops", count)
}
