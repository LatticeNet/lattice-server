package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

var graphOptionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// graphSubscriptionIdentityOption is one identity in a graph_options answer.
//
// Selectable is the contract: a client offers an identity exactly when it is
// true, and Reason is set exactly when it is false. Status is an open set of
// display words, not a closed enum, and a client must not decide eligibility
// from it. Today it is eligible, or for an identity that is not selectable
// one of disabled (identity_disabled), suspended (identity_suspended, an
// operator suspension), expired (identity_expired), over_quota
// (identity_over_quota) and incomplete (identity_unversioned,
// vless_credential_missing). The only consumer, the Sub-Store plugin,
// validates Status as bounded text, lists the selectable identities only,
// and shows Status as text, so a new word reaches it as a label.
type graphSubscriptionIdentityOption struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Selectable bool   `json:"selectable"`
}

type graphSubscriptionRootOption struct {
	LineUUID            string   `json:"line_uuid"`
	Label               string   `json:"label"`
	SourceNode          string   `json:"source_node_id"`
	Source              string   `json:"source"`
	TargetLabel         string   `json:"target_label,omitempty"`
	Status              string   `json:"status"`
	PathSummary         string   `json:"path_summary"`
	Reason              string   `json:"reason,omitempty"`
	EligibleIdentityIDs []string `json:"eligible_identity_ids"`
	Selectable          bool     `json:"selectable"`
}

type graphSubscriptionOptionsResponse struct {
	SchemaVersion  int                               `json:"schema_version"`
	OK             bool                              `json:"ok"`
	OptionsVersion string                            `json:"options_version,omitempty"`
	Identities     []graphSubscriptionIdentityOption `json:"identities"`
	Roots          []graphSubscriptionRootOption     `json:"roots"`
	Error          *graphSubscriptionError           `json:"error,omitempty"`
}

func (response graphSubscriptionOptionsResponse) Clone() graphSubscriptionOptionsResponse {
	response.Identities = append(make([]graphSubscriptionIdentityOption, 0, len(response.Identities)), response.Identities...)
	response.Roots = append(make([]graphSubscriptionRootOption, 0, len(response.Roots)), response.Roots...)
	for i := range response.Roots {
		response.Roots[i].EligibleIdentityIDs = append(make([]string, 0, len(response.Roots[i].EligibleIdentityIDs)), response.Roots[i].EligibleIdentityIDs...)
	}
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

// graphIdentityPolicyOption is the option status and reason for an identity
// its policy suspends.
func graphIdentityPolicyOption(policy vpnUserPolicy) (status, reason string) {
	switch policy.Reason {
	case vpnSuspendReasonDisabled:
		return "disabled", "identity_disabled"
	case vpnSuspendReasonOperator:
		return "suspended", "identity_suspended"
	case vpnSuspendReasonExpiry:
		return "expired", "identity_expired"
	default:
		return "over_quota", "identity_over_quota"
	}
}

func graphSubscriptionOptionsFromCapture(capture func() (lineChainCompileSnapshot, error), now time.Time) (graphSubscriptionOptionsResponse, error) {
	snapshot, err := capture()
	if err != nil {
		return graphSubscriptionOptionsResponse{}, err
	}
	return graphSubscriptionOptions(snapshot, now)
}

func graphSubscriptionOptions(snapshot lineChainCompileSnapshot, now time.Time) (graphSubscriptionOptionsResponse, error) {
	denylist := graphOptionSecretDenylist(snapshot)
	identityIDs := make([]string, 0, len(snapshot.Users))
	for id := range snapshot.Users {
		identityIDs = append(identityIDs, id)
	}
	sort.Strings(identityIDs)
	if len(identityIDs) > model.MaxSubscriptionSourceVisits {
		return graphSubscriptionOptionsResponse{}, composeFailure("bounds_exceeded")
	}

	identities := make([]graphSubscriptionIdentityOption, 0, len(identityIDs))
	eligibleBindings := make(map[string][]string)
	allCredentialUUIDs := make(map[string]bool)
	for _, id := range identityIDs {
		identity := snapshot.Users[id]
		if credential, ok := vpnCredentialForProtocol(identity.Credentials, "vless"); ok && credential.UUID != "" {
			allCredentialUUIDs[strings.ToLower(credential.UUID)] = true
		}
		option := graphSubscriptionIdentityOption{ID: identity.ID, Label: safeGraphOptionText(firstNonEmpty(identity.Name, identity.Email), "VPN identity", false, denylist), Status: "eligible", Selectable: true}
		// Eligibility follows the identity's effective status, the one the
		// managed render and the line plans use, so an identity over its
		// quota is no more eligible here than an expired one.
		policy := snapshot.identityPolicy(identity, now)
		switch {
		case !policy.Active():
			option.Status, option.Reason = graphIdentityPolicyOption(policy)
			option.Selectable = false
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
					eligibleBindings[binding.LineHashID] = appendUniqueSorted(eligibleBindings[binding.LineHashID], identity.ID)
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
		if allCredentialUUIDs[uuid] {
			continue
		}
		lines := snapshot.Lines[uuid]
		option := graphSubscriptionRootOption{LineUUID: uuid, Status: "unresolved", Reason: "root_unavailable", EligibleIdentityIDs: []string{}}
		if len(lines) == 1 {
			line := lines[0]
			option.Label = safeGraphOptionText(firstNonEmpty(line.Name, line.Tag), "Managed line", false, denylist)
			option.SourceNode = safeGraphOptionText(line.NodeID, "unknown node", true, denylist)
			option.Source = safeGraphOptionText(line.Source, "unknown", false, denylist)
			option.PathSummary = option.Label
			if definition, ok := snapshot.Chains.Definitions[uuid]; ok {
				option.Status = safeGraphOptionText(definition.Status, "unresolved", false, denylist)
				if targetLines := snapshot.Lines[strings.ToLower(definition.TargetLineUUID)]; len(targetLines) == 1 {
					option.TargetLabel = safeGraphOptionText(firstNonEmpty(targetLines[0].Name, targetLines[0].Tag), "Managed line", false, denylist)
				}
			}
			if _, _, err := composeLine(snapshot, uuid); err != nil {
				option.Reason = composeFailureView(err).Code
				option.Status = graphOptionFailureStatus(option.Reason)
			} else if path, terminal, err := composeDeclaredPath(snapshot, uuid, activeSources, &totalTraversalVisits); err != nil {
				option.Reason = composeFailureView(err).Code
				option.Status = graphOptionFailureStatus(option.Reason)
			} else if len(eligibleBindings[line.LineHashID]) == 0 {
				option.Reason = "identity_unavailable"
			} else {
				option.EligibleIdentityIDs = append(option.EligibleIdentityIDs, eligibleBindings[line.LineHashID]...)
				option.Selectable = true
				option.Reason = ""
				option.Status = store.LineChainStatusConverged
				terminalLabel := option.TargetLabel
				if terminalLines := snapshot.Lines[terminal.LineUUID]; len(terminalLines) == 1 {
					terminalLabel = safeGraphOptionText(firstNonEmpty(terminalLines[0].Name, terminalLines[0].Tag), "Managed line", false, denylist)
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
		option.PathSummary = safeGraphOptionText(option.PathSummary, option.Label, false, denylist)
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
	response := graphSubscriptionOptionsResponse{SchemaVersion: 1, OK: true, OptionsVersion: "ov1:" + hex.EncodeToString(sum[:]), Identities: identities, Roots: roots}
	final, err := json.Marshal(response)
	if err != nil || len(final) > model.MaxSubscriptionResponseBytes {
		return graphSubscriptionOptionsResponse{}, composeFailure("bounds_exceeded")
	}
	return response, nil
}

func safeGraphOptionText(value, fallback string, allowUUID bool, denylist []string) string {
	value = strings.TrimSpace(value)
	if strings.ContainsFunc(value, unicode.IsControl) {
		return fallback
	}
	lower := strings.ToLower(value)
	if value == "" || strings.Contains(lower, "://") || strings.Contains(lower, "private key") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.HasPrefix(lower, "lat$") || (!allowUUID && graphOptionUUID.MatchString(lower)) {
		return fallback
	}
	for _, secret := range denylist {
		if secret != "" && strings.Contains(lower, strings.ToLower(secret)) {
			return fallback
		}
	}
	if len(value) > 128 {
		for end := 128; end > 0; end-- {
			if value[end]&0xc0 != 0x80 {
				value = value[:end]
				break
			}
		}
	}
	if value == "" {
		return fallback
	}
	return value
}

func graphOptionSecretDenylist(snapshot lineChainCompileSnapshot) []string {
	secrets := make([]string, 0)
	for _, identity := range snapshot.Users {
		if identity.SubID != "" {
			secrets = append(secrets, identity.SubID)
		}
		for _, credential := range identity.Credentials {
			secrets = append(secrets, credential.UUID, credential.Password)
		}
	}
	for _, definition := range snapshot.Definitions {
		secrets = append(secrets, definition.RealityPrivateKey)
	}
	return secrets
}

func appendUniqueSorted(values []string, value string) []string {
	i := sort.SearchStrings(values, value)
	if i < len(values) && values[i] == value {
		return values
	}
	values = append(values, "")
	copy(values[i+1:], values[i:])
	values[i] = value
	return values
}

func graphOptionFailureStatus(reason string) string {
	switch reason {
	case "graph_busy":
		return store.LineChainStatusApplying
	case "graph_drifted", "source_missing", "target_missing", "inputs_changed":
		return store.LineChainStatusDrifted
	default:
		return "unresolved"
	}
}

func graphOptionHopCount(count int) string {
	if count == 1 {
		return "1 hop"
	}
	return fmt.Sprintf("%d hops", count)
}
