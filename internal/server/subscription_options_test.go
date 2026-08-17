package server

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestGraphSubscriptionOptionsAreDeterministicSecretFreeAndDefensivelyCloned(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	identity := snapshot.Users["identity"]
	identity.Name = "Primary identity"
	snapshot.Users["identity"] = identity

	first, err := graphSubscriptionOptions(snapshot, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	second, err := graphSubscriptionOptions(snapshot, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !first.OK || first.SchemaVersion != 1 || first.OptionsVersion == "" || !reflect.DeepEqual(first, second) {
		t.Fatalf("options are not deterministic: first=%+v second=%+v", first, second)
	}
	if len(first.Identities) != 1 || !first.Identities[0].Selectable || first.Identities[0].Label != "Primary identity" {
		t.Fatalf("identity options=%+v", first.Identities)
	}
	if len(first.Roots) != 2 || !first.Roots[0].Selectable || first.Roots[0].SourceNode == "" || first.Roots[0].PathSummary == "" {
		t.Fatalf("root options=%+v", first.Roots)
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{composeIdentityUUID, "vless://", "PRIVATE KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "0123456789abcdef"} {
		if strings.Contains(string(raw), canary) {
			t.Fatalf("options leaked secret/public credential material %q: %s", canary, raw)
		}
	}

	clone := first.Clone()
	clone.Identities[0].Label = "mutated"
	clone.Roots[0].Label = "mutated"
	clone.Roots[0].EligibleIdentityIDs[0] = "mutated"
	if first.Identities[0].Label == "mutated" || first.Roots[0].Label == "mutated" || first.Roots[0].EligibleIdentityIDs[0] == "mutated" {
		t.Fatalf("clone aliases source: source=%+v clone=%+v", first, clone)
	}
}

func TestGraphSubscriptionOptionsBindRootsToEligibleIdentities(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	primary := snapshot.Users["identity"]
	primary.Name = "Primary"
	snapshot.Users["identity"] = primary
	snapshot.Users["identity-b"] = VpnUser{ID: "identity-b", Name: "Secondary", Enabled: true, SubscriptionGeneration: 2,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "44444444-4444-4444-8444-444444444444"}},
		Bindings:    []LineBinding{{LineHashID: "terminal-hash", Enabled: true}}}

	response, err := graphSubscriptionOptions(snapshot, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(response.Roots[0].EligibleIdentityIDs, []string{"identity"}) || !reflect.DeepEqual(response.Roots[1].EligibleIdentityIDs, []string{"identity-b"}) {
		t.Fatalf("cross-identity root authority=%+v", response.Roots)
	}

	secondary := snapshot.Users["identity-b"]
	secondary.Bindings = append(secondary.Bindings, LineBinding{LineHashID: "root-hash", Enabled: true})
	snapshot.Users["identity-b"] = secondary
	changed, err := graphSubscriptionOptions(snapshot, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if response.OptionsVersion == changed.OptionsVersion || !reflect.DeepEqual(changed.Roots[0].EligibleIdentityIDs, []string{"identity", "identity-b"}) {
		t.Fatalf("eligibility relation was not versioned: before=%+v after=%+v", response.Roots, changed.Roots)
	}
}

func TestGraphSubscriptionOptionsOmitRootsEqualToSelectableCredential(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity VpnUser
	}{
		{name: "selectable", identity: VpnUser{ID: "identity", Enabled: true, SubscriptionGeneration: 1,
			Credentials: []VpnCredential{{Protocol: "vless", UUID: composeRootUUID}}}},
		{name: "disabled", identity: VpnUser{ID: "disabled", Enabled: false,
			Credentials: []VpnCredential{{Protocol: "vless", UUID: composeRootUUID}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := testGraphComposeSnapshot()
			if tc.name == "selectable" {
				snapshot.Users["identity"] = tc.identity
			} else {
				snapshot.Users[tc.identity.ID] = tc.identity
			}
			response, err := graphSubscriptionOptions(snapshot, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ToLower(string(wire)), composeRootUUID) {
				t.Fatalf("credential/root collision leaked through options: %s", wire)
			}
		})
	}
}

func TestGraphSubscriptionOptionsSanitizeHostileDisplayInputsBeforeVersioning(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	identity := snapshot.Users["identity"]
	identity.Name = "vless://credential-canary"
	snapshot.Users["identity"] = identity
	line := snapshot.Lines[composeRootUUID][0]
	line.Name = "PRIVATE KEY credential-canary"
	line.NodeID = "node\ncredential-canary"
	line.Source = "lat$credential-canary"
	snapshot.Lines[composeRootUUID] = []Line{line}

	response, err := graphSubscriptionOptions(snapshot, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "credential-canary") || response.Identities[0].Label != "VPN identity" || response.Roots[0].Label != "Managed line" {
		t.Fatalf("hostile display input reached options/version: %s", raw)
	}
}

func TestGraphSubscriptionOptionsCaptureExactlyOnceAndExposeIneligibleReasons(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	identity := snapshot.Users["identity"]
	identity.Enabled = false
	snapshot.Users["identity"] = identity
	attempt := store.LineChainAttempt{SourceLineUUID: composeRootUUID, Status: store.LineChainStatusApplying}
	snapshot.Chains.Attempts[composeRootUUID] = attempt

	calls := 0
	response, err := graphSubscriptionOptionsFromCapture(func() (lineChainCompileSnapshot, error) {
		calls++
		return snapshot, nil
	}, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("capture calls=%d want 1", calls)
	}
	if len(response.Identities) != 1 || response.Identities[0].Selectable || response.Identities[0].Reason != "identity_disabled" {
		t.Fatalf("identity reason=%+v", response.Identities)
	}
	if len(response.Roots) == 0 || response.Roots[0].Selectable || response.Roots[0].Reason != "graph_busy" {
		t.Fatalf("root reason=%+v", response.Roots)
	}
}

func TestDecodeStrictGraphOptionsRequestAcceptsOnlyCanonicalEmptyObject(t *testing.T) {
	if err := decodeStrictGraphOptionsRequest([]byte(`{}`)); err != nil {
		t.Fatalf("canonical empty object rejected: %v", err)
	}
	for _, hostile := range []string{"", "null", `[]`, `{"x":1}`, `{"x":1,"x":2}`, `{} null`} {
		if err := decodeStrictGraphOptionsRequest([]byte(hostile)); err == nil {
			t.Fatalf("hostile request accepted: %q", hostile)
		}
	}
}

func TestGraphSubscriptionOptionsEmptySuccessSerializesRequiredArrays(t *testing.T) {
	response, err := graphSubscriptionOptions(lineChainCompileSnapshot{
		Lines: map[string][]Line{}, Definitions: map[string]managedLineDef{}, Users: map[string]VpnUser{},
		Chains: store.LineChainSnapshot{Definitions: map[string]store.LineChainDefinition{}, Attempts: map[string]store.LineChainAttempt{}},
	}, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"identities":[]`) || !strings.Contains(string(raw), `"roots":[]`) {
		t.Fatalf("required empty arrays omitted: %s", raw)
	}
}

func TestGraphSubscriptionOptionsDeduplicatesBindingsAndBoundsPathSummary(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	identity := snapshot.Users["identity"]
	identity.Bindings = append(identity.Bindings, identity.Bindings[0], identity.Bindings[0])
	snapshot.Users["identity"] = identity
	line := snapshot.Lines[composeRootUUID][0]
	line.Name = strings.Repeat("é", 100)
	snapshot.Lines[composeRootUUID] = []Line{line}
	first, err := graphSubscriptionOptions(snapshot, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	identity.Bindings = []LineBinding{identity.Bindings[2], identity.Bindings[0], identity.Bindings[1]}
	snapshot.Users["identity"] = identity
	second, err := graphSubscriptionOptions(snapshot, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Roots[0].EligibleIdentityIDs, []string{"identity"}) || first.OptionsVersion != second.OptionsVersion {
		t.Fatalf("binding permutation changed authority: first=%+v second=%+v", first.Roots[0], second.Roots[0])
	}
	if len(first.Roots[0].PathSummary) > 128 || !utf8.ValidString(first.Roots[0].PathSummary) {
		t.Fatalf("unbounded path summary bytes=%d %q", len(first.Roots[0].PathSummary), first.Roots[0].PathSummary)
	}
}

func TestGraphSubscriptionOptionsDenyActualSecretsEmbeddedInEveryDisplayField(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	credential := snapshot.Users["identity"].Credentials[0].UUID
	privateKey := "private-key-material-canary"
	identity := snapshot.Users["identity"]
	identity.Name = "prefix-" + credential + "-suffix"
	identity.SubID = "subscription-token-canary"
	snapshot.Users["identity"] = identity
	line := snapshot.Lines[composeRootUUID][0]
	line.Name = "name-" + credential
	line.NodeID = "node-" + strings.ToUpper(credential)
	line.Source = "source-" + credential
	snapshot.Lines[composeRootUUID] = []Line{line}
	definition := snapshot.Definitions[composeRootUUID]
	definition.RealityPrivateKey = privateKey
	snapshot.Definitions[composeRootUUID] = definition
	terminal := snapshot.Lines[composeTerminalUUID][0]
	terminal.Name = "target-" + strings.ToUpper(privateKey)
	snapshot.Lines[composeTerminalUUID] = []Line{terminal}
	response, err := graphSubscriptionOptions(snapshot, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(response)
	for _, secret := range []string{credential, strings.ToUpper(credential), identity.SubID, privateKey, strings.ToUpper(privateKey)} {
		if strings.Contains(string(raw), secret) || strings.Contains(response.OptionsVersion, secret) {
			t.Fatalf("secret %q reached options: %s", secret, raw)
		}
	}
}
