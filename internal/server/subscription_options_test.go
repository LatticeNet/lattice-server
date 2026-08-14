package server

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

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
	if first.Identities[0].Label == "mutated" || first.Roots[0].Label == "mutated" {
		t.Fatalf("clone aliases source: source=%+v clone=%+v", first, clone)
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
