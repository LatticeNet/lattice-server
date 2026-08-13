package server

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const (
	composeRootUUID     = "11111111-1111-4111-8111-111111111111"
	composeTerminalUUID = "22222222-2222-4222-8222-222222222222"
	composeIdentityUUID = "33333333-3333-4333-8333-333333333333"
)

func testGraphComposeSnapshot() lineChainCompileSnapshot {
	line := func(uuid, hash, node, downstream, host string, port int) Line {
		return Line{LineUUID: uuid, LineHashID: hash, NodeID: node, Core: model.ProxyCoreSingbox, Type: model.ProxyProtocolVLESS,
			Transport: model.ProxyTransportTCP, Security: model.ProxySecurityReality, Name: uuid, Tag: "in-" + node,
			PublicHost: host, ListenPort: port, DownstreamLineUUID: downstream, Overlay: true, OverlayStatus: managedLineStatusApplied, Status: "ok"}
	}
	definition := func(uuid, node string, port int) managedLineDef {
		return managedLineDef{LineUUID: uuid, NodeID: node, Port: port, SNI: "example.com", RealityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ShortID: "0123456789abcdef", Status: managedLineStatusApplied}
	}
	return lineChainCompileSnapshot{
		Lines: map[string][]Line{
			composeRootUUID:     {line(composeRootUUID, "root-hash", "node-root", composeTerminalUUID, "root.example.com", 443)},
			composeTerminalUUID: {line(composeTerminalUUID, "terminal-hash", "node-terminal", "", "terminal.example.com", 8443)},
		},
		Definitions: map[string]managedLineDef{
			composeRootUUID: definition(composeRootUUID, "node-root", 443), composeTerminalUUID: definition(composeTerminalUUID, "node-terminal", 8443),
		},
		Users: map[string]VpnUser{"identity": {ID: "identity", Enabled: true, SubscriptionGeneration: 7,
			Credentials: []VpnCredential{{Protocol: model.ProxyProtocolVLESS, UUID: composeIdentityUUID}},
			Bindings:    []LineBinding{{LineHashID: "root-hash", Enabled: true}}}},
		Nodes: map[string]model.Node{"node-root": {ID: "node-root"}, "node-terminal": {ID: "node-terminal"}, "unrelated": {ID: "unrelated"}},
		Chains: store.LineChainSnapshot{Definitions: map[string]store.LineChainDefinition{
			composeRootUUID:     {SourceLineUUID: composeRootUUID, TargetLineUUID: composeTerminalUUID, Status: store.LineChainStatusConverged, Generation: 4, ObservationRevision: 8},
			composeTerminalUUID: {SourceLineUUID: composeTerminalUUID, Status: store.LineChainStatusConverged, Generation: 2, ObservationRevision: 9},
		}, Attempts: map[string]store.LineChainAttempt{}, Revision: 10},
	}
}

func TestComposeGraphSubscriptionIsCanonicalSecretFreeAndStable(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	req := graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeRootUUID}}
	first, err := composeGraphSubscription(snapshot, req, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	second, err := composeGraphSubscription(snapshot, req, time.Unix(1_800_000_000, 0))
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("identical snapshot was not byte-stable: err=%v\nfirst=%+v\nsecond=%+v", err, first, second)
	}
	if !first.OK || !strings.HasPrefix(first.SourceVersion, "sv1:") || len(first.Entries) != 1 || first.Raw != first.Entries[0] {
		t.Fatalf("unexpected compose response: %+v", first)
	}
	if strings.Contains(string(first.SourceManifest), composeIdentityUUID) || strings.Contains(string(first.SourceManifest), "vless://") {
		t.Fatalf("manifest contains credential or URI: %s", first.SourceManifest)
	}
	var manifest graphSubscriptionManifest
	if err := json.Unmarshal(first.SourceManifest, &manifest); err != nil || manifest.Identity.Generation != 7 ||
		len(manifest.Entries) != 1 || len(manifest.Entries[0].Path) != 1 || manifest.Entries[0].Terminal.LineUUID != composeTerminalUUID {
		t.Fatalf("manifest mismatch: %+v err=%v", manifest, err)
	}

	unrelated := testGraphComposeSnapshot()
	unrelated.Nodes["unrelated"] = model.Node{ID: "unrelated", Name: "changed"}
	unchanged, _ := composeGraphSubscription(unrelated, req, time.Now())
	if unchanged.SourceVersion != first.SourceVersion {
		t.Fatalf("unrelated fleet mutation changed source version: %s != %s", unchanged.SourceVersion, first.SourceVersion)
	}
	rotated := testGraphComposeSnapshot()
	user := rotated.Users["identity"]
	user.SubscriptionGeneration++
	rotated.Users["identity"] = user
	changed, _ := composeGraphSubscription(rotated, req, time.Now())
	if changed.SourceVersion == first.SourceVersion {
		t.Fatal("credential generation did not change source version")
	}
}

func TestComposeGraphSubscriptionFailsAllOrNoneWithRedactedStableError(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	snapshot.Chains.Attempts["approval"] = store.LineChainAttempt{SourceLineUUID: composeRootUUID, Status: store.LineChainStatusApplying}
	_, err := composeGraphSubscription(snapshot, graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeRootUUID}}, time.Now())
	view := composeFailureView(err)
	if view.Code != "graph_busy" || strings.Contains(view.Message, composeRootUUID) || strings.Contains(view.Message, "root.example.com") {
		t.Fatalf("unstable or sensitive error: %+v", view)
	}

	snapshot = testGraphComposeSnapshot()
	snapshot.Lines[composeRootUUID][0].DownstreamLineUUID = ""
	_, err = composeGraphSubscription(snapshot, graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeRootUUID}}, time.Now())
	if got := composeFailureView(err); got.Code != "graph_drifted" {
		t.Fatalf("drift error = %+v", got)
	}
}
