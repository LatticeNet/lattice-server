package server

import (
	"encoding/json"
	"fmt"
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
	var manifest model.SubscriptionSourceManifestV1
	if err := json.Unmarshal(first.SourceManifest, &manifest); err != nil || manifest.Identity.Generation != 7 ||
		len(manifest.Entries) != 1 || len(manifest.Entries[0].Path) != 1 || manifest.Entries[0].Terminal.LineUUID != composeTerminalUUID {
		t.Fatalf("manifest mismatch: %+v err=%v", manifest, err)
	}
	decoded, err := model.DecodeSubscriptionSourceManifest(first.SourceManifest)
	if err != nil || !reflect.DeepEqual(decoded, manifest) || manifest.Entries[0].Endpoint.Label != composeRootUUID || manifest.Entries[0].Endpoint.Flow != "xtls-rprx-vision" || manifest.Entries[0].Endpoint.ALPN == nil {
		t.Fatalf("SDK canonical manifest mismatch: %+v err=%v", decoded, err)
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
	publicDrift := testGraphComposeSnapshot()
	publicDrift.Lines[composeRootUUID][0].Name = "changed-label"
	drifted, _ := composeGraphSubscription(publicDrift, req, time.Now())
	if drifted.SourceVersion == first.SourceVersion {
		t.Fatal("public renderer input did not change source version")
	}
}

func TestComposeGraphSubscriptionRejectsCredentialAsPublicRootWithoutLeak(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	identity := snapshot.Users["identity"]
	identity.Credentials[0].UUID = composeRootUUID
	snapshot.Users["identity"] = identity
	response, err := composeGraphSubscription(snapshot, graphSubscriptionRequest{
		SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeRootUUID},
	}, time.Now())
	if err == nil || response.OK || response.Raw != "" || response.SourceVersion != "" || len(response.Entries) != 0 || len(response.SourceManifest) != 0 {
		t.Fatalf("credential/root collision did not fail closed: response=%+v err=%v", response, err)
	}
	public := composeFailureView(err)
	wire, marshalErr := json.Marshal(public)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(strings.ToLower(string(wire)), composeRootUUID) {
		t.Fatalf("credential leaked through compose error: %s", wire)
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

func TestComposeGraphSubscriptionFailureMatrixAndRetainedBaseline(t *testing.T) {
	req := graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeRootUUID}}
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name   string
		code   string
		mutate func(*lineChainCompileSnapshot, *graphSubscriptionRequest)
	}{
		{name: "identity whitespace", code: "invalid_request", mutate: func(_ *lineChainCompileSnapshot, r *graphSubscriptionRequest) { r.IdentityID = " identity" }},
		{name: "root whitespace", code: "invalid_request", mutate: func(_ *lineChainCompileSnapshot, r *graphSubscriptionRequest) { r.EntryRoots[0] += " " }},
		{name: "duplicate root", code: "invalid_request", mutate: func(_ *lineChainCompileSnapshot, r *graphSubscriptionRequest) {
			r.EntryRoots = append(r.EntryRoots, r.EntryRoots[0])
		}},
		{name: "root bound exceeded", code: "bounds_exceeded", mutate: func(_ *lineChainCompileSnapshot, r *graphSubscriptionRequest) {
			r.EntryRoots = make([]string, model.MaxSubscriptionSourceRoots+1)
		}},
		{name: "absent root", code: "root_unavailable", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) { delete(s.Lines, composeRootUUID) }},
		{name: "ambiguous root", code: "root_unavailable", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			s.Lines[composeRootUUID] = append(s.Lines[composeRootUUID], s.Lines[composeRootUUID][0])
		}},
		{name: "unbound root", code: "identity_unavailable", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			u := s.Users["identity"]
			u.Bindings = nil
			s.Users["identity"] = u
		}},
		{name: "disabled identity", code: "identity_unavailable", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			u := s.Users["identity"]
			u.Enabled = false
			s.Users["identity"] = u
		}},
		{name: "expired identity", code: "identity_unavailable", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			u := s.Users["identity"]
			u.ExpiresAt = now
			s.Users["identity"] = u
		}},
		{name: "missing credential", code: "identity_unavailable", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			u := s.Users["identity"]
			u.Credentials = nil
			s.Users["identity"] = u
		}},
		{name: "planned root", code: "graph_busy", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			s.Chains.Attempts["plan"] = store.LineChainAttempt{SourceLineUUID: composeRootUUID, Status: store.LineChainStatusPlanned}
		}},
		{name: "applying reachable terminal", code: "graph_busy", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			s.Chains.Attempts["apply"] = store.LineChainAttempt{SourceLineUUID: composeTerminalUUID, Status: store.LineChainStatusApplying}
		}},
		{name: "not converged", code: "graph_not_converged", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			d := s.Chains.Definitions[composeRootUUID]
			d.Status = store.LineChainStatusDrifted
			s.Chains.Definitions[composeRootUUID] = d
		}},
		{name: "undeclared", code: "graph_undeclared", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			delete(s.Chains.Definitions, composeRootUUID)
		}},
		{name: "observed drift", code: "graph_drifted", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			s.Lines[composeRootUUID][0].DownstreamLineUUID = ""
		}},
		{name: "cycle", code: "graph_cycle", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			d := s.Chains.Definitions[composeTerminalUUID]
			d.TargetLineUUID = composeRootUUID
			s.Chains.Definitions[composeTerminalUUID] = d
			s.Lines[composeTerminalUUID][0].DownstreamLineUUID = composeRootUUID
		}},
		{name: "unsupported endpoint", code: "unsupported_line", mutate: func(s *lineChainCompileSnapshot, _ *graphSubscriptionRequest) {
			s.Lines[composeRootUUID][0].Transport = model.ProxyTransportWS
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := testGraphComposeSnapshot()
			request := req
			request.EntryRoots = append([]string(nil), req.EntryRoots...)
			tt.mutate(&snapshot, &request)
			response, err := composeGraphSubscription(snapshot, request, now)
			if got := composeFailureView(err); got.Code != tt.code {
				t.Fatalf("error = %+v, response=%+v, want code %q", got, response, tt.code)
			}
			if response.OK || response.SourceVersion != "" || len(response.SourceManifest) != 0 || len(response.Entries) != 0 || response.Raw != "" {
				t.Fatalf("failure returned partial content: %+v", response)
			}
		})
	}

	snapshot := testGraphComposeSnapshot()
	snapshot.Chains.Attempts["failed"] = store.LineChainAttempt{SourceLineUUID: composeRootUUID, Status: store.LineChainStatusFailed}
	if response, err := composeGraphSubscription(snapshot, req, now); err != nil || !response.OK {
		t.Fatalf("failed attempt shadowed retained converged baseline: response=%+v err=%v", response, err)
	}
}

func TestComposeGraphSubscriptionRootOrderAndTombstoneAreCanonicalInputs(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	user := snapshot.Users["identity"]
	user.Bindings = append(user.Bindings, LineBinding{LineHashID: "terminal-hash", Enabled: true})
	snapshot.Users["identity"] = user
	now := time.Unix(1_700_000_000, 0)
	forward, err := composeGraphSubscription(snapshot, graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeRootUUID, composeTerminalUUID}}, now)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := composeGraphSubscription(snapshot, graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity", EntryRoots: []string{composeTerminalUUID, composeRootUUID}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if forward.SourceVersion == reverse.SourceVersion || reflect.DeepEqual(forward.Entries, reverse.Entries) || forward.Raw == reverse.Raw {
		t.Fatalf("root reorder did not change ordered output: forward=%+v reverse=%+v", forward, reverse)
	}
	var manifest model.SubscriptionSourceManifestV1
	if err := json.Unmarshal(forward.SourceManifest, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Entries[1].Path) != 0 || manifest.Entries[1].Terminal.LineUUID != composeTerminalUUID || manifest.Entries[1].Terminal.Generation != 2 {
		t.Fatalf("committed converged tombstone was not emitted as terminal: %+v", manifest.Entries[1])
	}
}

func TestComposeGraphSubscriptionBoundsActualTraversalAcrossSharedSuffixes(t *testing.T) {
	snapshot := testGraphComposeSnapshot()
	secondRoot := "44444444-4444-4444-8444-444444444444"
	sharedCount := model.MaxSubscriptionSourceVisits / 2
	shared := make([]string, sharedCount)
	for i := range shared {
		shared[i] = fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", i+1)
	}
	line := func(uuid, hash, downstream string) Line {
		return Line{LineUUID: uuid, LineHashID: hash, NodeID: "node-root", Core: model.ProxyCoreSingbox, Type: model.ProxyProtocolVLESS,
			Transport: model.ProxyTransportTCP, Security: model.ProxySecurityReality, Name: "entry", Tag: "in-entry", PublicHost: "entry.example.com",
			ListenPort: 443, DownstreamLineUUID: downstream, Overlay: true, OverlayStatus: managedLineStatusApplied, Status: "ok"}
	}
	managed := func(uuid string) managedLineDef {
		return managedLineDef{LineUUID: uuid, NodeID: "node-root", Port: 443, SNI: "entry.example.com",
			RealityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "0123456789abcdef", Status: managedLineStatusApplied}
	}
	for i, uuid := range shared {
		target := ""
		if i+1 < len(shared) {
			target = shared[i+1]
		}
		snapshot.Lines[uuid] = []Line{line(uuid, "shared-"+uuid, target)}
		snapshot.Definitions[uuid] = managed(uuid)
		snapshot.Chains.Definitions[uuid] = store.LineChainDefinition{SourceLineUUID: uuid, TargetLineUUID: target,
			Status: store.LineChainStatusConverged, Generation: 1, ObservationRevision: 1}
	}
	for _, root := range []string{composeRootUUID, secondRoot} {
		snapshot.Lines[root] = []Line{line(root, "hash-"+root, shared[0])}
		snapshot.Definitions[root] = managed(root)
		snapshot.Chains.Definitions[root] = store.LineChainDefinition{SourceLineUUID: root, TargetLineUUID: shared[0],
			Status: store.LineChainStatusConverged, Generation: 1, ObservationRevision: 1}
	}
	user := snapshot.Users["identity"]
	user.Bindings = []LineBinding{{LineHashID: "hash-" + composeRootUUID, Enabled: true}, {LineHashID: "hash-" + secondRoot, Enabled: true}}
	snapshot.Users["identity"] = user

	visits := 0
	if _, _, err := composeDeclaredPath(snapshot, composeRootUUID, nil, &visits); err != nil {
		t.Fatalf("first shared path failed at %d visits: %v", visits, err)
	}
	if visits != sharedCount+1 {
		t.Fatalf("first path visits = %d, want %d", visits, sharedCount+1)
	}
	if _, _, err := composeDeclaredPath(snapshot, secondRoot, nil, &visits); composeFailureView(err).Code != "bounds_exceeded" {
		t.Fatalf("second path error = %v at %d visits", err, visits)
	}
	if visits != model.MaxSubscriptionSourceVisits+1 {
		t.Fatalf("budget failed at visit %d, want %d", visits, model.MaxSubscriptionSourceVisits+1)
	}
	response, err := composeGraphSubscription(snapshot, graphSubscriptionRequest{SchemaVersion: 1, IdentityID: "identity",
		EntryRoots: []string{composeRootUUID, secondRoot}}, time.Unix(1_700_000_000, 0))
	if composeFailureView(err).Code != "bounds_exceeded" || response.OK || response.SourceVersion != "" || len(response.SourceManifest) != 0 || len(response.Entries) != 0 || response.Raw != "" {
		t.Fatalf("amplified traversal returned partial content: response=%+v err=%v", response, err)
	}
}
