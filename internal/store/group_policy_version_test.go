package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Design 32 R6: an outbound policy save names the version it was read at, and
// a stale one is refused instead of overwriting the newer policy.
func TestSaveGroupPolicyRefusesAStaleVersion(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.SaveGroupPolicy(model.GroupNetPolicy{ID: "gnp_a", Enabled: true}, 0)
	if err != nil || created.Version != 1 {
		t.Fatalf("create = %+v, %v; want version 1", created, err)
	}
	edited, err := s.SaveGroupPolicy(model.GroupNetPolicy{ID: "gnp_a", Name: "web", Enabled: true}, 1)
	if err != nil || edited.Version != 2 {
		t.Fatalf("edit at the stored version = %+v, %v; want version 2", edited, err)
	}
	before := s.testPersistCalls
	if _, err := s.SaveGroupPolicy(model.GroupNetPolicy{ID: "gnp_a", Name: "stale", Enabled: true}, 1); !errors.Is(err, ErrGroupPolicyVersion) {
		t.Fatalf("edit at a stale version = %v, want ErrGroupPolicyVersion", err)
	}
	if got, _ := s.GroupPolicy("gnp_a"); got.Name != "web" || got.Version != 2 || s.testPersistCalls != before {
		t.Fatalf("a refused save must not land: %+v (%d writes)", got, s.testPersistCalls-before)
	}
	if _, err := s.SaveGroupPolicy(model.GroupNetPolicy{ID: "gnp_gone", Enabled: true}, 3); !errors.Is(err, ErrGroupPolicyVersion) {
		t.Fatalf("a versioned save of a policy that is gone = %v, want ErrGroupPolicyVersion", err)
	}
	// A client that sends no version is not checked, and still counts.
	if err := s.UpsertGroupPolicy(model.GroupNetPolicy{ID: "gnp_a", Name: "unchecked", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GroupPolicy("gnp_a"); got.Version != 3 {
		t.Fatalf("an unversioned save = %+v, want version 3", got)
	}
}

// The node delete cascade rewrites policies, so it moves their version: an
// editor that read the policy before the node went must not save it back.
func TestNodeDeleteMovesTheVersionOfAPolicyItRewrites(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"n1", "n2"} {
		if err := s.UpsertNode(model.Node{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	scoped, err := s.SaveGroupPolicy(model.GroupNetPolicy{ID: "gnp_scope", Enabled: true, Scope: &model.TargetSelector{Nodes: []string{"n1", "n2"}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := s.SaveGroupPolicy(model.GroupNetPolicy{ID: "gnp_remote", Enabled: true, Scope: &model.TargetSelector{Nodes: []string{"n2"}}, Rules: []model.GroupNetRule{
		{ID: "r", Action: model.NetRuleAllow, Direction: model.NetDirEgress, Protocol: model.NetProtoTCP, Ports: []int{22}, Remote: model.NetEndpoint{Kind: model.NetRefNode, NodeID: "n1"}},
	}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteNode("n1"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []model.GroupNetPolicy{scoped, remote} {
		got, _ := s.GroupPolicy(want.ID)
		if got.Version != want.Version+1 {
			t.Fatalf("%s version after the cascade = %d, want %d", want.ID, got.Version, want.Version+1)
		}
	}
}

// A policy stored before versions existed has none on disk. It loads as
// version 1, so an editor that read it sends 1 and a second editor's stale
// save is refused from the first save after the upgrade.
func TestAnUnversionedStoredPolicyLoadsAsVersionOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"group_policies":{"gnp_old":{"id":"gnp_old","enabled":true,"priority":10}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadJSONState(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.GroupPolicies["gnp_old"].Version; got != 1 {
		t.Fatalf("loaded version = %d, want 1", got)
	}
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	s.state.GroupPolicies["gnp_old"] = st.GroupPolicies["gnp_old"]
	if saved, err := s.SaveGroupPolicy(model.GroupNetPolicy{ID: "gnp_old", Name: "first", Enabled: true}, 1); err != nil || saved.Version != 2 {
		t.Fatalf("first save at the loaded version = %+v, %v", saved, err)
	}
	if _, err := s.SaveGroupPolicy(model.GroupNetPolicy{ID: "gnp_old", Name: "second", Enabled: true}, 1); !errors.Is(err, ErrGroupPolicyVersion) {
		t.Fatalf("the other editor's save = %v, want ErrGroupPolicyVersion", err)
	}
}
