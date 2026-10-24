package store

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// A check definition that names a group, as a source or as a target, holds
// the group the way an outbound policy does, and the one refusal lists every
// kind of user together, in both state stores. Before the two refusals were
// joined, the policy refusal returned first and hid the checks, and the bolt
// store did not look at checks at all.
func TestDeleteGroupRefusalListsPoliciesAndCheckDefinitions(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "grp_edge", Name: "edge", Slug: "edge", Color: "sky"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroupPolicy(model.GroupNetPolicy{ID: "gnp_a", Scope: &model.TargetSelector{Groups: []string{"grp_edge"}}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	defs := []model.CheckDefinition{
		{ID: "chk_src", CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "from edge", Type: model.MonitorTypeTCP,
			Sources: model.TargetSelector{Groups: []string{"grp_edge"}}, Targets: model.TargetSelector{Nodes: []string{"node-a"}}}},
		{ID: "chk_tgt", CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "to edge", Type: model.MonitorTypeTCP,
			Sources: model.TargetSelector{Nodes: []string{"node-a"}}, Targets: model.TargetSelector{Groups: []string{"grp_edge"}}}},
		{ID: "chk_other", CheckDefinitionSpec: model.CheckDefinitionSpec{Name: "elsewhere", Type: model.MonitorTypeTCP,
			Sources: model.TargetSelector{Nodes: []string{"node-a"}}, Targets: model.TargetSelector{Groups: []string{"grp_other"}}}},
	}
	for _, def := range defs {
		if _, _, err := s.SaveCheckDefinition(def, 0, "admin", nil, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(name string, err error) {
		t.Helper()
		var inUse *GroupInUseError
		if !errors.As(err, &inUse) {
			t.Fatalf("%s: want a GroupInUseError, got %v", name, err)
		}
		if !slices.Equal(inUse.PolicyIDs, []string{"gnp_a"}) || !slices.Equal(inUse.CheckDefinitionIDs, []string{"chk_src", "chk_tgt"}) {
			t.Fatalf("%s: refusal = %+v, want the policy and both checks", name, inUse)
		}
	}
	refused("json store", s.DeleteGroup("grp_edge"))

	bs, err := OpenBoltState(filepath.Join(dir, "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	if err := bs.ImportState(s.state); err != nil {
		t.Fatal(err)
	}
	refused("bolt store", bs.DeleteGroup("grp_edge"))

	// Once nothing names it, the group deletes.
	if err := s.DeleteGroupPolicy("gnp_a"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"chk_src", "chk_tgt"} {
		if _, err := s.DeleteCheckDefinition(id, 1, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteGroup("grp_edge"); err != nil {
		t.Fatalf("an unused group must delete, got %v", err)
	}
}
