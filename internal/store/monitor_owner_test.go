package store

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Each owner a monitor can carry reads as one class: an operator's check and
// a definition's are authored, everything but an operator's is generated, and
// an owner the server does not know is generated and nothing more.
func TestMonitorOwnerOf(t *testing.T) {
	for _, tc := range []struct {
		managedBy string
		want      MonitorOwner
		generated bool
		authored  bool
		defID     string
	}{
		{"", MonitorOwnerOperator, false, true, ""},
		{model.MonitorManagedLatency, MonitorOwnerPathSet, true, false, ""},
		{model.MonitorManagedBeacon, MonitorOwnerBeaconReach, true, false, ""},
		{MonitorManagedCheckPrefix + "def_web", MonitorOwnerDefinition, true, true, "def_web"},
		// A definition prefix with no id names no definition.
		{MonitorManagedCheckPrefix, MonitorOwnerUnknown, true, false, ""},
		{"something-newer", MonitorOwnerUnknown, true, false, ""},
	} {
		mon := model.Monitor{ID: "mon_x", ManagedBy: tc.managedBy}
		owner := MonitorOwnerOf(mon)
		if owner != tc.want || owner.Generated() != tc.generated || owner.Authored() != tc.authored {
			t.Errorf("%q: owner %d generated %v authored %v, want %d %v %v", tc.managedBy, owner, owner.Generated(), owner.Authored(), tc.want, tc.generated, tc.authored)
		}
		if id, ok := MonitorDefinitionID(mon); id != tc.defID || ok != (tc.defID != "") {
			t.Errorf("%q: definition id %q %v, want %q", tc.managedBy, id, ok, tc.defID)
		}
	}
}
