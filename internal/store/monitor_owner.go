package store

import (
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

// MonitorOwner names who decides a monitor's fields, read from its
// ManagedBy. Every place that treats a monitor by its owner asks this, so a
// new owner is one case here rather than a string test at each site.
type MonitorOwner int

const (
	// MonitorOwnerOperator: an operator made the check (ManagedBy empty).
	MonitorOwnerOperator MonitorOwner = iota
	// MonitorOwnerPathSet: the latency path set generated the check
	// (model.MonitorManagedLatency); its policy is the path set's.
	MonitorOwnerPathSet
	// MonitorOwnerBeaconReach: a beacon plan generated the check to learn
	// whether the beacon answers (model.MonitorManagedBeacon). It is not a
	// path and never pages.
	MonitorOwnerBeaconReach
	// MonitorOwnerDefinition: the check was expanded from a check
	// definition (MonitorManagedCheckPrefix plus the definition id, design
	// 32 D1). Nothing writes one yet.
	MonitorOwnerDefinition
	// MonitorOwnerUnknown: a generated check whose owner this server does
	// not know, say one written by a newer server. It is treated as
	// generated and is otherwise left alone.
	MonitorOwnerUnknown
)

// MonitorManagedCheckPrefix starts ManagedBy on a monitor expanded from a
// check definition: "check:<definition id>".
const MonitorManagedCheckPrefix = "check:"

// MonitorOwnerOf classifies mon by its ManagedBy.
func MonitorOwnerOf(mon model.Monitor) MonitorOwner {
	switch mon.ManagedBy {
	case "":
		return MonitorOwnerOperator
	case model.MonitorManagedLatency:
		return MonitorOwnerPathSet
	case model.MonitorManagedBeacon:
		return MonitorOwnerBeaconReach
	}
	if _, ok := MonitorDefinitionID(mon); ok {
		return MonitorOwnerDefinition
	}
	return MonitorOwnerUnknown
}

// MonitorDefinitionID is the id of the check definition mon was expanded
// from, false when something else owns mon.
func MonitorDefinitionID(mon model.Monitor) (string, bool) {
	id, ok := strings.CutPrefix(mon.ManagedBy, MonitorManagedCheckPrefix)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// Generated reports whether the monitor changes only through what generates
// it, so a direct edit or delete is refused: it would be undone by the next
// sync.
func (o MonitorOwner) Generated() bool {
	return o != MonitorOwnerOperator
}

// Authored reports whether the monitor is a check an operator wrote,
// directly or as a check definition, so its own fields are the operator's
// intent: it pages by its own policy, is scoped as a check the caller must
// be able to read, lists its own paths, counts toward a beacon's sources,
// and has a node target resolved when it is handed to an agent.
func (o MonitorOwner) Authored() bool {
	return o == MonitorOwnerOperator || o == MonitorOwnerDefinition
}
