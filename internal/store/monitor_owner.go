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
	// 32 D1), or adopted by one from the path set (CheckDefinitionID set,
	// ManagedBy still model.MonitorManagedLatency, design 32 R1).
	MonitorOwnerDefinition
	// MonitorOwnerUnknown: a generated check whose owner this server does
	// not know, say one written by a newer server. It is treated as
	// generated and is otherwise left alone.
	MonitorOwnerUnknown
)

// MonitorManagedCheckPrefix starts ManagedBy on a monitor expanded from a
// check definition: "check:<definition id>".
const MonitorManagedCheckPrefix = "check:"

// MonitorOwnerOf classifies mon by its CheckDefinitionID, then its
// ManagedBy: a path set monitor a definition adopted is the definition's,
// though it keeps ManagedBy "latency" for the release before the migration.
func MonitorOwnerOf(mon model.Monitor) MonitorOwner {
	if mon.CheckDefinitionID != "" {
		return MonitorOwnerDefinition
	}
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
// from or adopted by, false when something else owns mon.
func MonitorDefinitionID(mon model.Monitor) (string, bool) {
	if mon.CheckDefinitionID != "" {
		return mon.CheckDefinitionID, true
	}
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

// MonitorOwnerKey is the owner a managed sync files mon under: its check
// definition's owner (CheckDefinitionOwner) when it names one, else its
// ManagedBy, empty for an operator's check. Every place that groups managed
// monitors by owner asks this, so an adopted monitor, whose ManagedBy still
// reads "latency", is synced, deleted and forgotten with its definition.
func MonitorOwnerKey(mon model.Monitor) string {
	if mon.CheckDefinitionID != "" {
		return CheckDefinitionOwner(mon.CheckDefinitionID)
	}
	return mon.ManagedBy
}
