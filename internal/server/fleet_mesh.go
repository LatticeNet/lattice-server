package server

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Fleet mesh becomes an ordinary check (design 32 R1). At start the control
// plane migrates the stored path set, or the defaults in force when none is
// stored, into check definitions named Fleet mesh, once:
//
//   - one definition per distinct method the path set's sources used (their
//     pins, else the path set's method), so no definition needs a method per
//     source; the default method's is model.CheckFleetMeshID;
//   - the region rule (every node outside mainland China) becomes the whole
//     fleet minus the nodes it left out now, so a node that joins later is
//     measured unless excluded, which the migration's audit record says;
//   - disabled pairs become excluded pairs of the definition whose sources
//     hold the pair's source;
//   - every path set monitor is adopted, by (method, target node), by the
//     definition whose method can produce it (the default method's first),
//     so its id and history continue; one no definition can produce is kept
//     paused by the default one;
//   - an alert policy the path set left empty reads off, as it did there.
//
// The stored path set stays, marked migrated (store.MigratePathSet holds the
// rollback rules). A path set already marked is never migrated again; one
// that lost its marker because the release before the migration wrote the
// state is migrated again from what that release ran, into the same ids.

// fleetMeshMigration is what migrating a path set writes.
type fleetMeshMigration struct {
	config model.LatencyProbeConfig
	defs   []model.CheckDefinition
	// adopt is every path set monitor id and the definition that adopts it.
	adopt map[string]string
	// leftOut are the nodes the region rule did not measure, now excluded.
	leftOut []string
}

// fleetMeshMethodName names a definition made for sources pinned to method.
var fleetMeshMethodName = map[string]string{
	model.LatencyMethodTCP:    "TCP",
	model.LatencyMethodICMP:   "ICMP",
	model.LatencyMethodBeacon: "Beacon",
	model.LatencyMethodAuto:   "Auto",
}

// pathSetMonitorKey is the method and target node of a path set monitor id.
func pathSetMonitorKey(monitorID string) (method, target string, ok bool) {
	if target, ok := strings.CutPrefix(monitorID, latencyICMPMonitorPrefix); ok {
		return model.MonitorTypeICMP, target, true
	}
	if target, ok := strings.CutPrefix(monitorID, model.LatencyMonitorPrefixBeacon); ok {
		return model.MonitorTypeBeacon, target, true
	}
	if target, ok := strings.CutPrefix(monitorID, latencyMonitorPrefix); ok {
		return model.MonitorTypeTCP, target, true
	}
	return "", "", false
}

// planFleetMeshMigration is the migration of cfg against nodes, with the
// path set's monitors pathSet and the stored definitions of the ids it
// writes (stored), at now. It reads nothing else, so the same inputs always
// produce the same definitions and the same adoption.
func planFleetMeshMigration(cfg model.LatencyProbeConfig, nodes []model.Node, pathSet []model.Monitor, stored map[string]model.CheckDefinition, now time.Time) fleetMeshMigration {
	byID := make(map[string]model.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	defaultMethod := latencySourceMethod(model.LatencyProbeConfig{Method: cfg.Method}, "")

	// Sources by the method in force for each; an id naming no node is
	// dropped, as the path set's plan only noted it.
	bySourceMethod := map[string][]string{}
	for _, sourceID := range cleanNodeList(cfg.Sources) {
		if _, ok := byID[sourceID]; !ok {
			continue
		}
		method := latencySourceMethod(cfg, sourceID)
		bySourceMethod[method] = append(bySourceMethod[method], sourceID)
	}
	methods := make([]string, 0, len(bySourceMethod)+1)
	for method := range bySourceMethod {
		if method != defaultMethod {
			methods = append(methods, method)
		}
	}
	sort.Strings(methods)
	if len(bySourceMethod[defaultMethod]) > 0 || len(bySourceMethod) == 0 {
		methods = append([]string{defaultMethod}, methods...)
	}

	// The target set: the region rule as the fleet minus what it leaves out
	// now, or the included nodes when the rule is off. Excluded wins.
	excluded := map[string]bool{}
	for _, nodeID := range cfg.ExcludeTargets {
		if _, ok := byID[nodeID]; ok {
			excluded[nodeID] = true
		}
	}
	included := map[string]bool{}
	for _, nodeID := range cfg.IncludeTargets {
		included[nodeID] = true
	}
	var targets model.TargetSelector
	var leftOut []string
	if cfg.AutoTargets {
		targets.All = true
		for _, n := range nodes {
			if _, region := latencyRegion(n); region != model.LatencyRegionOutside && !included[n.ID] && !excluded[n.ID] {
				leftOut = append(leftOut, n.ID)
			}
		}
		sort.Strings(leftOut)
		for nodeID := range excluded {
			targets.Exclude = append(targets.Exclude, nodeID)
		}
		targets.Exclude = append(targets.Exclude, leftOut...)
		sort.Strings(targets.Exclude)
	} else {
		for _, nodeID := range cleanNodeList(cfg.IncludeTargets) {
			if _, ok := byID[nodeID]; ok && !excluded[nodeID] {
				targets.Nodes = append(targets.Nodes, nodeID)
			}
		}
	}

	interval, timeout := cfg.IntervalSec, cfg.TimeoutSec
	if interval <= 0 {
		interval = model.LatencyProbeDefaultIntervalSec
	}
	if timeout <= 0 {
		timeout = model.LatencyProbeDefaultTimeoutSec
	}
	alert := cfg.Alert
	if alert == "" {
		alert = model.MonitorAlertOff
	}
	at := now.UTC()

	out := fleetMeshMigration{adopt: map[string]string{}, leftOut: leftOut}
	for _, method := range methods {
		def := model.CheckDefinition{ID: model.CheckFleetMeshID}
		def.Name = model.CheckFleetMeshName
		if method != defaultMethod {
			def.ID = model.CheckFleetMeshID + "_" + method
			def.Name = model.CheckFleetMeshName + " (" + fleetMeshMethodName[method] + ")"
		}
		def.Type = method
		sources := bySourceMethod[method]
		if len(sources) > 0 {
			def.Sources = model.TargetSelector{Nodes: slices.Clone(sources)}
		}
		def.Targets = model.TargetSelector{All: targets.All, Nodes: slices.Clone(targets.Nodes), Exclude: slices.Clone(targets.Exclude)}
		def.IntervalSec, def.TimeoutSec = interval, timeout
		if method != model.LatencyMethodTCP {
			def.Packets = model.MonitorPacketsDefault
		}
		def.Alert, def.AlertAfter = alert, cfg.AlertAfter
		if cfg.Degraded != nil {
			rule := *cfg.Degraded
			def.Degraded = &rule
		}
		def.Enabled = cfg.Enabled
		seen := map[string]bool{}
		for _, pair := range cfg.DisabledPairs {
			key := latencyPairKey(pair.Source, pair.Target)
			_, sourceOK := byID[pair.Source]
			_, targetOK := byID[pair.Target]
			if !sourceOK || !targetOK || pair.Source == pair.Target || seen[key] || !slices.Contains(sources, pair.Source) {
				continue
			}
			seen[key] = true
			def.ExcludedPairs = append(def.ExcludedPairs, pair)
		}
		sortLatencyPairs(def.ExcludedPairs)
		def.CreatedAt, def.UpdatedAt, def.UpdatedBy, def.Version = at, at, systemActorID, 1
		if prior, ok := stored[def.ID]; ok {
			def.CreatedAt, def.Version = prior.CreatedAt, prior.Version+1
		}
		out.defs = append(out.defs, def)
	}

	// Adoption: each path set monitor by the definition that holds most of
	// the sources it measured from, one of its own method before an auto
	// one, so a pinned source's monitors stay with its pin instead of going
	// to an auto definition whose sources never used that method. A
	// definition that can produce the method comes first, else the first
	// one.
	ids := make([]string, 0, len(pathSet))
	monitorByID := map[string]model.Monitor{}
	for _, mon := range pathSet {
		ids = append(ids, mon.ID)
		monitorByID[mon.ID] = mon
	}
	sort.Strings(ids)
	for _, monitorID := range ids {
		method, target, ok := pathSetMonitorKey(monitorID)
		if !ok {
			continue
		}
		chosen, best := 0, -1
		for i, def := range out.defs {
			if def.Type != method && def.Type != model.CheckMethodAuto {
				continue
			}
			score := 0
			for _, sourceID := range monitorByID[monitorID].NodeIDs {
				if slices.Contains(def.Sources.Nodes, sourceID) {
					score += 2
				}
			}
			if def.Type == method {
				score++
			}
			if score > best {
				chosen, best = i, score
			}
		}
		def := &out.defs[chosen]
		def.Adopted = append(def.Adopted, model.CheckAdoption{Method: method, TargetNode: target, MonitorID: monitorID})
		out.adopt[monitorID] = def.ID
	}

	out.config = cfg
	defIDs := make([]string, 0, len(out.defs))
	for _, def := range out.defs {
		defIDs = append(defIDs, def.ID)
	}
	out.config.Migrated = &model.LatencyProbeMigration{At: at, Definitions: defIDs}
	return out
}

// isFleetMeshID reports whether id is a definition the path set became
// (chk_fleet_mesh, or chk_fleet_mesh_<method> for a pinned method).
func isFleetMeshID(id string) bool {
	return id == model.CheckFleetMeshID || strings.HasPrefix(id, model.CheckFleetMeshID+"_")
}

// migratePathSet migrates the path set into check definitions unless it is
// migrated already, then syncs the definitions so the adopted monitors take
// their definition's form at once. It reports whether it migrated.
//
// It runs once at start, before the listeners and the sweeps, so it takes
// latencySync without monitorSaves, which the lock order puts first: no
// save can be running yet.
//
// After a rollback the older release drops the marker, and the next start
// migrates again from the path set it ran: that path set wins over the
// Fleet mesh definitions left from before, whose ids and versions the audit
// record names as replaced.
func (s *Server) migratePathSet(now time.Time) (bool, error) {
	s.latencySync.Lock()
	cfg, stored := s.store.LatencyProbeConfig()
	if stored && cfg.Migrated != nil {
		s.latencySync.Unlock()
		return false, nil
	}
	nodes := s.store.Nodes()
	if !stored {
		// A fresh install, or one that never saved: the defaults in force.
		cfg = defaultLatencyProbeConfig(nodes)
	}
	var pathSet []model.Monitor
	for _, mon := range s.store.Monitors() {
		if store.MonitorOwnerOf(mon) == store.MonitorOwnerPathSet {
			pathSet = append(pathSet, mon)
		}
	}
	prior := map[string]model.CheckDefinition{}
	for _, def := range s.store.CheckDefinitions() {
		if isFleetMeshID(def.ID) {
			prior[def.ID] = def
		}
	}
	m := planFleetMeshMigration(cfg, nodes, pathSet, prior, now)
	err := s.store.MigratePathSet(m.config, m.defs, m.adopt, now)
	s.latencySync.Unlock()
	if err != nil {
		if after, _ := s.store.LatencyProbeConfig(); after.Migrated == nil {
			return false, fmt.Errorf("migrate the path set: %w", err)
		}
		// The write committed and only its directory sync went unconfirmed:
		// the migration holds, so the rest of it runs.
		s.logger.Printf("latency probes: path set migrated, durability unconfirmed: %v", err)
	}
	s.monitorPaths.dropPlan()
	adopted := make([]string, 0, len(m.adopt))
	for monitorID := range m.adopt {
		adopted = append(adopted, monitorID)
	}
	sort.Strings(adopted)
	replaced := make([]string, 0, len(prior))
	for defID, def := range prior {
		replaced = append(replaced, defID+"@v"+strconv.FormatInt(def.Version, 10))
	}
	sort.Strings(replaced)
	s.recordAudit(model.AuditEvent{
		ID:       id.New("audit"),
		At:       now.UTC(),
		ActorID:  systemActorID,
		Action:   "monitor.latency.migrate",
		Scope:    "monitor:admin",
		Decision: "allow",
		Metadata: map[string]string{
			"definitions":    latencyIDList(m.config.Migrated.Definitions),
			"adopted":        latencyIDList(adopted),
			"config":         strconv.FormatInt(cfg.Version, 10),
			"config_kind":    map[bool]string{true: "stored", false: "defaults"}[stored],
			"left_out":       latencyIDList(m.leftOut),
			"excluded_pairs": strconv.Itoa(len(cfg.DisabledPairs)),
			"replaced":       latencyIDList(replaced),
			"note":           "the region rule became the whole fleet minus left_out: a node that joins later is measured unless excluded",
		},
	})
	if _, err := s.syncCheckDefinitions(now, "migration"); err != nil {
		return true, fmt.Errorf("path set migrated; its definitions sync on the next sweep: %w", err)
	}
	return true, nil
}

// pathSetMigratedError answers a write to a migrated path set, naming the
// definitions to edit instead.
func pathSetMigratedError(cfg model.LatencyProbeConfig) error {
	var ids []string
	if cfg.Migrated != nil {
		ids = cfg.Migrated.Definitions
	}
	return apiErrorf(model.APIErrorPathSetMigrated, "the path set is now the check definitions %s (Fleet mesh); edit them under Checks", strings.Join(ids, ", "))
}
