package store

import (
	"errors"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The latency probe configuration and the monitors generated from it.
//
// The configuration is operator intent written on an edit, so it lives in the
// JSON state beside the monitors it produces. The generated monitors are
// ordinary monitors marked with ManagedBy; the control plane rewrites them
// when the configuration or the fleet changes, and SyncManagedMonitors writes
// the state file only when one of them actually changed, so a stable fleet
// costs no writes at all. Their results take the same hot-store path as any
// other monitor's.

// ErrLatencyProbeVersion is returned when a save names a configuration
// version other than the stored one: someone else saved in between.
var ErrLatencyProbeVersion = errors.New("latency probe configuration changed since it was read")

// LatencyProbeConfig returns the stored configuration, false when no
// operator has saved one.
func (s *Store) LatencyProbeConfig() (model.LatencyProbeConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.LatencyProbes == nil {
		return model.LatencyProbeConfig{}, false
	}
	return cloneLatencyProbeConfig(*s.state.LatencyProbes), true
}

// SetLatencyProbeConfig stores cfg when expected is the stored version (zero
// while none is stored) and returns it as stored, with the next version.
func (s *Store) SetLatencyProbeConfig(cfg model.LatencyProbeConfig, expected int64, actor string, at time.Time) (model.LatencyProbeConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var current int64
	if s.state.LatencyProbes != nil {
		current = s.state.LatencyProbes.Version
	}
	if expected != current {
		return model.LatencyProbeConfig{}, ErrLatencyProbeVersion
	}
	stored := cloneLatencyProbeConfig(cfg)
	stored.Version = current + 1
	stored.UpdatedAt = at.UTC()
	stored.UpdatedBy = actor
	prior := s.state.LatencyProbes
	s.state.LatencyProbes = &stored
	if err := s.Save(); err != nil {
		s.state.LatencyProbes = prior
		return model.LatencyProbeConfig{}, err
	}
	return cloneLatencyProbeConfig(stored), nil
}

func cloneLatencyProbeConfig(cfg model.LatencyProbeConfig) model.LatencyProbeConfig {
	cfg.Sources = slices.Clone(cfg.Sources)
	cfg.IncludeTargets = slices.Clone(cfg.IncludeTargets)
	cfg.ExcludeTargets = slices.Clone(cfg.ExcludeTargets)
	cfg.DisabledPairs = slices.Clone(cfg.DisabledPairs)
	cfg.SourceMethods = maps.Clone(cfg.SourceMethods)
	if cfg.Degraded != nil {
		rule := *cfg.Degraded
		cfg.Degraded = &rule
	}
	return cfg
}

// ManagedMonitorChanges says what SyncManagedMonitors did, by monitor id.
type ManagedMonitorChanges struct {
	Created []string
	Updated []string
	Deleted []string
}

// Changed reports whether anything was written.
func (c ManagedMonitorChanges) Changed() bool {
	return len(c.Created)+len(c.Updated)+len(c.Deleted) > 0
}

// SyncManagedMonitors makes the monitors marked managedBy equal desired:
// it creates the missing ones, rewrites the ones that differ, and deletes
// the managed ones desired no longer lists, with their history. Monitors an
// operator made, and monitors managed by anything else, are never touched,
// and a desired monitor whose id an operator's monitor already holds is
// skipped. The state file is written once, and only when something changed.
func (s *Store) SyncManagedMonitors(managedBy string, desired []model.Monitor, now time.Time) (ManagedMonitorChanges, error) {
	if strings.TrimSpace(managedBy) == "" {
		return ManagedMonitorChanges{}, errors.New("managed monitors need an owner")
	}
	changes, err := s.SyncManagedMonitorSets(map[string][]model.Monitor{managedBy: desired}, now)
	return changes[managedBy], err
}

// SyncManagedMonitorSets is SyncManagedMonitors for several owners at once,
// keyed by owner: every owner's monitors are brought in line under one lock
// and written in one state write, so a sweep that changes many check
// definitions pays for one write, not one per definition. An owner of a
// check definition that no longer exists keeps no monitors, whatever its set
// says, so a sync racing a delete cannot bring the deleted definition's
// monitors back.
func (s *Store) SyncManagedMonitorSets(sets map[string][]model.Monitor, now time.Time) (map[string]ManagedMonitorChanges, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changes, undo, err := s.applyManagedSetsLocked(sets, now)
	if err != nil || !managedChangesAny(changes) {
		return changes, err
	}
	// A write that reached the disk but could not be made durable (the
	// directory sync failed) keeps what it wrote in memory too, so memory
	// never reads older than the file.
	committed, err := s.persistState(s.jsonPersistState())
	if !committed {
		undo.revert(s)
		return map[string]ManagedMonitorChanges{}, err
	}
	undo.committed(s)
	return changes, err
}

// DiffManagedMonitorSets says what SyncManagedMonitorSets(sets) would do
// now, and writes nothing: a dry run reads it, so it judges by the very
// rule the sync writes by. assume names check definitions the dry run treats
// as existing, such as one a create has not stored yet.
func (s *Store) DiffManagedMonitorSets(sets map[string][]model.Monitor, assume ...string) (map[string]ManagedMonitorChanges, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	plan, err := s.planManagedSetsLocked(sets, func(definitionID string) bool {
		_, exists := s.state.CheckDefinitions[definitionID]
		return exists || slices.Contains(assume, definitionID)
	})
	return plan.changes, err
}

func managedChangesAny(changes map[string]ManagedMonitorChanges) bool {
	for _, c := range changes {
		if c.Changed() {
			return true
		}
	}
	return false
}

// managedUndo is what applyManagedSetsLocked changed in memory, so a failed
// state write can put it back.
type managedUndo struct {
	monitors map[string]*model.Monitor
	series   map[string][]MonitorResultRecord
	deleted  []string
}

func newManagedUndo() managedUndo {
	return managedUndo{monitors: map[string]*model.Monitor{}, series: map[string][]MonitorResultRecord{}}
}

func (u *managedUndo) remember(s *Store, id string) {
	if _, seen := u.monitors[id]; seen {
		return
	}
	if mon, ok := s.state.Monitors[id]; ok {
		u.monitors[id] = &mon
	} else {
		u.monitors[id] = nil
	}
}

// revert puts the remembered monitors and series back after a failed write.
// The hot store's rows of deleted monitors are already gone, so such a
// monitor survives with an empty history; deleting it again (the next sync,
// or the operator's retried delete or forget, which names the same
// monitors) finishes the job.
func (u managedUndo) revert(s *Store) {
	for id, mon := range u.monitors {
		if mon == nil {
			delete(s.state.Monitors, id)
		} else {
			s.state.Monitors[id] = *mon
		}
	}
	for id, series := range u.series {
		s.state.MonResults[id] = series
	}
}

// committed forgets the persistence marks of deleted monitors once their
// deletion is on disk.
func (u managedUndo) committed(s *Store) {
	for _, id := range u.deleted {
		for key := range s.monitorPersistedAt {
			if strings.HasPrefix(key, id+"\x00") {
				delete(s.monitorPersistedAt, key)
			}
		}
	}
}

// deleteMonitorsLocked removes monitors with their history, remembering
// them in undo. The hot store's rows of every one go first, in one
// transaction, as DeleteMonitor does it for one: a failure there changes
// nothing.
func (s *Store) deleteMonitorsLocked(ids []string, undo *managedUndo) error {
	if len(ids) == 0 {
		return nil
	}
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.DeleteMonitorsResults(ids); err != nil {
			return err
		}
	}
	for _, id := range ids {
		s.deletePathDegradedMemLocked(func(p MonitorPair) bool { return p.MonitorID == id })
		undo.remember(s, id)
		delete(s.state.Monitors, id)
		if series, ok := s.state.MonResults[id]; ok {
			undo.series[id] = series
			delete(s.state.MonResults, id)
		}
		undo.deleted = append(undo.deleted, id)
	}
	return nil
}

// managedPlan is what a sync of some sets does: what changes by owner, the
// records it writes by id, and the ids it deletes, sorted.
type managedPlan struct {
	changes map[string]ManagedMonitorChanges
	writes  map[string]model.Monitor
	deletes []string
}

// planManagedSetsLocked judges sets against the stored monitors and changes
// nothing. definitionExists says whether a check definition owner's
// definition exists; an owner whose definition does not keeps nothing.
func (s *Store) planManagedSetsLocked(sets map[string][]model.Monitor, definitionExists func(string) bool) (managedPlan, error) {
	plan := managedPlan{changes: make(map[string]ManagedMonitorChanges, len(sets)), writes: map[string]model.Monitor{}}
	owners := make([]string, 0, len(sets))
	want := make(map[string]map[string]model.Monitor, len(sets))
	claimed := map[string]string{}
	for owner, desired := range sets {
		if strings.TrimSpace(owner) == "" {
			return managedPlan{}, errors.New("managed monitors need an owner")
		}
		if definitionID, ok := strings.CutPrefix(owner, MonitorManagedCheckPrefix); ok && !definitionExists(definitionID) {
			desired = nil
		}
		owners = append(owners, owner)
		set := make(map[string]model.Monitor, len(desired))
		for _, mon := range desired {
			if mon.ID == "" || strings.ContainsAny(mon.ID, "/\x00") {
				return managedPlan{}, errors.New("managed monitor id is empty or malformed")
			}
			if other, taken := claimed[mon.ID]; taken && other != owner {
				return managedPlan{}, errors.New("managed monitor " + mon.ID + " is desired by two owners")
			}
			claimed[mon.ID] = owner
			set[mon.ID] = managedDesired(owner, mon)
		}
		want[owner] = set
	}
	sort.Strings(owners)
	for id, mon := range s.state.Monitors {
		set, synced := want[mon.ManagedBy]
		if !synced {
			continue
		}
		if _, ok := set[id]; !ok {
			plan.deletes = append(plan.deletes, id)
			c := plan.changes[mon.ManagedBy]
			c.Deleted = append(c.Deleted, id)
			plan.changes[mon.ManagedBy] = c
		}
	}
	sort.Strings(plan.deletes)
	for _, owner := range owners {
		ids := make([]string, 0, len(want[owner]))
		for id := range want[owner] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		c := plan.changes[owner]
		sort.Strings(c.Deleted)
		for _, id := range ids {
			next := want[owner][id]
			current, exists := s.state.Monitors[id]
			switch {
			case exists && current.ManagedBy != owner:
				continue
			case exists && managedMonitorEqual(current, next):
				continue
			case exists:
				c.Updated = append(c.Updated, id)
			default:
				c.Created = append(c.Created, id)
			}
			plan.writes[id] = next
		}
		plan.changes[owner] = c
	}
	return plan, nil
}

// applyManagedSetsLocked applies sets in memory and says what changed, by
// owner. Nothing is written; on an error nothing has changed.
func (s *Store) applyManagedSetsLocked(sets map[string][]model.Monitor, now time.Time) (map[string]ManagedMonitorChanges, managedUndo, error) {
	undo := newManagedUndo()
	plan, err := s.planManagedSetsLocked(sets, func(definitionID string) bool {
		_, exists := s.state.CheckDefinitions[definitionID]
		return exists
	})
	if err != nil {
		return nil, undo, err
	}
	if err := s.deleteMonitorsLocked(plan.deletes, &undo); err != nil {
		return nil, newManagedUndo(), err
	}
	at := now.UTC()
	ids := make([]string, 0, len(plan.writes))
	for id := range plan.writes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		next := plan.writes[id]
		undo.remember(s, id)
		next.CreatedAt, next.UpdatedAt = at, at
		if current, exists := s.state.Monitors[id]; exists {
			next.CreatedAt = current.CreatedAt
		}
		s.state.Monitors[id] = next
	}
	return plan.changes, undo, nil
}

// managedDesired is a desired monitor as the sync stores it: stamped with
// its owner, its sources sorted.
func managedDesired(owner string, mon model.Monitor) model.Monitor {
	mon.ManagedBy = owner
	mon.NodeIDs = slices.Clone(mon.NodeIDs)
	sort.Strings(mon.NodeIDs)
	return mon
}

// managedMonitorEqual compares every field an agent, the console or the
// alerting acts on, which is every field but the version and the
// timestamps: those are bookkeeping. The comparison is of whole records, so
// a field added to the model is compared without being named here.
func managedMonitorEqual(a, b model.Monitor) bool {
	return reflect.DeepEqual(managedMonitorCompared(a), managedMonitorCompared(b))
}

// managedMonitorCompared is mon without its bookkeeping, and with an empty
// list read as a missing one, as the stored copy reads once it has been
// written and loaded again.
func managedMonitorCompared(mon model.Monitor) model.Monitor {
	mon.Version = 0
	mon.CreatedAt, mon.UpdatedAt = time.Time{}, time.Time{}
	if len(mon.NodeIDs) == 0 {
		mon.NodeIDs = nil
	}
	if len(mon.PausedNodeIDs) == 0 {
		mon.PausedNodeIDs = nil
	}
	if len(mon.Headers) == 0 {
		mon.Headers = nil
	}
	return mon
}
