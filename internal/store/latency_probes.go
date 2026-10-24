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
	if err := s.Save(); err != nil {
		undo.revert(s)
		return map[string]ManagedMonitorChanges{}, err
	}
	undo.committed(s)
	return changes, nil
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
// The hot store's rows of deleted monitors are already gone: the monitor
// survives with an empty history, which the next sync deletes again.
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
// them in undo. The hot store's rows go before the records, as DeleteMonitor
// does it: a failure there changes nothing.
func (s *Store) deleteMonitorsLocked(ids []string, undo *managedUndo) error {
	if s.runtimeBoltHot != nil {
		for _, id := range ids {
			if err := s.runtimeBoltHot.DeleteMonitorResults(id); err != nil {
				return err
			}
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

func newManagedUndo() managedUndo {
	return managedUndo{monitors: map[string]*model.Monitor{}, series: map[string][]MonitorResultRecord{}}
}

// applyManagedSetsLocked applies sets in memory and says what changed, by
// owner. Nothing is written; on an error nothing has changed.
func (s *Store) applyManagedSetsLocked(sets map[string][]model.Monitor, now time.Time) (map[string]ManagedMonitorChanges, managedUndo, error) {
	undo := newManagedUndo()
	out := make(map[string]ManagedMonitorChanges, len(sets))
	owners := make([]string, 0, len(sets))
	want := make(map[string]map[string]model.Monitor, len(sets))
	claimed := map[string]string{}
	for owner, desired := range sets {
		if strings.TrimSpace(owner) == "" {
			return nil, undo, errors.New("managed monitors need an owner")
		}
		if definitionID, ok := strings.CutPrefix(owner, MonitorManagedCheckPrefix); ok {
			if _, exists := s.state.CheckDefinitions[definitionID]; !exists {
				desired = nil
			}
		}
		owners = append(owners, owner)
		set := make(map[string]model.Monitor, len(desired))
		for _, mon := range desired {
			if mon.ID == "" || strings.ContainsAny(mon.ID, "/\x00") {
				return nil, undo, errors.New("managed monitor id is empty or malformed")
			}
			if other, taken := claimed[mon.ID]; taken && other != owner {
				return nil, undo, errors.New("managed monitor " + mon.ID + " is desired by two owners")
			}
			claimed[mon.ID] = owner
			set[mon.ID] = managedDesired(owner, mon)
		}
		want[owner] = set
	}
	sort.Strings(owners)
	var deletes []string
	deletedBy := map[string]string{}
	for id, mon := range s.state.Monitors {
		set, synced := want[mon.ManagedBy]
		if !synced {
			continue
		}
		if _, ok := set[id]; !ok {
			deletes = append(deletes, id)
			deletedBy[id] = mon.ManagedBy
		}
	}
	sort.Strings(deletes)
	if err := s.deleteMonitorsLocked(deletes, &undo); err != nil {
		return nil, newManagedUndo(), err
	}
	for _, id := range deletes {
		c := out[deletedBy[id]]
		c.Deleted = append(c.Deleted, id)
		out[deletedBy[id]] = c
	}
	at := now.UTC()
	for _, owner := range owners {
		ids := make([]string, 0, len(want[owner]))
		for id := range want[owner] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		c := out[owner]
		for _, id := range ids {
			next := want[owner][id]
			current, exists := s.state.Monitors[id]
			switch {
			case exists && current.ManagedBy != owner:
				continue
			case exists && managedMonitorEqual(current, next):
				continue
			}
			undo.remember(s, id)
			next.CreatedAt, next.UpdatedAt = at, at
			if exists {
				next.CreatedAt = current.CreatedAt
				c.Updated = append(c.Updated, id)
			} else {
				c.Created = append(c.Created, id)
			}
			s.state.Monitors[id] = next
		}
		out[owner] = c
	}
	return out, undo, nil
}

// managedDesired is a desired monitor as the sync stores it: stamped with
// its owner, its sources sorted.
func managedDesired(owner string, mon model.Monitor) model.Monitor {
	mon.ManagedBy = owner
	mon.NodeIDs = slices.Clone(mon.NodeIDs)
	sort.Strings(mon.NodeIDs)
	return mon
}

// DiffManagedMonitors says what SyncManagedMonitors(owner, desired) would
// do now, and writes nothing. A dry run reads it, so it judges by the same
// comparison the sync writes by.
func (s *Store) DiffManagedMonitors(owner string, desired []model.Monitor) ManagedMonitorChanges {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := make(map[string]model.Monitor, len(desired))
	for _, mon := range desired {
		want[mon.ID] = managedDesired(owner, mon)
	}
	var c ManagedMonitorChanges
	for id, mon := range s.state.Monitors {
		if _, ok := want[id]; !ok && mon.ManagedBy == owner {
			c.Deleted = append(c.Deleted, id)
		}
	}
	for id, next := range want {
		current, exists := s.state.Monitors[id]
		switch {
		case exists && current.ManagedBy != owner:
		case exists && managedMonitorEqual(current, next):
		case exists:
			c.Updated = append(c.Updated, id)
		default:
			c.Created = append(c.Created, id)
		}
	}
	sort.Strings(c.Created)
	sort.Strings(c.Updated)
	sort.Strings(c.Deleted)
	return c
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
