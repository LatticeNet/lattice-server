package store

import (
	"errors"
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
	var changes ManagedMonitorChanges
	if strings.TrimSpace(managedBy) == "" {
		return changes, errors.New("managed monitors need an owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	want := make(map[string]model.Monitor, len(desired))
	for _, mon := range desired {
		if mon.ID == "" || strings.ContainsAny(mon.ID, "/\x00") {
			return changes, errors.New("managed monitor id is empty or malformed")
		}
		mon.ManagedBy = managedBy
		mon.NodeIDs = slices.Clone(mon.NodeIDs)
		sort.Strings(mon.NodeIDs)
		want[mon.ID] = mon
	}
	var deletes []string
	for id, mon := range s.state.Monitors {
		if mon.ManagedBy != managedBy {
			continue
		}
		if _, ok := want[id]; !ok {
			deletes = append(deletes, id)
		}
	}
	sort.Strings(deletes)
	// History goes before the records, as DeleteMonitor does it: a failure
	// here changes nothing, and a failed state write after it leaves the
	// monitor with an empty history that the next sync deletes.
	if s.runtimeBoltHot != nil {
		for _, id := range deletes {
			if err := s.runtimeBoltHot.DeleteMonitorResults(id); err != nil {
				return ManagedMonitorChanges{}, err
			}
		}
	}
	prior := make(map[string]*model.Monitor)
	remember := func(id string) {
		if _, seen := prior[id]; seen {
			return
		}
		if mon, ok := s.state.Monitors[id]; ok {
			prior[id] = &mon
		} else {
			prior[id] = nil
		}
	}
	for _, id := range deletes {
		remember(id)
		delete(s.state.Monitors, id)
		changes.Deleted = append(changes.Deleted, id)
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	at := now.UTC()
	for _, id := range ids {
		next := want[id]
		current, exists := s.state.Monitors[id]
		switch {
		case exists && current.ManagedBy != managedBy:
			continue
		case exists && managedMonitorEqual(current, next):
			continue
		}
		remember(id)
		next.CreatedAt, next.UpdatedAt = at, at
		if exists {
			next.CreatedAt = current.CreatedAt
			changes.Updated = append(changes.Updated, id)
		} else {
			changes.Created = append(changes.Created, id)
		}
		s.state.Monitors[id] = next
	}
	if !changes.Changed() {
		return changes, nil
	}
	priorSeries := map[string][]MonitorResultRecord{}
	for _, id := range changes.Deleted {
		if series, ok := s.state.MonResults[id]; ok {
			priorSeries[id] = series
			delete(s.state.MonResults, id)
		}
	}
	if err := s.Save(); err != nil {
		for id, mon := range prior {
			if mon == nil {
				delete(s.state.Monitors, id)
			} else {
				s.state.Monitors[id] = *mon
			}
		}
		for id, series := range priorSeries {
			s.state.MonResults[id] = series
		}
		return ManagedMonitorChanges{}, err
	}
	for _, id := range changes.Deleted {
		for key := range s.monitorPersistedAt {
			if strings.HasPrefix(key, id+"\x00") {
				delete(s.monitorPersistedAt, key)
			}
		}
	}
	return changes, nil
}

// managedMonitorEqual compares what an agent and the console act on; the
// timestamps are bookkeeping.
func managedMonitorEqual(a, b model.Monitor) bool {
	return a.Name == b.Name && a.Type == b.Type && a.Target == b.Target &&
		a.IntervalSec == b.IntervalSec && a.TimeoutSec == b.TimeoutSec &&
		a.AssignAll == b.AssignAll && slices.Equal(a.NodeIDs, b.NodeIDs) &&
		a.ThresholdDays == b.ThresholdDays && a.Enabled == b.Enabled &&
		a.ManagedBy == b.ManagedBy
}
