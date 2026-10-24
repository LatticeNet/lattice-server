package store

import (
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Check definitions (design 32 D1). A definition is operator intent written
// on an edit, so it lives in the JSON state beside the monitors it expands
// into. The control plane plans the expansion; the store writes a definition
// together with its monitors in one state write, so a save never leaves the
// record and its monitors out of step.

var (
	// ErrCheckDefinitionVersion is returned when a save or delete names a
	// version other than the stored one: someone else saved in between.
	ErrCheckDefinitionVersion = errors.New("check definition changed since it was read")
	// ErrCheckDefinitionNotFound is returned for an id no definition has.
	ErrCheckDefinitionNotFound = errors.New("check definition not found")
	// ErrCheckDefinitionMonitors is returned when a delete or forget names
	// monitors that are not exactly the ones it would remove: the
	// confirmation the operator saw no longer matches.
	ErrCheckDefinitionMonitors = errors.New("the definition's monitors changed since they were confirmed; read it again")
)

// CheckDefinitionOwner is ManagedBy on a monitor expanded from definition id.
func CheckDefinitionOwner(id string) string { return MonitorManagedCheckPrefix + id }

func cloneCheckDefinition(def model.CheckDefinition) model.CheckDefinition {
	def.Sources = cloneTargetSelector(def.Sources)
	def.Targets = cloneTargetSelector(def.Targets)
	def.Addresses = slices.Clone(def.Addresses)
	def.Headers = slices.Clone(def.Headers)
	def.SecretsOrigins = slices.Clone(def.SecretsOrigins)
	if def.Degraded != nil {
		rule := *def.Degraded
		def.Degraded = &rule
	}
	return def
}

func cloneTargetSelector(sel model.TargetSelector) model.TargetSelector {
	sel.Nodes = slices.Clone(sel.Nodes)
	sel.Groups = slices.Clone(sel.Groups)
	sel.Exclude = slices.Clone(sel.Exclude)
	return sel
}

// CheckDefinitions returns every definition, oldest first, then by id: the
// order the packet budget is shared out in.
func (s *Store) CheckDefinitions() []model.CheckDefinition {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.CheckDefinition, 0, len(s.state.CheckDefinitions))
	for _, def := range s.state.CheckDefinitions {
		out = append(out, cloneCheckDefinition(def))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// CheckDefinition returns one definition.
func (s *Store) CheckDefinition(id string) (model.CheckDefinition, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	def, ok := s.state.CheckDefinitions[id]
	if !ok {
		return model.CheckDefinition{}, false
	}
	return cloneCheckDefinition(def), true
}

// SaveCheckDefinition stores def when expected is its stored version (zero
// for a new one) and, in the same state write, makes each owner in sets
// hold exactly its desired monitors (SyncManagedMonitorSets). It returns the
// definition as stored, with the next version, and what changed by owner.
func (s *Store) SaveCheckDefinition(def model.CheckDefinition, expected int64, actor string, sets map[string][]model.Monitor, now time.Time) (model.CheckDefinition, map[string]ManagedMonitorChanges, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, exists := s.state.CheckDefinitions[def.ID]
	var current int64
	if exists {
		current = prior.Version
	}
	if expected != current {
		return model.CheckDefinition{}, nil, ErrCheckDefinitionVersion
	}
	at := now.UTC()
	stored := cloneCheckDefinition(def)
	stored.Version = current + 1
	stored.UpdatedAt = at
	stored.UpdatedBy = actor
	stored.CreatedAt = at
	if exists {
		stored.CreatedAt = prior.CreatedAt
	}
	s.state.CheckDefinitions[def.ID] = stored
	restore := func() {
		if exists {
			s.state.CheckDefinitions[def.ID] = prior
		} else {
			delete(s.state.CheckDefinitions, def.ID)
		}
	}
	changes, undo, err := s.applyManagedSetsLocked(sets, now)
	if err != nil {
		restore()
		return model.CheckDefinition{}, nil, err
	}
	// A write on disk that could not be made durable keeps memory as the
	// file has it and still reports the error, as DeleteCheckDefinition does.
	committed, err := s.persistState(s.jsonPersistState())
	if !committed {
		undo.revert(s)
		restore()
		return model.CheckDefinition{}, nil, err
	}
	undo.committed(s)
	return cloneCheckDefinition(stored), changes, err
}

// CheckDefinitionCount is how many definitions are stored.
func (s *Store) CheckDefinitionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.state.CheckDefinitions)
}

// AnyDefinitionMonitor reports whether any stored monitor was expanded from
// a check definition, without copying the monitors.
func (s *Store) AnyDefinitionMonitor() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, mon := range s.state.Monitors {
		if MonitorOwnerOf(mon) == MonitorOwnerDefinition {
			return true
		}
	}
	return false
}

// DeleteCheckDefinition removes a definition and every monitor it expanded
// into, with their history, in one state write. expected is the version the
// operator read and monitorIDs the monitors they confirmed deleting; either
// differing from what is stored refuses the delete. Its monitors' incidents
// go once the write commits, as DeleteMonitor does it.
func (s *Store) DeleteCheckDefinition(id string, expected int64, monitorIDs []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	def, ok := s.state.CheckDefinitions[id]
	if !ok {
		return nil, ErrCheckDefinitionNotFound
	}
	if def.Version != expected {
		return nil, ErrCheckDefinitionVersion
	}
	owner := CheckDefinitionOwner(id)
	var held []string
	for monitorID, mon := range s.state.Monitors {
		if mon.ManagedBy == owner {
			held = append(held, monitorID)
		}
	}
	sort.Strings(held)
	confirmed := slices.Clone(monitorIDs)
	sort.Strings(confirmed)
	confirmed = slices.Compact(confirmed)
	if !slices.Equal(held, confirmed) {
		return nil, ErrCheckDefinitionMonitors
	}
	undo := newManagedUndo()
	if err := s.deleteMonitorsLocked(held, &undo); err != nil {
		return nil, err
	}
	delete(s.state.CheckDefinitions, id)
	committed, err := s.persistState(s.jsonPersistState())
	if !committed {
		undo.revert(s)
		s.state.CheckDefinitions[id] = def
		return nil, err
	}
	undo.committed(s)
	gone := map[string]bool{}
	for _, monitorID := range held {
		gone[monitorID] = true
	}
	_ = s.deleteIncidentsLocked(func(inc Incident) bool { return gone[inc.MonitorID] })
	return held, err
}

// ForgetCheckMonitors deletes, with their history, monitors of definition
// id that are paused. The caller has judged that their targets left the
// set; the store refuses any id that is not a paused monitor of the
// definition, so the operator's confirmation names exactly what goes.
func (s *Store) ForgetCheckMonitors(id string, monitorIDs []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.CheckDefinitions[id]; !ok {
		return nil, ErrCheckDefinitionNotFound
	}
	owner := CheckDefinitionOwner(id)
	ids := slices.Clone(monitorIDs)
	sort.Strings(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return nil, ErrCheckDefinitionMonitors
	}
	for _, monitorID := range ids {
		mon, ok := s.state.Monitors[monitorID]
		if !ok || mon.ManagedBy != owner || mon.Enabled {
			return nil, ErrCheckDefinitionMonitors
		}
	}
	undo := newManagedUndo()
	if err := s.deleteMonitorsLocked(ids, &undo); err != nil {
		return nil, err
	}
	committed, err := s.persistState(s.jsonPersistState())
	if !committed {
		undo.revert(s)
		return nil, err
	}
	undo.committed(s)
	gone := map[string]bool{}
	for _, monitorID := range ids {
		gone[monitorID] = true
	}
	_ = s.deleteIncidentsLocked(func(inc Incident) bool { return gone[inc.MonitorID] })
	return ids, err
}
