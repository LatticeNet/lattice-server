package store

import (
	"errors"
	"maps"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The path set's migration into check definitions (design 32 R1), the
// store's half: one write that stores the definitions, marks the path set
// migrated and files every path set monitor under the definition that
// adopts it. The control plane computes all three (internal/server
// fleet_mesh.go) and then syncs the definitions as usual.
//
// Expand, then contract. Nothing the release before the migration reads is
// taken away: the path set stays, its monitors keep ManagedBy "latency"
// (CheckDefinitionID, which that release does not know, is what files them
// under the definition), and a definition that adopted monitors is written
// with enabled false, its own setting kept in CheckDefinitionsEnabled
// (projectAdoptingDefinitions). After a rollback that release re-owns the
// path set's ids and plans the definition as a paused one, so it neither
// measures a pair twice nor deletes anything. Its first write drops every
// field it does not know (the marker, the adoption, the projection), so the
// next roll-forward migrates again from the path set it ran and adopts the
// same ids.

// ErrPathSetMigrated answers a migration of a path set already migrated.
var ErrPathSetMigrated = errors.New("the path set is already migrated")

// MigratePathSet stores cfg, which must carry its Migrated marker, as the
// path set, stores defs, each replacing any stored definition of its id,
// and files each monitor named in adopt (monitor id to definition id) under
// its definition, in one state write. A monitor adopt names that does not
// exist is skipped. It refuses a path set already marked migrated.
func (s *Store) MigratePathSet(cfg model.LatencyProbeConfig, defs []model.CheckDefinition, adopt map[string]string, now time.Time) error {
	if cfg.Migrated == nil {
		return errors.New("a migrated path set carries its marker")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.LatencyProbes != nil && s.state.LatencyProbes.Migrated != nil {
		return ErrPathSetMigrated
	}
	priorConfig := s.state.LatencyProbes
	priorDefs := maps.Clone(s.state.CheckDefinitions)
	priorMonitors := map[string]model.Monitor{}

	stored := cloneLatencyProbeConfig(cfg)
	stored.Migrated = &model.LatencyProbeMigration{At: cfg.Migrated.At.UTC(), Definitions: append([]string(nil), cfg.Migrated.Definitions...)}
	s.state.LatencyProbes = &stored
	for _, def := range defs {
		s.state.CheckDefinitions[def.ID] = cloneCheckDefinition(def)
	}
	at := now.UTC()
	for monitorID, definitionID := range adopt {
		mon, ok := s.state.Monitors[monitorID]
		if !ok {
			continue
		}
		priorMonitors[monitorID] = mon
		mon.CheckDefinitionID = definitionID
		mon.UpdatedAt = at
		s.state.Monitors[monitorID] = mon
	}
	committed, err := s.persistState(s.jsonPersistState())
	if !committed {
		s.state.LatencyProbes = priorConfig
		s.state.CheckDefinitions = priorDefs
		for id, mon := range priorMonitors {
			s.state.Monitors[id] = mon
		}
		return err
	}
	return err
}

// projectedState is st as the state file holds it: a definition that
// adopted path set monitors reads enabled false, with its own setting in
// CheckDefinitionsEnabled. st's maps are not changed.
func projectedState(st State) State {
	st.CheckDefinitionsEnabled = nil
	for id, def := range st.CheckDefinitions {
		if len(def.Adopted) == 0 {
			continue
		}
		if st.CheckDefinitionsEnabled == nil {
			st.CheckDefinitionsEnabled = map[string]bool{}
			st.CheckDefinitions = maps.Clone(st.CheckDefinitions)
		}
		st.CheckDefinitionsEnabled[id] = def.Enabled
		def.Enabled = false
		st.CheckDefinitions[id] = def
	}
	return st
}

// restoreProjection undoes projectedState on load. A definition whose
// adoption the state no longer holds (the release before the migration
// wrote the file) keeps the enabled false it was written with until the
// path set is migrated again.
func restoreProjection(st *State) {
	for id, def := range st.CheckDefinitions {
		if v, ok := st.CheckDefinitionsEnabled[id]; ok && len(def.Adopted) > 0 {
			def.Enabled = v
			st.CheckDefinitions[id] = def
		}
	}
	st.CheckDefinitionsEnabled = nil
}
