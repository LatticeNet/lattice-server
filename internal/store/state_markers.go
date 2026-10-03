package store

import "time"

// State markers are named timestamps in the state's Migrations map, written
// only by core. Most mark a one-time migration (MigrationRan); a few record a
// standing operator decision that core enforces, such as the retirement of
// the external Sub-Store auto-sync at the credential cutover.

// StateMarker reports when the marker was set, if it is.
func (s *Store) StateMarker(name string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.state.Migrations[name]
	return at, ok
}

// SetStateMarker sets name to at in one state write. A marker already set
// keeps its first time.
func (s *Store) SetStateMarker(name string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Migrations[name]; ok {
		return nil
	}
	migrations := make(map[string]time.Time, len(s.state.Migrations)+1)
	for k, v := range s.state.Migrations {
		migrations[k] = v
	}
	migrations[name] = at.UTC()
	staged := s.state
	staged.Migrations = migrations
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}
