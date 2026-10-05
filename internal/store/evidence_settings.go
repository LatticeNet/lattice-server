package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The evidence budgets: trace.db's size cap and TTLs, and logs.db's
// per-source cap. They live in the JSON state rather than in trace.db because
// they govern trace.db and must survive its deletion. Written only on an
// operator's edit.

// ErrEvidenceSettingsVersion is returned when a save names a settings version
// other than the stored one: someone else saved in between.
var ErrEvidenceSettingsVersion = errors.New("evidence settings changed since they were read")

// EvidenceSettings returns the stored settings, false when no operator has
// saved any.
func (s *Store) EvidenceSettings() (model.EvidenceSettings, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.EvidenceSettings == nil {
		return model.EvidenceSettings{}, false
	}
	return *s.state.EvidenceSettings, true
}

// SetEvidenceSettings stores cfg when expected is the stored version (zero
// while none is stored) and returns it as stored, with the next version.
func (s *Store) SetEvidenceSettings(cfg model.EvidenceSettings, expected int64, actor string, at time.Time) (model.EvidenceSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var current int64
	if s.state.EvidenceSettings != nil {
		current = s.state.EvidenceSettings.Version
	}
	if expected != current {
		return model.EvidenceSettings{}, ErrEvidenceSettingsVersion
	}
	stored := cfg
	stored.Version = current + 1
	stored.UpdatedAt = at.UTC()
	stored.UpdatedBy = actor
	prior := s.state.EvidenceSettings
	s.state.EvidenceSettings = &stored
	if err := s.Save(); err != nil {
		s.state.EvidenceSettings = prior
		return model.EvidenceSettings{}, err
	}
	return stored, nil
}

// boltKeyEvidenceSettings holds State.EvidenceSettings in the meta bucket, so
// the offline migrate round trip keeps them, as boltKeyLatencyProbes does for
// the latency configuration.
var boltKeyEvidenceSettings = []byte("evidence_settings")

func putBoltEvidenceSettings(tx *bolt.Tx, cfg *model.EvidenceSettings) error {
	meta := tx.Bucket(boltBucketMeta)
	if cfg == nil {
		return meta.Delete(boltKeyEvidenceSettings)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return meta.Put(boltKeyEvidenceSettings, raw)
}

func readBoltEvidenceSettings(tx *bolt.Tx) (*model.EvidenceSettings, error) {
	meta := tx.Bucket(boltBucketMeta)
	if meta == nil {
		return nil, nil
	}
	raw := meta.Get(boltKeyEvidenceSettings)
	if len(raw) == 0 {
		return nil, nil
	}
	var cfg model.EvidenceSettings
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode evidence settings: %w", err)
	}
	return &cfg, nil
}
