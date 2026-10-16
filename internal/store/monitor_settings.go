package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The monitor history setting: how long the five-minute rollups are kept.
// The raw rows (MonitorResultsPerPair per pair) and the one-hour rollups
// (model.MonitorCoarseRetentionDays) are fixed. Like the latency
// configuration it is operator intent written on an edit, so it lives in the
// JSON state and is mirrored into the hot store's meta bucket for the offline
// migrate round trip.

// ErrMonitorSettingsVersion is returned when a save names a settings version
// other than the stored one: someone else saved in between.
var ErrMonitorSettingsVersion = errors.New("monitor settings changed since they were read")

// MonitorHistoryLimits bounds one pair's history in the hot store.
type MonitorHistoryLimits struct {
	// PerPair is how many raw rows a pair keeps.
	PerPair int
	// FineKeep and CoarseKeep are how far behind the newest result each
	// rollup tier reaches. Zero means the default.
	FineKeep   time.Duration
	CoarseKeep time.Duration
}

// DefaultMonitorHistoryLimits are the limits before an operator saves a
// setting.
func DefaultMonitorHistoryLimits() MonitorHistoryLimits {
	return monitorHistoryLimitsFor(model.MonitorFineRetentionDefaultDays)
}

func monitorHistoryLimitsFor(fineDays int) MonitorHistoryLimits {
	return MonitorHistoryLimits{
		PerPair:    MonitorResultsPerPair,
		FineKeep:   time.Duration(fineDays)*24*time.Hour + monitorRetentionSlack,
		CoarseKeep: model.MonitorCoarseRetentionDays*24*time.Hour + monitorRetentionSlack,
	}
}

func (l MonitorHistoryLimits) keep(res time.Duration) time.Duration {
	def := DefaultMonitorHistoryLimits()
	if res == MonitorRollupCoarse {
		if l.CoarseKeep > 0 {
			return l.CoarseKeep
		}
		return def.CoarseKeep
	}
	if l.FineKeep > 0 {
		return l.FineKeep
	}
	return def.FineKeep
}

// rawKeep is how long a raw row may outlive the pair's newest result. Rows
// are bounded by count as they arrive; the age bound only matters for a
// pair that stopped (paused, unassigned, its check disabled), whose rows
// would otherwise stay until the monitor is deleted. No row outlives the
// longest tier.
func (l MonitorHistoryLimits) rawKeep() time.Duration { return l.keep(MonitorRollupCoarse) }

func (l MonitorHistoryLimits) perPair() int {
	if l.PerPair > 0 {
		return l.PerPair
	}
	return MonitorResultsPerPair
}

// effectiveMonitorFineDays is the fine retention in force for settings
// (nil before any save).
func effectiveMonitorFineDays(cfg *model.MonitorSettings) int {
	if cfg == nil || cfg.FineRetentionDays < model.MonitorFineRetentionMinDays || cfg.FineRetentionDays > model.MonitorFineRetentionMaxDays {
		return model.MonitorFineRetentionDefaultDays
	}
	return cfg.FineRetentionDays
}

func monitorHistoryLimitsOf(cfg *model.MonitorSettings) MonitorHistoryLimits {
	return monitorHistoryLimitsFor(effectiveMonitorFineDays(cfg))
}

// MonitorSettings returns the setting in force: the stored one, or the
// default at version zero.
func (s *Store) MonitorSettings() model.MonitorSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.MonitorSettings == nil {
		return model.MonitorSettings{FineRetentionDays: model.MonitorFineRetentionDefaultDays}
	}
	return *s.state.MonitorSettings
}

// MonitorHistoryLimits are the limits the hot store applies now.
func (s *Store) MonitorHistoryLimits() MonitorHistoryLimits {
	s.mu.Lock()
	defer s.mu.Unlock()
	return monitorHistoryLimitsOf(s.state.MonitorSettings)
}

// SetMonitorSettings stores cfg when expected is the stored version (zero
// while none is stored) and returns it as stored, with the next version.
// The caller validates the retention.
func (s *Store) SetMonitorSettings(cfg model.MonitorSettings, expected int64, actor string, at time.Time) (model.MonitorSettings, error) {
	if cfg.FineRetentionDays < model.MonitorFineRetentionMinDays || cfg.FineRetentionDays > model.MonitorFineRetentionMaxDays {
		return model.MonitorSettings{}, fmt.Errorf("fine_retention_days must be %d to %d", model.MonitorFineRetentionMinDays, model.MonitorFineRetentionMaxDays)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var current int64
	if s.state.MonitorSettings != nil {
		current = s.state.MonitorSettings.Version
	}
	if expected != current {
		return model.MonitorSettings{}, ErrMonitorSettingsVersion
	}
	stored := model.MonitorSettings{
		FineRetentionDays: cfg.FineRetentionDays,
		Version:           current + 1,
		UpdatedAt:         at.UTC(),
		UpdatedBy:         actor,
	}
	prior := s.state.MonitorSettings
	s.state.MonitorSettings = &stored
	if err := s.Save(); err != nil {
		s.state.MonitorSettings = prior
		return model.MonitorSettings{}, err
	}
	return stored, nil
}

// boltKeyMonitorSettings holds State.MonitorSettings in the meta bucket, as
// boltKeyLatencyProbes does for the latency configuration.
var boltKeyMonitorSettings = []byte("monitor_settings")

func putBoltMonitorSettings(tx *bolt.Tx, cfg *model.MonitorSettings) error {
	meta := tx.Bucket(boltBucketMeta)
	if cfg == nil {
		return meta.Delete(boltKeyMonitorSettings)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return meta.Put(boltKeyMonitorSettings, raw)
}

func readBoltMonitorSettings(tx *bolt.Tx) (*model.MonitorSettings, error) {
	meta := tx.Bucket(boltBucketMeta)
	if meta == nil {
		return nil, nil
	}
	raw := meta.Get(boltKeyMonitorSettings)
	if len(raw) == 0 {
		return nil, nil
	}
	var cfg model.MonitorSettings
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("decode monitor settings: %w", err)
	}
	return &cfg, nil
}
