package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The monitor history setting and the hourly pruning sweep.
//
// The operator sets how long five-minute rollups are kept (3 to 14 days);
// the raw rows and the 35-day hourly tier are fixed. The settings read shows
// the size the history occupies now, from bbolt's page statistics, and the
// size it will reach once every current path fills every tier at the setting
// shown, so a change is judged before it is saved.

const (
	// monitorPruneInterval is how often the history is swept.
	monitorPruneInterval = time.Hour
	// Per-key sizes the projection uses until a tier holds enough keys to
	// measure its own: a fine bucket is about 200 bytes once pages split, a
	// coarse one carries a wider histogram, a raw row about 180 bytes.
	monitorProjectFineBytes   = 210
	monitorProjectCoarseBytes = 260
	monitorProjectRowBytes    = 180
	monitorProjectLatestBytes = 400
	monitorProjectMinKeys     = 1000
)

// monitorPathCount is how many paths record history now: every source of
// every enabled check, less its paused sources, and one per tls check.
func (s *Server) monitorPathCount() int {
	nodes := len(s.store.Nodes())
	count := 0
	for _, mon := range s.store.Monitors() {
		if !mon.Enabled {
			continue
		}
		switch {
		case mon.Type == model.MonitorTypeTLS:
			count++
		case mon.AssignAll:
			count += max(nodes-len(mon.PausedNodeIDs), 0)
		default:
			for _, nodeID := range mon.NodeIDs {
				if !slices.Contains(mon.PausedNodeIDs, nodeID) {
					count++
				}
			}
		}
	}
	return count
}

// monitorProjectedBytes is the history's size once paths paths have filled
// every tier at fineDays, with per-key sizes measured where the store holds
// enough keys to say.
func monitorProjectedBytes(usage store.MonitorStorageUsage, paths, fineDays int) int64 {
	perKey := func(bytes int64, keys int, fallback int64) int64 {
		if keys >= monitorProjectMinKeys {
			return bytes / int64(keys)
		}
		return fallback
	}
	p := int64(paths)
	fine := perKey(usage.FineBytes, usage.FineKeys, monitorProjectFineBytes) * p * int64(fineDays) * int64(24*time.Hour/store.MonitorRollupFine)
	coarse := perKey(usage.CoarseBytes, usage.CoarseKeys, monitorProjectCoarseBytes) * p * model.MonitorCoarseRetentionDays * 24
	rows := perKey(usage.RowBytes, usage.RowKeys, monitorProjectRowBytes) * p * store.MonitorResultsPerPair
	latest := perKey(usage.LatestBytes, usage.LatestKeys, monitorProjectLatestBytes) * p
	return fine + coarse + rows + latest
}

func (s *Server) monitorSettingsView() (model.MonitorSettingsView, error) {
	cfg := s.store.MonitorSettings()
	usage, err := s.store.MonitorStorageUsage()
	if err != nil {
		return model.MonitorSettingsView{}, err
	}
	paths := s.monitorPathCount()
	return model.MonitorSettingsView{
		Version:             cfg.Version,
		FineRetentionDays:   cfg.FineRetentionDays,
		FineMinDays:         model.MonitorFineRetentionMinDays,
		FineMaxDays:         model.MonitorFineRetentionMaxDays,
		CoarseRetentionDays: model.MonitorCoarseRetentionDays,
		RawRowsPerPath:      store.MonitorResultsPerPair,
		Paths:               paths,
		MeasuredBytes:       usage.Total(),
		ProjectedBytes:      monitorProjectedBytes(usage, paths, cfg.FineRetentionDays),
		UpdatedAt:           cfg.UpdatedAt,
		UpdatedBy:           cfg.UpdatedBy,
	}, nil
}

// handleMonitorSettings answers GET /api/monitors/settings.
func (s *Server) handleMonitorSettings(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	view, err := s.monitorSettingsView()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleMonitorSettingsUpdate answers POST /api/monitors/settings/update. A
// save names the version it was read at; a stale one is refused with 409.
// The setting covers the whole fleet, so a node-confined token may not save
// it. A lower retention is enforced by a sweep started at once.
func (s *Server) handleMonitorSettingsUpdate(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedFleetWrite(w, p, "monitor.settings.update", "monitor:admin") {
		return
	}
	var req model.MonitorSettings
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if req.FineRetentionDays < model.MonitorFineRetentionMinDays || req.FineRetentionDays > model.MonitorFineRetentionMaxDays {
		writeError(w, http.StatusBadRequest, fmt.Errorf("fine_retention_days must be %d to %d", model.MonitorFineRetentionMinDays, model.MonitorFineRetentionMaxDays))
		return
	}
	now := s.now()
	old := s.store.MonitorSettings()
	stored, err := s.store.SetMonitorSettings(req, req.Version, p.ActorID, now)
	if errors.Is(err, store.ErrMonitorSettingsVersion) {
		writeError(w, http.StatusConflict, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:       id.New("audit"),
		At:       now.UTC(),
		Action:   "monitor.settings.update",
		Scope:    "monitor:admin",
		Decision: "allow",
		Metadata: map[string]string{
			"version":                 strconv.FormatInt(stored.Version, 10),
			"old_fine_retention_days": strconv.Itoa(old.FineRetentionDays),
			"new_fine_retention_days": strconv.Itoa(stored.FineRetentionDays),
		},
	})
	if stored.FineRetentionDays < old.FineRetentionDays {
		s.wakeMonitorHistoryPrune()
	}
	view, err := s.monitorSettingsView()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// pruneWake is the sweep's wake-up channel, made on first use.
func (m *monitorPathState) pruneWake() chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.wake == nil {
		m.wake = make(chan struct{}, 1)
	}
	return m.wake
}

// wakeMonitorHistoryPrune asks the sweep to run now; a wake-up already
// pending covers this one.
func (s *Server) wakeMonitorHistoryPrune() {
	select {
	case s.monitorPaths.pruneWake() <- struct{}{}:
	default:
	}
}

// startMonitorHistoryPrune sweeps once soon after start and then every
// monitorPruneInterval or when woken. It stops with the latency probe sweep
// at Close; a sweep running then stops between write transactions.
func (s *Server) startMonitorHistoryPrune() {
	s.wakeMonitorHistoryPrune()
	s.latencySyncLoops.Add(1)
	go func() {
		defer s.latencySyncLoops.Done()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-s.latencySyncStop:
				cancel()
			case <-ctx.Done():
			}
		}()
		ticker := time.NewTicker(monitorPruneInterval)
		defer ticker.Stop()
		wake := s.monitorPaths.pruneWake()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-wake:
			}
			if ctx.Err() != nil {
				return
			}
			s.pruneMonitorHistory(ctx)
		}
	}()
}

// pruneMonitorHistory runs one sweep and logs what it deleted.
func (s *Server) pruneMonitorHistory(ctx context.Context) (store.MonitorPruneReport, error) {
	s.monitorPaths.pruneMu.Lock()
	defer s.monitorPaths.pruneMu.Unlock()
	report, err := s.store.PruneMonitorHistory(ctx, s.now())
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logger.Printf("monitor history: prune: %v", err)
		}
		return report, err
	}
	if report.Rows+report.Fine+report.Coarse > 0 {
		s.logger.Printf("monitor history: pruned %d raw rows, %d five-minute and %d hourly buckets in %d writes",
			report.Rows, report.Fine, report.Coarse, report.Transactions)
	}
	return report, nil
}
