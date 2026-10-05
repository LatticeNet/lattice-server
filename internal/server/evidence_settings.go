package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/logstore"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/tracestore"
)

// Evidence settings: the local budgets that bound trace.db and logs.db.
//
// Until an administrator saves, the values in force are whatever the stores
// were opened with, which is today's behaviour: tracestore's defaults and the
// per-source cap from LATTICE_LOG_MAX_SOURCE_BYTES or 64 MiB. A save stores
// all five values in the state file and applies them to the running stores at
// once; from then on the stored values win over the environment variable, and
// GET names the variable it now ignores so the precedence is never a
// surprise. Upgrading changes nothing: no value is stored until someone saves.
//
// Design: lattice/docs/designs/design-26-evidence-retention.md section 6.

// envLogMaxSourceBytes is the environment variable that sets the per-source
// cap at boot (cmd/lattice-server/main.go).
const envLogMaxSourceBytes = "LATTICE_LOG_MAX_SOURCE_BYTES"

// evidenceSettingsBounds are the closed ranges a save must stay inside. The
// floors keep a mistyped value from emptying the stores within an hour; the
// ceilings keep one setting from claiming the disk. The rollup ceiling is the
// longest tier R2 will hold (400 days).
type evidenceSettingsBounds struct {
	TraceDBMaxBytes    [2]int64 `json:"trace_db_max_bytes"`
	RecordTTLSeconds   [2]int64 `json:"record_ttl_seconds"`
	LineTTLSeconds     [2]int64 `json:"line_ttl_seconds"`
	Rollup5mTTLSeconds [2]int64 `json:"rollup_5m_ttl_seconds"`
	RawSourceMaxBytes  [2]int64 `json:"raw_source_max_bytes"`
}

const (
	evidenceDay = int64(24 * 60 * 60)
	evidenceMiB = int64(1) << 20
)

var evidenceBounds = evidenceSettingsBounds{
	TraceDBMaxBytes:    [2]int64{256 * evidenceMiB, 16 << 30},
	RecordTTLSeconds:   [2]int64{evidenceDay, 90 * evidenceDay},
	LineTTLSeconds:     [2]int64{60 * 60, 30 * evidenceDay},
	Rollup5mTTLSeconds: [2]int64{evidenceDay, 400 * evidenceDay},
	RawSourceMaxBytes:  [2]int64{evidenceMiB, 1 << 30},
}

// evidenceSettingsView is the GET and POST answer.
type evidenceSettingsView struct {
	Settings model.EvidenceSettings `json:"settings"`
	// Stored is false while the values are the boot defaults.
	Stored bool `json:"stored"`
	// EnvIgnored names environment variables that are set but overridden by
	// the stored settings.
	EnvIgnored []string               `json:"env_ignored,omitempty"`
	Bounds     evidenceSettingsBounds `json:"bounds"`
}

// initEvidenceSettings runs once in New, before any loop that reads the
// limits starts: it makes the retention kick and applies stored settings to
// the stores, so boot and an edit take the same path.
func (s *Server) initEvidenceSettings() {
	s.traceRetentionKick = make(chan struct{}, 1)
	if cfg, ok := s.store.EvidenceSettings(); ok {
		s.applyEvidenceSettings(cfg)
	}
}

// applyEvidenceSettings hands the budgets to the running stores. Neither
// store deletes anything in the call: trace.db enforces the new limits on its
// next retention pass, logs.db on each source's next append.
func (s *Server) applyEvidenceSettings(cfg model.EvidenceSettings) {
	if s.traceStore != nil {
		s.traceStore.SetLimits(tracestore.Options{
			RecordTTL: time.Duration(cfg.RecordTTLSeconds) * time.Second,
			LineTTL:   time.Duration(cfg.LineTTLSeconds) * time.Second,
			RollupTTL: time.Duration(cfg.Rollup5mTTLSeconds) * time.Second,
			MaxBytes:  cfg.TraceDBMaxBytes,
		})
	}
	if s.logStore != nil {
		s.logStore.SetSourceBytesCap(cfg.RawSourceMaxBytes)
	}
}

// effectiveEvidenceSettings is what is in force: the stored settings, or the
// values the stores were opened with.
func (s *Server) effectiveEvidenceSettings() (model.EvidenceSettings, bool) {
	if cfg, ok := s.store.EvidenceSettings(); ok {
		return cfg, true
	}
	limits := tracestore.Options{
		RecordTTL: tracestore.DefaultRecordTTL,
		LineTTL:   tracestore.DefaultLineTTL,
		RollupTTL: tracestore.DefaultRollupTTL,
		MaxBytes:  tracestore.DefaultMaxBytes,
	}
	if s.traceStore != nil {
		limits = s.traceStore.Limits()
	}
	rawCap := int64(logstore.DefaultMaxSourceBytes)
	if s.logStore != nil {
		rawCap = int64(s.logStore.SourceBytesCap())
	} else if env := logstore.EnvMaxSourceBytes(os.Getenv(envLogMaxSourceBytes)); env > 0 {
		rawCap = env
	}
	return model.EvidenceSettings{
		TraceDBMaxBytes:    limits.MaxBytes,
		RecordTTLSeconds:   int64(limits.RecordTTL / time.Second),
		LineTTLSeconds:     int64(limits.LineTTL / time.Second),
		Rollup5mTTLSeconds: int64(limits.RollupTTL / time.Second),
		RawSourceMaxBytes:  rawCap,
	}, false
}

func (s *Server) evidenceSettingsView() evidenceSettingsView {
	cfg, stored := s.effectiveEvidenceSettings()
	view := evidenceSettingsView{Settings: cfg, Stored: stored, Bounds: evidenceBounds}
	if stored && logstore.EnvMaxSourceBytes(os.Getenv(envLogMaxSourceBytes)) > 0 {
		view.EnvIgnored = []string{envLogMaxSourceBytes}
	}
	return view
}

// validateEvidenceSettings refuses any value outside its bounds. Every field
// is required: a zero is out of bounds, so a client cannot store a partial
// set by omission.
func validateEvidenceSettings(cfg model.EvidenceSettings) error {
	check := func(name string, v int64, b [2]int64) error {
		if v < b[0] || v > b[1] {
			return fmt.Errorf("%s must be between %d and %d", name, b[0], b[1])
		}
		return nil
	}
	return errors.Join(
		check("trace_db_max_bytes", cfg.TraceDBMaxBytes, evidenceBounds.TraceDBMaxBytes),
		check("record_ttl_seconds", cfg.RecordTTLSeconds, evidenceBounds.RecordTTLSeconds),
		check("line_ttl_seconds", cfg.LineTTLSeconds, evidenceBounds.LineTTLSeconds),
		check("rollup_5m_ttl_seconds", cfg.Rollup5mTTLSeconds, evidenceBounds.Rollup5mTTLSeconds),
		check("raw_source_max_bytes", cfg.RawSourceMaxBytes, evidenceBounds.RawSourceMaxBytes),
	)
}

// kickTraceRetention asks the retention loop for a pass now. It never blocks:
// a kick already pending covers this one.
func (s *Server) kickTraceRetention() {
	select {
	case s.traceRetentionKick <- struct{}{}:
	default:
	}
}

// saveEvidenceSettings stores req and applies it to the running stores, and
// returns the settings it replaced. One save at a time: two saves that
// interleave could otherwise apply in the opposite order to the one they were
// stored in, leaving the stores on the older settings until a restart, and
// report each other's values as old in the audit.
func (s *Server) saveEvidenceSettings(req model.EvidenceSettings, actor string, now time.Time) (old, stored model.EvidenceSettings, err error) {
	s.evidenceSettingsMu.Lock()
	defer s.evidenceSettingsMu.Unlock()
	old, _ = s.effectiveEvidenceSettings()
	stored, err = s.store.SetEvidenceSettings(model.EvidenceSettings{
		TraceDBMaxBytes:    req.TraceDBMaxBytes,
		RecordTTLSeconds:   req.RecordTTLSeconds,
		LineTTLSeconds:     req.LineTTLSeconds,
		Rollup5mTTLSeconds: req.Rollup5mTTLSeconds,
		RawSourceMaxBytes:  req.RawSourceMaxBytes,
	}, req.Version, actor, now)
	if err != nil {
		return old, stored, err
	}
	s.applyEvidenceSettings(stored)
	return old, stored, nil
}

// handleEvidenceSettings reads the budgets (GET, log:read) or saves them
// (POST, a full administrator only). A save names the version it was read at;
// a stale one is refused with 409 so two administrators cannot overwrite each
// other. Lowering a cap deletes the oldest evidence on the next pass, which is
// why the save is audited with every old and new value.
func (s *Server) handleEvidenceSettings(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "log:read") {
			return
		}
		writeJSON(w, http.StatusOK, s.evidenceSettingsView())
	case http.MethodPost:
		if !s.requireFullAdmin(w, p, "evidence.settings.set") {
			return
		}
		var req model.EvidenceSettings
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if err := validateEvidenceSettings(req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		now := s.now()
		old, stored, err := s.saveEvidenceSettings(req, p.ActorID, now)
		if errors.Is(err, store.ErrEvidenceSettingsVersion) {
			writeError(w, http.StatusConflict, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		meta := map[string]string{"version": strconv.FormatInt(stored.Version, 10)}
		for _, f := range []struct {
			name     string
			old, new int64
		}{
			{"trace_db_max_bytes", old.TraceDBMaxBytes, stored.TraceDBMaxBytes},
			{"record_ttl_seconds", old.RecordTTLSeconds, stored.RecordTTLSeconds},
			{"line_ttl_seconds", old.LineTTLSeconds, stored.LineTTLSeconds},
			{"rollup_5m_ttl_seconds", old.Rollup5mTTLSeconds, stored.Rollup5mTTLSeconds},
			{"raw_source_max_bytes", old.RawSourceMaxBytes, stored.RawSourceMaxBytes},
		} {
			meta["old_"+f.name] = strconv.FormatInt(f.old, 10)
			meta["new_"+f.name] = strconv.FormatInt(f.new, 10)
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:       id.New("audit"),
			At:       now.UTC(),
			Action:   "evidence.settings.set",
			Scope:    "*",
			Decision: "allow",
			Metadata: meta,
		})
		// A lower trace.db cap or TTL is enforced now rather than within the
		// hour. The per-source raw cap needs no pass: logs.db applies it on
		// each source's next append.
		if stored.TraceDBMaxBytes < old.TraceDBMaxBytes || stored.RecordTTLSeconds < old.RecordTTLSeconds ||
			stored.LineTTLSeconds < old.LineTTLSeconds || stored.Rollup5mTTLSeconds < old.Rollup5mTTLSeconds {
			s.kickTraceRetention()
		}
		writeJSON(w, http.StatusOK, s.evidenceSettingsView())
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}
