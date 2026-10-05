package server

import (
	"errors"
	"fmt"
	"math"
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
	// Stored is false while no administrator has saved.
	Stored bool `json:"stored"`
	// InvalidStored reports stored settings that fail validation (a
	// hand-edited state file, or bounds an upgrade tightened). They are not
	// applied: Settings shows the stores' own values under the stored
	// version, so the next save names that version and replaces them.
	InvalidStored bool `json:"invalid_stored,omitempty"`
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
	cfg, ok := s.store.EvidenceSettings()
	if !ok {
		return
	}
	if err := validateEvidenceSettings(cfg); err != nil {
		// A value no save could have stored might empty trace.db on the
		// first retention pass. Keep the stores on their own limits, delete
		// nothing, and say why; GET reports invalid_stored until a save
		// replaces the stored settings.
		s.logger.Printf("evidence settings: stored version %d is invalid and was not applied; trace.db and logs.db keep their own limits: %v", cfg.Version, err)
		return
	}
	s.applyEvidenceSettings(cfg)
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

// effectiveEvidenceSettings is what is in force: valid stored settings, or
// the values the stores were opened with. stored reports settings in the
// state file; invalid reports stored settings that fail validation and so
// were never applied, in which case the values are the stores' own under the
// stored version, author and time.
func (s *Server) effectiveEvidenceSettings() (cfg model.EvidenceSettings, stored, invalid bool) {
	saved, ok := s.store.EvidenceSettings()
	if ok && validateEvidenceSettings(saved) == nil {
		return saved, true, false
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
	cfg = model.EvidenceSettings{
		TraceDBMaxBytes:    limits.MaxBytes,
		RecordTTLSeconds:   int64(limits.RecordTTL / time.Second),
		LineTTLSeconds:     int64(limits.LineTTL / time.Second),
		Rollup5mTTLSeconds: int64(limits.RollupTTL / time.Second),
		RawSourceMaxBytes:  rawCap,
	}
	if ok {
		cfg.Version, cfg.UpdatedAt, cfg.UpdatedBy = saved.Version, saved.UpdatedAt, saved.UpdatedBy
	}
	return cfg, ok, ok
}

func (s *Server) evidenceSettingsView() evidenceSettingsView {
	cfg, stored, invalid := s.effectiveEvidenceSettings()
	view := evidenceSettingsView{Settings: cfg, Stored: stored, InvalidStored: invalid, Bounds: evidenceBounds}
	if stored && !invalid && logstore.EnvMaxSourceBytes(os.Getenv(envLogMaxSourceBytes)) > 0 {
		view.EnvIgnored = []string{envLogMaxSourceBytes}
	}
	return view
}

// validateEvidenceSettings refuses any value outside its bounds. Every field
// is required: a zero is out of bounds, so a client cannot store a partial
// set by omission. It runs on every save and on the stored settings at boot.
func validateEvidenceSettings(cfg model.EvidenceSettings) error {
	check := func(name string, v int64, b [2]int64) error {
		if v < b[0] || v > b[1] {
			return fmt.Errorf("%s must be between %d and %d", name, b[0], b[1])
		}
		return nil
	}
	ttl := func(name string, v int64, b [2]int64) error {
		// Checked apart from the bounds, so a later bound can never let a
		// TTL wrap time.Duration into a negative that deletes everything.
		if !evidenceSecondsFit(v) {
			return fmt.Errorf("%s does not fit a duration", name)
		}
		return check(name, v, b)
	}
	var order error
	if cfg.Rollup5mTTLSeconds < cfg.RecordTTLSeconds {
		order = errors.New("rollup_5m_ttl_seconds must be at least record_ttl_seconds: the trends would end before the records they sum")
	}
	return errors.Join(
		check("trace_db_max_bytes", cfg.TraceDBMaxBytes, evidenceBounds.TraceDBMaxBytes),
		ttl("record_ttl_seconds", cfg.RecordTTLSeconds, evidenceBounds.RecordTTLSeconds),
		ttl("line_ttl_seconds", cfg.LineTTLSeconds, evidenceBounds.LineTTLSeconds),
		ttl("rollup_5m_ttl_seconds", cfg.Rollup5mTTLSeconds, evidenceBounds.Rollup5mTTLSeconds),
		check("raw_source_max_bytes", cfg.RawSourceMaxBytes, evidenceBounds.RawSourceMaxBytes),
		order,
	)
}

// evidenceSecondsFit reports whether whole seconds convert to a
// time.Duration without overflow (about 292 years).
func evidenceSecondsFit(seconds int64) bool {
	return seconds >= 0 && seconds <= math.MaxInt64/int64(time.Second)
}

// enforceRawSourceCap brings every logs.db source under a lowered cap. Only
// an append evicts, so without this pass an idle source would keep its bytes
// above the new cap until it next receives a line. The evicted chunks free
// pages inside logs.db for its own reuse; bbolt never returns them to the
// filesystem, so the file keeps its size.
func (s *Server) enforceRawSourceCap() {
	n, err := s.logStore.EnforceSourceBytesCap()
	if err != nil {
		s.logger.Printf("evidence settings: bring raw log sources under the lowered cap: %v", err)
		return
	}
	if n > 0 {
		s.logger.Printf("evidence settings: brought %d raw log sources under the lowered cap", n)
	}
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
	old, _, _ = s.effectiveEvidenceSettings()
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
		// hour, and a lower raw cap now rather than on each source's next
		// append (enforceRawSourceCap).
		if stored.TraceDBMaxBytes < old.TraceDBMaxBytes || stored.RecordTTLSeconds < old.RecordTTLSeconds ||
			stored.LineTTLSeconds < old.LineTTLSeconds || stored.Rollup5mTTLSeconds < old.Rollup5mTTLSeconds {
			s.kickTraceRetention()
		}
		if stored.RawSourceMaxBytes < old.RawSourceMaxBytes && s.logStore != nil {
			go s.enforceRawSourceCap()
		}
		writeJSON(w, http.StatusOK, s.evidenceSettingsView())
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}
