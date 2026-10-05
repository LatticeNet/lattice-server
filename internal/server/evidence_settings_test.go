package server

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/logstore"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
	"github.com/LatticeNet/lattice-server/internal/tracestore"
)

// Evidence settings tests (design 26 R1, V8). The budgets bound what the
// server keeps, so the cases that matter are who may change them, that a
// change is never silent, and that the defaults are exactly today's values so
// an upgrade changes nothing.

type evidenceHarness struct {
	srv     *Server
	handler http.Handler
	st      *store.Store
	trace   *tracestore.Store
	logs    *logstore.Store
}

// newEvidenceServer builds a server over the given state store, a fresh
// trace.db and a logs.db opened with logCap (0 for the default), as main.go
// opens it from LATTICE_LOG_MAX_SOURCE_BYTES.
func newEvidenceServer(t *testing.T, st *store.Store, logCap int64) evidenceHarness {
	t.Helper()
	ts, err := tracestore.Open(filepath.Join(t.TempDir(), "trace.db"), secret.Disabled(), tracestore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.Close() })
	ls, err := logstore.Open(filepath.Join(t.TempDir(), "logs.db"), secret.Disabled(), logCap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ls.Close() })
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, TraceStore: ts, LogStore: ls})
	if err != nil {
		t.Fatal(err)
	}
	return evidenceHarness{srv: srv, handler: srv.Handler(), st: st, trace: ts, logs: ls}
}

func newEvidenceHarness(t *testing.T, logCap int64) evidenceHarness {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	return newEvidenceServer(t, st, logCap)
}

func decodeEvidenceView(t *testing.T, res *http.Response) evidenceSettingsView {
	t.Helper()
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("evidence settings: %d %s", res.StatusCode, body)
	}
	var view evidenceSettingsView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return view
}

// validEvidenceSettings is a full, in-bounds set read at version.
func validEvidenceSettings(version int64) map[string]any {
	return map[string]any{
		"trace_db_max_bytes":    int64(512 << 20),
		"record_ttl_seconds":    int64(7 * 86400),
		"line_ttl_seconds":      int64(2 * 86400),
		"rollup_5m_ttl_seconds": int64(30 * 86400),
		"raw_source_max_bytes":  int64(16 << 20),
		"version":               version,
	}
}

func TestEvidenceSettingsDefaultToTodaysValues(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	cookies, csrf := loginSession(t, h.handler)
	view := decodeEvidenceView(t, doTrace(t, h.handler, http.MethodGet, "/api/evidence/settings", cookies, csrf, nil))
	want := model.EvidenceSettings{
		TraceDBMaxBytes:    2 << 30,
		RecordTTLSeconds:   14 * 86400,
		LineTTLSeconds:     7 * 86400,
		Rollup5mTTLSeconds: 90 * 86400,
		RawSourceMaxBytes:  64 << 20,
	}
	if view.Settings != want || view.Stored || len(view.EnvIgnored) != 0 {
		t.Fatalf("defaults = %+v stored=%v env_ignored=%v, want %+v and nothing stored", view.Settings, view.Stored, view.EnvIgnored, want)
	}
	if view.Bounds != evidenceBounds {
		t.Fatalf("bounds = %+v, want %+v", view.Bounds, evidenceBounds)
	}

	// The per-source cap from LATTICE_LOG_MAX_SOURCE_BYTES is what logs.db
	// was opened with, and it is reported as the value in force.
	t.Setenv(envLogMaxSourceBytes, "33554432")
	env := newEvidenceHarness(t, logstore.EnvMaxSourceBytes("33554432"))
	cookies, csrf = loginSession(t, env.handler)
	view = decodeEvidenceView(t, doTrace(t, env.handler, http.MethodGet, "/api/evidence/settings", cookies, csrf, nil))
	if view.Settings.RawSourceMaxBytes != 32<<20 || view.Stored || len(view.EnvIgnored) != 0 {
		t.Fatalf("with the variable set: %+v stored=%v env_ignored=%v", view.Settings, view.Stored, view.EnvIgnored)
	}

	// Once saved, the stored value wins and the GET names the ignored variable.
	view = decodeEvidenceView(t, doTrace(t, env.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, validEvidenceSettings(0)))
	if !view.Stored || view.Settings.RawSourceMaxBytes != 16<<20 || len(view.EnvIgnored) != 1 || view.EnvIgnored[0] != envLogMaxSourceBytes {
		t.Fatalf("after a save: %+v stored=%v env_ignored=%v", view.Settings, view.Stored, view.EnvIgnored)
	}
	if got := env.logs.SourceBytesCap(); got != 16<<20 {
		t.Fatalf("logs.db cap = %d, want the stored %d over the variable", got, 16<<20)
	}
}

func TestEvidenceSettingsNeedAFullAdministrator(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	traceNode(t, h.st, "node-a")
	cookies, csrf := loginSession(t, h.handler)
	restricted := createPAT(t, h.handler, cookies, csrf, []string{"log:admin", "log:read"}, []string{"node-a"})
	readOnly := createPAT(t, h.handler, cookies, csrf, []string{"log:read"}, nil)

	// Reading needs only log:read, node restriction or not: the budgets are
	// server configuration and name no node.
	for name, token := range map[string]string{"node-restricted log:admin": restricted, "log:read": readOnly} {
		res := doBearerJSON(t, h.handler, http.MethodGet, "/api/evidence/settings", "", token)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"trace_db_max_bytes"`) {
			t.Fatalf("a %s token reading the settings: %d %s", name, res.StatusCode, body)
		}
	}

	body := string(mustJSON(t, validEvidenceSettings(0)))
	for name, token := range map[string]string{"node-restricted log:admin": restricted, "log:read": readOnly} {
		res := doBearerJSON(t, h.handler, http.MethodPost, "/api/evidence/settings", body, token)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("a %s token saved the settings: %d", name, res.StatusCode)
		}
	}
	if _, ok := h.st.EvidenceSettings(); ok {
		t.Fatal("a refused save stored settings")
	}
	denials := 0
	for _, ev := range h.st.AuditEvents() {
		if ev.Action == "evidence.settings.set" && ev.Decision == "deny" {
			denials++
		}
	}
	if denials != 2 {
		t.Fatalf("deny audits = %d, want 2", denials)
	}
}

func TestEvidenceSettingsRejectOutOfBounds(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	cookies, csrf := loginSession(t, h.handler)
	cases := map[string]func(map[string]any){
		"cap below the floor":       func(m map[string]any) { m["trace_db_max_bytes"] = int64(255 << 20) },
		"cap above the ceiling":     func(m map[string]any) { m["trace_db_max_bytes"] = int64(17 << 30) },
		"record TTL under a day":    func(m map[string]any) { m["record_ttl_seconds"] = int64(3600) },
		"line TTL over 30 days":     func(m map[string]any) { m["line_ttl_seconds"] = int64(31 * 86400) },
		"rollup TTL over 400 days":  func(m map[string]any) { m["rollup_5m_ttl_seconds"] = int64(401 * 86400) },
		"raw cap under a MiB":       func(m map[string]any) { m["raw_source_max_bytes"] = int64(1 << 19) },
		"a field left out":          func(m map[string]any) { delete(m, "line_ttl_seconds") },
		"an unknown field":          func(m map[string]any) { m["raw_pool_max_bytes"] = int64(1 << 30) },
		"a duration as nanoseconds": func(m map[string]any) { m["record_ttl_seconds"] = int64(7 * 86400 * time.Second) },
		"rollups shorter than records": func(m map[string]any) {
			m["record_ttl_seconds"] = int64(14 * 86400)
			m["rollup_5m_ttl_seconds"] = int64(7 * 86400)
		},
	}
	for name, mutate := range cases {
		body := validEvidenceSettings(0)
		mutate(body)
		res := doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, res.StatusCode)
		}
	}
	if _, ok := h.st.EvidenceSettings(); ok {
		t.Fatal("a refused save stored settings")
	}
	// The bounds themselves are inside.
	edge := map[string]any{
		"trace_db_max_bytes": evidenceBounds.TraceDBMaxBytes[0], "record_ttl_seconds": evidenceBounds.RecordTTLSeconds[1],
		"line_ttl_seconds": evidenceBounds.LineTTLSeconds[0], "rollup_5m_ttl_seconds": evidenceBounds.Rollup5mTTLSeconds[1],
		"raw_source_max_bytes": evidenceBounds.RawSourceMaxBytes[1], "version": 0,
	}
	decodeEvidenceView(t, doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, edge))
}

func TestEvidenceSettingsVersionConflict(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	cookies, csrf := loginSession(t, h.handler)
	first := decodeEvidenceView(t, doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, validEvidenceSettings(0)))
	if first.Settings.Version != 1 || !first.Stored {
		t.Fatalf("first save = %+v stored=%v", first.Settings, first.Stored)
	}
	stale := validEvidenceSettings(0)
	stale["record_ttl_seconds"] = int64(86400)
	res := doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, stale)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("a save from version 0 after version 1: %d, want 409", res.StatusCode)
	}
	if got, _ := h.st.EvidenceSettings(); got.RecordTTLSeconds != 7*86400 {
		t.Fatalf("the stale save landed: %+v", got)
	}
	stale["version"] = int64(1)
	if next := decodeEvidenceView(t, doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, stale)); next.Settings.Version != 2 {
		t.Fatalf("a save from the current version = %+v", next.Settings)
	}
}

func TestEvidenceSettingsApplyLive(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	cookies, csrf := loginSession(t, h.handler)
	traceMaxBytes := func() int64 {
		t.Helper()
		res := doTrace(t, h.handler, http.MethodGet, "/api/trace/stats", cookies, csrf, nil)
		defer res.Body.Close()
		var stats tracestore.Stats
		if err := json.NewDecoder(res.Body).Decode(&stats); err != nil {
			t.Fatal(err)
		}
		return stats.MaxBytes
	}
	if got := traceMaxBytes(); got != tracestore.DefaultMaxBytes {
		t.Fatalf("max_bytes before a save = %d, want the default %d", got, tracestore.DefaultMaxBytes)
	}
	decodeEvidenceView(t, doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, validEvidenceSettings(0)))
	if got := traceMaxBytes(); got != 512<<20 {
		t.Fatalf("max_bytes after a save = %d, want %d without a restart", got, 512<<20)
	}
	limits := h.trace.Limits()
	if limits.RecordTTL != 7*24*time.Hour || limits.LineTTL != 48*time.Hour || limits.RollupTTL != 30*24*time.Hour {
		t.Fatalf("trace limits = %+v", limits)
	}
	if got := h.logs.SourceBytesCap(); got != 16<<20 {
		t.Fatalf("logs.db cap = %d, want %d", got, 16<<20)
	}
}

// TestEvidenceSettingsLoweredTTLRunsRetentionNow: lowering a TTL kicks the
// retention loop, so a record past the new TTL goes now rather than within
// the hour the loop would otherwise sleep.
func TestEvidenceSettingsLoweredTTLRunsRetentionNow(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	cookies, csrf := loginSession(t, h.handler)
	// Let the loop's first pass go by, so only a kick can run the next one.
	time.Sleep(100 * time.Millisecond)
	old := time.Now().Add(-3 * 24 * time.Hour)
	if _, err := h.trace.AppendRecords([]model.ConnRecord{{
		NodeID: "node-a", CoreGeneration: 1, LogID: 1, StartedAt: old, EndedAt: old.Add(time.Second), CloseReason: model.CloseEOF,
	}}); err != nil {
		t.Fatal(err)
	}
	settings := validEvidenceSettings(0)
	settings["record_ttl_seconds"] = int64(86400)
	decodeEvidenceView(t, doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, settings))
	deadline := time.Now().Add(10 * time.Second)
	for {
		stats, err := h.trace.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if stats.Records == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a record past the lowered TTL is still held %s after the save", 10*time.Second)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestEvidenceSettingsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first := newEvidenceServer(t, st, 0)
	cookies, csrf := loginSession(t, first.handler)
	decodeEvidenceView(t, doTrace(t, first.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, validEvidenceSettings(0)))

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	second := newEvidenceServer(t, reopened, 0)
	// Applied at boot, before anyone reads them through the API.
	if got := second.trace.Limits().MaxBytes; got != 512<<20 {
		t.Fatalf("trace.db cap after a restart = %d, want %d", got, 512<<20)
	}
	if got := second.logs.SourceBytesCap(); got != 16<<20 {
		t.Fatalf("logs.db cap after a restart = %d, want %d", got, 16<<20)
	}
	cookies, csrf = loginSession(t, second.handler)
	view := decodeEvidenceView(t, doTrace(t, second.handler, http.MethodGet, "/api/evidence/settings", cookies, csrf, nil))
	if !view.Stored || view.Settings.Version != 1 {
		t.Fatalf("after a restart: %+v stored=%v", view.Settings, view.Stored)
	}
}

func TestEvidenceSettingsAreAudited(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	cookies, csrf := loginSession(t, h.handler)
	decodeEvidenceView(t, doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, validEvidenceSettings(0)))
	var found *model.AuditEvent
	for _, ev := range h.st.AuditEvents() {
		if ev.Action == "evidence.settings.set" && ev.Decision == "allow" {
			found = &ev
		}
	}
	if found == nil {
		t.Fatal("no allow audit for the save")
	}
	want := map[string]string{
		"version":                   "1",
		"old_trace_db_max_bytes":    "2147483648",
		"new_trace_db_max_bytes":    "536870912",
		"old_record_ttl_seconds":    "1209600",
		"new_record_ttl_seconds":    "604800",
		"old_line_ttl_seconds":      "604800",
		"new_line_ttl_seconds":      "172800",
		"old_rollup_5m_ttl_seconds": "7776000",
		"new_rollup_5m_ttl_seconds": "2592000",
		"old_raw_source_max_bytes":  "67108864",
		"new_raw_source_max_bytes":  "16777216",
	}
	for k, v := range want {
		if found.Metadata[k] != v {
			t.Errorf("audit metadata %s = %q, want %q", k, found.Metadata[k], v)
		}
	}
	if strings.TrimSpace(found.ActorID) == "" {
		t.Error("the audit names no actor")
	}
}

// TestEvidenceSettingsConcurrentSavesEndOnTheStoredValues races several
// administrators' saves. Whatever order they land in, the running stores end
// on the settings stored last, never on an earlier save applied late.
func TestEvidenceSettingsConcurrentSavesEndOnTheStoredValues(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	cookies, csrf := loginSession(t, h.handler)
	post := func(body map[string]any) int {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/settings", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Lattice-CSRF", csrf)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		return rec.Code
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				var version int64
				if cfg, ok := h.st.EvidenceSettings(); ok {
					version = cfg.Version
				}
				body := validEvidenceSettings(version)
				body["trace_db_max_bytes"] = int64(256+i) << 20
				body["raw_source_max_bytes"] = int64(1+i) << 20
				switch code := post(body); code {
				case http.StatusOK:
					return
				case http.StatusConflict:
					continue
				default:
					t.Errorf("save %d: %d", i, code)
					return
				}
			}
		}()
	}
	wg.Wait()
	stored, ok := h.st.EvidenceSettings()
	if !ok {
		t.Fatal("nothing stored")
	}
	if got := h.trace.Limits().MaxBytes; got != stored.TraceDBMaxBytes {
		t.Fatalf("trace.db runs on %d, stored is %d", got, stored.TraceDBMaxBytes)
	}
	if got := h.logs.SourceBytesCap(); int64(got) != stored.RawSourceMaxBytes {
		t.Fatalf("logs.db runs on %d, stored is %d", got, stored.RawSourceMaxBytes)
	}
}

// TestEvidenceSecondsFitGuardsTheDurationConversion: a TTL that would wrap
// time.Duration is refused whatever the bounds allow.
func TestEvidenceSecondsFitGuardsTheDurationConversion(t *testing.T) {
	limit := int64(math.MaxInt64 / int64(time.Second))
	for v, want := range map[int64]bool{0: true, 86400: true, limit: true, limit + 1: false, -1: false, math.MaxInt64: false} {
		if got := evidenceSecondsFit(v); got != want {
			t.Errorf("evidenceSecondsFit(%d) = %v, want %v", v, got, want)
		}
	}
	cfg := model.EvidenceSettings{TraceDBMaxBytes: 1 << 30, RecordTTLSeconds: limit + 1, LineTTLSeconds: 3600, Rollup5mTTLSeconds: limit + 1, RawSourceMaxBytes: 1 << 20}
	if err := validateEvidenceSettings(cfg); err == nil || !strings.Contains(err.Error(), "does not fit a duration") {
		t.Fatalf("validate an overflowing TTL = %v", err)
	}
}

// TestInvalidStoredEvidenceSettingsAreNotAppliedAtBoot: settings no save
// could have stored (a hand-edited state file) are refused at boot. The
// stores keep their own limits, nothing is deleted, and GET says why.
func TestInvalidStoredEvidenceSettingsAreNotAppliedAtBoot(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetEvidenceSettings(model.EvidenceSettings{
		TraceDBMaxBytes: 1, RecordTTLSeconds: 1, LineTTLSeconds: 1, Rollup5mTTLSeconds: 1, RawSourceMaxBytes: 1,
	}, 0, "hand-edit", time.Now()); err != nil {
		t.Fatal(err)
	}
	h := newEvidenceServer(t, st, 0)
	at := time.Now().Add(-time.Hour)
	if _, err := h.trace.AppendRecords([]model.ConnRecord{
		{NodeID: "node-a", CoreGeneration: 1, LogID: 1, StartedAt: at, EndedAt: at.Add(time.Second), CloseReason: model.CloseEOF},
		{NodeID: "node-a", CoreGeneration: 1, LogID: 2, StartedAt: at, EndedAt: at.Add(time.Second), CloseReason: model.CloseEOF},
	}); err != nil {
		t.Fatal(err)
	}
	if got := h.trace.Limits(); got.RecordTTL != tracestore.DefaultRecordTTL || got.MaxBytes != tracestore.DefaultMaxBytes {
		t.Fatalf("trace.db limits after booting on invalid settings = %+v, want its defaults", got)
	}
	if got := h.logs.SourceBytesCap(); got != logstore.DefaultMaxSourceBytes {
		t.Fatalf("logs.db cap = %d, want its default", got)
	}
	if _, err := h.trace.Retain(time.Now()); err != nil {
		t.Fatal(err)
	}
	if stats, err := h.trace.Stats(); err != nil || stats.Records != 2 {
		t.Fatalf("records after a retention pass = %d (%v), want both kept", stats.Records, err)
	}

	cookies, csrf := loginSession(t, h.handler)
	view := decodeEvidenceView(t, doTrace(t, h.handler, http.MethodGet, "/api/evidence/settings", cookies, csrf, nil))
	if !view.Stored || !view.InvalidStored || view.Settings.Version != 1 || view.Settings.RecordTTLSeconds != 14*86400 {
		t.Fatalf("GET = %+v stored=%v invalid=%v, want the defaults in force under stored version 1", view.Settings, view.Stored, view.InvalidStored)
	}
	// A save from that version replaces them.
	if view := decodeEvidenceView(t, doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, validEvidenceSettings(1))); view.InvalidStored || view.Settings.Version != 2 {
		t.Fatalf("after a save: %+v invalid=%v", view.Settings, view.InvalidStored)
	}
}

// TestEvidenceSettingsLoweredRawCapShrinksIdleSources: Append evicts only
// the source it writes to, so a lowered cap is enforced by one pass over
// every source on save rather than left until each next appends.
func TestEvidenceSettingsLoweredRawCapShrinksIdleSources(t *testing.T) {
	h := newEvidenceHarness(t, 0)
	cookies, csrf := loginSession(t, h.handler)
	line := strings.Repeat("x", 64<<10)
	base := time.Now().Add(-time.Hour)
	for _, source := range []string{"idle-a", "idle-b"} {
		for i := range 40 {
			if _, err := h.logs.Append(source, []model.LogLine{{At: base.Add(time.Duration(i) * time.Second), Line: line}}, "r", uint64(i+1), base); err != nil {
				t.Fatal(err)
			}
		}
		if meta, _, _, _ := h.logs.Stats(source); meta.Bytes <= 1<<20 {
			t.Fatalf("%s holds %d bytes; the test needs more than the new cap", source, meta.Bytes)
		}
	}
	settings := validEvidenceSettings(0)
	settings["raw_source_max_bytes"] = int64(1 << 20)
	decodeEvidenceView(t, doTrace(t, h.handler, http.MethodPost, "/api/evidence/settings", cookies, csrf, settings))
	deadline := time.Now().Add(10 * time.Second)
	for _, source := range []string{"idle-a", "idle-b"} {
		for {
			meta, _, _, _ := h.logs.Stats(source)
			if meta.Bytes <= 1<<20 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s still holds %d bytes over the lowered cap with no append", source, meta.Bytes)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// TestRetentionWaitEndsOnAKick: every wait in the retention loop, the hour
// and the retry delay after a truncated pass alike, goes through
// waitTraceRetention, which a settings save cuts short.
func TestRetentionWaitEndsOnAKick(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	// No background loops, so nothing else takes the kick.
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		srv.waitTraceRetention(time.Hour)
		close(done)
	}()
	srv.kickTraceRetention()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a kick did not end an hour's wait")
	}
}
