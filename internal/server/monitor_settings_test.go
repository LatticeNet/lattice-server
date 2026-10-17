package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

func decodeSettings(t *testing.T, res *http.Response) model.MonitorSettingsView {
	t.Helper()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("settings = %d", res.StatusCode)
	}
	var v model.MonitorSettingsView
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// The settings read shows the setting in force, the fixed tiers, the paths
// that record history and the size measured and projected; a save names its
// version, is bounded, is refused to a confined token, is audited, and a
// lower retention wakes the sweep.
func TestMonitorSettingsRoutes(t *testing.T) {
	srv, handler, st := newPathsServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"}, model.Node{ID: "node-b", Name: "b"}, model.Node{ID: "node-c", Name: "c"})
	for _, mon := range []model.Monitor{
		{ID: "mon-a", Name: "a", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a", "node-b"}, PausedNodeIDs: []string{"node-b"}, Enabled: true},
		{ID: "mon-all", Name: "all", Type: model.MonitorTypeTCP, Target: "203.0.113.9:80", IntervalSec: 60, TimeoutSec: 5, AssignAll: true, Enabled: true},
		{ID: "mon-off", Name: "off", Type: model.MonitorTypeTCP, Target: "203.0.113.9:22", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}},
		{ID: "mon-tls", Name: "cert", Type: model.MonitorTypeTLS, Target: "example.com:443", IntervalSec: 3600, TimeoutSec: 10, Enabled: true},
	} {
		if err := st.UpsertMonitor(mon); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if _, err := st.IngestAgentMonitorResults("node-a", []model.MonitorResult{{MonitorID: "mon-a", At: now, Success: true, LatencyMs: 9}}, now); err != nil {
		t.Fatal(err)
	}
	v := decodeSettings(t, doJSON(t, handler, http.MethodGet, "/api/monitors/settings", "", cookies, ""))
	// mon-a runs from one source, mon-all from three, mon-tls from the
	// control plane; mon-off is disabled.
	if v.Version != 0 || v.FineRetentionDays != 7 || v.FineMinDays != 3 || v.FineMaxDays != 14 || v.CoarseRetentionDays != 35 ||
		v.RawRowsPerPath != 1440 || v.Paths != 5 || v.MeasuredBytes <= 0 || v.ProjectedBytes <= v.MeasuredBytes {
		t.Fatalf("defaults = %+v", v)
	}
	want := int64(5) * (monitorProjectFineBytes*7*288 + monitorProjectCoarseBytes*35*24 + monitorProjectRowBytes*1440 + monitorProjectLatestBytes)
	if v.ProjectedBytes != want {
		t.Fatalf("projected = %d, want %d from the default per-key sizes", v.ProjectedBytes, want)
	}
	update := func(body string) *http.Response {
		return doJSON(t, handler, http.MethodPost, "/api/monitors/settings/update", body, cookies, csrf)
	}
	for body, status := range map[string]int{
		`{"version":0,"fine_retention_days":2}`:  http.StatusBadRequest,
		`{"version":0,"fine_retention_days":15}`: http.StatusBadRequest,
		`{"version":4,"fine_retention_days":5}`:  http.StatusConflict,
	} {
		res := update(body)
		res.Body.Close()
		if res.StatusCode != status {
			t.Fatalf("%s = %d, want %d", body, res.StatusCode, status)
		}
	}
	saved := decodeSettings(t, update(`{"version":0,"fine_retention_days":14}`))
	if saved.Version != 1 || saved.FineRetentionDays != 14 || saved.UpdatedBy == "" {
		t.Fatalf("saved = %+v", saved)
	}
	select {
	case <-srv.monitorPaths.pruneWake():
		t.Fatal("a longer retention woke the sweep")
	default:
	}
	lowered := decodeSettings(t, update(`{"version":1,"fine_retention_days":3}`))
	if lowered.Version != 2 || lowered.ProjectedBytes >= saved.ProjectedBytes {
		t.Fatalf("lowered = %+v (projected was %d)", lowered, saved.ProjectedBytes)
	}
	select {
	case <-srv.monitorPaths.pruneWake():
	default:
		t.Fatal("a lower retention did not wake the sweep")
	}
	if got := st.MonitorHistoryLimits(); got.FineKeep != 3*24*time.Hour+time.Hour {
		t.Fatalf("limits = %+v", got)
	}
	if !auditHasAction(t, st, "monitor.settings.update") {
		t.Fatal("the save was not audited")
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"monitor:admin", "monitor:read"}, []string{"node-a"})
	res := doBearerJSON(t, handler, http.MethodPost, "/api/monitors/settings/update", `{"version":2,"fine_retention_days":7}`, confined)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("confined save = %d", res.StatusCode)
	}
	confinedRead := doBearerJSON(t, handler, http.MethodGet, "/api/monitors/settings", "", confined)
	confinedRead.Body.Close()
	if confinedRead.StatusCode != http.StatusForbidden {
		t.Fatalf("confined read = %d", confinedRead.StatusCode)
	}
	reader := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, nil)
	if v := decodeSettings(t, doBearerJSON(t, handler, http.MethodGet, "/api/monitors/settings", "", reader)); v.Version != 2 {
		t.Fatalf("read with monitor:read = %+v", v)
	}
	res = doBearerJSON(t, handler, http.MethodPost, "/api/monitors/settings/update", `{"version":2,"fine_retention_days":7}`, reader)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("save with monitor:read = %d", res.StatusCode)
	}
}

// Once a tier holds enough keys, the projection uses the size per key it
// measures there.
func TestMonitorProjectionUsesMeasuredSizes(t *testing.T) {
	usage := store.MonitorStorageUsage{Measured: true, FineBytes: 400 * 2000, FineKeys: 2000, CoarseBytes: 10, CoarseKeys: 1}
	got := monitorProjectedBytes(usage, 10, 7)
	want := int64(10) * (400*7*288 + monitorProjectCoarseBytes*35*24 + monitorProjectRowBytes*1440 + monitorProjectLatestBytes)
	if got != want {
		t.Fatalf("projected = %d, want %d", got, want)
	}
}
