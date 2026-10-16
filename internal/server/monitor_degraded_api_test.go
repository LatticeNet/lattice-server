package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// lastAudit is the newest audit record of action (AuditEvents lists newest
// first).
func lastAudit(t *testing.T, st *store.Store, action string) model.AuditEvent {
	t.Helper()
	for _, ev := range st.AuditEvents() {
		if ev.Action == action {
			return ev
		}
	}
	t.Fatalf("no %s audit record", action)
	return model.AuditEvent{}
}

func apiErrorText(t *testing.T, res *http.Response) string {
	t.Helper()
	return readBody(t, res)
}

// The alert policy and the degraded thresholds on create and edit: bounds,
// the tls refusals, the canonical form, absent keeping, {} resetting, and
// audit records that name what changed.
func TestDegradedPolicyOnCheckSaves(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"})
	post := func(path, body string) *http.Response {
		return doJSON(t, handler, http.MethodPost, path, body, cookies, csrf)
	}
	res := post("/api/monitors", `{"name":"web","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"alert":"down_and_degraded","degraded":{"loss_percent":3.14,"latency_margin_ms":30}}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create = %d %s", res.StatusCode, readBody(t, res))
	}
	view := decodeMonitorView(t, res)
	if view.Alert != model.MonitorAlertDownAndDegraded || view.Degraded == nil || *view.Degraded != (model.MonitorDegradedRule{LossPercent: 3.1}) {
		t.Fatalf("created = alert %q degraded %+v", view.Alert, view.Degraded)
	}
	if ev := lastAudit(t, st, "monitor.create"); ev.Metadata["alert"] != model.MonitorAlertDownAndDegraded || ev.Metadata["degraded"] != "loss_percent=3.1" {
		t.Fatalf("create audit = %+v", ev.Metadata)
	}
	for body, want := range map[string]string{
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"degraded":{"loss_percent":60}}`:     "degraded.loss_percent must be 0.5 to 50",
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"degraded":{"loss_percent":0.4}}`:    "degraded.loss_percent must be 0.5 to 50",
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"degraded":{"latency_factor":-2}}`:   "degraded.latency_factor cannot be negative",
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"degraded":{"loss_factor":10.5}}`:    "degraded.loss_factor must be 1.2 to 10",
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"degraded":{"latency_margin_ms":4}}`: "degraded.latency_margin_ms must be 5 to 1000",
		`{"name":"x","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"alert":"loud"}`:                     "alert must be",
		`{"name":"x","type":"tls","target":"example.com:443","alert":"down_and_degraded"}`:                              "a tls check measures a certificate",
		`{"name":"x","type":"tls","target":"example.com:443","degraded":{}}`:                                            "a tls check measures a certificate",
	} {
		res := post("/api/monitors", body)
		if text := apiErrorText(t, res); res.StatusCode != http.StatusBadRequest || !strings.Contains(text, want) {
			t.Errorf("%s = %d %s, want 400 %q", body, res.StatusCode, text, want)
		}
	}
	// An editor that echoes the defaults stores nothing.
	res = post("/api/monitors", `{"name":"echo","type":"tcp","target":"203.0.113.9:443","node_ids":["node-a"],"degraded":{"loss_percent":2,"loss_factor":2,"latency_factor":2,"latency_margin_ms":30}}`)
	if v := decodeMonitorView(t, res); v.Degraded != nil {
		t.Fatalf("echoed defaults stored %+v", v.Degraded)
	}
	tls := decodeMonitorView(t, post("/api/monitors", `{"name":"cert","type":"tls","target":"example.com:443"}`))

	edit := func(body string) *http.Response { return post("/api/monitors/update", body) }
	id := view.ID
	// Absent keeps.
	v := decodeMonitorView(t, edit(`{"id":"`+id+`","version":1,"name":"web front"}`))
	if v.Degraded == nil || v.Degraded.LossPercent != 3.1 || v.Alert != model.MonitorAlertDownAndDegraded {
		t.Fatalf("an edit without degraded = %+v %q", v.Degraded, v.Alert)
	}
	// An object replaces the rule whole.
	v = decodeMonitorView(t, edit(`{"id":"`+id+`","version":2,"degraded":{"latency_margin_ms":50},"alert":"down"}`))
	if v.Degraded == nil || *v.Degraded != (model.MonitorDegradedRule{LatencyMarginMs: 50}) || v.Alert != model.MonitorAlertDown {
		t.Fatalf("replaced = %+v %q", v.Degraded, v.Alert)
	}
	ev := lastAudit(t, st, "monitor.update")
	if ev.Metadata["changed"] != "alert,degraded" || ev.Metadata["degraded"] != "latency_margin_ms=50" || ev.Metadata["alert"] != model.MonitorAlertDown {
		t.Fatalf("edit audit = %+v", ev.Metadata)
	}
	// {} resets to the defaults.
	v = decodeMonitorView(t, edit(`{"id":"`+id+`","version":3,"degraded":{}}`))
	if v.Degraded != nil {
		t.Fatalf("reset = %+v", v.Degraded)
	}
	if mon, _ := st.Monitor(id); mon.Degraded != nil {
		t.Fatalf("stored after reset = %+v", mon.Degraded)
	}
	if ev := lastAudit(t, st, "monitor.update"); ev.Metadata["degraded"] != "default" {
		t.Fatalf("reset audit = %+v", ev.Metadata)
	}
	// null keeps, an out-of-bounds value is refused, tls refuses both.
	v = decodeMonitorView(t, edit(`{"id":"`+id+`","version":4,"degraded":null,"name":"web"}`))
	if v.Version != 5 || v.Degraded != nil {
		t.Fatalf("null = %+v", v)
	}
	for body, want := range map[string]string{
		`{"id":"` + id + `","version":5,"degraded":{"loss_factor":1.1}}`:       "degraded.loss_factor must be 1.2 to 10",
		`{"id":"` + tls.ID + `","version":1,"alert":"down_and_degraded"}`:      "a tls check measures a certificate",
		`{"id":"` + tls.ID + `","version":1,"degraded":{"loss_percent":3}}`:    "a tls check measures a certificate",
		`{"id":"` + id + `","version":5,"alert":"degraded"}`:                   "alert must be",
		`{"id":"` + id + `","version":5,"degraded":{"latency_margin_ms":1e9}}`: "degraded.latency_margin_ms must be 5 to 1000",
	} {
		res := edit(body)
		if text := apiErrorText(t, res); res.StatusCode != http.StatusBadRequest || !strings.Contains(text, want) {
			t.Errorf("%s = %d %s, want 400 %q", body, res.StatusCode, text, want)
		}
	}
}

// The path set's alert, alert_after and degraded survive a save (the
// normalizer builds its output field by field), are bounded, are audited,
// and become the policy its generated checks read.
func TestDegradedPolicyOnPathSetSaves(t *testing.T) {
	srv, handler, st := latencyFleet(t)
	cookies, csrf := loginSession(t, handler)
	in := model.LatencyProbeConfig{Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: []string{"node-sh"}, AutoTargets: true,
		Alert: model.MonitorAlertDownAndDegraded, AlertAfter: 4, Degraded: &model.MonitorDegradedRule{LossFactor: 3.04, LatencyMarginMs: 30}}
	out, err := srv.normalizeLatencyProbeConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Alert != model.MonitorAlertDownAndDegraded || out.AlertAfter != 4 || out.Degraded == nil || *out.Degraded != (model.MonitorDegradedRule{LossFactor: 3}) {
		t.Fatalf("normalized = alert %q after %d degraded %+v", out.Alert, out.AlertAfter, out.Degraded)
	}
	status, plan, body := putLatencyConfig(t, handler, cookies, csrf, in)
	if status != http.StatusOK || plan.Config.Alert != model.MonitorAlertDownAndDegraded || plan.Config.AlertAfter != 4 || plan.Config.Degraded == nil {
		t.Fatalf("save = %d %s", status, body)
	}
	stored, _ := st.LatencyProbeConfig()
	if stored.Alert != model.MonitorAlertDownAndDegraded || stored.AlertAfter != 4 || stored.Degraded == nil || stored.Degraded.LossFactor != 3 {
		t.Fatalf("stored = %+v", stored)
	}
	ev := lastAudit(t, st, "monitor.latency.config")
	if ev.Metadata["alert"] != model.MonitorAlertDownAndDegraded || ev.Metadata["alert_after"] != "4" || ev.Metadata["degraded"] != "loss_factor=3" ||
		!strings.Contains(ev.Metadata["changed"], "alert,alert_after,degraded") {
		t.Fatalf("path set audit = %+v", ev.Metadata)
	}
	// Its generated checks read the path set's policy.
	res := doJSON(t, handler, http.MethodGet, "/api/monitors", "", cookies, csrf)
	var views []monitorView
	if err := json.NewDecoder(res.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	generated := 0
	for _, v := range views {
		if v.ManagedBy == model.MonitorManagedLatency {
			generated++
			if v.Alert != model.MonitorAlertDownAndDegraded || v.AlertAfter != 4 || v.Degraded != nil {
				t.Fatalf("generated view = alert %q after %d degraded %+v", v.Alert, v.AlertAfter, v.Degraded)
			}
		}
	}
	if generated == 0 {
		t.Fatal("no generated check in the list")
	}
	// Saved again without the fields, they reset: the path set is saved
	// whole, and empty reads as off.
	again := model.LatencyProbeConfig{Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: []string{"node-sh"}, AutoTargets: true, Version: stored.Version}
	if status, plan, body := putLatencyConfig(t, handler, cookies, csrf, again); status != http.StatusOK || plan.Config.Alert != "" || plan.Config.Degraded != nil {
		t.Fatalf("save without the fields = %d %s", status, body)
	}
	if p := srv.monitorPolicy(model.Monitor{ManagedBy: model.MonitorManagedLatency}); p.alert != model.MonitorAlertOff || p.after != 2 {
		t.Fatalf("policy of a default path set = %+v", p)
	}
	stored, _ = st.LatencyProbeConfig()
	for _, tc := range []struct {
		cfg  model.LatencyProbeConfig
		want string
	}{
		{model.LatencyProbeConfig{Alert: "loud"}, "alert must be"},
		{model.LatencyProbeConfig{AlertAfter: 21}, "alert_after must be 1 to 20"},
		{model.LatencyProbeConfig{AlertAfter: -1}, "alert_after must be 1 to 20"},
		{model.LatencyProbeConfig{Degraded: &model.MonitorDegradedRule{LatencyFactor: 11}}, "degraded.latency_factor must be 1.2 to 10"},
	} {
		cfg := tc.cfg
		cfg.Enabled, cfg.IntervalSec, cfg.TimeoutSec, cfg.Sources, cfg.Version = true, 60, 5, []string{"node-sh"}, stored.Version
		if status, _, body := putLatencyConfig(t, handler, cookies, csrf, cfg); status != http.StatusBadRequest || !strings.Contains(body, tc.want) {
			t.Errorf("%+v = %d %s, want 400 %q", tc.cfg, status, body, tc.want)
		}
	}
}

// The series carries the baseline of the pair the path is judged on: not
// ready under 24 hours, triggers from the check's own thresholds once ready,
// null for tls; and the previous period when asked, aligned with the
// buckets, null where empty, from the coarse tier when the finer one does
// not reach, refused for any other compare, scoped as the series is.
func TestPathSeriesBaselineAndPrevious(t *testing.T) {
	var history []store.MonitorResultRecord
	history = append(history, baselineHistory("mon-young", "node-sh", degradedBase, 14, 40)...)
	history = append(history, baselineHistory("mon-margin", "node-sh", degradedBase, 168, 40)...)
	history = append(history, windowRuns("mon-margin", "node-sh", degradedBase, fastRuns)...)
	// Two weeks of hourly runs whose latency changes every hour.
	hour := degradedBase.Truncate(time.Hour)
	for h := 1; h <= 14*24; h++ {
		at := hour.Add(-time.Duration(h)*time.Hour + 20*time.Minute)
		history = append(history, store.MonitorResultRecord{
			MonitorResult: model.MonitorResult{MonitorID: "mon-long", NodeID: "node-sh", At: at, Success: true, LatencyMs: float64(30 + h%7*10)},
			ReceivedAt:    at,
		})
	}
	history = append(history, baselineHistory(latencyMonitorID("node-jp"), "node-sh", degradedBase, 30, 40)...)
	f := openDegradedFixture(t, t.TempDir(), history)
	f.pathSet(model.LatencyProbeConfig{Degraded: &model.MonitorDegradedRule{LatencyFactor: 3}})
	f.operatorCheck("mon-young", "", nil, "node-sh")
	f.operatorCheck("mon-margin", "", &model.MonitorDegradedRule{LatencyMarginMs: 50}, "node-sh")
	f.operatorCheck("mon-long", "", nil, "node-sh")
	if err := f.st.UpsertMonitor(model.Monitor{ID: "mon-tls", Name: "cert", Type: model.MonitorTypeTLS, Target: "example.com:443", IntervalSec: 3600, TimeoutSec: 10, ThresholdDays: 14, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	handler := f.srv.Handler()
	cookies, csrf := loginSession(t, handler)
	get := func(path string) (int, model.PathSeries, string) {
		res := doJSON(t, handler, http.MethodGet, path, "", cookies, csrf)
		body := readBody(t, res)
		var out model.PathSeries
		if res.StatusCode == http.StatusOK {
			if err := json.Unmarshal([]byte(body), &out); err != nil {
				t.Fatal(err)
			}
		}
		return res.StatusCode, out, body
	}
	status, young, body := get("/api/monitors/series?monitor=mon-young&source=node-sh&window=24h")
	if status != http.StatusOK || !strings.Contains(body, `"baseline":{`) || strings.Contains(body, `"previous"`) {
		t.Fatalf("young series = %d %s", status, body)
	}
	b := young.Baseline
	if b.Hours != 14 || b.Ready || b.P50Ms == nil || *b.P50Ms != 40 || b.Loss == nil || *b.Loss != 0 || b.TriggerP50Ms != nil || b.TriggerLoss != nil ||
		b.Rule != (model.MonitorDegradedRule{LossPercent: 2, LossFactor: 2, LatencyFactor: 2, LatencyMarginMs: 30}) ||
		!b.To.Equal(hour) || !b.From.Equal(hour.Add(-7*24*time.Hour)) {
		t.Fatalf("young baseline = %+v", b)
	}
	_, margin, _ := get("/api/monitors/series?monitor=mon-margin&source=node-sh&window=1h")
	b = margin.Baseline
	if !b.Ready || b.Hours != 168 || b.TriggerP50Ms == nil || *b.TriggerP50Ms != 90 || b.TriggerLoss == nil || *b.TriggerLoss != 0.02 || b.Rule.LatencyMarginMs != 50 {
		t.Fatalf("margin baseline = %+v (trigger %v)", b, b.TriggerP50Ms)
	}
	if status, tls, body := get("/api/monitors/series?monitor=mon-tls&window=24h"); status != http.StatusOK || tls.Baseline != nil || !strings.Contains(body, `"baseline":null`) {
		t.Fatalf("tls series = %d %s", status, body)
	}
	// A generated path's baseline is its current check's, under the path
	// set's thresholds.
	_, gen, _ := get("/api/monitors/series?source=node-sh&target_node=node-jp&window=24h")
	b = gen.Baseline
	if b == nil || !b.Ready || b.Hours != 30 || b.Rule.LatencyFactor != 3 || b.TriggerP50Ms == nil || *b.TriggerP50Ms != 120 {
		t.Fatalf("generated baseline = %+v", b)
	}

	// The hour before: four runs a hour, at :03, :18, :33 and :48.
	status, s, _ := get("/api/monitors/series?monitor=mon-margin&source=node-sh&window=1h&compare=previous")
	if status != http.StatusOK || s.Previous == nil {
		t.Fatalf("1h with previous = %d %+v", status, s.Previous)
	}
	p := s.Previous
	if p.OffsetSeconds != 3600 || p.StepSeconds != 60 || len(p.P50Ms) != len(s.Buckets) || !p.From.Equal(s.From.Add(-time.Hour)) || !p.To.Equal(s.To.Add(-time.Hour)) {
		t.Fatalf("previous = offset %d step %d len %d of %d from %s", p.OffsetSeconds, p.StepSeconds, len(p.P50Ms), len(s.Buckets), p.From)
	}
	filled := 0
	for i, v := range p.P50Ms {
		minute := s.Buckets[i].T.Add(-time.Hour).Minute()
		want := minute == 3 || minute == 18 || minute == 33 || minute == 48
		if (v != nil) != want {
			t.Errorf("previous step %d (%s) = %v", i, s.Buckets[i].T.Add(-time.Hour).Format("15:04"), v)
		}
		if v != nil {
			filled++
			if *v != 40 {
				t.Errorf("previous step %d = %v", i, *v)
			}
		}
	}
	if filled != 4 {
		t.Fatalf("%d previous steps hold a run, want 4", filled)
	}
	// A week back lies beyond the seven days of five-minute buckets: one
	// hourly bucket gives its median to each of its quarter-hour steps.
	status, s, _ = get("/api/monitors/series?monitor=mon-long&source=node-sh&window=7d&compare=previous")
	if status != http.StatusOK || s.Previous == nil || s.Previous.StepSeconds != 3600 || len(s.Previous.P50Ms) != len(s.Buckets) {
		t.Fatalf("7d with previous = %d %+v", status, s.Previous)
	}
	byHour := map[time.Time]float64{}
	filled = 0
	for i, v := range s.Previous.P50Ms {
		if v == nil {
			continue
		}
		filled++
		h := s.Buckets[i].T.Add(-7 * 24 * time.Hour).Truncate(time.Hour)
		if prior, seen := byHour[h]; seen && prior != *v {
			t.Fatalf("steps of the hour %s differ: %v and %v", h, prior, *v)
		}
		byHour[h] = *v
	}
	if filled < 600 || len(byHour) < 150 {
		t.Fatalf("previous week: %d steps over %d hours", filled, len(byHour))
	}
	for path, want := range map[string]int{
		"/api/monitors/series?monitor=mon-margin&source=node-sh&compare=next":               http.StatusBadRequest,
		"/api/monitors/series?monitor=mon-margin&source=node-sh&compare=":                   http.StatusBadRequest,
		"/api/monitors/series?monitor=mon-margin&source=node-sh&compare=previous&compare=x": http.StatusBadRequest,
	} {
		if status, _, body := get(path); status != want {
			t.Errorf("%s = %d %s, want %d", path, status, body, want)
		}
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"monitor:read"}, []string{"node-hk"})
	res := doBearerJSON(t, handler, http.MethodGet, "/api/monitors/series?monitor=mon-margin&source=node-sh&compare=previous", "", confined)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("confined previous = %d", res.StatusCode)
	}
}
