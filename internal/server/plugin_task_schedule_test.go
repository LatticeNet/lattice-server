package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const schedPluginID = "p.sched"

// schedManifest declares a runtime interface with a schedulable method, a
// method that names an operator target, and a core-backed interface.
func schedManifest() plugin.Manifest {
	return plugin.Manifest{
		ID: schedPluginID, Name: "Scheduler", Type: plugin.TypeSystem, Capabilities: []string{"task:schedule"},
		Interfaces: []plugin.InterfaceContract{
			{Service: schedPluginID + "/jobs", MethodSpecs: []plugin.InterfaceMethod{
				{Name: "sync", Effect: "write"},
				{Name: "push", Effect: "write", OperatorTargetFields: []string{"destination"}},
			}},
			{Service: schedPluginID + "/shares", Backing: plugin.BackingCore, MethodSpecs: []plugin.InterfaceMethod{{Name: "list", Effect: "read"}}},
		},
	}
}

// schedServer is a server with the scheduling plugin loaded and active, and
// with the background loops off so only the test drives the scheduler.
func schedServer(t *testing.T, st *store.Store) *Server {
	t.Helper()
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.plugins = []plugin.Loaded{{Manifest: schedManifest(), Capabilities: []string{"task:schedule"}}}
	if err := st.UpsertPluginInstallation(model.PluginInstallation{ID: schedPluginID, Name: "Scheduler", Type: plugin.TypeSystem, Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	return srv
}

func schedBroker(t *testing.T, srv *Server, caps ...string) *plugin.Broker {
	t.Helper()
	return kvBroker(t, srv.pluginHostServices(), schedPluginID, caps...)
}

type scheduledCall struct {
	service, method string
	payload         string
}

// recordRuns replaces the plugin call with a recorder. release, when not nil,
// holds every run until it is closed.
func recordRuns(srv *Server, release chan struct{}) (func() []scheduledCall, *sync.WaitGroup) {
	var mu sync.Mutex
	var calls []scheduledCall
	started := &sync.WaitGroup{}
	srv.pluginSchedules.invoke = func(ctx context.Context, pluginID, service, method string, payload json.RawMessage) ([]byte, error) {
		mu.Lock()
		calls = append(calls, scheduledCall{service: service, method: method, payload: string(payload)})
		mu.Unlock()
		started.Done()
		if release != nil {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []byte(`{}`), nil
	}
	return func() []scheduledCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]scheduledCall(nil), calls...)
	}, started
}

func at(hhmm string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", "2026-10-08 "+hhmm)
	if err != nil {
		panic(err)
	}
	return t
}

func TestTaskScheduleRunsTheMethodOnItsCron(t *testing.T) {
	st, _ := store.Open("")
	srv := schedServer(t, st)
	broker := schedBroker(t, srv, "task:schedule")
	schedule := sdkplugin.TaskSchedule{ID: "sync-all", Cron: "*/15 * * * *", Service: schedPluginID + "/jobs", Method: "sync", Payload: json.RawMessage(`{"all":true}`)}
	if err := broker.TaskSchedule(context.Background(), schedule); err != nil {
		t.Fatal(err)
	}
	calls, started := recordRuns(srv, nil)

	started.Add(1)
	srv.runDuePluginTaskSchedules(at("12:15").Add(37 * time.Second))
	srv.pluginSchedules.runs.Wait()
	srv.runDuePluginTaskSchedules(at("12:16"))
	srv.runDuePluginTaskSchedules(at("12:29"))
	srv.pluginSchedules.runs.Wait()
	got := calls()
	if len(got) != 1 || got[0] != (scheduledCall{service: schedPluginID + "/jobs", method: "sync", payload: `{"all":true}`}) {
		t.Fatalf("runs = %+v, want one sync at 12:15", got)
	}
	// Another pass over the same minute starts nothing more.
	srv.runDuePluginTaskSchedules(at("12:15").Add(50 * time.Second))
	started.Add(1)
	srv.runDuePluginTaskSchedules(at("12:30"))
	srv.pluginSchedules.runs.Wait()
	if n := len(calls()); n != 2 {
		t.Fatalf("runs after 12:30 = %d, want 2", n)
	}
	runs := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == "plugin.task.schedule.run" && ev.Metadata["outcome"] == "ok" && ev.Metadata["schedule_id"] == "sync-all" {
			runs++
		}
	}
	if runs != 2 {
		t.Fatalf("audited %d runs, want 2", runs)
	}

	// An inactive plugin's schedules wait; they are not dropped.
	if err := st.SetPluginStatus(schedPluginID, model.PluginStatusDisabled); err != nil {
		t.Fatal(err)
	}
	srv.runDuePluginTaskSchedules(at("12:45"))
	srv.pluginSchedules.runs.Wait()
	if n := len(calls()); n != 2 {
		t.Fatalf("a disabled plugin's schedule ran: %d runs", n)
	}
}

func TestTaskScheduleRefusesAFourMinuteIntervalAndA65thSchedule(t *testing.T) {
	st, _ := store.Open("")
	srv := schedServer(t, st)
	broker := schedBroker(t, srv, "task:schedule")
	ctx := context.Background()
	for _, cron := range []string{"*/4 * * * *", "0,4 * * * *", "* * * * *"} {
		err := broker.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: "tight", Cron: cron, Service: schedPluginID + "/jobs", Method: "sync"})
		if err == nil || !strings.Contains(err.Error(), "minimum") {
			t.Fatalf("cron %q = %v, want the five-minute minimum", cron, err)
		}
	}
	if err := broker.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: "five", Cron: "*/5 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
		t.Fatalf("a five-minute schedule = %v", err)
	}
	for i := 2; i <= sdkplugin.MaxTaskSchedulesPerPlugin; i++ {
		if err := broker.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: fmt.Sprintf("job-%02d", i), Cron: "0 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
			t.Fatalf("schedule %d = %v", i, err)
		}
	}
	err := broker.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: "job-65", Cron: "0 * * * *", Service: schedPluginID + "/jobs", Method: "sync"})
	if err == nil || !strings.Contains(err.Error(), "at most 64") {
		t.Fatalf("a 65th schedule = %v", err)
	}
	// Replacing one of the 64 is not a 65th.
	if err := broker.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: "job-02", Cron: "30 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
		t.Fatalf("replacing a schedule at the cap = %v", err)
	}
	record, err := srv.pluginTaskScheduleRecord(schedPluginID)
	if err != nil || len(record.Schedules) != sdkplugin.MaxTaskSchedulesPerPlugin {
		t.Fatalf("stored %d schedules, %v", len(record.Schedules), err)
	}
	if removed, err := broker.TaskUnschedule(ctx, "job-02"); err != nil || !removed {
		t.Fatalf("unschedule = %v, %v", removed, err)
	}
	if removed, err := broker.TaskUnschedule(ctx, "job-02"); err != nil || removed {
		t.Fatalf("unscheduling twice = %v, %v", removed, err)
	}
	if err := broker.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: "job-65", Cron: "0 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
		t.Fatalf("a schedule after one was removed = %v", err)
	}
}

func TestTaskScheduleTargetsOnlyTheCallersOwnRuntimeMethods(t *testing.T) {
	st, _ := store.Open("")
	srv := schedServer(t, st)
	ctx := context.Background()
	without := schedBroker(t, srv, "kv:write")
	if err := without.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: "a", Cron: "0 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); !errors.Is(err, plugin.ErrCapabilityDenied) {
		t.Fatalf("task.schedule without task:schedule = %v", err)
	}
	if _, err := without.TaskUnschedule(ctx, "a"); !errors.Is(err, plugin.ErrCapabilityDenied) {
		t.Fatalf("task.unschedule without task:schedule = %v", err)
	}
	requirePluginHostAudit(t, st, "plugin.host.task.schedule", "task:schedule", schedPluginID, "deny", "")

	broker := schedBroker(t, srv, "task:schedule")
	refused := map[string]sdkplugin.TaskSchedule{
		"undeclared method":   {ID: "a", Cron: "0 * * * *", Service: schedPluginID + "/jobs", Method: "wipe"},
		"undeclared service":  {ID: "a", Cron: "0 * * * *", Service: schedPluginID + "/other", Method: "sync"},
		"core-backed service": {ID: "a", Cron: "0 * * * *", Service: schedPluginID + "/shares", Method: "list"},
		"operator target":     {ID: "a", Cron: "0 * * * *", Service: schedPluginID + "/jobs", Method: "push"},
		"another plugin":      {ID: "a", Cron: "0 * * * *", Service: "p.other/jobs", Method: "sync"},
	}
	for name, schedule := range refused {
		if err := broker.TaskSchedule(ctx, schedule); err == nil {
			t.Fatalf("%s: admitted", name)
		}
	}
	if record, _ := srv.pluginTaskScheduleRecord(schedPluginID); len(record.Schedules) != 0 {
		t.Fatalf("refused schedules were stored: %+v", record.Schedules)
	}
	// Neither the operator KV API nor a plugin bucket reaches the schedules.
	if !reservedLineSecretKVBucket(pluginTaskScheduleKVBucket) || strings.HasPrefix(pluginTaskScheduleKVBucket, pluginKVBucketPrefix) {
		t.Fatal("the schedule bucket is reachable through a KV path")
	}
}

func TestTaskScheduleNeverRunsTwoOfOneIDAtOnce(t *testing.T) {
	st, _ := store.Open("")
	srv := schedServer(t, st)
	broker := schedBroker(t, srv, "task:schedule")
	ctx := context.Background()
	for _, id := range []string{"slow", "other"} {
		if err := broker.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: id, Cron: "*/5 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
			t.Fatal(err)
		}
	}
	release := make(chan struct{})
	calls, started := recordRuns(srv, release)

	started.Add(2)
	srv.runDuePluginTaskSchedules(at("09:00"))
	started.Wait()
	// Both are still running at 09:05: neither starts a second run, and the
	// skip is audited.
	srv.runDuePluginTaskSchedules(at("09:05"))
	if n := len(calls()); n != 2 {
		t.Fatalf("runs while the first were in flight = %d, want 2", n)
	}
	skipped := 0
	for _, ev := range st.AuditEvents() {
		if ev.Action == "plugin.task.schedule.run" && ev.Metadata["outcome"] == "skipped" {
			skipped++
		}
	}
	if skipped != 2 {
		t.Fatalf("audited %d skipped runs, want 2", skipped)
	}
	close(release)
	srv.pluginSchedules.runs.Wait()

	started.Add(2)
	srv.runDuePluginTaskSchedules(at("09:10"))
	srv.pluginSchedules.runs.Wait()
	got := calls()
	if len(got) != 4 {
		t.Fatalf("runs after the first finished = %d, want 4", len(got))
	}
}

// Schedules are stored state: a server that starts over the same store runs
// them without the plugin asking again.
func TestTaskSchedulesSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := schedServer(t, st)
	broker := schedBroker(t, srv, "task:schedule")
	if err := broker.TaskSchedule(context.Background(), sdkplugin.TaskSchedule{ID: "nightly", Cron: "30 3 * * *", Service: schedPluginID + "/jobs", Method: "sync", Payload: json.RawMessage(`{"scope":"all"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted, err := New(Options{Store: reopened, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	restarted.plugins = []plugin.Loaded{{Manifest: schedManifest(), Capabilities: []string{"task:schedule"}}}
	calls, started := recordRuns(restarted, nil)
	restarted.runDuePluginTaskSchedules(at("03:29"))
	started.Add(1)
	restarted.runDuePluginTaskSchedules(at("03:30"))
	restarted.pluginSchedules.runs.Wait()
	got := calls()
	if len(got) != 1 || got[0].payload != `{"scope":"all"}` || got[0].method != "sync" {
		t.Fatalf("runs after restart = %+v", got)
	}
}

func TestTaskScheduleCronMatchesLikeCron(t *testing.T) {
	cases := []struct {
		cron string
		when string
		want bool
	}{
		{"*/5 * * * *", "2026-10-08 12:05", true},
		{"*/5 * * * *", "2026-10-08 12:07", false},
		{"0 9 * * 1-5", "2026-10-09 09:00", true},  // Friday
		{"0 9 * * 1-5", "2026-10-10 09:00", false}, // Saturday
		{"0 0 * * 7", "2026-10-11 00:00", true},    // Sunday as 7
		{"0 0 * * 0", "2026-10-11 00:00", true},    // Sunday as 0
		{"0 0 1 * *", "2026-11-01 00:00", true},
		{"0 0 1 * *", "2026-11-02 00:00", false},
		// Both day fields restricted: either one matches, as in cron.
		{"0 0 13 * 5", "2026-10-09 00:00", true},  // a Friday, not the 13th
		{"0 0 13 * 5", "2026-10-13 00:00", true},  // the 13th, a Tuesday
		{"0 0 13 * 5", "2026-10-14 00:00", false}, // neither
		{"10-20/5 8 * 2,10 *", "2026-10-08 08:15", true},
		{"10-20/5 8 * 2,10 *", "2026-10-08 08:16", false},
		{"10-20/5 8 * 2,10 *", "2026-11-08 08:15", false},
	}
	for _, tc := range cases {
		spec, err := parseTaskScheduleCron(tc.cron)
		if err != nil {
			t.Fatalf("%q: %v", tc.cron, err)
		}
		when, _ := time.Parse("2006-01-02 15:04", tc.when)
		if got := spec.matches(when); got != tc.want {
			t.Fatalf("%q at %s = %v, want %v", tc.cron, tc.when, got, tc.want)
		}
	}
	for _, bad := range []string{"* * * *", "60 * * * *", "MON * * * *", "@hourly", "*/0 * * * *"} {
		if _, err := parseTaskScheduleCron(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
}

// Close stops the minute loop, cancels a scheduled run in flight, and returns
// only after that run has finished, so nothing calls the plugin runtime or
// reads the store once the server is closed.
func TestTaskSchedulerStopsAndCancelsItsRunsOnClose(t *testing.T) {
	st, _ := store.Open("")
	srv := schedServer(t, st)
	broker := schedBroker(t, srv, "task:schedule")
	if err := broker.TaskSchedule(context.Background(), sdkplugin.TaskSchedule{ID: "slow", Cron: "*/5 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
		t.Fatal(err)
	}
	var calls, finished atomic.Int32
	started := make(chan struct{}, 4)
	srv.pluginSchedules.invoke = func(ctx context.Context, _, _, _ string, _ json.RawMessage) ([]byte, error) {
		calls.Add(1)
		started <- struct{}{}
		// Only the run's context ends this call.
		<-ctx.Done()
		finished.Add(1)
		return nil, ctx.Err()
	}
	srv.startPluginTaskScheduler()
	srv.runDuePluginTaskSchedules(at("12:15"))
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("Close waited out its deadline")
	}
	if finished.Load() != 1 {
		t.Fatal("Close returned with a scheduled run still in flight")
	}
	loopDone := make(chan struct{})
	go func() {
		srv.pluginSchedules.loop.Wait()
		close(loopDone)
	}()
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the minute loop survived Close")
	}
	canceled := false
	for _, ev := range st.AuditEvents() {
		if ev.Action == "plugin.task.schedule.run" && ev.Metadata["outcome"] == "failed" && ev.Metadata["error_class"] == "canceled" {
			canceled = true
		}
	}
	if !canceled {
		t.Fatal("the run Close cancelled was not audited as canceled")
	}
	// After Close no pass starts a run.
	srv.runDuePluginTaskSchedules(at("12:30"))
	srv.pluginSchedules.runs.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("runs after Close = %d, want only the one before it", n)
	}
}

// A schedule is a standing use of task:schedule. When the signed manifest the
// server loads no longer grants it, the stored schedules stop running and are
// dropped, since the plugin can no longer unschedule them itself.
func TestTaskScheduleStopsWhenTheManifestNoLongerGrantsTheCapability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := schedServer(t, st)
	broker := schedBroker(t, srv, "task:schedule")
	if err := broker.TaskSchedule(context.Background(), sdkplugin.TaskSchedule{ID: "nightly", Cron: "30 3 * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// The plugin comes back re-signed without task:schedule.
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted, err := New(Options{Store: reopened, AdminPassword: testAdminPass, DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	revoked := schedManifest()
	revoked.Capabilities = []string{"kv:write"}
	restarted.plugins = []plugin.Loaded{{Manifest: revoked, Capabilities: []string{"kv:write"}}}
	calls, _ := recordRuns(restarted, nil)
	restarted.runDuePluginTaskSchedules(at("03:30"))
	restarted.pluginSchedules.runs.Wait()
	if got := calls(); len(got) != 0 {
		t.Fatalf("a schedule ran without task:schedule: %+v", got)
	}
	if record, err := restarted.pluginTaskScheduleRecord(schedPluginID); err != nil || len(record.Schedules) != 0 {
		t.Fatalf("revoked schedules are still stored: %+v, %v", record.Schedules, err)
	}
	dropped := false
	for _, ev := range reopened.AuditEvents() {
		if ev.Action == "plugin.task.schedule.revoke" && ev.Decision == "deny" && ev.Metadata["plugin_id"] == schedPluginID && ev.Metadata["schedules"] == "1" {
			dropped = true
		}
	}
	if !dropped {
		t.Fatal("dropping the schedules was not audited")
	}
	// The run path refuses on its own too, for a target checked after the pass.
	err = restarted.runPluginTaskSchedule(context.Background(), schedPluginID, sdkplugin.TaskSchedule{ID: "nightly", Cron: "30 3 * * *", Service: schedPluginID + "/jobs", Method: "sync"})
	if err == nil || !strings.Contains(err.Error(), "not granted task:schedule") {
		t.Fatalf("a run without the grant = %v", err)
	}
}

// A failed run is audited by class and length. The plugin's error text, which
// may carry a provider URL and its token, is not written anywhere in the row.
func TestTaskScheduleRunAuditKeepsNoPluginErrorText(t *testing.T) {
	st, _ := store.Open("")
	srv := schedServer(t, st)
	broker := schedBroker(t, srv, "task:schedule")
	if err := broker.TaskSchedule(context.Background(), sdkplugin.TaskSchedule{ID: "fetch", Cron: "*/5 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
		t.Fatal(err)
	}
	const secret = "tok-5f2c9a"
	message := "fetch https://provider.example/api/sub?token=" + secret + " failed: 502"
	srv.pluginSchedules.invoke = func(context.Context, string, string, string, json.RawMessage) ([]byte, error) {
		return nil, &pluginServiceError{message: message}
	}
	srv.runDuePluginTaskSchedules(at("10:05"))
	srv.pluginSchedules.runs.Wait()
	var row *model.AuditEvent
	for _, ev := range st.AuditEvents() {
		if ev.Action == "plugin.task.schedule.run" {
			row = &ev
		}
	}
	if row == nil || row.Metadata["outcome"] != "failed" {
		t.Fatalf("no failed run audited: %+v", row)
	}
	encoded, _ := json.Marshal(row)
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "provider.example") {
		t.Fatalf("the audit row carries the plugin's error text: %s", encoded)
	}
	if row.Metadata["error_class"] != "plugin_error" || row.Metadata["error_bytes"] != strconv.Itoa(len(message)) {
		t.Fatalf("audit metadata = %+v, want the plugin_error class and the text's length", row.Metadata)
	}
}

// The fired minutes are kept only for schedules still stored, so a plugin
// that churns schedule ids does not grow the map.
func TestTaskScheduleForgetsTheFiredMinuteOfARemovedSchedule(t *testing.T) {
	st, _ := store.Open("")
	srv := schedServer(t, st)
	broker := schedBroker(t, srv, "task:schedule")
	ctx := context.Background()
	for i := range 3 {
		if err := broker.TaskSchedule(ctx, sdkplugin.TaskSchedule{ID: fmt.Sprintf("job-%d", i), Cron: "*/5 * * * *", Service: schedPluginID + "/jobs", Method: "sync"}); err != nil {
			t.Fatal(err)
		}
	}
	_, started := recordRuns(srv, nil)
	started.Add(3)
	srv.runDuePluginTaskSchedules(at("08:05"))
	srv.pluginSchedules.runs.Wait()
	for _, id := range []string{"job-0", "job-2"} {
		if _, err := broker.TaskUnschedule(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	srv.runDuePluginTaskSchedules(at("08:06"))
	srv.pluginSchedules.mu.Lock()
	defer srv.pluginSchedules.mu.Unlock()
	if len(srv.pluginSchedules.fired) != 1 {
		t.Fatalf("fired holds %d schedules, want only the one still stored", len(srv.pluginSchedules.fired))
	}
	if _, ok := srv.pluginSchedules.fired[pluginTaskScheduleKey{pluginID: schedPluginID, id: "job-1"}]; !ok {
		t.Fatal("the stored schedule's fired minute was dropped")
	}
}
