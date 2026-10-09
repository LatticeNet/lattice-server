package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/plugin"
)

// Plugin task schedules (design 28): task.schedule and task.unschedule let a
// plugin holding task:schedule have the server call one of its own declared
// runtime methods on a cron schedule, with a fixed payload, as the plugin's
// own principal. The schedules are stored in the store, one KV entry per
// plugin in a bucket no plugin and no operator KV call can reach, so they
// survive a restart. The scheduler loop wakes on each minute, runs every
// schedule whose cron matches that minute in UTC through the plugin runtime,
// and never starts a run of one schedule while its previous run is in flight.
// A minute the server was down is not caught up, as cron does not. Close
// stops the loop, cancels the runs in flight and waits for them.
//
// A schedule is a standing use of task:schedule, so every pass checks the
// grant again against the signed manifest the server loaded. A plugin whose
// manifest no longer grants it has its schedules dropped, since its broker
// refuses task.unschedule as well and nothing else could remove them.
//
// A scheduled run binds no operator target: there is no operator call whose
// authenticated payload could name one, so a method that declares
// operator_target_fields cannot be scheduled.
//
// Runs do not go through the task queue, and no operator principal stands
// behind them: the method's declared operator scopes are not evaluated, and
// the signed, host-risk task:schedule capability is the only gate. The audit
// actor of a run is "plugin:<id>".

// pluginTaskScheduleKVBucket holds one entry per plugin id. It is reserved in
// reservedLineSecretKVBucket, and it is not "plugin:<id>", so neither the
// operator KV API nor a plugin's own kv calls can read or forge a schedule.
const pluginTaskScheduleKVBucket = "plugin-task-schedules"

// pluginTaskScheduleRunTimeout backstops one scheduled run, the plugin
// runtime's checkout wait included. The method's signed budget bounds the
// call itself; this is the five-minute minimum interval, so a stuck run is
// abandoned before the earliest next run of the same schedule could start.
const pluginTaskScheduleRunTimeout = sdkplugin.MinTaskScheduleInterval

// pluginTaskScheduleRecord is the stored value for one plugin.
type pluginTaskScheduleRecord struct {
	Schedules []sdkplugin.TaskSchedule `json:"schedules"`
}

type pluginTaskScheduleKey struct{ pluginID, id string }

// pluginTaskScheduler is the server's in-memory side of the schedules. Its
// zero value is ready to use.
type pluginTaskScheduler struct {
	// storeMu serializes read-modify-write of the stored sets, so two
	// concurrent task.schedule calls of one plugin cannot lose each other's
	// schedule or pass the per-plugin cap together.
	storeMu sync.Mutex

	mu sync.Mutex
	// inFlight holds the schedules with a run started and not yet finished.
	inFlight map[pluginTaskScheduleKey]bool
	// fired is the minute each schedule last fired, so a second pass over the
	// same minute starts nothing. Each pass forgets the schedules no longer
	// stored, so it holds no more keys than the store does.
	fired map[pluginTaskScheduleKey]time.Time
	// life is cancelled when Close stops the scheduler: the minute loop
	// returns and every run in flight has its plugin call cancelled. It is
	// made on first use, so the zero value still works. Once stopped is set
	// no loop and no run starts, which is what lets Close wait on loop and
	// runs without racing an Add.
	life    context.Context
	cancel  context.CancelFunc
	stopped bool
	// loop counts the minute loop and runs the runs in flight. Close waits
	// for both; tests wait for runs.
	loop sync.WaitGroup
	runs sync.WaitGroup
	// invoke is a test seam; nil calls the plugin through the runtime.
	invoke func(ctx context.Context, pluginID, service, method string, payload json.RawMessage) ([]byte, error)
}

// lifetimeLocked returns the context the loop and the runs derive from.
// Callers hold mu.
func (sch *pluginTaskScheduler) lifetimeLocked() context.Context {
	if sch.life == nil {
		sch.life, sch.cancel = context.WithCancel(context.Background())
	}
	return sch.life
}

// Schedule serves task.schedule (plugin.TaskScheduleHost). The broker has
// checked task:schedule, the schedule's shape and the five-minute minimum,
// and that the service is the plugin's own.
func (h *pluginTaskHost) Schedule(_ context.Context, pluginID string, schedule sdkplugin.TaskSchedule) error {
	s := h.server
	if err := schedule.Validate(); err != nil {
		return err
	}
	if err := s.pluginTaskScheduleMethodAllowed(pluginID, schedule.Service, schedule.Method); err != nil {
		return err
	}
	sch := &s.pluginSchedules
	sch.storeMu.Lock()
	defer sch.storeMu.Unlock()
	record, err := s.pluginTaskScheduleRecord(pluginID)
	if err != nil {
		return err
	}
	replaced := false
	for i := range record.Schedules {
		if record.Schedules[i].ID == schedule.ID {
			record.Schedules[i] = schedule
			replaced = true
		}
	}
	if !replaced {
		record.Schedules = append(record.Schedules, schedule)
	}
	if err := sdkplugin.ValidateTaskSchedules(record.Schedules); err != nil {
		return err
	}
	if err := s.putPluginTaskScheduleRecord(pluginID, record); err != nil {
		return err
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), At: s.now().UTC(),
		Action: "plugin.task.schedule", Scope: sdkplugin.CapabilityTaskSchedule, Decision: "allow",
		Metadata: map[string]string{
			"plugin_id": pluginID, "schedule_id": schedule.ID, "service": schedule.Service,
			"method": schedule.Method, "cron": schedule.Cron, "replaced": strconv.FormatBool(replaced),
		},
	})
	return nil
}

// Unschedule serves task.unschedule. A run already in flight finishes; no
// later run starts.
func (h *pluginTaskHost) Unschedule(_ context.Context, pluginID, scheduleID string) (bool, error) {
	s := h.server
	sch := &s.pluginSchedules
	sch.storeMu.Lock()
	defer sch.storeMu.Unlock()
	record, err := s.pluginTaskScheduleRecord(pluginID)
	if err != nil {
		return false, err
	}
	kept := record.Schedules[:0]
	removed := false
	for _, schedule := range record.Schedules {
		if schedule.ID == scheduleID {
			removed = true
			continue
		}
		kept = append(kept, schedule)
	}
	if !removed {
		return false, nil
	}
	record.Schedules = kept
	if err := s.putPluginTaskScheduleRecord(pluginID, record); err != nil {
		return false, err
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), At: s.now().UTC(),
		Action: "plugin.task.unschedule", Scope: sdkplugin.CapabilityTaskSchedule, Decision: "allow",
		Metadata: map[string]string{"plugin_id": pluginID, "schedule_id": scheduleID},
	})
	return true, nil
}

// pluginTaskScheduleMethodAllowed admits a schedule's target for a plugin
// whose loaded manifest grants task:schedule: an interface the plugin itself
// declares, served by its runtime rather than by core, and a method that
// interface declares and that names no operator target.
func (s *Server) pluginTaskScheduleMethodAllowed(pluginID, service, method string) error {
	loaded, ok := s.loadedPlugin(pluginID)
	if !ok {
		return fmt.Errorf("plugin %q is not loaded", pluginID)
	}
	if !pluginGrantsTaskSchedule(loaded) {
		return fmt.Errorf("plugin %q is not granted %s", pluginID, sdkplugin.CapabilityTaskSchedule)
	}
	if !strings.HasPrefix(service, pluginID+"/") {
		return fmt.Errorf("task schedule service %q is not one of this plugin's own services", service)
	}
	contract, ok := loaded.Manifest.InterfaceFor(service)
	if !ok {
		return fmt.Errorf("task schedule service %q is not declared by the plugin", service)
	}
	if contract.EffectiveBacking() != plugin.BackingRuntime {
		return fmt.Errorf("task schedule service %q is served by core, not by the plugin", service)
	}
	declared, ok := contract.MethodContract(method)
	if !ok {
		return fmt.Errorf("task schedule method %q is not declared on %q", method, service)
	}
	if len(declared.OperatorTargetFields) > 0 {
		return fmt.Errorf("task schedule method %q names an operator target, which a scheduled run has no operator call to bind", method)
	}
	if subStoreCoreOnlyMethod(service, method) {
		return fmt.Errorf("task schedule method %q runs only inside an approved plan apply", method)
	}
	return nil
}

// pluginGrantsTaskSchedule reads the grant from the capabilities the trust
// policy admitted at load, the same list the plugin's broker is built from.
func pluginGrantsTaskSchedule(loaded plugin.Loaded) bool {
	return slices.Contains(loaded.Capabilities, sdkplugin.CapabilityTaskSchedule)
}

func (s *Server) pluginTaskScheduleRecord(pluginID string) (pluginTaskScheduleRecord, error) {
	entry, ok := s.store.KVEntry(pluginTaskScheduleKVBucket, pluginID)
	if !ok {
		return pluginTaskScheduleRecord{}, nil
	}
	var record pluginTaskScheduleRecord
	if err := json.Unmarshal([]byte(entry.Value), &record); err != nil {
		return pluginTaskScheduleRecord{}, fmt.Errorf("stored task schedules of %q are unreadable: %w", pluginID, err)
	}
	return record, nil
}

func (s *Server) putPluginTaskScheduleRecord(pluginID string, record pluginTaskScheduleRecord) error {
	if len(record.Schedules) == 0 {
		return s.store.DeleteKV(pluginTaskScheduleKVBucket, pluginID)
	}
	sort.Slice(record.Schedules, func(i, j int) bool { return record.Schedules[i].ID < record.Schedules[j].ID })
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.store.PutKV(model.KVEntry{Bucket: pluginTaskScheduleKVBucket, Key: pluginID, Value: string(value)})
}

// startPluginTaskScheduler wakes on each minute and runs what is due, until
// Close stops it.
func (s *Server) startPluginTaskScheduler() {
	sch := &s.pluginSchedules
	sch.mu.Lock()
	if sch.stopped {
		sch.mu.Unlock()
		return
	}
	life := sch.lifetimeLocked()
	sch.loop.Add(1)
	sch.mu.Unlock()
	go func() {
		defer sch.loop.Done()
		timer := time.NewTimer(untilNextMinute(time.Now()))
		defer timer.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-timer.C:
			}
			s.runDuePluginTaskSchedules(s.now())
			timer.Reset(untilNextMinute(time.Now()))
		}
	}()
}

func untilNextMinute(now time.Time) time.Duration {
	return now.Truncate(time.Minute).Add(time.Minute).Sub(now)
}

// stopPluginTaskScheduler stops the minute loop, cancels the runs in flight
// and waits for both within ctx, so no run calls the plugin runtime or
// writes an audit after Close returns.
func (s *Server) stopPluginTaskScheduler(ctx context.Context) {
	sch := &s.pluginSchedules
	sch.mu.Lock()
	sch.stopped = true
	sch.lifetimeLocked()
	cancel := sch.cancel
	sch.mu.Unlock()
	cancel()
	done := make(chan struct{})
	go func() {
		sch.loop.Wait()
		sch.runs.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// runDuePluginTaskSchedules starts every stored schedule of an active plugin
// whose cron matches the minute of now, in UTC.
func (s *Server) runDuePluginTaskSchedules(now time.Time) {
	sch := &s.pluginSchedules
	sch.mu.Lock()
	stopped := sch.stopped
	sch.mu.Unlock()
	if stopped {
		return
	}
	minute := now.UTC().Truncate(time.Minute)
	stored := map[pluginTaskScheduleKey]bool{}
	for _, entry := range s.store.KV(pluginTaskScheduleKVBucket) {
		pluginID := entry.Key
		if loaded, ok := s.loadedPlugin(pluginID); ok && !pluginGrantsTaskSchedule(loaded) {
			s.revokePluginTaskSchedules(pluginID)
			continue
		}
		var record pluginTaskScheduleRecord
		if err := json.Unmarshal([]byte(entry.Value), &record); err != nil {
			s.logger.Printf("plugin task schedules of %s are unreadable: %v", pluginID, err)
			continue
		}
		for _, schedule := range record.Schedules {
			stored[pluginTaskScheduleKey{pluginID: pluginID, id: schedule.ID}] = true
		}
		if !s.pluginIsActive(pluginID) {
			continue
		}
		for _, schedule := range record.Schedules {
			spec, err := parseTaskScheduleCron(schedule.Cron)
			if err != nil || !spec.matches(minute) {
				continue
			}
			s.startPluginTaskScheduleRun(pluginID, schedule, minute)
		}
	}
	sch.mu.Lock()
	for key := range sch.fired {
		if !stored[key] {
			delete(sch.fired, key)
		}
	}
	sch.mu.Unlock()
}

// revokePluginTaskSchedules drops every stored schedule of a plugin whose
// loaded manifest does not grant task:schedule.
func (s *Server) revokePluginTaskSchedules(pluginID string) {
	sch := &s.pluginSchedules
	sch.storeMu.Lock()
	defer sch.storeMu.Unlock()
	record, err := s.pluginTaskScheduleRecord(pluginID)
	if err != nil {
		s.logger.Printf("plugin task schedules of %s: %v", pluginID, err)
	}
	if err := s.store.DeleteKV(pluginTaskScheduleKVBucket, pluginID); err != nil {
		s.logger.Printf("drop the plugin task schedules of %s: %v", pluginID, err)
		return
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), At: s.now().UTC(), ActorID: "system",
		Action: "plugin.task.schedule.revoke", Scope: sdkplugin.CapabilityTaskSchedule, Decision: "deny",
		Reason:   "the plugin's signed manifest no longer grants " + sdkplugin.CapabilityTaskSchedule,
		Metadata: map[string]string{"plugin_id": pluginID, "schedules": strconv.Itoa(len(record.Schedules))},
	})
}

// startPluginTaskScheduleRun starts one run unless this minute already fired
// the schedule, its previous run has not finished, or Close has begun.
func (s *Server) startPluginTaskScheduleRun(pluginID string, schedule sdkplugin.TaskSchedule, minute time.Time) {
	sch := &s.pluginSchedules
	key := pluginTaskScheduleKey{pluginID: pluginID, id: schedule.ID}
	sch.mu.Lock()
	if sch.stopped {
		sch.mu.Unlock()
		return
	}
	if sch.fired == nil {
		sch.fired = map[pluginTaskScheduleKey]time.Time{}
		sch.inFlight = map[pluginTaskScheduleKey]bool{}
	}
	if sch.fired[key].Equal(minute) {
		sch.mu.Unlock()
		return
	}
	sch.fired[key] = minute
	if sch.inFlight[key] {
		sch.mu.Unlock()
		s.recordPluginTaskScheduleRun(pluginID, schedule, "skipped", "the previous run of this schedule is still in flight", nil)
		return
	}
	sch.inFlight[key] = true
	sch.runs.Add(1)
	life := sch.lifetimeLocked()
	sch.mu.Unlock()
	go func() {
		defer func() {
			sch.mu.Lock()
			delete(sch.inFlight, key)
			sch.mu.Unlock()
			sch.runs.Done()
		}()
		err := s.runPluginTaskSchedule(life, pluginID, schedule)
		if err == nil {
			s.recordPluginTaskScheduleRun(pluginID, schedule, "ok", "", nil)
			return
		}
		class, reason := pluginTaskScheduleFailure(life, err)
		s.recordPluginTaskScheduleRun(pluginID, schedule, "failed", reason, map[string]string{
			"error_class": class, "error_bytes": strconv.Itoa(len(err.Error())),
		})
	}()
}

// taskScheduleTargetRefused is the server's own refusal of a stored
// schedule's target at run time. Its text names only the plugin, the service
// and the method, which the schedule's validation bounded when it was stored.
type taskScheduleTargetRefused struct{ err error }

func (e *taskScheduleTargetRefused) Error() string { return e.err.Error() }

func (s *Server) runPluginTaskSchedule(life context.Context, pluginID string, schedule sdkplugin.TaskSchedule) error {
	// The plugin may have been upgraded since the schedule was stored; a
	// method it no longer declares is not called.
	if err := s.pluginTaskScheduleMethodAllowed(pluginID, schedule.Service, schedule.Method); err != nil {
		return &taskScheduleTargetRefused{err: err}
	}
	ctx, cancel := context.WithTimeout(life, pluginTaskScheduleRunTimeout)
	defer cancel()
	payload := schedule.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if invoke := s.pluginSchedules.invoke; invoke != nil {
		_, err := invoke(ctx, pluginID, schedule.Service, schedule.Method, payload)
		return err
	}
	_, err := s.callRuntimePluginService(ctx, pluginID, schedule.Service, schedule.Method, payload, nil, nil)
	return err
}

// pluginTaskScheduleFailure is the only code that reads a failed run's
// error, and it returns a fixed class and reason, never the error's text. A
// plugin's error may carry a provider URL with its token (a Sub-Store fetch
// error does), and operators read the audit log. The plugin's own log keeps
// the detail; the audit row keeps the class and the text's length. Only the
// server's refusal of the target keeps its text.
func pluginTaskScheduleFailure(life context.Context, err error) (class, reason string) {
	var refused *taskScheduleTargetRefused
	var pluginErr *pluginServiceError
	switch {
	case errors.As(err, &refused):
		return "target_refused", refused.Error()
	case life.Err() != nil:
		return "canceled", "the server stopped during the run"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", "the run did not finish within its time limit"
	case errors.As(err, &pluginErr):
		return "plugin_error", "the plugin returned an error"
	default:
		return "call_failed", "the plugin call failed"
	}
}

func (s *Server) recordPluginTaskScheduleRun(pluginID string, schedule sdkplugin.TaskSchedule, outcome, reason string, extra map[string]string) {
	decision := "allow"
	if outcome == "skipped" {
		decision = "deny"
	}
	metadata := map[string]string{
		"plugin_id": pluginID, "schedule_id": schedule.ID, "service": schedule.Service,
		"method": schedule.Method, "outcome": outcome,
	}
	for k, v := range extra {
		metadata[k] = v
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), At: s.now().UTC(), ActorID: pluginTaskActorPrefix + pluginID,
		Action: "plugin.task.schedule.run", Scope: sdkplugin.CapabilityTaskSchedule, Decision: decision, Reason: reason,
		Metadata: metadata,
	})
}

// taskScheduleCron is a parsed TaskSchedule.Cron: one bit per allowed value.
type taskScheduleCron struct {
	minute, hour, dom, month, dow uint64
	// domAny and dowAny record a field that starts with "*". As in cron, a day
	// matches both day fields when either is unrestricted, and either one when
	// both are restricted.
	domAny, dowAny bool
}

// parseTaskScheduleCron parses the dialect TaskSchedule.Cron documents. The
// broker has already run the SDK's Validate on every stored schedule; this
// parse refuses the same inputs rather than trusting that.
func parseTaskScheduleCron(expr string) (taskScheduleCron, error) {
	if _, err := sdkplugin.CronMinInterval(expr); err != nil {
		return taskScheduleCron{}, err
	}
	fields := strings.Fields(expr)
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	var sets [5]uint64
	for i, field := range fields {
		set, err := parseTaskScheduleCronField(field, bounds[i][0], bounds[i][1])
		if err != nil {
			return taskScheduleCron{}, err
		}
		sets[i] = set
	}
	// Day of week 7 is Sunday, as 0 is.
	if sets[4]&(1<<7) != 0 {
		sets[4] |= 1
	}
	return taskScheduleCron{
		minute: sets[0], hour: sets[1], dom: sets[2], month: sets[3], dow: sets[4],
		domAny: strings.HasPrefix(fields[2], "*"), dowAny: strings.HasPrefix(fields[4], "*"),
	}, nil
}

func parseTaskScheduleCronField(field string, lo, hi int) (uint64, error) {
	var set uint64
	for _, item := range strings.Split(field, ",") {
		rangePart, stepPart, hasStep := strings.Cut(item, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepPart)
			if err != nil || n < 1 {
				return 0, fmt.Errorf("invalid step in %q", item)
			}
			step = n
		}
		start, end := lo, hi
		if rangePart != "*" {
			a, b, isRange := strings.Cut(rangePart, "-")
			var err error
			if start, err = strconv.Atoi(a); err != nil {
				return 0, fmt.Errorf("invalid value in %q", item)
			}
			end = start
			if isRange {
				if end, err = strconv.Atoi(b); err != nil {
					return 0, fmt.Errorf("invalid range in %q", item)
				}
			}
		}
		if start < lo || end > hi || start > end {
			return 0, errors.New("cron field value out of range")
		}
		for v := start; v <= end; v += step {
			set |= 1 << uint(v)
		}
	}
	return set, nil
}

// matches reports whether the schedule fires in the minute of t.
func (c taskScheduleCron) matches(t time.Time) bool {
	if c.minute&(1<<uint(t.Minute())) == 0 || c.hour&(1<<uint(t.Hour())) == 0 || c.month&(1<<uint(t.Month())) == 0 {
		return false
	}
	domOK := c.dom&(1<<uint(t.Day())) != 0
	dowOK := c.dow&(1<<uint(t.Weekday())) != 0
	if c.domAny || c.dowAny {
		return domOK && dowOK
	}
	return domOK || dowOK
}
