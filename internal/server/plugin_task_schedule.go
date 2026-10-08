package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// A minute the server was down is not caught up, as cron does not.
//
// A scheduled run binds no operator target: there is no operator call whose
// authenticated payload could name one, so a method that declares
// operator_target_fields cannot be scheduled.

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
	// same minute starts nothing.
	fired map[pluginTaskScheduleKey]time.Time
	// runs counts runs in flight, for tests that wait for them.
	runs sync.WaitGroup
	// invoke is a test seam; nil calls the plugin through the runtime.
	invoke func(ctx context.Context, pluginID, service, method string, payload json.RawMessage) ([]byte, error)
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

// pluginTaskScheduleMethodAllowed admits a schedule's target: an interface the
// plugin itself declares, served by its runtime rather than by core, and a
// method that interface declares and that names no operator target.
func (s *Server) pluginTaskScheduleMethodAllowed(pluginID, service, method string) error {
	loaded, ok := s.loadedPlugin(pluginID)
	if !ok {
		return fmt.Errorf("plugin %q is not loaded", pluginID)
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
	return nil
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

// startPluginTaskScheduler wakes on each minute and runs what is due.
func (s *Server) startPluginTaskScheduler() {
	go func() {
		for {
			now := time.Now()
			timer := time.NewTimer(now.Truncate(time.Minute).Add(time.Minute).Sub(now))
			<-timer.C
			s.runDuePluginTaskSchedules(s.now())
		}
	}()
}

// runDuePluginTaskSchedules starts every stored schedule of an active plugin
// whose cron matches the minute of now, in UTC.
func (s *Server) runDuePluginTaskSchedules(now time.Time) {
	minute := now.UTC().Truncate(time.Minute)
	for _, entry := range s.store.KV(pluginTaskScheduleKVBucket) {
		pluginID := entry.Key
		if !s.pluginIsActive(pluginID) {
			continue
		}
		var record pluginTaskScheduleRecord
		if err := json.Unmarshal([]byte(entry.Value), &record); err != nil {
			s.logger.Printf("plugin task schedules of %s are unreadable: %v", pluginID, err)
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
}

// startPluginTaskScheduleRun starts one run unless this minute already fired
// the schedule or its previous run has not finished.
func (s *Server) startPluginTaskScheduleRun(pluginID string, schedule sdkplugin.TaskSchedule, minute time.Time) {
	sch := &s.pluginSchedules
	key := pluginTaskScheduleKey{pluginID: pluginID, id: schedule.ID}
	sch.mu.Lock()
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
		s.recordPluginTaskScheduleRun(pluginID, schedule, "skipped", "the previous run of this schedule is still in flight")
		return
	}
	sch.inFlight[key] = true
	sch.runs.Add(1)
	sch.mu.Unlock()
	go func() {
		defer func() {
			sch.mu.Lock()
			delete(sch.inFlight, key)
			sch.mu.Unlock()
			sch.runs.Done()
		}()
		outcome, reason := "ok", ""
		if err := s.runPluginTaskSchedule(pluginID, schedule); err != nil {
			outcome, reason = "failed", boundAuditReason(err.Error())
		}
		s.recordPluginTaskScheduleRun(pluginID, schedule, outcome, reason)
	}()
}

func (s *Server) runPluginTaskSchedule(pluginID string, schedule sdkplugin.TaskSchedule) error {
	// The plugin may have been upgraded since the schedule was stored; a
	// method it no longer declares is not called.
	if err := s.pluginTaskScheduleMethodAllowed(pluginID, schedule.Service, schedule.Method); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), pluginTaskScheduleRunTimeout)
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

func (s *Server) recordPluginTaskScheduleRun(pluginID string, schedule sdkplugin.TaskSchedule, outcome, reason string) {
	decision := "allow"
	if outcome == "skipped" {
		decision = "deny"
	}
	s.recordAudit(model.AuditEvent{
		ID: id.New("audit"), At: s.now().UTC(), ActorID: pluginTaskActorPrefix + pluginID,
		Action: "plugin.task.schedule.run", Scope: sdkplugin.CapabilityTaskSchedule, Decision: decision, Reason: reason,
		Metadata: map[string]string{
			"plugin_id": pluginID, "schedule_id": schedule.ID, "service": schedule.Service,
			"method": schedule.Method, "outcome": outcome,
		},
	})
}

// boundAuditReason keeps a plugin-authored error to a size an audit row
// carries, on a rune boundary.
func boundAuditReason(reason string) string {
	const limit = 512
	if len(reason) <= limit {
		return reason
	}
	cut := limit
	for cut > 0 && (reason[cut]&0xC0) == 0x80 {
		cut--
	}
	return reason[:cut] + "..."
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
