package telemetry

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPluginSystemPoolHistogramBoundariesAndCumulativeOutput(t *testing.T) {
	r := NewRegistry()
	boundaries := []struct {
		value time.Duration
		label string
	}{
		{time.Millisecond, "0.001"},
		{5 * time.Millisecond, "0.005"},
		{10 * time.Millisecond, "0.01"},
		{25 * time.Millisecond, "0.025"},
		{50 * time.Millisecond, "0.05"},
		{100 * time.Millisecond, "0.1"},
		{250 * time.Millisecond, "0.25"},
		{500 * time.Millisecond, "0.5"},
		{time.Second, "1"},
		{2 * time.Second, "2"},
		{3 * time.Second, "3"},
		{5 * time.Second, "5"},
		{10 * time.Second, "10"},
		{15 * time.Second, "15"},
		{30 * time.Second, "30"},
	}
	for _, boundary := range boundaries {
		r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseQueue, boundary.value)
	}
	r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseQueue, 30*time.Second+time.Nanosecond)

	histogram := r.Snapshot().PluginSystemPool.Duration(PluginSystemPoolDurationPhaseQueue)
	for bucket, boundary := range boundaries {
		want := uint64(bucket + 1)
		if got := histogram.Buckets[bucket]; got != want {
			t.Fatalf("cumulative bucket %s = %d, want %d", boundary.label, got, want)
		}
	}
	if got, want := histogram.Buckets[15], uint64(16); got != want {
		t.Fatalf("+Inf bucket = %d, want %d", got, want)
	}
	if got, want := histogram.Count, uint64(16); got != want {
		t.Fatalf("count = %d, want %d", got, want)
	}

	metrics := r.Prometheus()
	for bucket, boundary := range boundaries {
		want := `lattice_plugin_system_pool_duration_seconds_bucket{phase="queue",le="` + boundary.label + `"} ` + strconv.Itoa(bucket+1)
		if !strings.Contains(metrics, want) {
			t.Fatalf("Prometheus output missing %q:\n%s", want, metrics)
		}
	}
	for _, want := range []string{
		`lattice_plugin_system_pool_duration_seconds_bucket{phase="queue",le="+Inf"} 16`,
		`lattice_plugin_system_pool_duration_seconds_count{phase="queue"} 16`,
		`lattice_plugin_system_pool_duration_seconds_sum{phase="queue"} 96.941000001`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("Prometheus output missing %q:\n%s", want, metrics)
		}
	}
}

func TestPluginSystemPoolNegativeDurationClampsToZero(t *testing.T) {
	r := NewRegistry()
	r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseStart, -time.Second)

	histogram := r.Snapshot().PluginSystemPool.Duration(PluginSystemPoolDurationPhaseStart)
	if histogram.Count != 1 || histogram.SumSeconds != 0 {
		t.Fatalf("negative duration snapshot = count %d, sum %f; want count 1, sum 0", histogram.Count, histogram.SumSeconds)
	}
	for bucket, got := range histogram.Buckets {
		if got != 1 {
			t.Fatalf("negative duration bucket %s = %d, want 1", pluginSystemPoolDurationBucketLabels[bucket], got)
		}
	}
	if !strings.Contains(r.Prometheus(), `lattice_plugin_system_pool_duration_seconds_sum{phase="start"} 0.000000000`) {
		t.Fatal("negative duration did not render as a zero sum")
	}
}

func TestPluginSystemPoolDurationSumDoesNotOverflow(t *testing.T) {
	r := NewRegistry()
	maximum := time.Duration(math.MaxInt64)
	r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseHandler, maximum)
	r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseHandler, maximum)

	histogram := r.Snapshot().PluginSystemPool.Duration(PluginSystemPoolDurationPhaseHandler)
	wantSum := 2 * float64(math.MaxInt64) / float64(time.Second)
	if histogram.Count != 2 {
		t.Fatalf("count = %d, want 2", histogram.Count)
	}
	if histogram.SumSeconds <= 0 || math.Abs(histogram.SumSeconds-wantSum) > 0.00001 {
		t.Fatalf("overflow-safe sum = %.9f, want approximately %.9f", histogram.SumSeconds, wantSum)
	}
	for bucket := 0; bucket < 15; bucket++ {
		if got := histogram.Buckets[bucket]; got != 0 {
			t.Fatalf("finite bucket %s = %d, want 0", pluginSystemPoolDurationBucketLabels[bucket], got)
		}
	}
	if got := histogram.Buckets[15]; got != 2 {
		t.Fatalf("+Inf bucket = %d, want 2", got)
	}
	wantMetric := `lattice_plugin_system_pool_duration_seconds_sum{phase="handler"} ` + fmt.Sprintf("%.9f", wantSum)
	if !strings.Contains(r.Prometheus(), wantMetric) {
		t.Fatalf("Prometheus output missing overflow-safe sum %q", wantMetric)
	}
}

func TestPluginSystemPoolUnknownValuesAreIgnoredAndCardinalityIsFixed(t *testing.T) {
	if PluginSystemPoolDurationPhaseUnknown != 0 ||
		PluginSystemPoolLifecycleEventUnknown != 0 ||
		PluginSystemPoolCircuitTransitionUnknown != 0 ||
		PluginSystemPoolRetirementReasonUnknown != 0 {
		t.Fatal("all plugin-system pool Unknown enum values must be zero")
	}

	r := NewRegistry()
	baseline := pluginSystemPoolSampleLines(r.Prometheus())
	if got := len(baseline); got != 83 {
		t.Fatalf("fresh plugin-system pool sample cardinality = %d, want 83", got)
	}
	for _, phase := range []string{"queue", "start", "handler", "total"} {
		for _, boundary := range []string{"0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2", "3", "5", "10", "15", "30", "+Inf"} {
			want := `lattice_plugin_system_pool_duration_seconds_bucket{phase="` + phase + `",le="` + boundary + `"} 0`
			if !containsExactLine(baseline, want) {
				t.Fatalf("fresh metrics missing exact predeclared bucket %q", want)
			}
		}
	}
	for _, forbidden := range []string{"{plugin=", ",plugin=", "{generation=", ",generation=", "{pid=", ",pid=", "{path=", ",path=", "{error=", ",error="} {
		if strings.Contains(strings.Join(baseline, "\n"), forbidden) {
			t.Fatalf("plugin-system pool metrics contain forbidden label %q", forbidden)
		}
	}

	for i := 0; i < 100_000; i++ {
		r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhase(100+i), time.Second)
		r.ObservePluginSystemPoolLifecycle(PluginSystemPoolLifecycleEvent(100 + i))
		r.ObservePluginSystemPoolCircuit(PluginSystemPoolCircuitTransition(100 + i))
		r.ObservePluginSystemPoolRetirement(PluginSystemPoolRetirementReason(100 + i))
	}
	if got := r.Snapshot().PluginSystemPool; got != (PluginSystemPoolSnapshot{}) {
		t.Fatalf("unknown enum observations changed registry state: %#v", got)
	}

	after := pluginSystemPoolSampleLines(r.Prometheus())
	if len(after) != 83 {
		t.Fatalf("hostile unknown observations changed sample cardinality to %d", len(after))
	}
	if strings.Join(after, "\n") != strings.Join(baseline, "\n") {
		t.Fatalf("unknown enum observations changed metrics:\nbefore:\n%s\nafter:\n%s", strings.Join(baseline, "\n"), strings.Join(after, "\n"))
	}
}

func TestPluginSystemPoolCountersAndDefaultAPI(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	for _, phase := range []PluginSystemPoolDurationPhase{
		PluginSystemPoolDurationPhaseQueue,
		PluginSystemPoolDurationPhaseStart,
		PluginSystemPoolDurationPhaseHandler,
		PluginSystemPoolDurationPhaseTotal,
	} {
		ObservePluginSystemPoolDuration(phase, 25*time.Millisecond)
	}
	for _, event := range []PluginSystemPoolLifecycleEvent{
		PluginSystemPoolLifecycleEventWorkerStartSuccess,
		PluginSystemPoolLifecycleEventWorkerStartFailure,
		PluginSystemPoolLifecycleEventInvocationReusable,
		PluginSystemPoolLifecycleEventInvocationFailure,
	} {
		ObservePluginSystemPoolLifecycle(event)
	}
	ObservePluginSystemPoolCircuit(PluginSystemPoolCircuitTransitionOpened)
	for _, reason := range []PluginSystemPoolRetirementReason{
		PluginSystemPoolRetirementReasonPoisoned,
		PluginSystemPoolRetirementReasonMaxUses,
		PluginSystemPoolRetirementReasonMaxAge,
		PluginSystemPoolRetirementReasonCircuitOpen,
		PluginSystemPoolRetirementReasonShutdown,
		PluginSystemPoolRetirementReasonRejected,
	} {
		ObservePluginSystemPoolRetirement(reason)
	}

	metrics := Prometheus()
	for _, want := range []string{
		`lattice_plugin_system_pool_duration_seconds_count{phase="queue"} 1`,
		`lattice_plugin_system_pool_duration_seconds_count{phase="start"} 1`,
		`lattice_plugin_system_pool_duration_seconds_count{phase="handler"} 1`,
		`lattice_plugin_system_pool_duration_seconds_count{phase="total"} 1`,
		`lattice_plugin_system_pool_lifecycle_total{event="worker_start_success"} 1`,
		`lattice_plugin_system_pool_lifecycle_total{event="worker_start_failure"} 1`,
		`lattice_plugin_system_pool_lifecycle_total{event="invocation_reusable"} 1`,
		`lattice_plugin_system_pool_lifecycle_total{event="invocation_failure"} 1`,
		`lattice_plugin_system_pool_circuit_transitions_total{transition="opened"} 1`,
		`lattice_plugin_system_pool_worker_retirements_total{reason="poisoned"} 1`,
		`lattice_plugin_system_pool_worker_retirements_total{reason="max_uses"} 1`,
		`lattice_plugin_system_pool_worker_retirements_total{reason="max_age"} 1`,
		`lattice_plugin_system_pool_worker_retirements_total{reason="circuit_open"} 1`,
		`lattice_plugin_system_pool_worker_retirements_total{reason="shutdown"} 1`,
		`lattice_plugin_system_pool_worker_retirements_total{reason="rejected"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("default Prometheus output missing %q:\n%s", want, metrics)
		}
	}
}

func TestPluginSystemPoolMetadataIsExactAndUnique(t *testing.T) {
	metrics := NewRegistry().Prometheus()
	wants := []string{
		"# HELP lattice_plugin_system_pool_duration_seconds Warm-pool operation latency by phase.",
		"# TYPE lattice_plugin_system_pool_duration_seconds histogram",
		"# HELP lattice_plugin_system_pool_lifecycle_total Warm-pool lifecycle events.",
		"# TYPE lattice_plugin_system_pool_lifecycle_total counter",
		"# HELP lattice_plugin_system_pool_circuit_transitions_total Warm-pool circuit-breaker transitions.",
		"# TYPE lattice_plugin_system_pool_circuit_transitions_total counter",
		"# HELP lattice_plugin_system_pool_worker_retirements_total Warm-pool worker retirements.",
		"# TYPE lattice_plugin_system_pool_worker_retirements_total counter",
	}
	for _, want := range wants {
		if got := countExactLine(metrics, want); got != 1 {
			t.Fatalf("metadata line %q occurs %d times, want exactly once", want, got)
		}
	}
}

func TestPluginSystemPoolConcurrentObservationsAreExact(t *testing.T) {
	const goroutines = 32
	const observations = 2_000
	r := NewRegistry()

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < observations; j++ {
				r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseTotal, time.Second)
				r.ObservePluginSystemPoolLifecycle(PluginSystemPoolLifecycleEventInvocationReusable)
				r.ObservePluginSystemPoolCircuit(PluginSystemPoolCircuitTransitionOpened)
				r.ObservePluginSystemPoolRetirement(PluginSystemPoolRetirementReasonPoisoned)
			}
		}()
	}
	wg.Wait()

	want := uint64(goroutines * observations)
	snapshot := r.Snapshot().PluginSystemPool
	if got := snapshot.Duration(PluginSystemPoolDurationPhaseTotal).Count; got != want {
		t.Fatalf("duration count = %d, want %d", got, want)
	}
	if got, wantSum := snapshot.Duration(PluginSystemPoolDurationPhaseTotal).SumSeconds, float64(want); got != wantSum {
		t.Fatalf("duration sum = %.9f, want %.9f", got, wantSum)
	}
	for bucket, got := range snapshot.Duration(PluginSystemPoolDurationPhaseTotal).Buckets {
		wantBucket := want
		if bucket < 8 {
			wantBucket = 0
		}
		if got != wantBucket {
			t.Fatalf("duration bucket %s = %d, want %d", pluginSystemPoolDurationBucketLabels[bucket], got, wantBucket)
		}
	}
	if got := snapshot.LifecycleCount(PluginSystemPoolLifecycleEventInvocationReusable); got != want {
		t.Fatalf("lifecycle count = %d, want %d", got, want)
	}
	if got := snapshot.CircuitCount(PluginSystemPoolCircuitTransitionOpened); got != want {
		t.Fatalf("circuit count = %d, want %d", got, want)
	}
	if got := snapshot.RetirementCount(PluginSystemPoolRetirementReasonPoisoned); got != want {
		t.Fatalf("retirement count = %d, want %d", got, want)
	}
}

func TestPluginSystemPoolSnapshotIsolationAndReset(t *testing.T) {
	r := NewRegistry()
	r.ObserveStoreSave(time.Second, errors.New("save failed"))
	r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseStart, 10*time.Millisecond)
	r.ObservePluginSystemPoolLifecycle(PluginSystemPoolLifecycleEventWorkerStartFailure)
	r.ObservePluginSystemPoolCircuit(PluginSystemPoolCircuitTransitionOpened)
	r.ObservePluginSystemPoolRetirement(PluginSystemPoolRetirementReasonRejected)
	before := r.Snapshot()

	r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseStart, 20*time.Millisecond)
	r.ObservePluginSystemPoolLifecycle(PluginSystemPoolLifecycleEventWorkerStartFailure)
	if got := before.PluginSystemPool.Duration(PluginSystemPoolDurationPhaseStart).Count; got != 1 {
		t.Fatalf("captured snapshot mutated after observation: count = %d", got)
	}
	if got := before.PluginSystemPool.LifecycleCount(PluginSystemPoolLifecycleEventWorkerStartFailure); got != 1 {
		t.Fatalf("captured lifecycle snapshot mutated after observation: count = %d", got)
	}
	if got := before.PluginSystemPool.CircuitCount(PluginSystemPoolCircuitTransitionOpened); got != 1 {
		t.Fatalf("captured circuit snapshot count = %d, want 1", got)
	}
	if got := before.PluginSystemPool.RetirementCount(PluginSystemPoolRetirementReasonRejected); got != 1 {
		t.Fatalf("captured retirement snapshot count = %d, want 1", got)
	}

	r.Reset()
	after := r.Snapshot()
	if got := after.PluginSystemPool.Duration(PluginSystemPoolDurationPhaseStart).Count; got != 0 {
		t.Fatalf("duration count after reset = %d, want 0", got)
	}
	if got := after.PluginSystemPool.LifecycleCount(PluginSystemPoolLifecycleEventWorkerStartFailure); got != 0 {
		t.Fatalf("lifecycle count after reset = %d, want 0", got)
	}
	if got := after.PluginSystemPool.CircuitCount(PluginSystemPoolCircuitTransitionOpened); got != 0 {
		t.Fatalf("circuit count after reset = %d, want 0", got)
	}
	if got := after.PluginSystemPool.RetirementCount(PluginSystemPoolRetirementReasonRejected); got != 0 {
		t.Fatalf("retirement count after reset = %d, want 0", got)
	}
	if len(after.Store) != 0 {
		t.Fatalf("existing store metrics survived reset: %#v", after.Store)
	}
	if got := len(pluginSystemPoolSampleLines(r.Prometheus())); got != 83 {
		t.Fatalf("reset removed predeclared samples: got %d, want 83", got)
	}
}

func TestPluginSystemPoolMetricsDoNotChangeExistingFamilies(t *testing.T) {
	r := NewRegistry()
	r.ObserveStoreSave(2*time.Millisecond, nil)
	r.ObserveAuditAppend(errors.New("audit failed"))
	r.ObserveHTTPRequest("/api/test", 201, 3*time.Millisecond, true)
	r.ObserveAgentRequest("/api/agent/test", 503, 4*time.Millisecond)

	before := r.Prometheus()
	r.ObservePluginSystemPoolDuration(PluginSystemPoolDurationPhaseQueue, time.Millisecond)
	r.ObservePluginSystemPoolLifecycle(PluginSystemPoolLifecycleEventWorkerStartSuccess)
	r.ObservePluginSystemPoolCircuit(PluginSystemPoolCircuitTransitionOpened)
	r.ObservePluginSystemPoolRetirement(PluginSystemPoolRetirementReasonShutdown)
	after := r.Prometheus()

	for _, metric := range []string{
		"lattice_store_save_total",
		"lattice_store_save_duration_seconds",
		"lattice_audit_append_total",
		"lattice_http_requests_total",
		"lattice_http_request_duration_seconds",
		"lattice_http_slow_requests_total",
		"lattice_agent_requests_total",
		"lattice_agent_request_duration_seconds",
	} {
		if got, want := metricLines(after, metric), metricLines(before, metric); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("existing family %s changed after pool observations:\nbefore=%q\nafter=%q", metric, want, got)
		}
	}
}

func pluginSystemPoolSampleLines(metrics string) []string {
	var lines []string
	for _, line := range strings.Split(metrics, "\n") {
		if strings.HasPrefix(line, "lattice_plugin_system_pool_") {
			lines = append(lines, line)
		}
	}
	return lines
}

func metricLines(metrics, family string) []string {
	var lines []string
	for _, line := range strings.Split(metrics, "\n") {
		if strings.HasPrefix(line, family) {
			lines = append(lines, line)
		}
	}
	return lines
}

func containsExactLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

func countExactLine(metrics, want string) int {
	count := 0
	for _, line := range strings.Split(metrics, "\n") {
		if line == want {
			count++
		}
	}
	return count
}

func BenchmarkPluginSystemPoolUnknownObservation(b *testing.B) {
	r := NewRegistry()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.ObservePluginSystemPoolLifecycle(PluginSystemPoolLifecycleEvent(-1 - i))
	}
}

func TestPluginSystemPoolSampleLinesHelperSanity(t *testing.T) {
	lines := pluginSystemPoolSampleLines("# HELP ignored\n" +
		"lattice_plugin_system_pool_x 1\n" +
		"other 2\n" +
		"lattice_plugin_system_pool_y " + strconv.Itoa(3) + "\n")
	if strings.Join(lines, ",") != "lattice_plugin_system_pool_x 1,lattice_plugin_system_pool_y 3" {
		t.Fatalf("unexpected helper output: %q", lines)
	}
}
