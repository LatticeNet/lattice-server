package telemetry

import (
	"strings"
	"time"
)

type PluginSystemPoolDurationPhase int

const (
	PluginSystemPoolDurationPhaseUnknown PluginSystemPoolDurationPhase = iota
	PluginSystemPoolDurationPhaseQueue
	PluginSystemPoolDurationPhaseStart
	PluginSystemPoolDurationPhaseHandler
	PluginSystemPoolDurationPhaseTotal
)

type PluginSystemPoolLifecycleEvent int

const (
	PluginSystemPoolLifecycleEventUnknown PluginSystemPoolLifecycleEvent = iota
	PluginSystemPoolLifecycleEventWorkerStartSuccess
	PluginSystemPoolLifecycleEventWorkerStartFailure
	PluginSystemPoolLifecycleEventInvocationReusable
	PluginSystemPoolLifecycleEventInvocationFailure
)

type PluginSystemPoolCircuitTransition int

const (
	PluginSystemPoolCircuitTransitionUnknown PluginSystemPoolCircuitTransition = iota
	PluginSystemPoolCircuitTransitionOpened
)

type PluginSystemPoolRetirementReason int

const (
	PluginSystemPoolRetirementReasonUnknown PluginSystemPoolRetirementReason = iota
	PluginSystemPoolRetirementReasonPoisoned
	PluginSystemPoolRetirementReasonMaxUses
	PluginSystemPoolRetirementReasonMaxAge
	PluginSystemPoolRetirementReasonCircuitOpen
	PluginSystemPoolRetirementReasonShutdown
	PluginSystemPoolRetirementReasonRejected
)

const (
	pluginSystemPoolDurationPhaseCount     = 4
	pluginSystemPoolLifecycleEventCount    = 4
	pluginSystemPoolCircuitTransitionCount = 1
	pluginSystemPoolRetirementReasonCount  = 6
)

var pluginSystemPoolDurationBuckets = [...]time.Duration{
	time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2 * time.Second,
	3 * time.Second,
	5 * time.Second,
	10 * time.Second,
	15 * time.Second,
	30 * time.Second,
}

var pluginSystemPoolDurationBucketLabels = [...]string{
	"0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5",
	"1", "2", "3", "5", "10", "15", "30", "+Inf",
}

type PluginSystemPoolDurationHistogram struct {
	Buckets    [len(pluginSystemPoolDurationBucketLabels)]uint64
	Count      uint64
	SumSeconds float64
}

type PluginSystemPoolSnapshot struct {
	Durations          [pluginSystemPoolDurationPhaseCount]PluginSystemPoolDurationHistogram
	Lifecycle          [pluginSystemPoolLifecycleEventCount]uint64
	CircuitTransitions [pluginSystemPoolCircuitTransitionCount]uint64
	Retirements        [pluginSystemPoolRetirementReasonCount]uint64
}

func (s PluginSystemPoolSnapshot) Duration(phase PluginSystemPoolDurationPhase) PluginSystemPoolDurationHistogram {
	index, ok := pluginSystemPoolDurationPhaseIndex(phase)
	if !ok {
		return PluginSystemPoolDurationHistogram{}
	}
	return s.Durations[index]
}

func (s PluginSystemPoolSnapshot) LifecycleCount(event PluginSystemPoolLifecycleEvent) uint64 {
	index, ok := pluginSystemPoolLifecycleEventIndex(event)
	if !ok {
		return 0
	}
	return s.Lifecycle[index]
}

func (s PluginSystemPoolSnapshot) CircuitCount(transition PluginSystemPoolCircuitTransition) uint64 {
	index, ok := pluginSystemPoolCircuitTransitionIndex(transition)
	if !ok {
		return 0
	}
	return s.CircuitTransitions[index]
}

func (s PluginSystemPoolSnapshot) RetirementCount(reason PluginSystemPoolRetirementReason) uint64 {
	index, ok := pluginSystemPoolRetirementReasonIndex(reason)
	if !ok {
		return 0
	}
	return s.Retirements[index]
}

func (r *Registry) ObservePluginSystemPoolDuration(phase PluginSystemPoolDurationPhase, d time.Duration) {
	index, ok := pluginSystemPoolDurationPhaseIndex(phase)
	if !ok {
		return
	}
	// Elapsed durations should not be negative. Clamp host clock anomalies rather
	// than exporting an invalid negative histogram sum.
	if d < 0 {
		d = 0
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	histogram := &r.pluginSystemPool.Durations[index]
	histogram.Count++
	histogram.SumSeconds += d.Seconds()
	for bucket, upperBound := range pluginSystemPoolDurationBuckets {
		if d <= upperBound {
			for cumulative := bucket; cumulative < len(histogram.Buckets); cumulative++ {
				histogram.Buckets[cumulative]++
			}
			return
		}
	}
	histogram.Buckets[len(histogram.Buckets)-1]++
}

func (r *Registry) ObservePluginSystemPoolLifecycle(event PluginSystemPoolLifecycleEvent) {
	index, ok := pluginSystemPoolLifecycleEventIndex(event)
	if !ok {
		return
	}
	r.mu.Lock()
	r.pluginSystemPool.Lifecycle[index]++
	r.mu.Unlock()
}

func (r *Registry) ObservePluginSystemPoolCircuit(transition PluginSystemPoolCircuitTransition) {
	index, ok := pluginSystemPoolCircuitTransitionIndex(transition)
	if !ok {
		return
	}
	r.mu.Lock()
	r.pluginSystemPool.CircuitTransitions[index]++
	r.mu.Unlock()
}

func (r *Registry) ObservePluginSystemPoolRetirement(reason PluginSystemPoolRetirementReason) {
	index, ok := pluginSystemPoolRetirementReasonIndex(reason)
	if !ok {
		return
	}
	r.mu.Lock()
	r.pluginSystemPool.Retirements[index]++
	r.mu.Unlock()
}

func writePluginSystemPoolMetrics(b *strings.Builder, snapshot PluginSystemPoolSnapshot) {
	writeLine(b, "# HELP lattice_plugin_system_pool_duration_seconds Warm-pool operation latency by phase.")
	writeLine(b, "# TYPE lattice_plugin_system_pool_duration_seconds histogram")
	for phase := PluginSystemPoolDurationPhaseQueue; phase <= PluginSystemPoolDurationPhaseTotal; phase++ {
		histogram := snapshot.Duration(phase)
		phaseLabel, _ := pluginSystemPoolDurationPhaseLabel(phase)
		for bucket, upperBound := range pluginSystemPoolDurationBucketLabels {
			writeLine(b, "lattice_plugin_system_pool_duration_seconds_bucket{phase=\"%s\",le=\"%s\"} %d", phaseLabel, upperBound, histogram.Buckets[bucket])
		}
		writeLine(b, "lattice_plugin_system_pool_duration_seconds_count{phase=\"%s\"} %d", phaseLabel, histogram.Count)
		writeLine(b, "lattice_plugin_system_pool_duration_seconds_sum{phase=\"%s\"} %.9f", phaseLabel, histogram.SumSeconds)
	}

	writeLine(b, "# HELP lattice_plugin_system_pool_lifecycle_total Warm-pool lifecycle events.")
	writeLine(b, "# TYPE lattice_plugin_system_pool_lifecycle_total counter")
	for event := PluginSystemPoolLifecycleEventWorkerStartSuccess; event <= PluginSystemPoolLifecycleEventInvocationFailure; event++ {
		label, _ := pluginSystemPoolLifecycleEventLabel(event)
		writeLine(b, "lattice_plugin_system_pool_lifecycle_total{event=\"%s\"} %d", label, snapshot.LifecycleCount(event))
	}

	writeLine(b, "# HELP lattice_plugin_system_pool_circuit_transitions_total Warm-pool circuit-breaker transitions.")
	writeLine(b, "# TYPE lattice_plugin_system_pool_circuit_transitions_total counter")
	writeLine(b, "lattice_plugin_system_pool_circuit_transitions_total{transition=\"opened\"} %d", snapshot.CircuitCount(PluginSystemPoolCircuitTransitionOpened))

	writeLine(b, "# HELP lattice_plugin_system_pool_worker_retirements_total Warm-pool worker retirements.")
	writeLine(b, "# TYPE lattice_plugin_system_pool_worker_retirements_total counter")
	for reason := PluginSystemPoolRetirementReasonPoisoned; reason <= PluginSystemPoolRetirementReasonRejected; reason++ {
		label, _ := pluginSystemPoolRetirementReasonLabel(reason)
		writeLine(b, "lattice_plugin_system_pool_worker_retirements_total{reason=\"%s\"} %d", label, snapshot.RetirementCount(reason))
	}
}

func pluginSystemPoolDurationPhaseIndex(phase PluginSystemPoolDurationPhase) (int, bool) {
	switch phase {
	case PluginSystemPoolDurationPhaseQueue:
		return 0, true
	case PluginSystemPoolDurationPhaseStart:
		return 1, true
	case PluginSystemPoolDurationPhaseHandler:
		return 2, true
	case PluginSystemPoolDurationPhaseTotal:
		return 3, true
	default:
		return 0, false
	}
}

func pluginSystemPoolDurationPhaseLabel(phase PluginSystemPoolDurationPhase) (string, bool) {
	switch phase {
	case PluginSystemPoolDurationPhaseQueue:
		return "queue", true
	case PluginSystemPoolDurationPhaseStart:
		return "start", true
	case PluginSystemPoolDurationPhaseHandler:
		return "handler", true
	case PluginSystemPoolDurationPhaseTotal:
		return "total", true
	default:
		return "", false
	}
}

func pluginSystemPoolLifecycleEventIndex(event PluginSystemPoolLifecycleEvent) (int, bool) {
	switch event {
	case PluginSystemPoolLifecycleEventWorkerStartSuccess:
		return 0, true
	case PluginSystemPoolLifecycleEventWorkerStartFailure:
		return 1, true
	case PluginSystemPoolLifecycleEventInvocationReusable:
		return 2, true
	case PluginSystemPoolLifecycleEventInvocationFailure:
		return 3, true
	default:
		return 0, false
	}
}

func pluginSystemPoolLifecycleEventLabel(event PluginSystemPoolLifecycleEvent) (string, bool) {
	switch event {
	case PluginSystemPoolLifecycleEventWorkerStartSuccess:
		return "worker_start_success", true
	case PluginSystemPoolLifecycleEventWorkerStartFailure:
		return "worker_start_failure", true
	case PluginSystemPoolLifecycleEventInvocationReusable:
		return "invocation_reusable", true
	case PluginSystemPoolLifecycleEventInvocationFailure:
		return "invocation_failure", true
	default:
		return "", false
	}
}

func pluginSystemPoolCircuitTransitionIndex(transition PluginSystemPoolCircuitTransition) (int, bool) {
	switch transition {
	case PluginSystemPoolCircuitTransitionOpened:
		return 0, true
	default:
		return 0, false
	}
}

func pluginSystemPoolRetirementReasonIndex(reason PluginSystemPoolRetirementReason) (int, bool) {
	switch reason {
	case PluginSystemPoolRetirementReasonPoisoned:
		return 0, true
	case PluginSystemPoolRetirementReasonMaxUses:
		return 1, true
	case PluginSystemPoolRetirementReasonMaxAge:
		return 2, true
	case PluginSystemPoolRetirementReasonCircuitOpen:
		return 3, true
	case PluginSystemPoolRetirementReasonShutdown:
		return 4, true
	case PluginSystemPoolRetirementReasonRejected:
		return 5, true
	default:
		return 0, false
	}
}

func pluginSystemPoolRetirementReasonLabel(reason PluginSystemPoolRetirementReason) (string, bool) {
	switch reason {
	case PluginSystemPoolRetirementReasonPoisoned:
		return "poisoned", true
	case PluginSystemPoolRetirementReasonMaxUses:
		return "max_uses", true
	case PluginSystemPoolRetirementReasonMaxAge:
		return "max_age", true
	case PluginSystemPoolRetirementReasonCircuitOpen:
		return "circuit_open", true
	case PluginSystemPoolRetirementReasonShutdown:
		return "shutdown", true
	case PluginSystemPoolRetirementReasonRejected:
		return "rejected", true
	default:
		return "", false
	}
}
