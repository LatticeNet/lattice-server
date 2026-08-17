package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

// The adapter's mapping must be total: every plugin-side value lands on its
// exact telemetry series. A new plugin-side value without a mapping would
// silently vanish into the Unknown series, so this test enumerates them all
// and asserts per-series deltas against the process registry.
func TestPluginPoolTelemetryMapsEveryValueExactly(t *testing.T) {
	adapter := pluginPoolTelemetry{}
	before := telemetry.CurrentSnapshot().PluginSystemPool

	durationPairs := []struct {
		in   plugin.SystemPoolDurationPhase
		want telemetry.PluginSystemPoolDurationPhase
	}{
		{plugin.SystemPoolDurationQueue, telemetry.PluginSystemPoolDurationPhaseQueue},
		{plugin.SystemPoolDurationStart, telemetry.PluginSystemPoolDurationPhaseStart},
		{plugin.SystemPoolDurationHandler, telemetry.PluginSystemPoolDurationPhaseHandler},
		{plugin.SystemPoolDurationTotal, telemetry.PluginSystemPoolDurationPhaseTotal},
	}
	for _, pair := range durationPairs {
		adapter.ObserveSystemPoolDuration(pair.in, 3*time.Millisecond)
	}

	lifecyclePairs := []struct {
		in   plugin.SystemPoolLifecycleEvent
		want telemetry.PluginSystemPoolLifecycleEvent
	}{
		{plugin.SystemPoolLifecycleWorkerStartSuccess, telemetry.PluginSystemPoolLifecycleEventWorkerStartSuccess},
		{plugin.SystemPoolLifecycleWorkerStartFailure, telemetry.PluginSystemPoolLifecycleEventWorkerStartFailure},
		{plugin.SystemPoolLifecycleInvocationReusable, telemetry.PluginSystemPoolLifecycleEventInvocationReusable},
		{plugin.SystemPoolLifecycleInvocationFailure, telemetry.PluginSystemPoolLifecycleEventInvocationFailure},
	}
	for _, pair := range lifecyclePairs {
		adapter.ObserveSystemPoolLifecycle(pair.in)
	}

	adapter.ObserveSystemPoolCircuit(plugin.SystemPoolCircuitOpened)

	retirementPairs := []struct {
		in   plugin.SystemPoolRetirementReason
		want telemetry.PluginSystemPoolRetirementReason
	}{
		{plugin.SystemPoolRetirementPoisoned, telemetry.PluginSystemPoolRetirementReasonPoisoned},
		{plugin.SystemPoolRetirementMaxUses, telemetry.PluginSystemPoolRetirementReasonMaxUses},
		{plugin.SystemPoolRetirementMaxAge, telemetry.PluginSystemPoolRetirementReasonMaxAge},
		{plugin.SystemPoolRetirementCircuitOpen, telemetry.PluginSystemPoolRetirementReasonCircuitOpen},
		{plugin.SystemPoolRetirementShutdown, telemetry.PluginSystemPoolRetirementReasonShutdown},
		{plugin.SystemPoolRetirementRejected, telemetry.PluginSystemPoolRetirementReasonRejected},
	}
	for _, pair := range retirementPairs {
		adapter.ObserveSystemPoolRetirement(pair.in)
	}

	after := telemetry.CurrentSnapshot().PluginSystemPool
	for _, pair := range durationPairs {
		delta := after.Duration(pair.want).Count - before.Duration(pair.want).Count
		if delta != 1 {
			t.Errorf("duration phase %v: count delta=%d, want 1", pair.want, delta)
		}
	}
	for _, pair := range lifecyclePairs {
		delta := after.LifecycleCount(pair.want) - before.LifecycleCount(pair.want)
		if delta != 1 {
			t.Errorf("lifecycle event %v: delta=%d, want 1", pair.want, delta)
		}
	}
	if delta := after.CircuitCount(telemetry.PluginSystemPoolCircuitTransitionOpened) - before.CircuitCount(telemetry.PluginSystemPoolCircuitTransitionOpened); delta != 1 {
		t.Errorf("circuit opened: delta=%d, want 1", delta)
	}
	for _, pair := range retirementPairs {
		delta := after.RetirementCount(pair.want) - before.RetirementCount(pair.want)
		if delta != 1 {
			t.Errorf("retirement reason %v: delta=%d, want 1", pair.want, delta)
		}
	}
}

// Out-of-range plugin values must land on the Unknown series rather than on
// any real one, so hostile or future enum values cannot skew real metrics.
func TestPluginPoolTelemetryRoutesUnknownValuesToUnknown(t *testing.T) {
	adapter := pluginPoolTelemetry{}
	before := telemetry.CurrentSnapshot().PluginSystemPool
	adapter.ObserveSystemPoolDuration(plugin.SystemPoolDurationPhase(99), time.Millisecond)
	adapter.ObserveSystemPoolLifecycle(plugin.SystemPoolLifecycleEvent(99))
	adapter.ObserveSystemPoolCircuit(plugin.SystemPoolCircuitTransition(99))
	adapter.ObserveSystemPoolRetirement(plugin.SystemPoolRetirementReason(99))
	after := telemetry.CurrentSnapshot().PluginSystemPool
	if after != before {
		t.Errorf("unknown values changed real series: before=%+v after=%+v", before, after)
	}
}
