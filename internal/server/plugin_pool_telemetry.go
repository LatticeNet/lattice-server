package server

import (
	"time"

	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/telemetry"
)

// pluginPoolTelemetry adapts the plugin runtime's pool observer to the
// process-wide telemetry registry. The mapping is exact and total: every
// plugin-side value lands on its telemetry counterpart, and any value outside
// the known set lands on the registry's Unknown series, which it counts
// without growing state.
type pluginPoolTelemetry struct{}

func (pluginPoolTelemetry) ObserveSystemPoolDuration(phase plugin.SystemPoolDurationPhase, d time.Duration) {
	telemetry.ObservePluginSystemPoolDuration(pluginPoolDurationPhase(phase), d)
}

func (pluginPoolTelemetry) ObserveSystemPoolLifecycle(event plugin.SystemPoolLifecycleEvent) {
	telemetry.ObservePluginSystemPoolLifecycle(pluginPoolLifecycleEvent(event))
}

func (pluginPoolTelemetry) ObserveSystemPoolCircuit(transition plugin.SystemPoolCircuitTransition) {
	telemetry.ObservePluginSystemPoolCircuit(pluginPoolCircuitTransition(transition))
}

func (pluginPoolTelemetry) ObserveSystemPoolRetirement(reason plugin.SystemPoolRetirementReason) {
	telemetry.ObservePluginSystemPoolRetirement(pluginPoolRetirementReason(reason))
}

func pluginPoolDurationPhase(phase plugin.SystemPoolDurationPhase) telemetry.PluginSystemPoolDurationPhase {
	switch phase {
	case plugin.SystemPoolDurationQueue:
		return telemetry.PluginSystemPoolDurationPhaseQueue
	case plugin.SystemPoolDurationStart:
		return telemetry.PluginSystemPoolDurationPhaseStart
	case plugin.SystemPoolDurationHandler:
		return telemetry.PluginSystemPoolDurationPhaseHandler
	case plugin.SystemPoolDurationTotal:
		return telemetry.PluginSystemPoolDurationPhaseTotal
	default:
		return telemetry.PluginSystemPoolDurationPhaseUnknown
	}
}

func pluginPoolLifecycleEvent(event plugin.SystemPoolLifecycleEvent) telemetry.PluginSystemPoolLifecycleEvent {
	switch event {
	case plugin.SystemPoolLifecycleWorkerStartSuccess:
		return telemetry.PluginSystemPoolLifecycleEventWorkerStartSuccess
	case plugin.SystemPoolLifecycleWorkerStartFailure:
		return telemetry.PluginSystemPoolLifecycleEventWorkerStartFailure
	case plugin.SystemPoolLifecycleInvocationReusable:
		return telemetry.PluginSystemPoolLifecycleEventInvocationReusable
	case plugin.SystemPoolLifecycleInvocationFailure:
		return telemetry.PluginSystemPoolLifecycleEventInvocationFailure
	default:
		return telemetry.PluginSystemPoolLifecycleEventUnknown
	}
}

func pluginPoolCircuitTransition(transition plugin.SystemPoolCircuitTransition) telemetry.PluginSystemPoolCircuitTransition {
	switch transition {
	case plugin.SystemPoolCircuitOpened:
		return telemetry.PluginSystemPoolCircuitTransitionOpened
	default:
		return telemetry.PluginSystemPoolCircuitTransitionUnknown
	}
}

func pluginPoolRetirementReason(reason plugin.SystemPoolRetirementReason) telemetry.PluginSystemPoolRetirementReason {
	switch reason {
	case plugin.SystemPoolRetirementPoisoned:
		return telemetry.PluginSystemPoolRetirementReasonPoisoned
	case plugin.SystemPoolRetirementMaxUses:
		return telemetry.PluginSystemPoolRetirementReasonMaxUses
	case plugin.SystemPoolRetirementMaxAge:
		return telemetry.PluginSystemPoolRetirementReasonMaxAge
	case plugin.SystemPoolRetirementCircuitOpen:
		return telemetry.PluginSystemPoolRetirementReasonCircuitOpen
	case plugin.SystemPoolRetirementShutdown:
		return telemetry.PluginSystemPoolRetirementReasonShutdown
	case plugin.SystemPoolRetirementRejected:
		return telemetry.PluginSystemPoolRetirementReasonRejected
	default:
		return telemetry.PluginSystemPoolRetirementReasonUnknown
	}
}
