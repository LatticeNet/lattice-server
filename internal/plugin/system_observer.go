package plugin

import "time"

// SystemPoolDurationPhase names one measured span of a pooled invocation or
// worker start. The zero value is deliberately invalid so an unset phase can
// never masquerade as a real one.
type SystemPoolDurationPhase int

const (
	// SystemPoolDurationQueue is the wait for a pooled worker, successful or
	// not: the time an invocation spent owning no worker.
	SystemPoolDurationQueue SystemPoolDurationPhase = iota + 1
	// SystemPoolDurationStart is one worker start attempt, from spawn to
	// readiness or failure.
	SystemPoolDurationStart
	// SystemPoolDurationHandler is the span the invocation actually held the
	// worker's transport.
	SystemPoolDurationHandler
	// SystemPoolDurationTotal is the whole pooled invocation as the caller
	// experienced it, queue included.
	SystemPoolDurationTotal
)

// SystemPoolLifecycleEvent names one countable pool outcome.
type SystemPoolLifecycleEvent int

const (
	// SystemPoolLifecycleWorkerStartSuccess is a worker that reached readiness.
	SystemPoolLifecycleWorkerStartSuccess SystemPoolLifecycleEvent = iota + 1
	// SystemPoolLifecycleWorkerStartFailure is a start attempt that did not,
	// canceled shutdown attempts excluded.
	SystemPoolLifecycleWorkerStartFailure
	// SystemPoolLifecycleInvocationReusable is an invocation whose worker came
	// back reusable.
	SystemPoolLifecycleInvocationReusable
	// SystemPoolLifecycleInvocationFailure is an invocation that poisoned its
	// worker.
	SystemPoolLifecycleInvocationFailure
)

// SystemPoolCircuitTransition names a circuit-breaker state change.
type SystemPoolCircuitTransition int

// SystemPoolCircuitOpened is the closed-to-open transition. Re-arming is not
// observed here: the pool opens the circuit at a decision point, but closing
// arrives from operator recovery flows whose truth lives elsewhere.
const SystemPoolCircuitOpened SystemPoolCircuitTransition = 1

// SystemPoolRetirementReason names why exactly one worker left the pool.
type SystemPoolRetirementReason int

const (
	// SystemPoolRetirementPoisoned is an invocation-declared terminal failure.
	SystemPoolRetirementPoisoned SystemPoolRetirementReason = iota + 1
	// SystemPoolRetirementMaxUses is the configured use ceiling.
	SystemPoolRetirementMaxUses
	// SystemPoolRetirementMaxAge is the configured age ceiling.
	SystemPoolRetirementMaxAge
	// SystemPoolRetirementCircuitOpen is a worker dropped because the circuit
	// opened, at lease end or from the idle set.
	SystemPoolRetirementCircuitOpen
	// SystemPoolRetirementShutdown is a worker dropped by drain or close.
	SystemPoolRetirementShutdown
	// SystemPoolRetirementRejected is a worker the pool refused to keep: built
	// for a superseded generation, arriving past capacity, or otherwise valid
	// work the pool's current state has no place for.
	SystemPoolRetirementRejected
)

// SystemPoolObserver receives warm-pool observations at the exact points where
// the pool decides a worker's or invocation's fate. Implementations must be
// cheap and must not call back into the runner or pool; a nil observer is
// valid and observes nothing.
type SystemPoolObserver interface {
	ObserveSystemPoolDuration(phase SystemPoolDurationPhase, d time.Duration)
	ObserveSystemPoolLifecycle(event SystemPoolLifecycleEvent)
	ObserveSystemPoolCircuit(transition SystemPoolCircuitTransition)
	ObserveSystemPoolRetirement(reason SystemPoolRetirementReason)
}

func observeSystemPoolDuration(obs SystemPoolObserver, phase SystemPoolDurationPhase, d time.Duration) {
	if obs != nil {
		obs.ObserveSystemPoolDuration(phase, d)
	}
}

func observeSystemPoolLifecycle(obs SystemPoolObserver, event SystemPoolLifecycleEvent) {
	if obs != nil {
		obs.ObserveSystemPoolLifecycle(event)
	}
}

func observeSystemPoolCircuit(obs SystemPoolObserver, transition SystemPoolCircuitTransition) {
	if obs != nil {
		obs.ObserveSystemPoolCircuit(transition)
	}
}

func observeSystemPoolRetirements(obs SystemPoolObserver, reason SystemPoolRetirementReason, count int) {
	if obs == nil {
		return
	}
	for range count {
		obs.ObserveSystemPoolRetirement(reason)
	}
}
