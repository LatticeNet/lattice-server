package plugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	DefaultInvokeTimeoutMS   = 10_000
	DefaultInvokeStdoutBytes = 1 << 20
	DefaultInvokeStderrBytes = 1 << 20
	DefaultInvokeHostCalls   = 64

	HostMaxInvokeTimeoutMS   = 30_000
	HostMaxInvokeStdoutBytes = 8 << 20
	HostMaxInvokeStderrBytes = 1 << 20
	HostMaxInvokeHostCalls   = 64
)

// InvokeBudgetSpec is signed method-level runtime data. An absent budget stays
// additive and resolves to the old global defaults; a present budget must be
// complete so host_calls:0 can be used intentionally to forbid host calls.
type InvokeBudgetSpec struct {
	TimeoutMS   int `json:"timeout_ms"`
	StdoutBytes int `json:"stdout_bytes"`
	StderrBytes int `json:"stderr_bytes"`
	HostCalls   int `json:"host_calls"`
}

func (b *InvokeBudgetSpec) UnmarshalJSON(data []byte) error {
	var raw struct {
		TimeoutMS   *int `json:"timeout_ms"`
		StdoutBytes *int `json:"stdout_bytes"`
		StderrBytes *int `json:"stderr_bytes"`
		HostCalls   *int `json:"host_calls"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	if err := ensureNoTrailingJSON(dec); err != nil {
		return err
	}
	if raw.TimeoutMS == nil || raw.StdoutBytes == nil || raw.StderrBytes == nil || raw.HostCalls == nil {
		return errors.New("invoke budget requires timeout_ms, stdout_bytes, stderr_bytes and host_calls")
	}
	*b = InvokeBudgetSpec{
		TimeoutMS:   *raw.TimeoutMS,
		StdoutBytes: *raw.StdoutBytes,
		StderrBytes: *raw.StderrBytes,
		HostCalls:   *raw.HostCalls,
	}
	return nil
}

func DefaultInvokeBudgetSpec() InvokeBudgetSpec {
	return InvokeBudgetSpec{
		TimeoutMS:   DefaultInvokeTimeoutMS,
		StdoutBytes: DefaultInvokeStdoutBytes,
		StderrBytes: DefaultInvokeStderrBytes,
		HostCalls:   DefaultInvokeHostCalls,
	}
}

func ValidateInvokeBudgetSpec(b InvokeBudgetSpec) error {
	if err := validateInvokeBudgetPositive(b); err != nil {
		return err
	}
	if b.TimeoutMS > HostMaxInvokeTimeoutMS {
		return fmt.Errorf("timeout_ms %d exceeds host maximum %d", b.TimeoutMS, HostMaxInvokeTimeoutMS)
	}
	if b.StdoutBytes > HostMaxInvokeStdoutBytes {
		return fmt.Errorf("stdout_bytes %d exceeds host maximum %d", b.StdoutBytes, HostMaxInvokeStdoutBytes)
	}
	if b.StderrBytes > HostMaxInvokeStderrBytes {
		return fmt.Errorf("stderr_bytes %d exceeds host maximum %d", b.StderrBytes, HostMaxInvokeStderrBytes)
	}
	if b.HostCalls > HostMaxInvokeHostCalls {
		return fmt.Errorf("host_calls %d exceeds host maximum %d", b.HostCalls, HostMaxInvokeHostCalls)
	}
	return nil
}

func validateInvokeBudgetPositive(b InvokeBudgetSpec) error {
	if b.TimeoutMS <= 0 {
		return errors.New("timeout_ms must be positive")
	}
	if b.StdoutBytes <= 0 {
		return errors.New("stdout_bytes must be positive")
	}
	if b.StderrBytes <= 0 {
		return errors.New("stderr_bytes must be positive")
	}
	if b.HostCalls < 0 {
		return errors.New("host_calls must be non-negative")
	}
	return nil
}

type ResolvedInvokeBudget struct {
	Timeout     time.Duration
	StdoutBytes int
	StderrBytes int
	HostCalls   int
	Declared    bool
}

func ResolveInvokeBudget(spec *InvokeBudgetSpec, defaults InvokeBudgetSpec) ResolvedInvokeBudget {
	declared := spec != nil
	b := defaults
	if declared {
		b = *spec
	}
	b = clampInvokeBudget(b)
	if b.TimeoutMS <= 0 {
		b.TimeoutMS = DefaultInvokeTimeoutMS
	}
	if b.StdoutBytes <= 0 {
		b.StdoutBytes = DefaultInvokeStdoutBytes
	}
	if b.StderrBytes <= 0 {
		b.StderrBytes = DefaultInvokeStderrBytes
	}
	if b.HostCalls < 0 {
		b.HostCalls = 0
	}
	return ResolvedInvokeBudget{
		Timeout:     time.Duration(b.TimeoutMS) * time.Millisecond,
		StdoutBytes: b.StdoutBytes,
		StderrBytes: b.StderrBytes,
		HostCalls:   b.HostCalls,
		Declared:    declared,
	}
}

func clampInvokeBudget(b InvokeBudgetSpec) InvokeBudgetSpec {
	if b.TimeoutMS > HostMaxInvokeTimeoutMS {
		b.TimeoutMS = HostMaxInvokeTimeoutMS
	}
	if b.StdoutBytes > HostMaxInvokeStdoutBytes {
		b.StdoutBytes = HostMaxInvokeStdoutBytes
	}
	if b.StderrBytes > HostMaxInvokeStderrBytes {
		b.StderrBytes = HostMaxInvokeStderrBytes
	}
	if b.HostCalls > HostMaxInvokeHostCalls {
		b.HostCalls = HostMaxInvokeHostCalls
	}
	return b
}
