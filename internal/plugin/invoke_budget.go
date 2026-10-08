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
	// HostMaxInvokeHostCalls bounds what a signed manifest may declare per
	// method. 64 was sized for CRUD shapes; the sub-store plugin's real shapes
	// run past it — an export reattaches one program key per script file and
	// the store caps at 256 records (2 + 256 = 258), and a migration is that
	// plus three upstream fetches (263). 512 covers the store-bounded worst
	// cases with headroom while still killing a runaway plugin.
	HostMaxInvokeHostCalls = 512

	// DefaultInvokeHTTPResponseBytes is the HTTP response body an http.do or
	// http.operator.do host call may return to a method whose budget names
	// none. It is the flat limit every method had before budgets carried one.
	DefaultInvokeHTTPResponseBytes = 256 << 10
	// HostMaxInvokeHTTPResponseBytes is the most a signed budget may name
	// (design 28: the subscription service's fetch and an artifact restore).
	HostMaxInvokeHTTPResponseBytes = 8 << 20
)

// InvokeBudgetSpec is signed method-level runtime data. An absent budget stays
// additive and resolves to the old global defaults; a present budget must be
// complete so host_calls:0 can be used intentionally to forbid host calls.
type InvokeBudgetSpec struct {
	TimeoutMS   int `json:"timeout_ms"`
	StdoutBytes int `json:"stdout_bytes"`
	StderrBytes int `json:"stderr_bytes"`
	HostCalls   int `json:"host_calls"`
	// HTTPResponseBytes bounds the body of each HTTP response an http.do or
	// http.operator.do host call returns to this method. Optional and in the
	// SDK's position: zero is absent from the wire and resolves to
	// DefaultInvokeHTTPResponseBytes, so a budget signed before the field
	// existed encodes, signs and means exactly what it did.
	HTTPResponseBytes int `json:"http_response_bytes,omitempty"`
}

func (b *InvokeBudgetSpec) UnmarshalJSON(data []byte) error {
	var raw struct {
		TimeoutMS   *int `json:"timeout_ms"`
		StdoutBytes *int `json:"stdout_bytes"`
		StderrBytes *int `json:"stderr_bytes"`
		HostCalls   *int `json:"host_calls"`

		HTTPResponseBytes *int `json:"http_response_bytes"`
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
	// An explicit zero would encode back as absent, which means the default,
	// so the signed bytes would no longer say what the budget means.
	if raw.HTTPResponseBytes != nil && *raw.HTTPResponseBytes <= 0 {
		return errors.New("invoke budget http_response_bytes must be positive when present")
	}
	*b = InvokeBudgetSpec{
		TimeoutMS:   *raw.TimeoutMS,
		StdoutBytes: *raw.StdoutBytes,
		StderrBytes: *raw.StderrBytes,
		HostCalls:   *raw.HostCalls,
	}
	if raw.HTTPResponseBytes != nil {
		b.HTTPResponseBytes = *raw.HTTPResponseBytes
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
	if b.HTTPResponseBytes > HostMaxInvokeHTTPResponseBytes {
		return fmt.Errorf("http_response_bytes %d exceeds host maximum %d", b.HTTPResponseBytes, HostMaxInvokeHTTPResponseBytes)
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
	if b.HTTPResponseBytes < 0 {
		return errors.New("http_response_bytes must be non-negative")
	}
	return nil
}

type ResolvedInvokeBudget struct {
	Timeout     time.Duration
	StdoutBytes int
	StderrBytes int
	HostCalls   int
	// HTTPResponseBytes bounds each HTTP response body a host call returns.
	HTTPResponseBytes int
	Declared          bool
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
	if b.HTTPResponseBytes <= 0 {
		b.HTTPResponseBytes = DefaultInvokeHTTPResponseBytes
	}
	return ResolvedInvokeBudget{
		Timeout:           time.Duration(b.TimeoutMS) * time.Millisecond,
		StdoutBytes:       b.StdoutBytes,
		StderrBytes:       b.StderrBytes,
		HostCalls:         b.HostCalls,
		HTTPResponseBytes: b.HTTPResponseBytes,
		Declared:          declared,
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
	if b.HTTPResponseBytes > HostMaxInvokeHTTPResponseBytes {
		b.HTTPResponseBytes = HostMaxInvokeHTTPResponseBytes
	}
	return b
}
