package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type testRuntimeCloser func(context.Context) error

func (f testRuntimeCloser) Close(ctx context.Context) error { return f(ctx) }

func TestServeUntilContextClosesRuntimeOnImmediateServeError(t *testing.T) {
	serveErr := errors.New("serve failed")
	closeErr := errors.New("runtime close failed")
	var calls atomic.Int32
	err := serveUntilContext(context.Background(), time.Second, &http.Server{}, testRuntimeCloser(func(context.Context) error {
		calls.Add(1)
		return closeErr
	}), func() error { return serveErr })
	if calls.Load() != 1 || !errors.Is(err, serveErr) || !errors.Is(err, closeErr) {
		t.Fatalf("calls=%d err=%v", calls.Load(), err)
	}
}

func TestServeUntilContextDeadlineDoesNotWaitForHungRuntimeClose(t *testing.T) {
	signalCtx, signal := context.WithCancel(context.Background())
	signal()
	releaseClose := make(chan struct{})
	releaseServe := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveUntilContext(signalCtx, 20*time.Millisecond, &http.Server{}, testRuntimeCloser(func(context.Context) error {
			<-releaseClose // deliberately ignores its context
			return nil
		}), func() error {
			<-releaseServe
			return http.ErrServerClosed
		})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err=%v want deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for runtime that ignored cancellation")
	}
	close(releaseClose)
	close(releaseServe)
}

func TestServeUntilContextImmediateErrorDoesNotWaitForHungRuntimeClose(t *testing.T) {
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveUntilContext(context.Background(), 20*time.Millisecond, &http.Server{}, testRuntimeCloser(func(context.Context) error {
			<-release
			return nil
		}), func() error { return errors.New("serve failed") })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err=%v want deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("immediate serve failure waited for noncooperative runtime close")
	}
	close(release)
}

func TestServeUntilContextDoesNotWaitForNonreturningServe(t *testing.T) {
	signalCtx, signal := context.WithCancel(context.Background())
	signal()
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveUntilContext(signalCtx, 20*time.Millisecond, &http.Server{}, testRuntimeCloser(func(context.Context) error { return nil }), func() error {
			<-release
			return nil
		})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err=%v want deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for nonreturning serve")
	}
	close(release)
}
