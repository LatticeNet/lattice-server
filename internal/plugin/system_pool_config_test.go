package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewSystemRunnerRejectsInvalidPoolConfigurationBeforeRuntimeUse(t *testing.T) {
	valid := SystemPoolConfig{Size: 1, MaxOverflow: 0, StartTimeout: time.Second, MaxUses: 1, MaxAge: time.Minute}
	tests := []struct {
		name string
		dir  string
		edit func(*SystemPoolConfig)
	}{
		{name: "empty runtime dir", dir: ""},
		{name: "size below", edit: func(c *SystemPoolConfig) { c.Size = 0 }},
		{name: "size above", edit: func(c *SystemPoolConfig) { c.Size = 33 }},
		{name: "overflow below", edit: func(c *SystemPoolConfig) { c.MaxOverflow = -1 }},
		{name: "overflow above", edit: func(c *SystemPoolConfig) { c.MaxOverflow = 32 }},
		{name: "capacity above", edit: func(c *SystemPoolConfig) { c.Size, c.MaxOverflow = 2, 31 }},
		{name: "start timeout below", edit: func(c *SystemPoolConfig) { c.StartTimeout = time.Second - 1 }},
		{name: "start timeout above", edit: func(c *SystemPoolConfig) { c.StartTimeout = 60*time.Second + 1 }},
		{name: "max uses below", edit: func(c *SystemPoolConfig) { c.MaxUses = 0 }},
		{name: "max uses above", edit: func(c *SystemPoolConfig) { c.MaxUses = 65537 }},
		{name: "max age below", edit: func(c *SystemPoolConfig) { c.MaxAge = time.Minute - 1 }},
		{name: "max age above", edit: func(c *SystemPoolConfig) { c.MaxAge = 24*time.Hour + 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runtimeDir := tc.dir
			if tc.name != "empty runtime dir" {
				runtimeDir = t.TempDir() + "/must-not-exist"
			}
			cfg := valid
			if tc.edit != nil {
				tc.edit(&cfg)
			}
			runner, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: runtimeDir, Pool: &cfg})
			if err == nil || runner != nil {
				t.Fatalf("runner=%v err=%v, want nil runner and error", runner, err)
			}
			if runtimeDir != "" {
				if _, statErr := os.Stat(runtimeDir); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("invalid constructor created runtime artifact: %v", statErr)
				}
			}
		})
	}
}

func TestNewSystemRunnerPoolDefaultsAndExplicitZeroOverflow(t *testing.T) {
	defaults, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	want := SystemPoolConfig{Size: 1, MaxOverflow: 1, StartTimeout: 15 * time.Second, MaxUses: 256, MaxAge: time.Hour}
	if defaults.poolConfig != want {
		t.Fatalf("defaults=%+v want=%+v", defaults.poolConfig, want)
	}

	explicit := SystemPoolConfig{Size: 1, MaxOverflow: 0, StartTimeout: time.Second, MaxUses: 1, MaxAge: time.Minute}
	runner, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), Pool: &explicit})
	if err != nil {
		t.Fatal(err)
	}
	if runner.poolConfig != explicit {
		t.Fatalf("explicit=%+v want=%+v", runner.poolConfig, explicit)
	}
}

func TestNewSystemRunnerPoolBoundsAreInclusive(t *testing.T) {
	tests := []SystemPoolConfig{
		{Size: 1, MaxOverflow: 0, StartTimeout: time.Second, MaxUses: 1, MaxAge: time.Minute},
		{Size: 1, MaxOverflow: 31, StartTimeout: 60 * time.Second, MaxUses: 65536, MaxAge: 24 * time.Hour},
		{Size: 32, MaxOverflow: 0, StartTimeout: 60 * time.Second, MaxUses: 65536, MaxAge: 24 * time.Hour},
	}
	for _, cfg := range tests {
		runner, err := NewSystemRunner(SystemRunnerOptions{RuntimeDir: t.TempDir(), Pool: &cfg})
		if err != nil {
			t.Fatalf("inclusive config %+v: %v", cfg, err)
		}
		if runner.poolConfig != cfg {
			t.Fatalf("config=%+v want exact %+v", runner.poolConfig, cfg)
		}
	}
}

func TestSystemRunnerPoolSizeTwoPrepareThenActivate(t *testing.T) {
	t.Setenv("LATTICE_TEST_V2_HELPER", "1")
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	bundleDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundleDir, artifactFileName), binary, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded := Loaded{
		Manifest:   Manifest{ID: "p.pool-size-two", Name: "pool size two", Type: TypeSystem, Runtime: &RuntimeSpec{Protocol: RuntimeProtocolStdioJSONV2}},
		BundlePath: bundleDir,
	}
	cfg := SystemPoolConfig{Size: 2, MaxOverflow: 0, StartTimeout: 5 * time.Second, MaxUses: 256, MaxAge: time.Hour}
	runner, err := NewSystemRunner(SystemRunnerOptions{
		RuntimeDir: t.TempDir(), EnvAllowlist: []string{"LATTICE_TEST_V2_HELPER"}, Pool: &cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Prepare(t.Context(), RunnerStartRequest{PluginID: loaded.Manifest.ID, Generation: 1, Loaded: loaded}); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	p := runner.st[loaded.Manifest.ID][1].pool
	runner.mu.Unlock()

	spawnStarted := make(chan struct{})
	allowReady := make(chan struct{})
	secondReady := make(chan struct{})
	p.mu.Lock()
	p.replenishFn = func(ctx context.Context, generation uint64) (*pooledWorker, error) {
		close(spawnStarted)
		select {
		case <-allowReady:
			return &pooledWorker{generation: generation, started: time.Now()}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	p.successFn = func(uint64) { close(secondReady) }
	workers, starting := len(p.workers), p.starting
	p.mu.Unlock()
	if workers != 1 || starting != 0 {
		t.Fatalf("prepared pool workers=%d starting=%d, want 1/0", workers, starting)
	}
	select {
	case <-spawnStarted:
		t.Fatal("prepare replenished to configured size before activation")
	default:
	}

	if err := runner.ActivateGeneration(loaded.Manifest.ID, 1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-spawnStarted:
	case <-time.After(time.Second):
		t.Fatal("activation did not request the second persistent worker")
	}
	close(allowReady)
	select {
	case <-secondReady:
	case <-time.After(time.Second):
		t.Fatal("second persistent worker did not become ready")
	}
	p.mu.Lock()
	workers, starting = len(p.workers), p.starting
	p.mu.Unlock()
	if workers != 2 || starting != 0 {
		t.Fatalf("activated pool workers=%d starting=%d, want 2/0", workers, starting)
	}
	if err := runner.Stop(t.Context(), RunnerStopRequest{PluginID: loaded.Manifest.ID, Generation: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredSystemPoolZeroOverflowDoesNotSpawnForBlockedSecondInvoke(t *testing.T) {
	p := newConfiguredSystemPool(1, 0, 256, time.Hour, 1)
	worker := startReadyTestWorker(t, "LATTICE_TEST_V2_HOST=1", "LATTICE_TEST_V2_STALL=1")
	if err := p.publishTransport(1, worker, time.Now()); err != nil {
		t.Fatal(err)
	}
	var spawnCalls atomic.Int64
	p.replenishFn = func(context.Context, uint64) (*pooledWorker, error) {
		spawnCalls.Add(1)
		return nil, errors.New("unexpected overflow spawn")
	}
	p.activate()

	firstObserved := make(chan struct{})
	firstCtx, cancelFirst := context.WithCancel(t.Context())
	broker := newTestBroker(t, retirementTestPluginID, []string{"log:write"}, HostServices{
		Log: cancelOnLog{seen: firstObserved, cancel: func() {}},
	})
	runner := runnerWithPool(p, broker)
	firstDone := make(chan error, 1)
	go func() {
		_, err := runner.Invoke(firstCtx, InvokeRequest{PluginID: retirementTestPluginID, Generation: 1})
		firstDone <- err
	}()
	select {
	case <-firstObserved:
	case <-time.After(2 * time.Second):
		cancelFirst()
		t.Fatal("first invocation did not occupy the real v2 worker")
	}

	secondCtx, cancelSecond := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelSecond()
	if _, err := runner.Invoke(secondCtx, InvokeRequest{PluginID: retirementTestPluginID, Generation: 1}); !errors.Is(err, context.DeadlineExceeded) {
		cancelFirst()
		t.Fatalf("second invocation error=%v, want deadline exceeded", err)
	}
	if got := spawnCalls.Load(); got != 0 {
		cancelFirst()
		t.Fatalf("zero-overflow waiter spawned %d worker(s)", got)
	}

	p.mu.Lock()
	p.replenishFn = nil
	p.mu.Unlock()
	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first invocation error=%v, want canceled", err)
	}
	p.abortClose(1)
}
