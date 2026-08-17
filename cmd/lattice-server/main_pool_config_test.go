package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/plugin"
)

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestParsePluginRuntimePoolConfigDefaultsEnvAndFlagPrecedence(t *testing.T) {
	defaults := plugin.SystemPoolConfig{Size: 1, MaxOverflow: 1, StartTimeout: 15 * time.Second, MaxUses: 256, MaxAge: time.Hour}
	cfg, err := parsePluginRuntimePoolConfig(nil, mapLookup(nil))
	if err != nil || !reflect.DeepEqual(cfg, defaults) {
		t.Fatalf("defaults=%+v err=%v want=%+v", cfg, err, defaults)
	}

	env := map[string]string{
		"LATTICE_PLUGIN_RUNTIME_POOL_SIZE":            "3",
		"LATTICE_PLUGIN_RUNTIME_POOL_MAX_OVERFLOW":    "0",
		"LATTICE_PLUGIN_RUNTIME_WORKER_START_TIMEOUT": "20s",
		"LATTICE_PLUGIN_RUNTIME_WORKER_MAX_USES":      "400",
		"LATTICE_PLUGIN_RUNTIME_WORKER_MAX_AGE":       "2h",
	}
	cfg, err = parsePluginRuntimePoolConfig(nil, mapLookup(env))
	wantEnv := plugin.SystemPoolConfig{Size: 3, MaxOverflow: 0, StartTimeout: 20 * time.Second, MaxUses: 400, MaxAge: 2 * time.Hour}
	if err != nil || !reflect.DeepEqual(cfg, wantEnv) {
		t.Fatalf("env=%+v err=%v want=%+v", cfg, err, wantEnv)
	}

	args := []string{"-plugin-runtime-pool-size=4", "-plugin-runtime-pool-max-overflow=0", "-plugin-runtime-worker-start-timeout=30s", "-plugin-runtime-worker-max-uses=500", "-plugin-runtime-worker-max-age=3h"}
	cfg, err = parsePluginRuntimePoolConfig(args, mapLookup(env))
	wantFlags := plugin.SystemPoolConfig{Size: 4, MaxOverflow: 0, StartTimeout: 30 * time.Second, MaxUses: 500, MaxAge: 3 * time.Hour}
	if err != nil || !reflect.DeepEqual(cfg, wantFlags) {
		t.Fatalf("flags=%+v err=%v want=%+v", cfg, err, wantFlags)
	}
}

func TestParsePluginRuntimePoolConfigRejectsMalformedAndOutOfRange(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{name: "malformed env int", env: map[string]string{"LATTICE_PLUGIN_RUNTIME_POOL_SIZE": "many"}},
		{name: "empty env int", env: map[string]string{"LATTICE_PLUGIN_RUNTIME_POOL_SIZE": ""}},
		{name: "malformed env duration", env: map[string]string{"LATTICE_PLUGIN_RUNTIME_WORKER_MAX_AGE": "later"}},
		{name: "empty env duration", env: map[string]string{"LATTICE_PLUGIN_RUNTIME_WORKER_MAX_AGE": ""}},
		{name: "malformed flag int", args: []string{"-plugin-runtime-pool-size=many"}},
		{name: "malformed flag duration", args: []string{"-plugin-runtime-worker-start-timeout=later"}},
		{name: "size out of range", args: []string{"-plugin-runtime-pool-size=0"}},
		{name: "overflow out of range", args: []string{"-plugin-runtime-pool-max-overflow=-1"}},
		{name: "capacity out of range", args: []string{"-plugin-runtime-pool-size=32", "-plugin-runtime-pool-max-overflow=1"}},
		{name: "timeout out of range", args: []string{"-plugin-runtime-worker-start-timeout=999ms"}},
		{name: "uses out of range", args: []string{"-plugin-runtime-worker-max-uses=65537"}},
		{name: "age out of range", args: []string{"-plugin-runtime-worker-max-age=25h"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePluginRuntimePoolConfig(tc.args, mapLookup(tc.env)); err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatalf("args=%v env=%v error=%v", tc.args, tc.env, err)
			}
		})
	}
}

func TestParsePluginRuntimePoolConfigAcceptsInclusiveBounds(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want plugin.SystemPoolConfig
	}{
		{
			name: "minimum",
			args: []string{"-plugin-runtime-pool-size=1", "-plugin-runtime-pool-max-overflow=0", "-plugin-runtime-worker-start-timeout=1s", "-plugin-runtime-worker-max-uses=1", "-plugin-runtime-worker-max-age=1m"},
			want: plugin.SystemPoolConfig{Size: 1, MaxOverflow: 0, StartTimeout: time.Second, MaxUses: 1, MaxAge: time.Minute},
		},
		{
			name: "maximum capacity via overflow",
			args: []string{"-plugin-runtime-pool-size=1", "-plugin-runtime-pool-max-overflow=31", "-plugin-runtime-worker-start-timeout=60s", "-plugin-runtime-worker-max-uses=65536", "-plugin-runtime-worker-max-age=24h"},
			want: plugin.SystemPoolConfig{Size: 1, MaxOverflow: 31, StartTimeout: 60 * time.Second, MaxUses: 65536, MaxAge: 24 * time.Hour},
		},
		{
			name: "maximum primary",
			args: []string{"-plugin-runtime-pool-size=32", "-plugin-runtime-pool-max-overflow=0", "-plugin-runtime-worker-start-timeout=60s", "-plugin-runtime-worker-max-uses=65536", "-plugin-runtime-worker-max-age=24h"},
			want: plugin.SystemPoolConfig{Size: 32, MaxOverflow: 0, StartTimeout: 60 * time.Second, MaxUses: 65536, MaxAge: 24 * time.Hour},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePluginRuntimePoolConfig(tc.args, mapLookup(nil))
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("config=%+v err=%v want=%+v", got, err, tc.want)
			}
		})
	}
}
