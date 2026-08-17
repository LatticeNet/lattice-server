package plugin

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
)

func TestTransportTeardownExitClassification(t *testing.T) {
	tests := []struct {
		name string
		code string
		want bool
	}{
		{name: "ordinary exit 7", code: "exit 7", want: false},
		{name: "owned SIGTERM", code: "kill -TERM $$", want: true},
		{name: "owned SIGKILL", code: "kill -KILL $$", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := exec.Command("/bin/sh", "-c", tc.code).Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("command error=%T %v, want *exec.ExitError", err, err)
			}
			if got := isExpectedTransportTeardownExit(err); got != tc.want {
				status, _ := exitErr.Sys().(syscall.WaitStatus)
				t.Fatalf("classification=%v want=%v status=%v", got, tc.want, status)
			}
		})
	}
}

func TestTransportAbortExposesInjectedGroupFailure(t *testing.T) {
	tr := startReadyTestWorker(t)
	injected := errors.New("injected group confirmation failure")
	tr.reapProcessGroupFn = func() error {
		_ = tr.reapProcessGroup()
		return injected
	}
	tr.requestAbort()
	err := tr.waitAbort(t.Context())
	var residual *processGroupResidualError
	if !errors.As(err, &residual) || residual.PGID != tr.pgid || residual.Stage != "group-extinction" || !errors.Is(err, injected) {
		t.Fatalf("abort error=%v residual=%#v", err, residual)
	}
	assertProcessGroupGone(t, tr.pgid)
}
