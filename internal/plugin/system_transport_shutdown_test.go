package plugin

import (
	"errors"
	"os"
	"testing"
)

func TestTransportAbortSuppressesOnlyOwnedSignals(t *testing.T) {
	tests := []struct {
		name     string
		flags    []string
		prewait  bool
		wantErr  bool
		wantKill bool
	}{
		{name: "ordinary exit 7", flags: []string{"LATTICE_TEST_V2_EXIT_AFTER_READY_CODE=7"}, prewait: true, wantErr: true},
		{name: "self SIGTERM", flags: []string{"LATTICE_TEST_V2_EXIT_AFTER_READY_SIGNAL=TERM"}, prewait: true, wantErr: true},
		{name: "owned SIGTERM"},
		{name: "owned SIGKILL", flags: []string{"LATTICE_TEST_V2_IGNORE_TERM=1"}, wantKill: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := append(os.Environ(), "LATTICE_TEST_V2_HELPER=1")
			env = append(env, tc.flags...)
			tr, err := startSystemWorker(t.Context(), os.Args[0], t.TempDir(), env)
			if err != nil {
				t.Fatal(err)
			}
			if err := tr.awaitReadyContext(t.Context(), 1); err != nil {
				t.Fatal(err)
			}
			if tc.prewait {
				<-tr.waitDone
			}
			tr.requestAbort()
			err = tr.waitAbort(t.Context())
			if (err != nil) != tc.wantErr {
				t.Fatalf("abort error=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantKill && !tr.ownedKill {
				t.Fatal("owned SIGKILL escalation was not recorded")
			}
			assertProcessGroupGone(t, tr.pgid)
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
