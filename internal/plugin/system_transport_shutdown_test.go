package plugin

import (
	"errors"
	"testing"
)

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
