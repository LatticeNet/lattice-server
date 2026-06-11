package audit

import (
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

type Sink interface {
	AppendAudit(model.AuditEvent) error
}

func Record(s Sink, ev model.AuditEvent) error {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	if ev.Decision == "" {
		ev.Decision = "allow"
	}
	return s.AppendAudit(ev)
}
