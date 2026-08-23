package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// collectAuditPage replaced a filter over a materialised copy of the whole
// audit log. These pin what the walk must still produce: an exact count, the
// right window, an exact early stop on a time bound, and an honest answer when
// the scan cap cuts the walk short.

func descendingEvents(n int, action func(int) string) []model.AuditEvent {
	base := time.Unix(1_700_000_000, 0).UTC()
	out := make([]model.AuditEvent, 0, n)
	for i := n - 1; i >= 0; i-- {
		out = append(out, model.AuditEvent{
			ID:       fmt.Sprintf("a%06d", i),
			At:       base.Add(time.Duration(i) * time.Minute),
			Action:   action(i),
			Decision: "allow",
		})
	}
	return out
}

func sliceScan(events []model.AuditEvent) func(func(model.AuditEvent) bool) error {
	return func(visit func(model.AuditEvent) bool) error {
		for _, ev := range events {
			if !visit(ev) {
				return nil
			}
		}
		return nil
	}
}

func everythingVisible(model.AuditEvent) bool { return true }

func TestCollectAuditPageCountsEveryMatchAndReturnsOneWindow(t *testing.T) {
	events := descendingEvents(1000, func(i int) string {
		if i%2 == 0 {
			return "node.update"
		}
		return "task.create"
	})

	page, err := collectAuditPage(sliceScan(events), everythingVisible, auditQuerySpec{action: "node.update", limit: 10, offset: 0})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 500 {
		t.Fatalf("total=%d, want every match counted (500)", page.Total)
	}
	if len(page.Events) != 10 {
		t.Fatalf("returned %d events, want one page of 10", len(page.Events))
	}
	if page.Events[0].ID != "a000998" {
		t.Fatalf("the page must start at the newest match, got %s", page.Events[0].ID)
	}
	if !page.Complete {
		t.Fatal("a walk that reached the end must report a complete count")
	}

	offsetPage, err := collectAuditPage(sliceScan(events), everythingVisible, auditQuerySpec{action: "node.update", limit: 10, offset: 10})
	if err != nil {
		t.Fatal(err)
	}
	if offsetPage.Total != 500 {
		t.Fatalf("offset must not change the total, got %d", offsetPage.Total)
	}
	if offsetPage.Events[0].ID != "a000978" {
		t.Fatalf("offset window starts at %s, want the eleventh match", offsetPage.Events[0].ID)
	}
}

func TestCollectAuditPageStopsAtTheTimeBound(t *testing.T) {
	events := descendingEvents(1000, func(int) string { return "node.update" })
	base := time.Unix(1_700_000_000, 0).UTC()

	visited := 0
	counting := func(visit func(model.AuditEvent) bool) error {
		for _, ev := range events {
			visited++
			if !visit(ev) {
				return nil
			}
		}
		return nil
	}

	page, err := collectAuditPage(counting, everythingVisible, auditQuerySpec{atFrom: base.Add(990 * time.Minute), limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 10 {
		t.Fatalf("total=%d, want the 10 events inside the window", page.Total)
	}
	// The walk is newest-first and the log is in append order, so everything
	// past the bound is older; continuing would be wasted work, not accuracy.
	if visited > 11 {
		t.Fatalf("the walk examined %d records past a bound it could have stopped at", visited)
	}
}

func TestCollectAuditPageSaysWhenItStoppedShort(t *testing.T) {
	events := descendingEvents(auditScanCap+50, func(int) string { return "node.update" })

	page, err := collectAuditPage(sliceScan(events), everythingVisible, auditQuerySpec{limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if page.Complete {
		t.Fatal("a walk cut off by the scan cap must not claim a complete count")
	}
	if page.Scanned != auditScanCap {
		t.Fatalf("scanned=%d, want the cap %d", page.Scanned, auditScanCap)
	}
	if page.Total != auditScanCap {
		t.Fatalf("total=%d, want the matches inside the scanned window", page.Total)
	}
	if len(page.Events) != 5 {
		t.Fatalf("returned %d events, want the requested page of 5", len(page.Events))
	}
}

func TestCollectAuditPageAppliesVisibilityBeforeCounting(t *testing.T) {
	events := descendingEvents(100, func(int) string { return "node.update" })
	for i := range events {
		if i%4 == 0 {
			events[i].NodeID = "visible-node"
		} else {
			events[i].NodeID = "hidden-node"
		}
	}
	visible := func(ev model.AuditEvent) bool { return ev.NodeID == "visible-node" }

	page, err := collectAuditPage(sliceScan(events), visible, auditQuerySpec{limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 25 {
		t.Fatalf("total=%d, want only the events this principal may see", page.Total)
	}
	for _, ev := range page.Events {
		if ev.NodeID != "visible-node" {
			t.Fatalf("a hidden node's event reached the page: %+v", ev)
		}
	}
}
