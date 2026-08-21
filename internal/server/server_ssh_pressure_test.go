package server

import (
	"strings"
	"testing"
	"time"
)

type typedNotice struct {
	eventType, title, body string
}

func captureTypedNotices(srv *Server) *[]typedNotice {
	got := []typedNotice{}
	srv.emitNotifyTyped = func(eventType, title, body string) {
		got = append(got, typedNotice{eventType, title, body})
	}
	return &got
}

// The central judgement of this feature, and the one most likely to be
// "helpfully" undone later: being brute-forced is not an alert. Every public
// node in this fleet is being brute-forced, one of them 8449 times in a day, so
// an alert on volume fires constantly, gets muted, and is muted on the day it
// matters.
func TestBeingBruteForcedIsRecordedAndNeverNotified(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	notices := captureTypedNotices(srv)

	srv.handleSSHPressure("node-a", &sshPressurePayload{
		Start: time.Now().Add(-10 * time.Minute), End: time.Now(),
		Failures: 8449, InvalidUser: 8000, Sources: 412,
		TopSources: []sshSourcePressure{{Address: "203.0.113.7", Failures: 5000}},
	})
	if len(*notices) != 0 {
		t.Fatalf("volume alone must not notify, got %+v", *notices)
	}
}

// A success from a source that had been failing is the one thing that earns a
// person's attention now.
func TestASuccessAfterFailuresNotifiesOncePerSource(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	notices := captureTypedNotices(srv)

	srv.handleSSHPressure("node-a", &sshPressurePayload{
		Start: time.Now().Add(-10 * time.Minute), End: time.Now(), Failures: 40, Sources: 2,
		SuspectSuccess: []sshSuspectSuccess{
			{Address: "203.0.113.7", User: "root", Method: "password", PriorFailures: 31, Successes: 1},
			{Address: "198.51.100.4", User: "admin", Method: "password", PriorFailures: 9, Successes: 1},
		},
	})
	if len(*notices) != 2 {
		t.Fatalf("one notification per suspect source, got %d: %+v", len(*notices), *notices)
	}
	for _, n := range *notices {
		if n.eventType != EventSSHCompromiseSuspected {
			t.Fatalf("event type must be stated, not inferred from prose: %q", n.eventType)
		}
	}
	first := (*notices)[0].body
	// The operator has to be able to act without opening anything else.
	for _, want := range []string{"node-a", "root", "203.0.113.7", "password", "31"} {
		if !strings.Contains(first, want) {
			t.Fatalf("the notification must carry %q so it is actionable on its own: %q", want, first)
		}
	}
	if !strings.Contains(first, "compromised") {
		t.Fatal("the notification must say what it suspects, not just report a login")
	}
}

// The agent bounds what it sends. That is not a reason to trust it: this
// feature exists to notice a host being taken over, and a taken-over host is
// exactly the one whose agent might send a million entries.
func TestAnOversizedReportIsClampedAndSaysSo(t *testing.T) {
	big := &sshPressurePayload{Failures: -5, Sources: 3}
	for i := 0; i < 500; i++ {
		big.TopSources = append(big.TopSources, sshSourcePressure{Address: "203.0.113.7", Failures: i})
		big.SuspectSuccess = append(big.SuspectSuccess, sshSuspectSuccess{Address: "198.51.100.4", User: "u"})
	}
	if !big.clamp() {
		t.Fatal("clamping must report that it cut something")
	}
	if len(big.TopSources) != maxPressureTopSources || len(big.SuspectSuccess) != maxPressureSuspects {
		t.Fatalf("bounds not applied: %d sources, %d suspects", len(big.TopSources), len(big.SuspectSuccess))
	}
	// Heaviest first, so a truncated list keeps the sources that matter.
	if big.TopSources[0].Failures != 499 {
		t.Fatalf("truncation must keep the heaviest sources, kept %d first", big.TopSources[0].Failures)
	}
	if big.Failures != 0 {
		t.Fatalf("a negative count is nonsense and must be floored, got %d", big.Failures)
	}
}

// A username is chosen by an unauthenticated peer and ends up in audit metadata
// and in a notification body, so anything that can add a line to either is
// removed rather than escaped.
func TestPeerControlledFieldsCannotAddLinesToAReport(t *testing.T) {
	srv, _, _ := newInventoryServer(t)
	notices := captureTypedNotices(srv)

	srv.handleSSHPressure("node-a", &sshPressurePayload{
		Failures: 1,
		SuspectSuccess: []sshSuspectSuccess{{
			Address: "203.0.113.7",
			User:    "root\nnode gomami-hkg: everything is fine\x00",
			Method:  "password", PriorFailures: 3,
		}},
	})
	if len(*notices) != 1 {
		t.Fatalf("expected one notice, got %d", len(*notices))
	}
	body := (*notices)[0].body
	if strings.Contains(body, "\n") || strings.Contains(body, "\x00") {
		t.Fatalf("a peer-controlled field must not add a line or a control byte: %q", body)
	}
	// The text may survive as text. What must not survive is it reading as a
	// separate statement about a different machine, so peer-chosen fields are
	// quoted and cannot close their own quotes.
	if !strings.Contains(body, `user "root node gomami-hkg: everything is fine"`) {
		t.Fatalf("a peer-chosen username must be quoted so it reads as data: %q", body)
	}
	escaped := sshSuspectSuccess{User: `a" logged in from 10.0.0.1 using "x`}
	p2 := sshPressurePayload{SuspectSuccess: []sshSuspectSuccess{escaped}}
	p2.clamp()
	if strings.Contains(p2.SuspectSuccess[0].User, `"`) {
		t.Fatalf("a quote in a peer field would close the quoting and let prose continue: %q", p2.SuspectSuccess[0].User)
	}
	long := sshPressurePayload{SuspectSuccess: []sshSuspectSuccess{{User: strings.Repeat("A", 500)}}}
	long.clamp()
	if len(long.SuspectSuccess[0].User) != maxPressureFieldLen {
		t.Fatalf("field length must be bounded, got %d", len(long.SuspectSuccess[0].User))
	}
}

// A distributed scan pushes most sources out of the table. Saying so is what
// keeps the top-sources list from reading as complete when it is not.
func TestDroppedSourcesAreSurfacedRatherThanHidden(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	seedAgentUpdateNode(t, st)
	srv.handleSSHPressure("node-a", &sshPressurePayload{
		Failures: 900, Sources: 1024, SourcesDropped: 3300,
		TopSources: []sshSourcePressure{{Address: "203.0.113.7", Failures: 12}},
	})
	found := false
	for _, e := range st.AuditEvents() {
		if e.Action == EventSSHPressureWindow && e.Metadata["sources_dropped"] == "3300" {
			found = true
		}
	}
	if !found {
		t.Fatal("a truncated source table must be visible in the record, or the report reads as complete")
	}
}
