package server

import (
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// The degraded rule at every boundary D13 names: the baseline gate at 23 and
// 24 hours, the probe floor at 29 and 30, the latency floor at 4 and 5 runs,
// strict comparison at exactly each trigger, each threshold just under and
// just over, and a check's own thresholds over the defaults.
func TestJudgeDegradedAtEveryBoundary(t *testing.T) {
	def := model.MonitorDegradedRule{}
	ready := degradedBaseline{hours: 24, loss: 0, hasLoss: true, p50: 40, hasP50: true}
	quietWindow := degradedWindow{probes: 300, lost: 0, runs: 15, p50: 40, hasP50: true}
	for _, tc := range []struct {
		name   string
		rule   model.MonitorDegradedRule
		base   degradedBaseline
		win    degradedWindow
		reason string
	}{
		{"healthy", def, ready, quietWindow, ""},
		// The gate: 23 hours never judge, however bad the window.
		{"gate 23 hours", def, degradedBaseline{hours: 23, hasLoss: true, p50: 40, hasP50: true},
			degradedWindow{probes: 300, lost: 150, runs: 15, p50: 400, hasP50: true}, ""},
		{"gate 24 hours", def, ready, degradedWindow{probes: 300, lost: 150, runs: 15, p50: 400, hasP50: true}, model.PathReasonDegradedLossLatency},
		// The probe floor guards the loss ratio.
		{"29 probes", def, ready, degradedWindow{probes: 29, lost: 10, runs: 15, p50: 40, hasP50: true}, ""},
		{"30 probes", def, ready, degradedWindow{probes: 30, lost: 10, runs: 15, p50: 40, hasP50: true}, model.PathReasonDegradedLoss},
		// The loss floor (loss_percent): base loss 0, trigger 2 percent.
		{"loss exactly at the floor", def, ready, degradedWindow{probes: 300, lost: 6, runs: 15, p50: 40, hasP50: true}, ""},
		{"loss just over the floor", def, ready, degradedWindow{probes: 300, lost: 7, runs: 15, p50: 40, hasP50: true}, model.PathReasonDegradedLoss},
		// The loss factor: base loss 5 percent, trigger 10 percent.
		{"loss exactly at the factor", def, degradedBaseline{hours: 30, loss: 0.05, hasLoss: true, p50: 40, hasP50: true},
			degradedWindow{probes: 300, lost: 30, runs: 15, p50: 40, hasP50: true}, ""},
		{"loss just over the factor", def, degradedBaseline{hours: 30, loss: 0.05, hasLoss: true, p50: 40, hasP50: true},
			degradedWindow{probes: 300, lost: 31, runs: 15, p50: 40, hasP50: true}, model.PathReasonDegradedLoss},
		// The latency factor: base 100 ms, trigger 200 ms (over 100 + 30).
		{"p50 exactly at the factor", def, degradedBaseline{hours: 24, hasLoss: true, p50: 100, hasP50: true},
			degradedWindow{probes: 300, runs: 15, p50: 200, hasP50: true}, ""},
		{"p50 just over the factor", def, degradedBaseline{hours: 24, hasLoss: true, p50: 100, hasP50: true},
			degradedWindow{probes: 300, runs: 15, p50: 200.01, hasP50: true}, model.PathReasonDegradedLatency},
		// The latency margin: base 20 ms, trigger 50 ms (over 2 x 20).
		{"p50 exactly at the margin", def, degradedBaseline{hours: 24, hasLoss: true, p50: 20, hasP50: true},
			degradedWindow{probes: 300, runs: 15, p50: 50, hasP50: true}, ""},
		{"p50 just over the margin", def, degradedBaseline{hours: 24, hasLoss: true, p50: 20, hasP50: true},
			degradedWindow{probes: 300, runs: 15, p50: 50.01, hasP50: true}, model.PathReasonDegradedLatency},
		// The latency floor.
		{"4 runs", def, ready, degradedWindow{probes: 300, runs: 4, p50: 400, hasP50: true}, ""},
		{"5 runs", def, ready, degradedWindow{probes: 300, runs: 5, p50: 400, hasP50: true}, model.PathReasonDegradedLatency},
		// No baseline median, no latency arm.
		{"no baseline median", def, degradedBaseline{hours: 24, loss: 1, hasLoss: true},
			degradedWindow{probes: 300, lost: 299, runs: 15, p50: 400, hasP50: true}, ""},
		// A check's own thresholds win over the defaults.
		{"custom loss floor holds", model.MonitorDegradedRule{LossPercent: 5}, ready,
			degradedWindow{probes: 300, lost: 12, runs: 15, p50: 40, hasP50: true}, ""},
		{"custom loss floor passed", model.MonitorDegradedRule{LossPercent: 5}, ready,
			degradedWindow{probes: 300, lost: 16, runs: 15, p50: 40, hasP50: true}, model.PathReasonDegradedLoss},
		{"custom margin holds", model.MonitorDegradedRule{LatencyMarginMs: 100}, ready,
			degradedWindow{probes: 300, runs: 15, p50: 120, hasP50: true}, ""},
		{"custom margin passed", model.MonitorDegradedRule{LatencyMarginMs: 100}, ready,
			degradedWindow{probes: 300, runs: 15, p50: 141, hasP50: true}, model.PathReasonDegradedLatency},
		{"custom factors", model.MonitorDegradedRule{LossFactor: 4, LatencyFactor: 5}, degradedBaseline{hours: 24, loss: 0.05, hasLoss: true, p50: 40, hasP50: true},
			degradedWindow{probes: 300, lost: 59, runs: 15, p50: 199, hasP50: true}, ""},
	} {
		found, reason, loss, latency := judgeDegraded(tc.rule, tc.base, tc.win)
		if reason != tc.reason || found != (tc.reason != "") {
			t.Errorf("%s: found %v reason %q, want %q", tc.name, found, reason, tc.reason)
			continue
		}
		if (loss != nil) != (tc.reason == model.PathReasonDegradedLoss || tc.reason == model.PathReasonDegradedLossLatency) {
			t.Errorf("%s: loss evidence %+v", tc.name, loss)
		}
		if (latency != nil) != (tc.reason == model.PathReasonDegradedLatency || tc.reason == model.PathReasonDegradedLossLatency) {
			t.Errorf("%s: latency evidence %+v", tc.name, latency)
		}
	}
	// The evidence carries the figures the trigger was judged on, rounded as
	// the matrix rounds.
	_, _, loss, latency := judgeDegraded(def, degradedBaseline{hours: 100, loss: 0.004, hasLoss: true, p50: 64.04, hasP50: true},
		degradedWindow{probes: 290, lost: 12, runs: 14, p50: 180.06, hasP50: true})
	if loss == nil || loss.Value != 0.0414 || loss.Baseline != 0.004 || loss.Trigger != 0.02 || loss.Sent != 290 || loss.Lost != 12 {
		t.Fatalf("loss evidence = %+v", loss)
	}
	if latency == nil || latency.P50Ms != 180.1 || latency.BaselineMs != 64 || latency.TriggerMs != 128.1 || latency.Runs != 14 {
		t.Fatalf("latency evidence = %+v", latency)
	}
}

// One evaluation per row, a minute apart unless the row says otherwise.
type degradedStepRow struct {
	at    time.Duration
	found bool
	quiet bool
	// want is the entry afterwards: "", "pending", "degraded" or
	// "clearing"; step the store write it caused.
	want string
	step pathDegradedStep
}

func runDegradedSteps(t *testing.T, name string, rows []degradedStepRow) *pathDegradedEntry {
	t.Helper()
	base := time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)
	var e *pathDegradedEntry
	for i, row := range rows {
		now := base.Add(row.at)
		reason := ""
		if row.found {
			reason = model.PathReasonDegradedLoss
		}
		next, step := stepPathDegraded(e, row.found, reason, nil, nil, row.quiet, now)
		got := ""
		switch {
		case next == nil:
		case next.pending:
			got = "pending"
		case next.rec.Clearing():
			got = "clearing"
		default:
			got = "degraded"
		}
		if got != row.want || step != row.step {
			t.Fatalf("%s row %d (+%s, found %v): entry %q step %d, want %q step %d", name, i, row.at, row.found, got, step, row.want, row.step)
		}
		e = next
	}
	return e
}

// The record table of D13: two consecutive findings enter, ten minutes
// without the condition leave, a finding while clearing cancels it, and a
// late tick does not reset a pending entry.
func TestStepPathDegradedTable(t *testing.T) {
	m := time.Minute
	e := runDegradedSteps(t, "enter on the second", []degradedStepRow{
		{0, true, false, "pending", stepNone},
		{m, true, false, "degraded", stepEnter},
		{2 * m, true, false, "degraded", stepNone},
	})
	if want := time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC); !e.rec.Since.Equal(want) || !e.rec.EnteredAt.Equal(want.Add(m)) || !e.rec.EvaluatedAt.Equal(want.Add(2*m)) {
		t.Fatalf("since %s entered %s evaluated %s", e.rec.Since, e.rec.EnteredAt, e.rec.EvaluatedAt)
	}
	runDegradedSteps(t, "one finding is not enough", []degradedStepRow{
		{0, true, false, "pending", stepNone},
		{m, false, false, "", stepNone},
		{2 * m, true, false, "pending", stepNone},
		{3 * m, false, false, "", stepNone},
	})
	runDegradedSteps(t, "a late tick still counts", []degradedStepRow{
		{0, true, false, "pending", stepNone},
		{7 * m, true, false, "degraded", stepEnter},
	})
	runDegradedSteps(t, "leave after ten minutes absent", []degradedStepRow{
		{0, true, false, "pending", stepNone},
		{m, true, false, "degraded", stepEnter},
		{2 * m, false, false, "clearing", stepStartClearing},
		{3 * m, false, false, "clearing", stepNone},
		{11*m + 59*time.Second, false, false, "clearing", stepNone},
		{12 * m, false, false, "", stepLeave},
	})
	e = runDegradedSteps(t, "a finding during clearing cancels it", []degradedStepRow{
		{0, true, false, "pending", stepNone},
		{m, true, false, "degraded", stepEnter},
		{2 * m, false, false, "clearing", stepStartClearing},
		{9 * m, true, false, "degraded", stepStopClearing},
		{10 * m, false, false, "clearing", stepStartClearing},
		{19 * m, false, false, "clearing", stepNone},
		{20 * m, false, false, "", stepLeave},
	})
	if e != nil {
		t.Fatalf("left entry = %+v", e)
	}
	// Flapping input: alternating findings never enter, and once degraded
	// they keep it from ever leaving, at two writes per round.
	var flap []degradedStepRow
	for i := 0; i < 10; i++ {
		want := "pending"
		if i%2 == 1 {
			want = ""
		}
		flap = append(flap, degradedStepRow{time.Duration(i) * m, i%2 == 0, false, want, stepNone})
	}
	runDegradedSteps(t, "flapping before entering", flap)
	flap = []degradedStepRow{{0, true, false, "pending", stepNone}, {m, true, false, "degraded", stepEnter}}
	for i := 2; i < 40; i++ {
		row := degradedStepRow{time.Duration(i) * m, false, false, "clearing", stepStartClearing}
		if i%2 == 1 {
			row = degradedStepRow{time.Duration(i) * m, true, false, "degraded", stepStopClearing}
		}
		flap = append(flap, row)
	}
	runDegradedSteps(t, "flapping once degraded", flap)
	// Quiet is decided when the entry enters, and kept.
	e = runDegradedSteps(t, "quiet at entry", []degradedStepRow{
		{0, true, false, "pending", stepNone},
		{m, true, true, "degraded", stepEnter},
		{2 * m, true, false, "degraded", stepNone},
	})
	if !e.rec.Quiet {
		t.Fatal("an entry that entered while the path read down must stay quiet")
	}
}

func TestDegradedMessages(t *testing.T) {
	since := time.Date(2026, 10, 16, 14, 2, 0, 0, time.UTC)
	rec := degradedRecordForTest(since)
	msg := pathDegradedMessage("cd-hs-sh to tyo-3", rec)
	if msg.title != "Path degraded: cd-hs-sh to tyo-3" ||
		msg.detail != "Loss 4.2% over the last hour (12 of 290 probes), above its trigger of 2% (7-day loss 0.4%). Degraded since 14:02 UTC." ||
		msg.line != "cd-hs-sh to tyo-3: loss 4.2% (usual 0.4%)" {
		t.Fatalf("open message = %+v", msg)
	}
	rec.ClearSince = since.Add(68 * time.Minute)
	rec.Latency = &model.PathLatencyEvidence{P50Ms: 180, Runs: 14, BaselineMs: 64, TriggerMs: 128}
	msg = pathDegradedMessage("ssh on cd-hs-sh", rec)
	if msg.line != "ssh on cd-hs-sh: loss 4.2% (usual 0.4%), median 180 ms (usual 64 ms)" {
		t.Fatalf("both arms line = %q", msg.line)
	}
	rcv := pathRecoveredMessage("cd-hs-sh to tyo-3", pathDegradedEntry{rec: rec})
	if rcv.title != "Path recovered: cd-hs-sh to tyo-3" || rcv.detail != "Back to its usual level since 15:10 UTC after 1 h 8 min degraded." {
		t.Fatalf("recovery = %+v", rcv)
	}
	for d, want := range map[time.Duration]string{30 * time.Second: "under a minute", 45 * time.Minute: "45 min", 2 * time.Hour: "2 h", 68 * time.Minute: "1 h 8 min"} {
		if got := formatDegradedSpan(d); got != want {
			t.Errorf("span %s = %q, want %q", d, got, want)
		}
	}
}

// degradedRecordForTest is a degraded record whose loss arm held.
func degradedRecordForTest(since time.Time) store.PathDegradedRecord {
	return store.PathDegradedRecord{Since: since, EnteredAt: since.Add(time.Minute), Reason: model.PathReasonDegradedLoss, EvaluatedAt: since.Add(time.Minute),
		Loss: &model.PathLossEvidence{Value: 0.042, Baseline: 0.004, Trigger: 0.02, Sent: 290, Lost: 12}}
}
