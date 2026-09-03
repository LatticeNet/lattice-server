package server

import (
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// An operator reading the usage screen needs to tell an attribution that failed
// from one that was never possible. sing-box builds its stats user allowlist by
// name, so a credential with no name has no per-user counter and its bytes stay
// in the inbound total for as long as the config says so: no binding and no
// rediscovery changes that, only naming it on the box does.
//
// On this fleet that is the ordinary case, not an edge. Of 141 credentials
// across 25 nodes, 140 carry no name, and the screen said "line usage, no user"
// for every one of them.
func TestUnattributedLineReasonNamesTheCause(t *testing.T) {
	for _, tc := range []struct {
		name           string
		named, unnamed int
		placed         map[string]string
		want           string
	}{
		{
			name: "a node that reports nothing says nothing",
			want: "line usage, no user",
		},
		{
			name:    "one unnamed credential is uncountable, not unattributed",
			unnamed: 1,
			want: "line usage, no user; 1 credential on this line carries no name, " +
				"so the node cannot count them individually",
		},
		{
			name:    "several read as a sentence too",
			unnamed: 3,
			want: "line usage, no user; 3 credentials on this line carry no name, " +
				"so the node cannot count them individually",
		},
		{
			name:  "a mixed line says the unnamed part is only in the line total",
			named: 1, unnamed: 2, placed: map[string]string{"u_1111111111111111": "vpnuser_a"},
			want: "line usage, no user; 2 credentials on this line carry no name and " +
				"are counted only in the line total",
		},
		{
			name:  "a named credential the server cannot place is the opposite problem",
			named: 1,
			want: "line usage, no user; 1 named credential on this line resolves to " +
				"no identity the server knows",
		},
		{
			name:  "several unplaceable names agree with the verb",
			named: 2,
			want: "line usage, no user; 2 named credentials on this line resolve to " +
				"no identity the server knows",
		},
		{
			name:  "every name placed, so the failure is elsewhere and nothing is claimed",
			named: 1, placed: map[string]string{"u_1111111111111111": "vpnuser_a"},
			want: "line usage, no user",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &usageLineFacts{
				Line:  Line{NamedUsers: tc.named, UnnamedUsers: tc.unnamed},
				Named: tc.placed,
			}
			if got := unattributedLineReason(f); got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// The reason reaches the wire, and only on the rows where no rule fired. A row
// a rule did claim keeps that rule's own reason.
func TestUnattributedReasonReachesTheUsageRow(t *testing.T) {
	ctx := &usageAttributionContext{nodeName: map[string]string{}, users: map[string]VpnUser{}}
	unnamed := &usageLineFacts{
		Line:  Line{LineHashID: "line_1", NamedUsers: 0, UnnamedUsers: 2},
		Named: map[string]string{}, Role: usageRoleDirect,
	}
	rows := ctx.attributeLine("n1", "in-x", unnamed, usageLineTraffic{Inbound: usageCounter{Uplink: 10, Downlink: 20}})
	if len(rows) != 1 || rows[0].Attribution != usageAttributionNone {
		t.Fatalf("rows: %+v", rows)
	}
	if !strings.Contains(rows[0].AttributionReason, "carry no name") {
		t.Fatalf("reason = %q, want the uncountable-credential cause", rows[0].AttributionReason)
	}

	// A bound line is attributed by the binding rule, so its reason is that
	// rule's and the credential-naming note has no business overwriting it.
	bound := &usageLineFacts{
		Line:  Line{LineHashID: "line_2", UnnamedUsers: 2},
		Named: map[string]string{}, Bound: []string{"vpnuser_a"}, Role: usageRoleDirect,
	}
	rows = ctx.attributeLine("n1", "in-y", bound, usageLineTraffic{Inbound: usageCounter{Uplink: 10, Downlink: 20}})
	if len(rows) != 1 || rows[0].Attribution != usageAttributionBinding {
		t.Fatalf("rows: %+v", rows)
	}
	if rows[0].AttributionReason != "only enabled binding on this line" {
		t.Fatalf("the binding rule lost its own reason: %q", rows[0].AttributionReason)
	}
}

// Whatever a node reports, a value the server cannot read leaves the line
// saying nothing about its credentials rather than putting a wrong number on an
// operator's screen.
func TestDiscoveredUserNamingRejectsUnreadableReports(t *testing.T) {
	for _, tc := range []struct {
		name, named, unnamed string
		wantNamed, wantUn    int
	}{
		{"absent", "", "", 0, 0},
		{"plain counts", "1", "2", 1, 2},
		{"whitespace tolerated", " 1 ", " 2 ", 1, 2},
		{"not a number", "many", "2", 0, 2},
		{"negative", "-1", "2", 0, 2},
		{"absurd", "999999999", "2", 0, 2},
		{"float", "1.5", "2", 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			named, unnamed := discoveredUserNaming(model.SingBoxNode{Metadata: map[string]string{
				singBoxNamedUsersKey: tc.named, singBoxUnnamedUsersKey: tc.unnamed,
			}})
			if named != tc.wantNamed || unnamed != tc.wantUn {
				t.Fatalf("got %d/%d, want %d/%d", named, unnamed, tc.wantNamed, tc.wantUn)
			}
		})
	}
}

// End to end from the node's report to the row an operator reads.
func TestUnattributedReasonFromAReportedNode(t *testing.T) {
	srv := usageTestServer(t, time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))
	if err := srv.store.UpsertNode(model.Node{ID: "node-a", Name: "Node A", PublicIP: "203.0.113.5"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{ID: "prof-a", NodeID: "node-a", Core: "sing-box"}); err != nil {
		t.Fatal(err)
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"node-a": {NodeID: "node-a", At: srv.now(), Status: "ok", Nodes: []model.SingBoxNode{
			{Name: "legacy.json", Protocol: "vless", Network: "tcp", Address: "203.0.113.5", Port: "443",
				OutboundRef: "direct", Metadata: map[string]string{
					singBoxNamedUsersKey: "0", singBoxUnnamedUsersKey: "1",
				}},
		}},
	}
	srv.singboxInvMu.Unlock()
	groups := srv.buildLineGroups()
	ln := findLine(t, groups, "node-a", "legacy.json")
	if ln.NamedUsers != 0 || ln.UnnamedUsers != 1 {
		t.Fatalf("line naming counts = %d/%d, want 0/1", ln.NamedUsers, ln.UnnamedUsers)
	}
	ctx := srv.usageAttributionContext()
	rows := ctx.attributeLine("node-a", "legacy.json", ctx.byNodeTag["node-a"]["legacy.json"],
		usageLineTraffic{Inbound: usageCounter{Uplink: 100, Downlink: 200}})
	if len(rows) != 1 || !strings.Contains(rows[0].AttributionReason, "cannot count them individually") {
		t.Fatalf("row: %+v", rows)
	}
}

// A line can carry both an unnamed credential and a named one that resolves to
// nothing. Reported by a switch returning on first match, only the unnamed note
// appeared, and that is the less actionable of the two: an unnamed credential
// is a permanent property of the config, while a named credential the server
// cannot place means a real counter is being discarded.
//
// The defect is not the missing clause. It is that the clause shown reads as a
// complete explanation, so an operator addresses it and stops looking.
func TestUnattributedReasonReportsBothCausesWhenBothApply(t *testing.T) {
	f := &usageLineFacts{Line: Line{NamedUsers: 2, UnnamedUsers: 1}, Named: map[string]string{}}
	got := unattributedLineReason(f)

	if !strings.Contains(got, "carries no name") {
		t.Errorf("the unnamed-credential cause is missing: %q", got)
	}
	if !strings.Contains(got, "resolve to no identity the server knows") {
		t.Errorf("the named-but-unresolved cause is missing, which is the actionable one: %q", got)
	}
	// Subject-verb agreement holds independently on each clause: one unnamed
	// credential and two named ones, so "carries" and "resolve".
	if strings.Contains(got, "1 credentials") || strings.Contains(got, "2 named credential ") {
		t.Errorf("agreement is wrong on a combined reason: %q", got)
	}
}

// The single-cause reasons must not gain a stray separator or a second clause
// now that they are assembled rather than returned whole.
func TestUnattributedReasonKeepsSingleCauseWordingIntact(t *testing.T) {
	onlyUnnamed := unattributedLineReason(&usageLineFacts{Line: Line{UnnamedUsers: 2}, Named: map[string]string{}})
	if want := "line usage, no user; 2 credentials on this line carry no name, so the node cannot count them individually"; onlyUnnamed != want {
		t.Errorf("unnamed-only reason changed:\n got %q\nwant %q", onlyUnnamed, want)
	}
	onlyUnresolved := unattributedLineReason(&usageLineFacts{Line: Line{NamedUsers: 1}, Named: map[string]string{}})
	if want := "line usage, no user; 1 named credential on this line resolves to no identity the server knows"; onlyUnresolved != want {
		t.Errorf("unresolved-only reason changed:\n got %q\nwant %q", onlyUnresolved, want)
	}
	if bare := unattributedLineReason(&usageLineFacts{Line: Line{}, Named: map[string]string{}}); bare != "line usage, no user" {
		t.Errorf("the bare reason gained a separator: %q", bare)
	}
}
