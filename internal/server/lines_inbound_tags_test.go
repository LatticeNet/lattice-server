package server

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The shape this suite is built from was read off a production node
// (dmit-eb-wee). Every conf file in /etc/sing-box/conf follows the helper
// script's convention that the inbound tag is the file name, except one
// hand-written file that holds a relay pair: two inbounds whose tags are
// neither the file name nor each other, forwarding to a second node.
//
// sing-box keys its stats counters and its connection log by the inbound tags
// it actually loaded, so that file's traffic arrives under two tags no part of
// the read model had ever seen.
const (
	relayFile    = "VLESS-REALITY-17893.json"
	relayVLESS   = "inbound-for-aaitr-frontier-nat-vless-7899"
	relayHy2     = "inbound-for-aaitr-frontier-nat-hy2-7898"
	relayTagsRaw = `["` + relayHy2 + `","` + relayVLESS + `"]`
	plainFile    = "Hysteria2-17892.json"
)

// seedRelayPairNode stands up one node carrying a conventional line and the
// relay-pair file, with one identity bound to the relay-pair line.
func seedRelayPairNode(t *testing.T, srv *Server, inboundTags string) (relay Line, user VpnUser) {
	t.Helper()
	if err := srv.store.UpsertNode(model.Node{ID: "dmit-eb-wee", Name: "DMIT EB", PublicIP: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertProxyNodeProfile(model.ProxyNodeProfile{ID: "prof-dmit", NodeID: "dmit-eb-wee", Core: "sing-box"}); err != nil {
		t.Fatal(err)
	}
	metadata := map[string]string{}
	if inboundTags != "" {
		metadata[singBoxInboundTagsKey] = inboundTags
	}
	srv.singboxInvMu.Lock()
	srv.singboxInv = map[string]model.SingBoxInventory{
		"dmit-eb-wee": {NodeID: "dmit-eb-wee", At: srv.now(), Status: "ok", Nodes: []model.SingBoxNode{
			{Name: plainFile, Protocol: "hysteria2", Network: "hy2", Address: "203.0.113.7", Port: "17892", OutboundRef: "direct",
				Metadata: map[string]string{singBoxInboundTagsKey: `["` + plainFile + `"]`}},
			{Name: relayFile, Protocol: "vless", Network: "reality", Address: "203.0.113.7", Port: "7899",
				OutboundRef: "out-to-aaitr-frontier-nat-vless-7899", OutboundServer: "nat-us-28tz.aproxy.top", OutboundPort: "25499",
				Metadata: metadata},
		}},
	}
	srv.singboxInvMu.Unlock()
	groups := srv.buildLineGroups()
	relay = findLine(t, groups, "dmit-eb-wee", relayFile)
	user = VpnUser{ID: "vpnuser_relay", Email: "relay@example.com", Enabled: true,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "7b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"}},
		Bindings:    []LineBinding{{LineHashID: relay.LineHashID, Enabled: true}}}
	if err := srv.putVpnUser(user); err != nil {
		t.Fatal(err)
	}
	return relay, user
}

// The bug, end to end: counters keyed by the two real inbound tags reach the
// server, and before the node reported which tags the file holds there is
// nothing to join them to. Both are kept as unknown_line, which is honest but
// leaves real egress unattributable to any line or identity.
func TestUsageAttributionRelayPairWithoutReportedTags(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	seedRelayPairNode(t, srv, "")
	result := reportRelayPairUsage(t, srv)
	if result.UnknownLines != 2 {
		t.Fatalf("unknown lines = %d, want 2 (both relay-pair tags); result %+v", result.UnknownLines, result)
	}
	rows := relayPairRows(t, srv, now)
	for _, tag := range []string{relayVLESS, relayHy2} {
		got := rows[tag]
		if len(got) != 1 || got[0].Attribution != usageAttributionUnknownLine {
			t.Fatalf("%s rows = %+v, want one unknown_line row", tag, got)
		}
	}
}

// With the tags reported, both counters join to the line that owns them and
// the bytes reach the bound identity. This is the assertion that fails before
// the fix: the tags resolve to no line, so the rows read unknown_line and the
// identity is never named.
func TestUsageAttributionRelayPairJoinsReportedInboundTags(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	relay, user := seedRelayPairNode(t, srv, relayTagsRaw)
	if got := relay.InboundTags; len(got) != 2 || got[0] != relayHy2 || got[1] != relayVLESS {
		t.Fatalf("line inbound tags = %v", got)
	}
	result := reportRelayPairUsage(t, srv)
	if result.UnknownLines != 0 {
		t.Fatalf("unknown lines = %d, want 0; result %+v", result.UnknownLines, result)
	}
	rows := relayPairRows(t, srv, now)
	for _, tc := range []struct {
		tag              string
		uplink, downlink int64
	}{
		{relayVLESS, 500, 600},
		{relayHy2, 40, 70},
	} {
		got := rows[tc.tag]
		if len(got) != 1 {
			t.Fatalf("%s rows = %+v, want one", tc.tag, got)
		}
		row := got[0]
		if row.Attribution != usageAttributionBinding || row.UserID != user.ID || !row.Counted {
			t.Fatalf("%s row = %+v, want the bound identity counted", tc.tag, row)
		}
		if row.LineHashID != relay.LineHashID {
			t.Fatalf("%s row line = %q, want the relay-pair line %q", tc.tag, row.LineHashID, relay.LineHashID)
		}
		if row.Uplink != tc.uplink || row.Downlink != tc.downlink {
			t.Fatalf("%s row bytes = %d/%d, want %d/%d", tc.tag, row.Uplink, row.Downlink, tc.uplink, tc.downlink)
		}
	}
	// The line's own file name keeps its place: a node that reports its tags
	// does not lose the join every other consumer already uses.
	if got := rows[plainFile]; len(got) != 1 || got[0].Attribution != usageAttributionNone {
		t.Fatalf("%s rows = %+v", plainFile, got)
	}
}

// sing-box logs the core's inbound tag, so a connection on the relay pair is
// placed only if the same index backs trace attribution.
func TestTraceTopologyRelayPairInboundTags(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	srv := usageTestServer(t, now)
	relay, _ := seedRelayPairNode(t, srv, relayTagsRaw)
	records := []model.ConnRecord{
		{NodeID: "dmit-eb-wee", InboundTag: relayVLESS},
		{NodeID: "dmit-eb-wee", InboundTag: relayHy2},
		{NodeID: "dmit-eb-wee", InboundTag: plainFile},
		{NodeID: "dmit-eb-wee", InboundTag: "never-configured"},
	}
	srv.attributeTraceRecords(records)
	for i, want := range []string{relay.LineHashID, relay.LineHashID, "", ""} {
		if want == "" {
			continue
		}
		if records[i].LineHashID != want {
			t.Fatalf("record %d (%s) line = %q, want %q", i, records[i].InboundTag, records[i].LineHashID, want)
		}
		if records[i].LineUUID != relay.LineUUID {
			t.Fatalf("record %d line_uuid = %q, want %q", i, records[i].LineUUID, relay.LineUUID)
		}
	}
	if records[3].LineHashID != "" || records[3].LineUUID != "" {
		t.Fatalf("an unconfigured tag was placed: %+v", records[3])
	}
	if records[2].LineHashID == "" {
		t.Fatalf("the conventional line lost its own join: %+v", records[2])
	}
}

// The index rules, stated directly: a line's own tag outranks any tag another
// line reports, and a tag two lines both claim resolves to neither.
func TestLineInboundTagIndexPrecedence(t *testing.T) {
	groups := []LineGroup{{NodeID: "n1", Lines: []Line{
		{NodeID: "n1", LineHashID: "line_a", Tag: "a.json", InboundTags: []string{"shared", "only-a"}},
		{NodeID: "n1", LineHashID: "line_b", Tag: "b.json", InboundTags: []string{"shared", "a.json"}},
		{NodeID: "n1", LineHashID: "line_c", Tag: "c.json"},
	}}, {NodeID: "n2", Lines: []Line{
		{NodeID: "n2", LineHashID: "line_d", Tag: "d.json", InboundTags: []string{"only-a"}},
	}}}
	index := lineInboundTagIndex(groups)
	for _, tc := range []struct {
		node, tag, want string
	}{
		{"n1", "a.json", "line_a"}, // own tag beats line_b's claim on it
		{"n1", "b.json", "line_b"},
		{"n1", "c.json", "line_c"},
		{"n1", "only-a", "line_a"},
		{"n2", "only-a", "line_d"}, // a tag is unique per node, not per fleet
	} {
		got, ok := index[nodeTagKey{NodeID: tc.node, Tag: tc.tag}]
		if !ok || got.LineHashID != tc.want {
			t.Fatalf("%s/%s = %q (found %v), want %q", tc.node, tc.tag, got.LineHashID, ok, tc.want)
		}
	}
	if got, ok := index[nodeTagKey{NodeID: "n1", Tag: "shared"}]; ok {
		t.Fatalf("a tag two lines both claim resolved to %q; it must resolve to neither", got.LineHashID)
	}
	if len(index) != 6 {
		keys := make([]string, 0, len(index))
		for key, ln := range index {
			keys = append(keys, key.NodeID+"/"+key.Tag+"="+ln.LineHashID)
		}
		sort.Strings(keys)
		t.Fatalf("index keys = %v, want exactly the six resolvable ones", keys)
	}
}

// Whatever a node reports, a value the server cannot read yields nothing and
// simply leaves the line joined by its file name as before.
func TestDiscoveredInboundTagsRejectsUnreadableReports(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      []string
	}{
		{"absent", "", nil},
		{"not json", "inbound-a,inbound-b", nil},
		{"not an array", `{"tag":"inbound-a"}`, nil},
		{"array of objects", `[{"tag":"inbound-a"}]`, nil},
		{"blank entries dropped", `["", "  ", "inbound-a"]`, []string{"inbound-a"}},
		{"duplicates folded and sorted", `["b","a","b"]`, []string{"a", "b"}},
		{"over the cap", "[" + strings.TrimSuffix(strings.Repeat(`"t",`, maxDiscoveredInboundTags+1), ",") + "]", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := discoveredInboundTags(model.SingBoxNode{Metadata: map[string]string{singBoxInboundTagsKey: tc.raw}})
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// reportRelayPairUsage sends the baseline and one delta keyed by the tags the
// core actually loaded: the two relay-pair inbounds and the conventional line.
func reportRelayPairUsage(t *testing.T, srv *Server) proxyUsageApplyResult {
	t.Helper()
	mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "dmit-eb-wee", CoreUptimeSec: 100,
		InboundTraffic: map[string]model.ProxyTrafficCounter{
			relayVLESS: counter(1000, 2000), relayHy2: counter(10, 20), plainFile: counter(5, 5),
		}})
	return mustApplyUsage(t, srv, model.ProxyUsageSnapshot{NodeID: "dmit-eb-wee", CoreUptimeSec: 200,
		InboundTraffic: map[string]model.ProxyTrafficCounter{
			relayVLESS: counter(1500, 2600), relayHy2: counter(50, 90), plainFile: counter(15, 25),
		}})
}

func relayPairRows(t *testing.T, srv *Server, now time.Time) map[string][]usageLineRow {
	t.Helper()
	window, _ := parseUsagePeriod("today", now)
	report, _ := srv.buildUsageLines(srv.usageAttributionContext(), window)
	byTag := map[string][]usageLineRow{}
	for _, row := range report.Rows {
		byTag[row.Tag] = append(byTag[row.Tag], row)
	}
	return byTag
}
