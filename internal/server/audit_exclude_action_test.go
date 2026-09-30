package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestAuditExcludeActionDropsInsideTheScan(t *testing.T) {
	events := descendingEvents(300, func(i int) string {
		switch i % 3 {
		case 0:
			return "node.online"
		case 1:
			return "node.offline"
		}
		return "task.create"
	})
	cases := []struct {
		name      string
		query     string
		wantTotal int
	}{
		{"flips out", "exclude_action=node.online,node.offline&limit=10", 100},
		{"trailing star is the same prefix", "exclude_action=node.online*,node.offline*&limit=10", 100},
		{"a namespace prefix", "exclude_action=node.&limit=10", 100},
		{"duplicates collapse", "exclude_action=node.online,node.online,node.offline&limit=10", 100},
		{"combines with action", "action=node.*&exclude_action=node.offline&limit=10", 100},
		{"paging stays on the kept rows", "exclude_action=node.&limit=10&offset=95", 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := auditQuery(t, tc.query, events)
			if out.Total != tc.wantTotal {
				t.Fatalf("total = %d, want %d", out.Total, tc.wantTotal)
			}
			// Every record was examined; exclusion is a filter, not a shortcut.
			if out.Scanned != len(events) || !out.Complete {
				t.Fatalf("scanned=%d complete=%v, want %d and true", out.Scanned, out.Complete, len(events))
			}
			for _, ev := range out.Events {
				if strings.HasPrefix(tc.query, "exclude_action=node.&") && strings.HasPrefix(ev.Action, "node.") {
					t.Fatalf("excluded action %q returned", ev.Action)
				}
				if strings.Contains(tc.query, "node.offline") && ev.Action == "node.offline" {
					t.Fatalf("excluded action %q returned", ev.Action)
				}
			}
		})
	}
	// Paging past the kept rows: the last page holds the remainder.
	if out := auditQuery(t, "exclude_action=node.&limit=10&offset=95", events); len(out.Events) != 5 {
		t.Fatalf("offset 95 of 100 kept rows returned %d events, want 5", len(out.Events))
	}
}

func TestAuditExcludeActionValidation(t *testing.T) {
	sixteen := make([]string, 0, 17)
	for i := 0; i < maxAuditExcludeActions; i++ {
		sixteen = append(sixteen, fmt.Sprintf("a%d.", i))
	}
	ok := []string{
		strings.Join(sixteen, ","),
		strings.Join(append(sixteen, sixteen[0]), ","), // a repeat is not a seventeenth
		"plugin.host.rpc.call:svc/method",
		"",
	}
	for _, raw := range ok {
		if _, err := parseAuditExcludeActions(raw); err != nil {
			t.Fatalf("exclude_action=%q refused: %v", raw, err)
		}
	}
	bad := []string{
		strings.Join(append(sixteen, "extra."), ","),
		"*",
		"node online",
		"node.*.flip",
		"node.online;drop",
		strings.Repeat("a", maxAuditActionPrefixSize+1),
	}
	for _, raw := range bad {
		if _, err := parseAuditExcludeActions(raw); err == nil {
			t.Fatalf("exclude_action=%q accepted, want an error", raw)
		}
	}
}

func TestAuditExcludeActionOverHTTPStaysConfined(t *testing.T) {
	_, confined, st, now := newTaskQueryFixture(t)
	for i, spec := range []struct{ node, action string }{
		{"node-a", "node.online"},
		{"node-a", "node.offline"},
		{"node-a", "task.create"},
		{"node-c", "task.create"},
		{"node-c", "node.online"},
		{"", "login"},
	} {
		if err := st.AppendAudit(model.AuditEvent{
			ID: fmt.Sprintf("audit-x-%d", i), At: now.Add(time.Duration(i) * time.Second),
			NodeID: spec.node, Action: spec.action, Decision: "allow",
		}); err != nil {
			t.Fatal(err)
		}
	}
	code, body := confined.get(t, "/api/audit?exclude_action=node.online,node.offline")
	if code != http.StatusOK {
		t.Fatalf("audit = %d: %s", code, body)
	}
	var out auditQueryResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	// The confined reader sees node-a only; of node-a's three events two are
	// flips.
	if out.Total != 1 || len(out.Events) != 1 || out.Events[0].NodeID != "node-a" || out.Events[0].Action != "task.create" {
		t.Fatalf("confined audit with exclusion = total %d %+v", out.Total, out.Events)
	}
	if !out.Complete || out.Scanned < 6 {
		t.Fatalf("scanned=%d complete=%v", out.Scanned, out.Complete)
	}
	for _, query := range []string{"exclude_action=*", "exclude_action=bad%20value"} {
		if code, body := confined.get(t, "/api/audit?"+query); code != http.StatusBadRequest {
			t.Fatalf("audit?%s = %d, want 400: %s", query, code, body)
		}
	}
}
