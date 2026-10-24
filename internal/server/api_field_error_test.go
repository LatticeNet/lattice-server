package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// apiErrorOf decodes an error body, failing the test when it is not one.
func apiErrorOf(t *testing.T, raw string) model.APIError {
	t.Helper()
	var out model.APIErrorResponse
	if err := json.Unmarshal([]byte(raw), &out); err != nil || out.Error.Code == "" {
		t.Fatalf("not an error body: %s", raw)
	}
	return out.Error
}

// Design 32 R6: a refused save names the request field at fault, as a path
// into the JSON body, so the editor can focus it; a refusal about no one
// field keeps the old shape.
func TestRefusedCheckSavesNameTheirField(t *testing.T) {
	_, handler, _ := checkFleet(t)
	c := newCheckClient(t, handler)
	base := func() model.CheckDefinitionSave {
		return model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
			Name: "web", Type: model.MonitorTypeTCP, Enabled: true,
			Sources: model.TargetSelector{Nodes: []string{"node-sh"}},
			Targets: model.TargetSelector{Nodes: []string{"node-jp"}},
		}}
	}
	for _, tc := range []struct {
		name   string
		edit   func(*model.CheckDefinitionSave)
		status int
		field  string
	}{
		{"empty name", func(s *model.CheckDefinitionSave) { s.Name = " " }, http.StatusBadRequest, "name"},
		{"unknown method", func(s *model.CheckDefinitionSave) { s.Type = "udp" }, http.StatusBadRequest, "type"},
		{"second address malformed", func(s *model.CheckDefinitionSave) {
			s.Addresses = []string{"203.0.113.9:443", "no-port"}
		}, http.StatusBadRequest, "addresses[1]"},
		{"unknown excluded node, as sent", func(s *model.CheckDefinitionSave) {
			s.Targets = model.TargetSelector{All: true, Exclude: []string{"node-us", " node-gone "}}
		}, http.StatusBadRequest, "targets.exclude[1]"},
		{"no source", func(s *model.CheckDefinitionSave) { s.Sources = model.TargetSelector{} }, http.StatusBadRequest, "sources"},
		{"interval out of range", func(s *model.CheckDefinitionSave) { s.IntervalSec = 1 }, http.StatusBadRequest, "interval_sec"},
		{"timeout not below the interval", func(s *model.CheckDefinitionSave) { s.IntervalSec, s.TimeoutSec = 30, 30 }, http.StatusBadRequest, "timeout_sec"},
		{"packets on tcp", func(s *model.CheckDefinitionSave) { s.Packets = 3 }, http.StatusBadRequest, "packets"},
		{"alert", func(s *model.CheckDefinitionSave) { s.Alert = "loud" }, http.StatusBadRequest, "alert"},
		{"alert after", func(s *model.CheckDefinitionSave) { s.AlertAfter = 99 }, http.StatusBadRequest, "alert_after"},
		{"degraded rule", func(s *model.CheckDefinitionSave) {
			s.Degraded = &model.MonitorDegradedRule{LossPercent: -1}
		}, http.StatusBadRequest, "degraded"},
		{"http status set", func(s *model.CheckDefinitionSave) {
			s.Type, s.Targets, s.Addresses, s.ExpectStatus = model.MonitorTypeHTTP, model.TargetSelector{}, []string{"https://example.com/"}, "9xx"
		}, http.StatusBadRequest, "expect_status"},
	} {
		save := base()
		tc.edit(&save)
		code, raw := c.do(http.MethodPost, "/api/monitors/definitions", save)
		if code != tc.status {
			t.Fatalf("%s: = %d %s", tc.name, code, raw)
		}
		if got := apiErrorOf(t, raw).Field; got != tc.field {
			t.Fatalf("%s: field = %q, want %q (%s)", tc.name, got, tc.field, raw)
		}
	}

	// A refusal about no single field sends no field at all.
	code, raw := c.do(http.MethodPost, "/api/monitors/definitions", map[string]any{"id": "chk_x", "name": "x"})
	if code != http.StatusBadRequest || strings.Contains(raw, `"field"`) {
		t.Fatalf("create with an id = %d %s", code, raw)
	}
}

// Design 32 R6: a save that lost a race answers 409 with version_conflict,
// so the editor keeps the draft and offers to save it over the new version;
// another 409 keeps its own code.
func TestStaleSavesAnswerVersionConflict(t *testing.T) {
	_, handler, _ := checkFleet(t)
	c := newCheckClient(t, handler)
	def := c.create(model.CheckDefinitionSave{CheckDefinitionSpec: model.CheckDefinitionSpec{
		Name: "web", Type: model.MonitorTypeTCP, Enabled: true,
		Sources: model.TargetSelector{Nodes: []string{"node-sh"}},
		Targets: model.TargetSelector{Nodes: []string{"node-jp"}},
	}})
	stale := saveOf(def)
	stale.Name = "theirs"
	c.update(stale)
	stale.Name = "mine"
	code, raw := c.do(http.MethodPost, "/api/monitors/definitions/update", stale)
	if code != http.StatusConflict || apiErrorOf(t, raw).Code != model.APIErrorVersionConflict {
		t.Fatalf("stale definition edit = %d %s", code, raw)
	}
	code, raw = c.do(http.MethodPost, "/api/monitors/definitions/delete", model.CheckDefinitionDelete{ID: def.ID, Version: def.Version})
	if code != http.StatusConflict || apiErrorOf(t, raw).Code != model.APIErrorVersionConflict {
		t.Fatalf("stale definition delete = %d %s", code, raw)
	}

	// The single-check editor: a stale edit and an edit of a definition's
	// monitor, which is a 409 of another kind.
	code, raw = c.do(http.MethodPost, "/api/monitors", map[string]any{
		"name": "edge", "type": "tcp", "target": "203.0.113.9:443", "node_ids": []string{"node-sh"}, "timeout_sec": 40, "interval_sec": 30,
	})
	if code != http.StatusBadRequest || apiErrorOf(t, raw).Field != "timeout_sec" {
		t.Fatalf("create with a long timeout = %d %s", code, raw)
	}
	code, raw = c.do(http.MethodPost, "/api/monitors", map[string]any{
		"name": "edge", "type": "tcp", "target": "203.0.113.9:443", "node_ids": []string{"node-sh"},
	})
	if code != http.StatusOK {
		t.Fatalf("create = %d %s", code, raw)
	}
	var mon model.Monitor
	if err := json.Unmarshal([]byte(raw), &mon); err != nil {
		t.Fatal(err)
	}
	name := "edge 2"
	edit := model.MonitorUpdate{ID: mon.ID, Version: mon.Version, Name: &name}
	if code, raw = c.do(http.MethodPost, "/api/monitors/update", edit); code != http.StatusOK {
		t.Fatalf("edit = %d %s", code, raw)
	}
	code, raw = c.do(http.MethodPost, "/api/monitors/update", edit)
	if code != http.StatusConflict || apiErrorOf(t, raw).Code != model.APIErrorVersionConflict {
		t.Fatalf("stale check edit = %d %s", code, raw)
	}
	empty := ""
	code, raw = c.do(http.MethodPost, "/api/monitors/update", model.MonitorUpdate{ID: mon.ID, Version: mon.Version + 1, Name: &empty})
	if code != http.StatusBadRequest || apiErrorOf(t, raw).Field != "name" {
		t.Fatalf("edit with an empty name = %d %s", code, raw)
	}
	generated := def.Monitors[0].MonitorID
	code, raw = c.do(http.MethodPost, "/api/monitors/update", model.MonitorUpdate{ID: generated, Version: 1, Name: &name})
	if code != http.StatusConflict || apiErrorOf(t, raw).Code == model.APIErrorVersionConflict {
		t.Fatalf("edit of a definition's monitor = %d %s", code, raw)
	}
}
