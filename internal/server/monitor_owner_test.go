package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// A check expanded from a definition (design 32 D1) refuses a direct edit
// and a direct delete, and the refusal names the definition to change.
func TestDefinitionMonitorRefusesDirectEditAndDelete(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	upsertNodes(t, st, model.Node{ID: "node-a", Name: "a"})
	mon := model.Monitor{ID: "mon_chk_web_1", Name: "web", Type: model.MonitorTypeTCP, Target: "203.0.113.9:443", IntervalSec: 60, TimeoutSec: 5, NodeIDs: []string{"node-a"}, Enabled: true, ManagedBy: store.MonitorManagedCheckPrefix + "def_web"}
	if err := st.UpsertMonitor(mon); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct{ path, body string }{
		{"/api/monitors/update", `{"id":"mon_chk_web_1","version":0,"name":"mine now"}`},
		{"/api/monitors/delete", `{"id":"mon_chk_web_1"}`},
	} {
		res := doJSON(t, handler, http.MethodPost, call.path, call.body, cookies, csrf)
		var apiErr model.APIErrorResponse
		_ = json.NewDecoder(res.Body).Decode(&apiErr)
		res.Body.Close()
		if res.StatusCode != http.StatusConflict || !strings.Contains(apiErr.Error.Message, "check definition def_web") {
			t.Fatalf("%s = %d %q, want 409 naming the definition", call.path, res.StatusCode, apiErr.Error.Message)
		}
	}
	if stored, ok := st.Monitor(mon.ID); !ok || stored.Name != "web" {
		t.Fatalf("the definition's check changed: %+v %v", stored, ok)
	}
}

// A definition's check pages by its own policy, as an operator's does; a
// beacon's reachability check never pages.
func TestDefinitionMonitorPagesByItsOwnPolicy(t *testing.T) {
	pathSet := checkPolicy{alert: model.MonitorAlertDown, after: 5}
	own := model.Monitor{Alert: model.MonitorAlertDownAndDegraded, AlertAfter: 3, ManagedBy: store.MonitorManagedCheckPrefix + "def_web"}
	if got := monitorPolicyWith(own, pathSet); got.alert != model.MonitorAlertDownAndDegraded || got.after != 3 {
		t.Fatalf("definition policy = %+v", got)
	}
	if got := monitorAlertOf(own); got != model.MonitorAlertDownAndDegraded {
		t.Fatalf("definition alert = %q", got)
	}
	reach := model.Monitor{Alert: model.MonitorAlertDown, ManagedBy: model.MonitorManagedBeacon}
	if got := monitorPolicyWith(reach, pathSet); got.pagesDown() {
		t.Fatalf("beacon reach policy = %+v", got)
	}
}
