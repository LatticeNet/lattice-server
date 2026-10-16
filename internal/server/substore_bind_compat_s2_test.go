package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// TestS1PluginPlanStillBinds: server a127 serves plugin 0.17 unchanged. An
// S1-shaped plan, with no selection and no policy (the fields a 0.17 plugin
// never writes), decodes under the strict codec and binds against the line
// set the snapshot selected; a share of it serves every line of the
// selection to its identity.
func TestS1PluginPlanStillBinds(t *testing.T) {
	env := bindShareFixture(t)
	env.selection, env.policy = nil, nil
	plan := bindNodesPlan(t, env.rows)
	raw, err := model.EncodeSelectionPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"selection"`) || strings.Contains(string(raw), `"policy"`) {
		t.Fatalf("the S1 plan carries an S2 field: %s", raw)
	}
	if _, err := model.DecodeSelectionPlan(raw); err != nil {
		t.Fatalf("the S1 plan no longer decodes: %v", err)
	}
	rec := env.get("/sub/fleet/" + bindShareToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("an S1 plan's share: %d refusals %v", rec.Code, env.shareRefusals("sh-fleet"))
	}
	if got := env.nodeUUIDs(t, env.lastConvert(t)); len(got) != len(env.rows) {
		t.Fatalf("the S1 plan bound %d of %d lines", len(got), len(env.rows))
	}
}
