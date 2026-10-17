package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// The core half of S2-SR-2's refusal (substore_script_network.go).

// scriptNetworkPluginMessage is the plugin's refusal as its
// fleetScriptNetworkRefusal writes it, with a marker standing in for
// anything core must not relay.
const scriptNetworkPluginMessage = `fleet_script_network_unavailable: subscription "fleet-1" is fleet-bound, and a Script or Resolve Domain step ` +
	`asked for the network 1 time(s); a fleet-bound chain runs without a network until S3, so remove the network call or the step PLUGIN-TEXT-MARKER`

// scriptNetworkStepJSON is a stored step of a type, with a script marker in
// its arguments.
func scriptNetworkStepJSON(kind string, disabled bool) json.RawMessage {
	fields := map[string]any{"type": kind, "args": map[string]any{"mode": "script", "content": "await $substore.http.get('https://collector.invalid') // SCRIPT-MARKER"}}
	if disabled {
		fields["disabled"] = true
	}
	raw, _ := json.Marshal(fields)
	return raw
}

// putSubStoreStagedRecord writes a record's staged document as the plugin's
// store_staged.go does.
func putSubStoreStagedRecord(t testing.TB, st *store.Store, record map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"record": record, "base_revision": "rev-base", "staged_at": "2026-10-16T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: subStoreStagedKey(record["id"].(string)), Value: string(raw)}); err != nil {
		t.Fatal(err)
	}
}

// decodeScriptNetworkRefusal decodes a refusal's 409 body, and fails on any
// other error.
func decodeScriptNetworkRefusal(t *testing.T, err error) substoreScriptNetworkBody {
	t.Helper()
	var opErr *pluginOperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("want the typed refusal, got %v", err)
	}
	if opErr.StatusCode != http.StatusConflict {
		t.Fatalf("the refusal answers %d, want 409: %s", opErr.StatusCode, opErr.Body)
	}
	for _, leak := range []string{"PLUGIN-TEXT-MARKER", "time(s)", "SCRIPT-MARKER", "collector.invalid", "$substore"} {
		if strings.Contains(string(opErr.Body), leak) {
			t.Fatalf("the refusal carries %q: %s", leak, opErr.Body)
		}
	}
	var body struct {
		Error substoreScriptNetworkBody `json:"error"`
	}
	if err := json.Unmarshal(opErr.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != apiErrorFleetScriptNetworkUnavailable || !strings.HasPrefix(body.Error.Message, apiErrorFleetScriptNetworkUnavailable+": ") {
		t.Fatalf("the refusal's code or message: %+v", body.Error)
	}
	return body.Error
}

func requireRefusalStep(t *testing.T, what string, got substoreScriptNetworkBody, record string, position int, kind string) {
	t.Helper()
	if got.Record != record || got.Step == nil || got.Step.Position != position || got.Step.Type != kind {
		t.Fatalf("%s: record %q step %+v, want %q step %d (%s)", what, got.Record, got.Step, record, position, kind)
	}
	if !strings.Contains(got.Message, fmt.Sprintf("step %d (%s)", position, kind)) {
		t.Fatalf("%s: the message does not name the step: %q", what, got.Message)
	}
}

// TestSubstoreScriptNetworkRefusedMatchesOnlyALeadingCode: only the plugin's
// own refusal whose message leads with the code and a colon is lifted; the
// code later in the text, without its colon, as a prefix of another word, or
// on an error that is not the plugin's refusal is not.
func TestSubstoreScriptNetworkRefusedMatchesOnlyALeadingCode(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"the plugin's refusal":       {&pluginServiceError{message: scriptNetworkPluginMessage}, true},
		"the refusal wrapped":        {fmt.Errorf("render: %w", &pluginServiceError{message: scriptNetworkPluginMessage}), true},
		"the code later in the text": {&pluginServiceError{message: "collection \"c\": render failed: " + scriptNetworkPluginMessage}, false},
		"a leading space":            {&pluginServiceError{message: " " + scriptNetworkPluginMessage}, false},
		"the code alone":             {&pluginServiceError{message: apiErrorFleetScriptNetworkUnavailable}, false},
		"a longer code":              {&pluginServiceError{message: apiErrorFleetScriptNetworkUnavailable + "_v2: x"}, false},
		"not the plugin's refusal":   {errors.New(scriptNetworkPluginMessage), false},
		"a core refusal":             {rpcAPIError(http.StatusConflict, apiErrorFleetScriptNetworkUnavailable, scriptNetworkPluginMessage), false},
		"no error":                   {nil, false},
	} {
		if got := substoreScriptNetworkRefused(tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
	// The serve path's log names the class and the fixed code, never the
	// text.
	summary := subscriptionDiagnosticSummary(&pluginServiceError{message: scriptNetworkPluginMessage})
	if !strings.Contains(summary, "code="+apiErrorFleetScriptNetworkUnavailable) || strings.Contains(summary, "PLUGIN-TEXT-MARKER") || strings.Contains(summary, "fleet-1") {
		t.Fatalf("the summary of the refusal: %q", summary)
	}
	if summary := subscriptionDiagnosticSummary(&pluginServiceError{message: "render failed: " + scriptNetworkPluginMessage}); strings.Contains(summary, "code=") {
		t.Fatalf("a refusal that does not lead with the code was classed: %q", summary)
	}
}

// TestSubstoreFirstNetworkStep: the first enabled Script Operator, Script
// Filter or Resolve Domain Operator, numbered over every stored step.
func TestSubstoreFirstNetworkStep(t *testing.T) {
	sorter := chainStep(map[string]any{"type": "Sort Operator"})
	for name, tc := range map[string]struct {
		steps    []json.RawMessage
		position int
		kind     string
	}{
		"after a disabled script": {[]json.RawMessage{sorter, scriptNetworkStepJSON("Script Operator", true), json.RawMessage(`"unreadable"`),
			scriptNetworkStepJSON("Resolve Domain Operator", false), scriptNetworkStepJSON("Script Operator", false)}, 4, "Resolve Domain Operator"},
		"a script filter":     {[]json.RawMessage{scriptNetworkStepJSON("Script Filter", false)}, 1, "Script Filter"},
		"a script operator":   {[]json.RawMessage{sorter, scriptNetworkStepJSON("Script Operator", false)}, 2, "Script Operator"},
		"none":                {[]json.RawMessage{sorter, scriptNetworkStepJSON("Regex Filter", false)}, 0, ""},
		"only disabled steps": {[]json.RawMessage{scriptNetworkStepJSON("Script Filter", true)}, 0, ""},
		"no steps":            {nil, 0, ""},
	} {
		step := substoreFirstNetworkStep(tc.steps)
		switch {
		case tc.position == 0 && step != nil:
			t.Errorf("%s: found %+v", name, step)
		case tc.position != 0 && (step == nil || step.Position != tc.position || step.Type != tc.kind):
			t.Errorf("%s: found %+v, want step %d (%s)", name, step, tc.position, tc.kind)
		}
	}
}

// TestSubstoreScriptNetworkRefusalBody: the body names the record holding
// the step and the step, or the rendered record and no step, or neither for
// a draft; the message leads with the code.
func TestSubstoreScriptNetworkRefusalBody(t *testing.T) {
	got := decodeScriptNetworkRefusal(t, newSubstoreScriptNetworkRefusal("coll", "prov", &substoreScriptNetworkStep{Position: 3, Type: "Script Filter"}))
	requireRefusalStep(t, "a member's step", got, "prov", 3, "Script Filter")
	if !strings.Contains(got.Message, `record "coll" rendered`) || !strings.Contains(got.Message, `of record "prov"`) {
		t.Fatalf("the message does not name both records: %q", got.Message)
	}
	got = decodeScriptNetworkRefusal(t, newSubstoreScriptNetworkRefusal("coll", "", nil))
	if got.Record != "coll" || got.Step != nil {
		t.Fatalf("no step found: %+v", got)
	}
	refusal := newSubstoreScriptNetworkRefusal("", "", &substoreScriptNetworkStep{Position: 1, Type: "Script Operator"})
	got = decodeScriptNetworkRefusal(t, refusal)
	if got.Record != "" || got.Step == nil || !strings.Contains(got.Message, "the draft") {
		t.Fatalf("a draft: %+v", got)
	}
	if refusal.Error() != got.Message {
		t.Fatalf("Error() %q is not the message %q", refusal.Error(), got.Message)
	}
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(refusal.op.Body, &raw); err != nil || raw["error"]["record"] != nil {
		t.Fatalf("a draft's body names a record: %s", refusal.op.Body)
	}
}

// scriptNetworkRefusalSamplesFile holds refusals as core words them.
// tools/tsgen publishes it in the Sub-Store UI's core-types.ts, where the
// UI's parser reads every message back (scriptNetwork.test.ts there): the
// bridge relays a host error's message and code only, so the UI reads the
// record and the step out of this sentence, and a change of wording here
// has to fail on both sides at once.
const scriptNetworkRefusalSamplesFile = "testdata/script_network_refusals.json"

type scriptNetworkRefusalSample struct {
	Name     string                     `json:"name"`
	Rendered string                     `json:"rendered"`
	Record   string                     `json:"record"`
	Step     *substoreScriptNetworkStep `json:"step"`
	Message  string                     `json:"message"`
}

// TestScriptNetworkRefusalSamples holds every sample to the refusal core
// builds for it: the message byte for byte, the record the body names (the
// holder of the step, else the rendered record) and the step. The samples
// cover each shape a message takes: the rendered record's own step, a
// member's step, a draft, no step found, and ids with quotes, spaces and
// CJK, which %q escapes.
func TestScriptNetworkRefusalSamples(t *testing.T) {
	raw, err := os.ReadFile(scriptNetworkRefusalSamplesFile)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var samples []scriptNetworkRefusalSample
	if err := decoder.Decode(&samples); err != nil {
		t.Fatal(err)
	}
	shapes := map[string]bool{}
	for _, sample := range samples {
		holder := ""
		if sample.Step != nil {
			holder = sample.Record
		}
		refusal := newSubstoreScriptNetworkRefusal(sample.Rendered, holder, sample.Step)
		if refusal.Error() != sample.Message {
			t.Errorf("%s: core words it\n  %s\nbut the sample says\n  %s", sample.Name, refusal.Error(), sample.Message)
			continue
		}
		got := decodeScriptNetworkRefusal(t, refusal)
		if got.Record != sample.Record || got.Message != sample.Message || (got.Step == nil) != (sample.Step == nil) ||
			(got.Step != nil && *got.Step != *sample.Step) {
			t.Errorf("%s: the body says record %q step %+v, the sample record %q step %+v", sample.Name, got.Record, got.Step, sample.Record, sample.Step)
		}
		switch {
		case sample.Step == nil:
			shapes["no step"] = true
		case sample.Rendered == "":
			shapes["draft"] = true
		case sample.Record != sample.Rendered:
			shapes["member"] = true
		default:
			shapes["own"] = true
		}
		if strings.ContainsAny(sample.Record+sample.Rendered, "\" ") {
			shapes["escaped"] = true
		}
	}
	for _, shape := range []string{"own", "member", "draft", "no step", "escaped"} {
		if !shapes[shape] {
			t.Errorf("no sample covers %s", shape)
		}
	}
}

// TestSubstoreScriptNetworkStepSearch reads the step from the record
// documents: the rendered record's own chain at the revision rendered, then
// a collection's members by id and by tag, a member at its named revision
// (a deleted one skipped), a file's node source, a caller's chain in place
// of a sub's stored one but not a collection's, and a draft's chain.
func TestSubstoreScriptNetworkStepSearch(t *testing.T) {
	h := newSubStoreSvcHarness(t)
	sorter := chainStep(map[string]any{"type": "Sort Operator"})
	steps := func(raws ...json.RawMessage) []json.RawMessage { return raws }
	records, err := json.Marshal(map[string]any{"records": []map[string]any{
		{"id": "f", "source": "fleet", "process": steps(sorter, scriptNetworkStepJSON("Script Operator", false))},
		{"id": "quiet", "source": "fleet", "process": steps(sorter)},
		{"id": "p", "source": "local", "process": steps(scriptNetworkStepJSON("Script Filter", false))},
		{"id": "tagged", "source": "local", "tags": []string{"home"}, "process": steps(sorter, sorter, scriptNetworkStepJSON("Resolve Domain Operator", false))},
		{"id": "c", "kind": "collection", "members": []string{"c", "quiet", "p"}, "member_tags": []string{"home"}, "process": steps(sorter)},
		{"id": "file", "kind": "file", "node_source": "c"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	putSubStoreRecords(t, h.st, string(records))
	putSubStoreStagedRecord(t, h.st, map[string]any{"id": "f", "source": "fleet", "process": steps(scriptNetworkStepJSON("Resolve Domain Operator", false))})
	putSubStoreStagedRecord(t, h.st, map[string]any{"id": "p", "source": "local", "process": steps(sorter, scriptNetworkStepJSON("Script Operator", false))})

	for name, tc := range map[string]struct {
		render   substoreScriptNetworkRender
		record   string
		position int
		kind     string
	}{
		"live":                          {substoreScriptNetworkRender{SubscriptionID: "f"}, "f", 2, "Script Operator"},
		"the live revision named":       {substoreScriptNetworkRender{SubscriptionID: "f", Revision: "rev-f"}, "f", 2, "Script Operator"},
		"the staged revision":           {substoreScriptNetworkRender{SubscriptionID: "f", Revision: "rev-f-staged"}, "f", 1, "Resolve Domain Operator"},
		"an explicit member":            {substoreScriptNetworkRender{SubscriptionID: "c"}, "p", 1, "Script Filter"},
		"a staged member":               {substoreScriptNetworkRender{SubscriptionID: "c", MemberRevisions: map[string]string{"p": "rev-p-staged"}}, "p", 2, "Script Operator"},
		"a deleted member":              {substoreScriptNetworkRender{SubscriptionID: "c", MemberRevisions: map[string]string{"p": ""}}, "tagged", 3, "Resolve Domain Operator"},
		"a file's node source":          {substoreScriptNetworkRender{SubscriptionID: "file"}, "p", 1, "Script Filter"},
		"a caller's chain":              {substoreScriptNetworkRender{SubscriptionID: "quiet", Operators: steps(scriptNetworkStepJSON("Script Filter", false)), Override: true}, "quiet", 1, "Script Filter"},
		"a caller's chain on a missing": {substoreScriptNetworkRender{SubscriptionID: "gone", Operators: steps(sorter, scriptNetworkStepJSON("Script Filter", false)), Override: true}, "gone", 2, "Script Filter"},
		"a collection ignores a chain":  {substoreScriptNetworkRender{SubscriptionID: "c", Operators: steps(scriptNetworkStepJSON("Script Operator", false)), Override: true}, "p", 1, "Script Filter"},
		"a draft":                       {substoreScriptNetworkRender{Operators: steps(sorter, scriptNetworkStepJSON("Script Operator", false)), Override: true}, "", 2, "Script Operator"},
		"no step":                       {substoreScriptNetworkRender{SubscriptionID: "quiet"}, "", 0, ""},
		"a missing record":              {substoreScriptNetworkRender{SubscriptionID: "gone"}, "", 0, ""},
		"a draft with no chain":         {substoreScriptNetworkRender{}, "", 0, ""},
	} {
		record, step := h.srv.substoreScriptNetworkStepFor(tc.render)
		switch {
		case tc.position == 0 && (record != "" || step != nil):
			t.Errorf("%s: found %q %+v", name, record, step)
		case tc.position != 0 && (record != tc.record || step == nil || step.Position != tc.position || step.Type != tc.kind):
			t.Errorf("%s: found %q %+v, want %q step %d (%s)", name, record, step, tc.record, tc.position, tc.kind)
		}
	}
	// The refusal of a render with no step found names the rendered record.
	got := decodeScriptNetworkRefusal(t, h.srv.substoreScriptNetworkRefusalFor(substoreScriptNetworkRender{SubscriptionID: "quiet"}))
	if got.Record != "quiet" || got.Step != nil {
		t.Fatalf("no step found: %+v", got)
	}
	// The gateway's relays read the record and the caller's chain from the
	// payload; a payload that does not decode names nothing.
	got = decodeScriptNetworkRefusal(t, h.srv.substoreScriptNetworkRelayRefusal(json.RawMessage(`{"subscription_id":"quiet","operators":[{"type":"Script Operator"}]}`)))
	requireRefusalStep(t, "a preview of unsaved steps", got, "quiet", 1, "Script Operator")
	got = decodeScriptNetworkRefusal(t, h.srv.substoreScriptNetworkRelayRefusal(json.RawMessage(`{"subscription_id":"f","revision":"rev-f-staged"}`)))
	requireRefusalStep(t, "a render of the staged revision", got, "f", 1, "Resolve Domain Operator")
	got = decodeScriptNetworkRefusal(t, h.srv.substoreScriptNetworkRelayRefusal(json.RawMessage(`{"source":"fleet","operators":[{"type":"Sort Operator"},{"type":"Script Filter"}]}`)))
	requireRefusalStep(t, "a draft", got, "", 2, "Script Filter")
	if got = decodeScriptNetworkRefusal(t, h.srv.substoreScriptNetworkRelayRefusal(json.RawMessage(`{"subscription_id":"f","operators":"nope"}`))); got.Record != "" || got.Step != nil {
		t.Fatalf("a payload that does not decode: %+v", got)
	}
	for _, method := range []string{"preview", "preview_draft", "render"} {
		if !substoreScriptNetworkRelayMethod(subStorePluginID, s2SubscriptionService(), method) {
			t.Errorf("%s is not relayed as the typed refusal", method)
		}
	}
	for _, call := range [][3]string{{subStorePluginID, s2SubscriptionService(), "save"}, {"other", "other/subscription", "preview"}, {subStorePluginID, subStorePlansService, "preview"}} {
		if substoreScriptNetworkRelayMethod(call[0], call[1], call[2]) {
			t.Errorf("%v is relayed as the typed refusal", call)
		}
	}
}

// s2SubscriptionService is the plugin's subscription service.
func s2SubscriptionService() string { return subStorePluginID + "/subscription" }

// TestSubstoreBindPreviewAnswersScriptNetworkRefusal: bind.preview answers
// the plugin's refusal with the typed 409 naming the stored step, and a
// render error that only carries the code later in its text stays "the
// record did not render".
func TestSubstoreBindPreviewAnswersScriptNetworkRefusal(t *testing.T) {
	env := bindShareFixture(t)
	records, _ := json.Marshal(map[string]any{"records": []map[string]any{{"id": "fleet-1", "source": "fleet",
		"process": []json.RawMessage{chainStep(map[string]any{"type": "Sort Operator"}), scriptNetworkStepJSON("Script Operator", false)}}}})
	putSubStoreRecords(t, env.st, string(records))
	renderErr := error(&pluginServiceError{message: scriptNetworkPluginMessage})
	env.srv.substoreCatalogue.bind.renderPlan = func(context.Context, substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
		return nil, "", renderErr
	}
	reader := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:read", "substore:read"}}}
	request := []byte(`{"subscription_id":"fleet-1","identity_id":"` + bindIdentityID + `"}`)
	_, err := env.srv.substoreBindRPC(bindOperatorCtx(reader), "preview", request)
	requireRefusalStep(t, "bind.preview", decodeScriptNetworkRefusal(t, err), "fleet-1", 2, "Script Operator")

	renderErr = &pluginServiceError{message: "render failed: " + scriptNetworkPluginMessage}
	_, err = env.srv.substoreBindRPC(bindOperatorCtx(reader), "preview", request)
	if got := catalogueAPIError(t, err); got.Code != model.APIErrorBadGateway || got.Message != "sub-store/bind preview: the record did not render" {
		t.Fatalf("a render error with the code later in its text: %+v", got)
	}
}

// TestSubStorePlanProposeAnswersScriptNetworkRefusal: propose over the real
// bind previewer answers the plugin's refusal of the staged revision with the
// typed 409 naming the staged step, and files no plan.
func TestSubStorePlanProposeAnswersScriptNetworkRefusal(t *testing.T) {
	h := newSubStorePlanHarness(t)
	sorter := chainStep(map[string]any{"type": "Sort Operator"})
	h.graph.setSteps(t, "rec", true, sorter, scriptNetworkStepJSON("Script Filter", true), scriptNetworkStepJSON("Script Operator", false))
	h.srv.subStoreSvc.previewer = substoreBindPlansPreviewer{s: h.srv}
	h.srv.substoreCatalogue.bind.renderPlan = func(_ context.Context, q substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
		if q.Revision == "rev-2" {
			return nil, "", &pluginServiceError{message: scriptNetworkPluginMessage}
		}
		return nil, "rev-1", nil
	}
	approvals := len(h.st.Approvals())
	_, err := h.call(subStoreSvcAdmin, subStorePlansService, "propose", `{"subscription_id":"rec","from_revision":"rev-1","to_revision":"rev-2"}`)
	requireRefusalStep(t, "propose", decodeScriptNetworkRefusal(t, err), "rec", 3, "Script Operator")
	if len(h.st.Approvals()) != approvals {
		t.Fatal("a refused propose filed a plan")
	}
}

// TestSubStorePlanDecisionAnswersScriptNetworkRefusal: a plan whose staged
// revision the plugin refuses at the decision stays pending, applies
// nothing, and the approver reads the code and the step.
func TestSubStorePlanDecisionAnswersScriptNetworkRefusal(t *testing.T) {
	h := newSubStorePlanHarness(t)
	h.graph.setSteps(t, "rec", true, scriptNetworkStepJSON("Resolve Domain Operator", false))
	reply := h.propose(t)
	h.previewer.setErr(h.srv.substoreScriptNetworkRefusalFor(substoreScriptNetworkRender{SubscriptionID: "rec", Revision: "rev-2"}))
	res := h.approve(subStorePlanApprover, reply.ApprovalID, reply.PlanSHA256, true)
	if res.Code != http.StatusConflict || apiErrorCodeOf(t, res.Body.Bytes()) != apiErrorFleetScriptNetworkUnavailable ||
		!strings.Contains(res.Body.String(), "step 1 (Resolve Domain Operator)") || !strings.Contains(res.Body.String(), "the plan stays pending") {
		t.Fatalf("approve with the staged chain refused: %d %s", res.Code, res.Body.String())
	}
	if h.appliedCount() != 0 || h.status(reply.ApprovalID).Status != model.ApprovalPending {
		t.Fatalf("a refused preview applied (%d) or decided the plan (%s)", h.appliedCount(), h.status(reply.ApprovalID).Status)
	}
}
