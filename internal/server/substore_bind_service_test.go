package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// bindOperatorCtx is an operator's own call to the bind service through the
// plugin gateway.
func bindOperatorCtx(p principal) context.Context {
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, p)
	return context.WithValue(ctx, operatorCoreCallKey{}, substoreBindService)
}

// bind.preview answers what one identity receives from one record revision:
// entries and exclusions with reasons, and no credential.
func TestSubstoreBindPreviewIsCredentialFree(t *testing.T) {
	env := bindShareFixture(t)
	var revisions []string
	env.srv.substoreCatalogue.bind.renderPlan = func(_ context.Context, q substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
		revisions = append(revisions, q.Revision)
		if q.SubscriptionID != "fleet-1" || q.PluginID != subStorePluginID {
			t.Fatalf("preview rendered %s/%s", q.PluginID, q.SubscriptionID)
		}
		plan := bindNodesPlan(t, env.rows)
		plan.Nodes[1] = bindNode(t, env.rows[1], plan.Nodes[1].Placeholders["uuid"], map[string]any{"server": "relay.attacker.example"})
		return &plan, "r6", nil
	}
	reader := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:read", "substore:read"}}}
	out, err := env.srv.substoreBindRPC(bindOperatorCtx(reader), "preview", []byte(`{"subscription_id":"fleet-1","revision":"r7","identity_id":"`+bindIdentityID+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if carriesCredential(string(out), bindIdentityUUID) || strings.Contains(string(out), model.PlanPlaceholderPrefix) {
		t.Fatalf("the preview carries a credential or a placeholder: %s", out)
	}
	var reply substoreBindPreviewReply
	if err := json.Unmarshal(out, &reply); err != nil {
		t.Fatal(err)
	}
	if len(revisions) != 1 || revisions[0] != "r7" || reply.Revision != "r7" || reply.LiveRevision != "r6" || reply.IdentityStatus != model.ProxyUserStatusActive {
		t.Fatalf("revisions %v, reply %+v", revisions, reply)
	}
	if len(reply.Entries) != len(env.rows)-1 || len(reply.Excluded) != 1 || reply.Excluded[0].Index != 1 ||
		reply.Excluded[0].Reason != "plan_rejected:server" || reply.Refused != "" || reply.FleetNodes != len(env.rows) {
		t.Fatalf("reply %+v", reply)
	}

	// A record that renders a document has nothing to bind.
	env.srv.substoreCatalogue.bind.renderPlan = func(context.Context, substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
		return nil, "", nil
	}
	if _, err := env.srv.substoreBindRPC(bindOperatorCtx(reader), "preview", []byte(`{"subscription_id":"fleet-1","identity_id":"`+bindIdentityID+`"}`)); err == nil ||
		catalogueAPIError(t, err).Code != apiErrorSubstoreNotFleetBound {
		t.Fatalf("a document record: %v", err)
	}
	for name, request := range map[string]string{
		"an unknown field":    `{"subscription_id":"fleet-1","identity_id":"` + bindIdentityID + `","bind":true}`,
		"no identity":         `{"subscription_id":"fleet-1"}`,
		"an unknown identity": `{"subscription_id":"fleet-1","identity_id":"nobody"}`,
	} {
		if _, err := env.srv.substoreBindRPC(bindOperatorCtx(reader), "preview", []byte(request)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// Both scopes are checked in core.
	for _, scopes := range [][]string{{"substore:read"}, {"vpncore:read"}} {
		p := principal{Principal: rbac.Principal{ActorID: "op", Scopes: scopes}}
		if _, err := env.srv.substoreBindRPC(bindOperatorCtx(p), "preview", []byte(`{"subscription_id":"fleet-1","identity_id":"`+bindIdentityID+`"}`)); err == nil {
			t.Fatalf("preview with only %v was allowed", scopes)
		}
	}
}

// bind.reveal_entry returns one bound line's URI only under vpncore:admin,
// the operator's own call and the step-up reveal gate. Without step-up it is
// refused and the refusal audited; with it, the reveal is audited and no
// audit record holds the URI or the credential.
func TestSubstoreBindRevealEntryNeedsStepUpAndIsAudited(t *testing.T) {
	env := bindFixture(t, 1, 2)
	s := env.srv
	line := env.rows[0].LineUUID
	session := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:admin"}}, sessionID: "sess-reveal"}
	request := func(grant string) []byte {
		raw, _ := json.Marshal(map[string]string{"identity_id": bindIdentityID, "line_uuid": line, "step_up_grant": grant})
		return raw
	}

	_, err := s.substoreBindRPC(bindOperatorCtx(session), "reveal_entry", request(""))
	if err == nil || catalogueAPIError(t, err).Code != apiErrorStepUpRequired {
		t.Fatalf("a reveal without step-up: %v", err)
	}
	denied := false
	for _, ev := range env.st.AuditEvents() {
		if ev.Action == auditActionSubstoreBindRevealEntry && ev.Decision == "deny" && ev.Metadata["line_uuid"] == line {
			denied = true
		}
	}
	if !denied {
		t.Fatal("a refused reveal must be audited")
	}

	grant, _, err := s.issueStepUpGrant(session)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.substoreBindRPC(bindOperatorCtx(session), "reveal_entry", request(grant))
	if err != nil {
		t.Fatal(err)
	}
	var reply substoreBindRevealEntryReply
	if err := json.Unmarshal(out, &reply); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reply.URI, "vless://"+bindIdentityUUID+"@"+env.rows[0].Template.Host+":") || !strings.Contains(reply.URI, "flow="+bindIdentityFlow) ||
		reply.LineUUID != line || reply.Label != "Node 000 vless-20000" {
		t.Fatalf("reply %+v", reply)
	}
	allowed := false
	for _, ev := range env.st.AuditEvents() {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), reply.URI) || carriesCredential(string(raw), bindIdentityUUID) {
			t.Fatalf("an audit record holds the URI or the credential: %s", raw)
		}
		if ev.Action == auditActionSubstoreBindRevealEntry && ev.Decision == "allow" && ev.Metadata["line_uuid"] == line &&
			ev.Metadata["identity_id"] == bindIdentityID && ev.Metadata["via"] == revealViaStepUp {
			allowed = true
		}
	}
	if !allowed {
		t.Fatal("an allowed reveal must be audited")
	}

	// A plugin method's rpc.call made while serving the operator gets no URI,
	// whatever the operator holds.
	viaPlugin := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, session)
	if _, err := s.substoreBindRPC(viaPlugin, "reveal_entry", request(grant)); err == nil {
		t.Fatal("reveal_entry answered a call that did not come through the gateway")
	}
	// vpncore:admin is checked in core.
	reader := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:read"}}, sessionID: "sess-reveal"}
	if _, err := s.substoreBindRPC(bindOperatorCtx(reader), "reveal_entry", request(grant)); err == nil {
		t.Fatal("reveal_entry at vpncore:read was allowed")
	}
	// A line the identity cannot be bound to now is refused by its reason.
	u := env.identity
	u.Bindings[0].AppliedCredentialSHA256 = ""
	if err := s.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	// Without step-up the gate answers first, so a caller learns nothing
	// about the identity or the line.
	if _, err := s.substoreBindRPC(bindOperatorCtx(session), "reveal_entry", request("")); err == nil || catalogueAPIError(t, err).Code != apiErrorStepUpRequired {
		t.Fatalf("an excluded line without step-up: %v", err)
	}
	unknown, _ := json.Marshal(map[string]string{"identity_id": "nobody", "line_uuid": line})
	if _, err := s.substoreBindRPC(bindOperatorCtx(session), "reveal_entry", unknown); err == nil || catalogueAPIError(t, err).Code != apiErrorStepUpRequired {
		t.Fatalf("an unknown identity without step-up: %v", err)
	}
	_, err = s.substoreBindRPC(bindOperatorCtx(session), "reveal_entry", request(grant))
	if err == nil {
		t.Fatal("an excluded line was revealed")
	}
	if apiErr := catalogueAPIError(t, err); apiErr.Code != apiErrorSubstoreLineExcluded || !strings.Contains(apiErr.Message, identityLineNotApplied) {
		t.Fatalf("an excluded line: %+v", apiErr)
	}
	excludedAudited := false
	for _, ev := range env.st.AuditEvents() {
		if ev.Action == auditActionSubstoreBindRevealEntry && ev.Decision == "deny" && strings.Contains(ev.Reason, identityLineNotApplied) &&
			ev.Metadata["line_uuid"] == line {
			excludedAudited = true
		}
	}
	if !excludedAudited {
		t.Fatal("an excluded line's refusal must be audited")
	}
}

// reveal_entry reached the way the console reaches it: through the plugin
// gateway, under a manifest that declares it at vpncore:admin. The gateway
// refuses an operator without that scope, the step-up gate holds, every call
// is audited by the gateway beside the reveal's own record, and core still
// refuses vpncore:read when a manifest under-declares the method.
func TestSubstoreBindRevealEntryThroughThePluginGateway(t *testing.T) {
	env := bindFixture(t, 1, 2)
	s := env.srv
	line := env.rows[0].LineUUID
	install := func(scope string) {
		manifest := e2eManifest(t)
		for i := range manifest.Interfaces {
			if c := &manifest.Interfaces[i]; c.Service == substoreBindService {
				c.MethodSpecs = append(c.MethodSpecs, plugin.InterfaceMethod{Name: "reveal_entry", Effect: plugin.InterfaceEffectRead, Scopes: []string{scope}})
			}
		}
		if err := plugin.ValidateManifest(manifest); err != nil {
			t.Fatal(err)
		}
		s.plugins = []plugin.Loaded{{Manifest: manifest, Capabilities: manifest.Capabilities}}
	}
	install("vpncore:admin")
	if err := env.st.UpsertPluginInstallation(model.PluginInstallation{ID: subStorePluginID, Name: "Sub-Store", Type: plugin.TypeSystem,
		Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	gateway := func(p principal, grant string) (int, []byte) {
		body, _ := json.Marshal(map[string]any{"id": subStorePluginID, "service": substoreBindService, "method": "reveal_entry",
			"payload": map[string]string{"identity_id": bindIdentityID, "line_uuid": line, "step_up_grant": grant}})
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.handlePluginCall(rec, req, p)
		return rec.Code, rec.Body.Bytes()
	}
	// audits counts the gateway's plugin.call records and the reveal's own.
	audits := func(action, decision string) int {
		n := 0
		for _, ev := range env.st.AuditEvents() {
			if ev.Action != action || ev.Decision != decision {
				continue
			}
			if action == "plugin.call" && (ev.Metadata["service"] != substoreBindService || ev.Metadata["method"] != "reveal_entry") {
				continue
			}
			if action == auditActionSubstoreBindRevealEntry && ev.Metadata["line_uuid"] != line {
				continue
			}
			n++
		}
		return n
	}
	admin := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:admin"}}, sessionID: "sess-reveal"}
	reader := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:read"}}, sessionID: "sess-reveal"}
	grant, _, err := s.issueStepUpGrant(admin)
	if err != nil {
		t.Fatal(err)
	}

	// The gateway asks for the scope the manifest declares.
	if code, body := gateway(reader, grant); code != http.StatusForbidden || carriesCredential(string(body), bindIdentityUUID) {
		t.Fatalf("reveal_entry at vpncore:read through the gateway: %d %s", code, body)
	}
	scopeDenied := false
	for _, ev := range env.st.AuditEvents() {
		if ev.Action == "plugin.call" && ev.Decision == "deny" && ev.Metadata["method"] == "reveal_entry" && ev.Reason == "missing scope vpncore:admin" {
			scopeDenied = true
		}
	}
	if !scopeDenied || audits(auditActionSubstoreBindRevealEntry, "deny") != 0 {
		t.Fatal("the gateway's scope refusal must be its own, and audited")
	}

	// Without step-up the reveal gate refuses, and the gateway and the
	// reveal both record it.
	code, body := gateway(admin, "")
	var refusal model.APIErrorResponse
	if code != http.StatusForbidden || json.Unmarshal(body, &refusal) != nil || refusal.Error.Code != apiErrorStepUpRequired ||
		carriesCredential(string(body), bindIdentityUUID) {
		t.Fatalf("a reveal without step-up through the gateway: %d %s", code, body)
	}
	if audits("plugin.call", "deny") != 2 || audits(auditActionSubstoreBindRevealEntry, "deny") != 1 {
		t.Fatal("a reveal refused for step-up must be audited by the gateway and by the reveal")
	}

	// With step-up the URI comes back, audited by both, and no audit record
	// holds it.
	code, body = gateway(admin, grant)
	if code != http.StatusOK {
		t.Fatalf("a stepped-up reveal through the gateway: %d %s", code, body)
	}
	var reply substoreBindRevealEntryReply
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reply.URI, "vless://"+bindIdentityUUID+"@"+env.rows[0].Template.Host+":") || reply.LineUUID != line {
		t.Fatalf("reply %+v", reply)
	}
	if audits("plugin.call", "allow") != 1 || audits(auditActionSubstoreBindRevealEntry, "allow") != 1 {
		t.Fatal("an allowed reveal must be audited by the gateway and by the reveal")
	}
	for _, ev := range env.st.AuditEvents() {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), reply.URI) || carriesCredential(string(raw), bindIdentityUUID) {
			t.Fatalf("an audit record holds the URI or the credential: %s", raw)
		}
	}

	// Core does not take the manifest's word for the scope: under one that
	// declares reveal_entry at vpncore:read, a stepped-up vpncore:read
	// operator passes the gateway and is still refused.
	install("vpncore:read")
	if code, body := gateway(reader, grant); code != http.StatusForbidden || carriesCredential(string(body), bindIdentityUUID) {
		t.Fatalf("an under-declared reveal_entry at vpncore:read: %d %s", code, body)
	}
	if audits(auditActionSubstoreBindRevealEntry, "allow") != 1 {
		t.Fatal("an under-declared reveal was recorded as a reveal")
	}
}

// bind.preview of a record whose snapshot does not say which lines it
// selected answers the refusal a share would, and binds nothing.
func TestSubstoreBindPreviewRefusesAPlanWithoutASelection(t *testing.T) {
	env := bindShareFixture(t)
	env.srv.substoreCatalogue.bind.renderPlan = func(context.Context, substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
		plan := bindNodesPlan(t, env.rows)
		return &plan, "", nil
	}
	reader := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:read", "substore:read"}}}
	out, err := env.srv.substoreBindRPC(bindOperatorCtx(reader), "preview", []byte(`{"subscription_id":"fleet-foreign","identity_id":"`+bindIdentityID+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var reply substoreBindPreviewReply
	if err := json.Unmarshal(out, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Refused != substoreBindRefusedSelection || len(reply.Entries) != 0 || reply.FleetNodes != len(env.rows) {
		t.Fatalf("reply %+v", reply)
	}
}
