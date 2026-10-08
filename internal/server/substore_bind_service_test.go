package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
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
	env.srv.substoreCatalogue.bind.renderPlan = func(_ context.Context, pluginID, subscriptionID, revision string, _ model.SubscriptionSnapshot) (*model.SelectionPlan, error) {
		revisions = append(revisions, revision)
		if subscriptionID != "fleet-1" || pluginID != subStorePluginID {
			t.Fatalf("preview rendered %s/%s", pluginID, subscriptionID)
		}
		plan := bindNodesPlan(t, env.rows)
		plan.Nodes[1] = bindNode(t, env.rows[1], plan.Nodes[1].Placeholders["uuid"], map[string]any{"server": "relay.attacker.example"})
		return &plan, nil
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
	if len(revisions) != 1 || revisions[0] != "r7" || reply.Revision != "r7" || reply.IdentityStatus != model.ProxyUserStatusActive {
		t.Fatalf("revisions %v, reply %+v", revisions, reply)
	}
	if len(reply.Entries) != len(env.rows)-1 || len(reply.Excluded) != 1 || reply.Excluded[0].Index != 1 ||
		reply.Excluded[0].Reason != "plan_rejected:server" || reply.Refused != "" || reply.FleetNodes != len(env.rows) {
		t.Fatalf("reply %+v", reply)
	}

	// A record that renders a document has nothing to bind.
	env.srv.substoreCatalogue.bind.renderPlan = func(context.Context, string, string, string, model.SubscriptionSnapshot) (*model.SelectionPlan, error) {
		return nil, nil
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
	_, err = s.substoreBindRPC(bindOperatorCtx(session), "reveal_entry", request(grant))
	if err == nil {
		t.Fatal("an excluded line was revealed")
	}
	if apiErr := catalogueAPIError(t, err); apiErr.Code != apiErrorSubstoreLineExcluded || !strings.Contains(apiErr.Message, identityLineNotApplied) {
		t.Fatalf("an excluded line: %+v", apiErr)
	}
}
