package server

import (
	"context"
	"encoding/json"
	"testing"
)

func TestVPNCoreSubscriptionsRPC(t *testing.T) {
	srv := newLinesTestServer(t)
	// enabled identity with a sub token + bindings + credentials
	if err := srv.putVpnUser(VpnUser{
		ID: "vu-1", Email: "a@example.com", Enabled: true, SubID: "tok-a",
		Credentials: []VpnCredential{{Protocol: "vless", UUID: "x"}},
		Bindings:    []LineBinding{{LineHashID: "line_x", Enabled: true}},
		CreatedAt:   srv.now(), UpdatedAt: srv.now(),
	}); err != nil {
		t.Fatal(err)
	}
	// disabled identity, no sub token
	if err := srv.putVpnUser(VpnUser{
		ID: "vu-2", Email: "b@example.com", Enabled: false,
		CreatedAt: srv.now(), UpdatedAt: srv.now(),
	}); err != nil {
		t.Fatal(err)
	}

	raw, err := srv.vpnCoreSubscriptionsRPC(context.Background(), "query", nil)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var out struct {
		Subscriptions []SubscriptionSummary `json:"subscriptions"`
		Count         int                   `json:"count"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Count != 2 {
		t.Fatalf("count wrong: %+v", out)
	}
	byID := map[string]SubscriptionSummary{}
	for _, s := range out.Subscriptions {
		byID[s.UserID] = s
	}
	a, b := byID["vu-1"], byID["vu-2"]
	if !a.Eligible || !a.HasSubToken || a.BindingCount != 1 || a.CredentialCount != 1 {
		t.Fatalf("vu-1 wrong: %+v", a)
	}
	if b.Eligible || b.HasSubToken {
		t.Fatalf("vu-2 (disabled) should be ineligible with no token: %+v", b)
	}
	if _, err := srv.vpnCoreSubscriptionsRPC(context.Background(), "bogus", nil); err == nil {
		t.Fatal("bogus method should error")
	}
}
