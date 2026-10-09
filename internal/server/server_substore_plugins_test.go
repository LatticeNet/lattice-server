package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func TestSubStoreSharesRPCListsOnlySubStoreSharesWithURLs(t *testing.T) {
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Store: st, AdminPassword: testAdminPass, PublicURL: "https://lattice.example/", DisableRenewalScheduler: true})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.pluginRPC.Owns(subStorePluginID, subStoreSharesService) {
		t.Fatal("sub-store shares core service was not registered to the sub-store plugin")
	}

	token := strings.Repeat("b", 32)
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "sh-sub", Slug: "alpha", Token: token, Enabled: true, DefaultFormat: "plain",
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "sub-1"}})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "sh-other", Slug: "other", Token: strings.Repeat("c", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: "latticenet.vpn-core", SubscriptionID: "x"}})
	mustUpsertShare(t, st, model.SubscriptionShare{ID: "sh-core", Slug: "coreuser", Token: strings.Repeat("d", 32), Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourceCoreProxyUser, ProxyUserID: "pu-1"}})

	admin := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"proxy:admin", "substore:admin"}}}
	ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, admin)
	out, err := srv.subStoreSharesRPC(ctx, "list", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Shares []subStoreShareRow `json:"shares"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Shares) != 1 {
		t.Fatalf("expected exactly the sub-store share, got %d rows: %+v", len(result.Shares), result.Shares)
	}
	row := result.Shares[0]
	if row.SubscriptionID != "sub-1" || row.ShareID != "sh-sub" || row.Slug != "alpha" || !row.Enabled || row.DefaultFormat != "plain" {
		t.Fatalf("unexpected row: %+v", row)
	}
	// A list carries no link: the token in it is the subscription's
	// credential.
	if row.Path != "" || row.URL != "" || row.Revealed || strings.Contains(string(out), token) || !strings.Contains(string(out), `"path":""`) {
		t.Fatalf("an unrevealed list must carry no token: %s", out)
	}

	// Asking for one share's link goes through the reveal gate, on the
	// operator's own gateway call. An admin session without step-up is
	// refused with the gate's code.
	srv.pluginRPC.SetOwnerActive(func(string) bool { return true })
	if _, err := srv.callCoreServiceForOperator(ctx, subStoreSharesService, "list", []byte(`{"share_id":"sh-sub"}`)); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("a reveal without step-up must be refused with 403, got %v", err)
	}
	// A token carrying secrets:reveal gets that row's link, and only that row's.
	revealer := principal{Principal: rbac.Principal{ActorID: "agent", TokenID: "token_reveal", Scopes: []string{"proxy:admin", rbac.SecretRevealScope}}, viaBearer: true}
	out, err = srv.callCoreServiceForOperator(context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, revealer), subStoreSharesService, "list", []byte(`{"share_id":"sh-sub"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	row = result.Shares[0]
	if row.Path != "/sub/alpha/"+token || row.URL != "https://lattice.example/sub/alpha/"+token || !row.Revealed {
		t.Fatalf("revealed row = %+v", row)
	}
	audited := false
	for _, ev := range st.AuditEvents() {
		if ev.Action == auditActionShareReveal && ev.Metadata["share_id"] == "sh-sub" && ev.Metadata["token_id"] == "token_reveal" {
			audited = true
		}
		for _, v := range ev.Metadata {
			if strings.Contains(v, token) {
				t.Fatalf("the audit trail holds the token: %+v", ev)
			}
		}
	}
	if !audited {
		t.Fatal("a token reveal of a share link must be audited with the token id")
	}
	if _, err := srv.callCoreServiceForOperator(ctx, subStoreSharesService, "list", []byte(`{"share_id":"sh-other"}`)); err == nil {
		t.Fatal("a share outside the sub-store plugin must not be revealed through its RPC")
	}

	// The handler re-checks proxy:admin itself: a manifest that misdeclared the
	// method's scopes must not widen who can read share URLs.
	limited := principal{Principal: rbac.Principal{ActorID: "op2", Scopes: []string{"substore:admin"}}}
	if _, err := srv.subStoreSharesRPC(context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, limited), "list", nil); err == nil {
		t.Fatal("list without proxy:admin must be denied")
	}
	if _, err := srv.subStoreSharesRPC(context.Background(), "list", nil); err == nil {
		t.Fatal("list without an operator principal must be denied")
	}
	if _, err := srv.subStoreSharesRPC(ctx, "mint", nil); err == nil {
		t.Fatal("unknown method must be refused")
	}
}
