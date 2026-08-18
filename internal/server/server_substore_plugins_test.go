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
	if row.Path != "/sub/alpha/"+token {
		t.Fatalf("path = %q", row.Path)
	}
	if row.URL != "https://lattice.example/sub/alpha/"+token {
		t.Fatalf("url = %q", row.URL)
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
