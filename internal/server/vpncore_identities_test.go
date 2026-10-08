package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The identity pickers' list names who a share may serve and whether that
// identity can be served now, and nothing a client could connect with.
func TestVPNCoreIdentitiesListIsCredentialFree(t *testing.T) {
	e := catalogueFixture(t, 1, 2)
	const activeUUID = "3d4e5f60-7182-4a9b-8c0d-1e2f3a4b5c6d"
	const activePassword = "trojan-secret-password"
	catalogueIdentity(t, e, activeUUID, activePassword)
	for _, u := range []VpnUser{
		{ID: "vu-off", Email: "off@example.com", Enabled: false, Credentials: []VpnCredential{{Protocol: "vless", UUID: "4e5f6071-8293-4bac-9d1e-2f3a4b5c6d7e"}}},
		{ID: "vu-old", Email: "old@example.com", Name: "Old", Group: "trial", Enabled: true, ExpiresAt: e.now.Add(-time.Hour),
			Credentials: []VpnCredential{{Protocol: "hysteria2", Password: "hy2-secret-password"}}},
	} {
		if err := e.srv.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := e.srv.vpnCoreIdentitiesRPC(context.Background(), "list", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{activeUUID, activePassword, "4e5f6071-8293-4bac-9d1e-2f3a4b5c6d7e", "hy2-secret-password"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("identities list carries a credential: %s", raw)
		}
	}
	for _, key := range []string{`"credentials"`, `"bindings"`, `"sub_id"`, `"link"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("identities list carries %s: %s", key, raw)
		}
	}
	var reply vpnCoreIdentitiesListReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatal(err)
	}
	byID := map[string]vpnCoreIdentityItem{}
	for _, item := range reply.Identities {
		byID[item.ID] = item
	}
	if reply.Count != 3 || len(byID) != 3 {
		t.Fatalf("list = %s", raw)
	}
	if got := byID["vu-cat"]; got.Status != model.ProxyUserStatusActive || got.BoundLines != 2 || got.Name != "Cat" || got.Email != "cat@example.com" {
		t.Fatalf("active identity = %+v", got)
	}
	if got := byID["vu-off"]; got.Status == model.ProxyUserStatusActive || got.Reason == "" || got.BoundLines != 0 {
		t.Fatalf("disabled identity = %+v", got)
	}
	if got := byID["vu-old"]; got.Status == model.ProxyUserStatusActive || got.ExpiresAt == nil || got.Group != "trial" {
		t.Fatalf("expired identity = %+v", got)
	}

	for method, request := range map[string]string{"list": `{"identity_id":"vu-cat"}`, "get": `{}`} {
		if _, err := e.srv.vpnCoreIdentitiesRPC(context.Background(), method, []byte(request)); catalogueAPIError(t, err).Code != model.APIErrorBadRequest {
			t.Fatalf("%s %s: %v", method, request, err)
		}
	}
	if _, err := e.srv.vpnCoreIdentitiesRPC(context.Background(), "list", nil); err != nil {
		t.Fatalf("an empty request: %v", err)
	}
}
