package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Leak table row 2: a share of a record that reads the identity-less vpn-core
// export, directly, through a combination (by member or by tag) or through a
// file's node source, is refused without the explicit flag, and created with
// it carries the flag in its view and its audit.
func TestSharingTheVPNCoreFleetFeedNeedsAnExplicitFlag(t *testing.T) {
	h := newRevealHarness(t)
	doc := `{"version":1,"records":[
		{"id":"fleet","name":"Everyone","source":"vpn-core","tags":["home"]},
		{"id":"alice-only","name":"Alice","source":"vpn-core","vpn_identity":"vpnuser_alice"},
		{"id":"graph","name":"Graph","source":"vpn-core-graph","vpn_identity":"vpnuser_alice","entry_roots":["x"]},
		{"id":"provider","name":"Provider","url":"https://provider.example/sub"},
		{"id":"combo-member","kind":"collection","name":"Combo","members":["provider","fleet"]},
		{"id":"combo-tag","kind":"collection","name":"Tagged","member_tags":["home"]},
		{"id":"combo-clean","kind":"collection","name":"Clean","members":["provider","alice-only"]},
		{"id":"clash-file","kind":"file","name":"Clash file","node_source":"combo-tag"}
	]}`
	if err := h.srv.store.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: usageSubStoreRecordsKey, Value: doc}); err != nil {
		t.Fatal(err)
	}
	create := func(slug, record string, flag bool) (int, string) {
		body := `{"slug":"` + slug + `","source":{"kind":"plugin","plugin_id":"latticenet.sub-store","subscription_id":"` + record + `"}`
		if flag {
			body += `,"publishes_fleet_credentials":true`
		}
		body += `}`
		res := doJSON(t, h.handler, http.MethodPost, "/api/subscription-shares", body, h.cookies, h.csrf)
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(raw)
	}
	for _, record := range []string{"fleet", "combo-member", "combo-tag", "clash-file"} {
		status, body := create("s-"+record, record, false)
		if status != http.StatusBadRequest || apiErrorCodeOf(t, []byte(body)) != apiErrorFleetFeedFlagRequired || !strings.Contains(body, "Everyone") {
			t.Fatalf("%s: a fleet feed share without the flag must be refused naming the feed, got %d %s", record, status, body)
		}
	}
	for _, record := range []string{"alice-only", "graph", "provider", "combo-clean"} {
		status, body := create("s-"+record, record, false)
		if status != http.StatusCreated || strings.Contains(body, shareExtraFleetCredentials) {
			t.Fatalf("%s: a record without the fleet feed must share as before, got %d %s", record, status, body)
		}
	}
	status, body := create("s-fleet-flagged", "fleet", true)
	if status != http.StatusCreated || !strings.Contains(body, `"publishes_fleet_credentials":true`) {
		t.Fatalf("with the flag the share is created and says so: %d %s", status, body)
	}
	audited := false
	for _, ev := range h.srv.store.AuditEvents() {
		if ev.Action == auditActionShareCreate && ev.Metadata[shareExtraFleetCredentials] == "true" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("a fleet feed share must be audited as one")
	}
	// A slug an identity link holds is taken for shares too.
	now := h.srv.now()
	if err := h.srv.putVpnUser(VpnUser{ID: "vpnuser_alice", Email: "a@example.com", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	slug := "u-sharedslug"
	if _, err := h.srv.issueIdentityLink(principal{}, "vpnuser_alice", identityLinkWriteRequest{Slug: &slug}); err != nil {
		t.Fatal(err)
	}
	if status, body := create(slug, "provider", false); status != http.StatusConflict {
		t.Fatalf("a share on an identity link's slug must be refused: %d %s", status, body)
	}
}

// The guard fails closed on a record list it cannot read, and the share
// views re-run it, so a record edited into the fleet feed after its share
// was made is named on every read instead of passing unseen.
func TestFleetFeedGuardFailsClosedAndRechecksOnRead(t *testing.T) {
	h := newRevealHarness(t)
	putRecords := func(doc string) {
		t.Helper()
		if err := h.srv.store.PutKV(model.KVEntry{Bucket: usageSubStoreKVBucket, Key: usageSubStoreRecordsKey, Value: doc}); err != nil {
			t.Fatal(err)
		}
	}
	create := func(slug, record string, flag bool) (int, string) {
		body := `{"slug":"` + slug + `","source":{"kind":"plugin","plugin_id":"latticenet.sub-store","subscription_id":"` + record + `"}`
		if flag {
			body += `,"publishes_fleet_credentials":true`
		}
		body += `}`
		res := doJSON(t, h.handler, http.MethodPost, "/api/subscription-shares", body, h.cookies, h.csrf)
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(raw)
	}
	list := func() map[string]shareView {
		t.Helper()
		res := doJSON(t, h.handler, http.MethodGet, "/api/subscription-shares", "", h.cookies, h.csrf)
		defer res.Body.Close()
		var views []shareView
		if err := json.NewDecoder(res.Body).Decode(&views); err != nil {
			t.Fatal(err)
		}
		out := map[string]shareView{}
		for _, v := range views {
			out[v.Slug] = v
		}
		return out
	}

	putRecords(`{"version":1,"records":[{"id":"provider","name":"Provider","url":"https://provider.example/sub"},
		{"id":"fleet","name":"Everyone","source":"vpn-core"}]}`)
	if status, body := create("s-provider", "provider", false); status != http.StatusCreated {
		t.Fatalf("a clean record shares: %d %s", status, body)
	}
	if status, body := create("s-fleet", "fleet", true); status != http.StatusCreated {
		t.Fatalf("a flagged fleet share is created: %d %s", status, body)
	}
	if views := list(); views["s-provider"].FleetFeedNow != "" || views["s-fleet"].FleetFeedNow != "" || !views["s-fleet"].PublishesFleetCredentials {
		t.Fatalf("clean and flagged shares carry no re-check answer: %+v", views)
	}

	// The provider record is edited into the identity-less vpn-core source.
	putRecords(`{"version":1,"records":[{"id":"provider","name":"Provider","source":"vpn-core"},
		{"id":"fleet","name":"Everyone","source":"vpn-core"}]}`)
	if views := list(); views["s-provider"].FleetFeedNow != fleetFeedNowFleet || views["s-fleet"].FleetFeedNow != "" {
		t.Fatalf("an edited record must be named on read: %+v", views)
	}

	// A record list that does not parse checks nothing, so it needs the flag.
	putRecords(`{"records":[`)
	status, body := create("s-unknown", "provider", false)
	if status != http.StatusBadRequest || apiErrorCodeOf(t, []byte(body)) != apiErrorFleetFeedFlagRequired || !strings.Contains(body, "cannot check") {
		t.Fatalf("an unreadable record list must need the flag: %d %s", status, body)
	}
	if status, body = create("s-unknown", "provider", true); status != http.StatusCreated || !strings.Contains(body, `"publishes_fleet_credentials":true`) {
		t.Fatalf("with the flag it is created and flagged: %d %s", status, body)
	}
	if views := list(); views["s-provider"].FleetFeedNow != fleetFeedNowUnknown {
		t.Fatalf("an unreadable list answers unknown on read: %+v", views["s-provider"])
	}
	// So does one over the size limit.
	putRecords(`{"records":[],"pad":"` + strings.Repeat("x", usageMaxSubStoreRecordsLen) + `"}`)
	if views := list(); views["s-provider"].FleetFeedNow != fleetFeedNowUnknown {
		t.Fatalf("an oversized list answers unknown on read: %+v", views["s-provider"])
	}
}
