package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func decodeBody[T any](t *testing.T, res *http.Response) T {
	t.Helper()
	defer res.Body.Close()
	var out T
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return out
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

type channelTestAnswer struct {
	OK       bool                    `json:"ok"`
	Delivery store.NotifyDelivery    `json:"delivery"`
	Health   notifyChannelHealthView `json:"health"`
}

// A stored channel is tested without its config leaving the server, the test
// shows in the Sent log, a success clears the channel's failing state, and a
// failure says why in classified words without counting toward failing.
func TestStoredChannelTest(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	create := doJSON(t, handler, http.MethodPost, "/api/notify/channels",
		`{"id":"nc-tg","name":"Telegram","kind":"telegram","config":{"token":"SECRET-TOKEN","chat_id":"123"}}`, cookies, csrf)
	if create.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %s", create.StatusCode, readAll(t, create))
	}
	create.Body.Close()
	fake := installFakeNotifySender(srv, func(string, int) error { return upstream(401) })

	res := doJSON(t, handler, http.MethodPost, "/api/notify/channels/test", `{"id":"nc-tg"}`, cookies, csrf)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("test: %d %s", res.StatusCode, readAll(t, res))
	}
	failed := decodeBody[channelTestAnswer](t, res)
	if failed.OK || failed.Delivery.Reason != "upstream status 401" || failed.Delivery.Role != store.NotifyRoleTest {
		t.Fatalf("failed test = %+v", failed)
	}
	if failed.Health.State != notifyHealthDegraded || failed.Health.ConsecutiveFailures != 0 || failed.Health.LastFailureKind != notifyKindUpstream4xx {
		t.Fatalf("health after a failed test = %+v", failed.Health)
	}

	// The channel is failing for real (three settled failures), then a test
	// succeeds: the test clears it and announces the recovery.
	if err := st.PutNotifyDelivery(store.NotifyDelivery{ID: "nd-x", EventID: "evt-x", ChannelID: "nc-tg", Source: store.NotifySourceServer, Outcome: store.NotifyOutcomeFailed, CreatedAt: failed.Delivery.CreatedAt},
		&store.NotifyChannelHealth{ChannelID: "nc-tg", LastAttemptAt: failed.Delivery.CreatedAt, LastFailureAt: failed.Delivery.CreatedAt, ConsecutiveFailures: 3, FailingSince: failed.Delivery.CreatedAt, Announced: true, AnnouncedAt: failed.Delivery.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	fake.setAnswer(nil)
	res = doJSON(t, handler, http.MethodPost, "/api/notify/channels/test", `{"id":"nc-tg"}`, cookies, csrf)
	body := readAll(t, res)
	if strings.Contains(body, "SECRET-TOKEN") {
		t.Fatal("the test answer carries the channel token")
	}
	var ok channelTestAnswer
	if err := json.Unmarshal([]byte(body), &ok); err != nil {
		t.Fatal(err)
	}
	if !ok.OK || ok.Delivery.Outcome != store.NotifyOutcomeSent || ok.Health.State != notifyHealthOK || ok.Health.ConsecutiveFailures != 0 {
		t.Fatalf("passed test = %+v", ok)
	}
	if got := fake.sentTo("nc-tg"); len(got) < 2 || got[0].title != "Lattice test" {
		t.Fatalf("sends = %+v", got)
	}
	if rows := st.NotifyDeliveries(store.NotifyDeliveryFilter{EventType: EventNotifyChannelOK}); len(rows) != 1 {
		t.Fatalf("recovery announcements = %+v", rows)
	}

	res = doJSON(t, handler, http.MethodPost, "/api/notify/channels/test", `{"id":"nc-missing"}`, cookies, csrf)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing channel: %d", res.StatusCode)
	}
	res.Body.Close()
}

// The Sent log lists the outbox newest first, filters it, and is refused to a
// token without notify:admin and to a node-confined one; the channel list,
// which now carries health, is refused to a confined token too.
func TestNotifyDeliveriesRoute(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-b", "Bark info")
	installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-b" {
			return upstream(400)
		}
		return nil
	})
	srv.notifyEventTyped(EventNodeOffline, "Node offline: alpha", "first")
	waitOutboxSettled(t, srv)
	srv.notifyEventTyped(EventServiceDown, "sing-box down on bravo", "second")
	waitOutboxSettled(t, srv)

	type page struct {
		Deliveries []store.NotifyDelivery `json:"deliveries"`
		Stored     int                    `json:"stored"`
		Durable    bool                   `json:"durable"`
		Max        int                    `json:"max"`
		Floor      int                    `json:"floor"`
	}
	all := decodeBody[page](t, doJSON(t, handler, http.MethodGet, "/api/notify/deliveries", "", cookies, ""))
	if len(all.Deliveries) != 4 || all.Stored != 4 || all.Durable || all.Max != store.MaxNotifyDeliveries || all.Floor != store.NotifyDeliveryFloorPerSource {
		t.Fatalf("page = %+v", all)
	}
	if all.Deliveries[0].EventType != EventServiceDown || all.Deliveries[3].EventType != EventNodeOffline {
		t.Fatalf("not newest first: %+v", all.Deliveries)
	}
	failed := decodeBody[page](t, doJSON(t, handler, http.MethodGet, "/api/notify/deliveries?outcome=failed", "", cookies, ""))
	if len(failed.Deliveries) != 2 || failed.Deliveries[0].ChannelID != "nc-b" {
		t.Fatalf("failed filter = %+v", failed.Deliveries)
	}
	byQuery := decodeBody[page](t, doJSON(t, handler, http.MethodGet, "/api/notify/deliveries?q=ALPHA&channel_id=nc-a", "", cookies, ""))
	if len(byQuery.Deliveries) != 1 || byQuery.Deliveries[0].Title != "Node offline: alpha" {
		t.Fatalf("query filter = %+v", byQuery.Deliveries)
	}
	limited := decodeBody[page](t, doJSON(t, handler, http.MethodGet, "/api/notify/deliveries?limit=1", "", cookies, ""))
	if len(limited.Deliveries) != 1 {
		t.Fatalf("limit = %+v", limited.Deliveries)
	}
	if res := doJSON(t, handler, http.MethodGet, "/api/notify/deliveries?limit=x", "", cookies, ""); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad limit: %d", res.StatusCode)
	}

	channels := decodeBody[[]notifyChannelView](t, doJSON(t, handler, http.MethodGet, "/api/notify/channels", "", cookies, ""))
	states := map[string]string{}
	for _, c := range channels {
		states[c.ID] = c.Health.State
	}
	if states["nc-a"] != notifyHealthOK || states["nc-b"] != notifyHealthDegraded {
		t.Fatalf("channel health states = %v", states)
	}

	sendOnly := createPAT(t, handler, cookies, csrf, []string{"notify:send"}, nil)
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/notify/deliveries", "", sendOnly); res.StatusCode != http.StatusForbidden {
		t.Fatalf("notify:send read the Sent log: %d", res.StatusCode)
	}
	if res := doBearerJSON(t, handler, http.MethodPost, "/api/notify/channels/test", `{"id":"nc-a"}`, sendOnly); res.StatusCode != http.StatusForbidden {
		t.Fatalf("notify:send tested a stored channel: %d", res.StatusCode)
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"notify:admin"}, []string{"node-a"})
	for _, path := range []string{"/api/notify/deliveries", "/api/notify/channels"} {
		if res := doBearerJSON(t, handler, http.MethodGet, path, "", confined); res.StatusCode != http.StatusForbidden {
			t.Fatalf("confined token read %s: %d", path, res.StatusCode)
		}
	}
	if res := doBearerJSON(t, handler, http.MethodPost, "/api/notify/channels/test", `{"id":"nc-a"}`, confined); res.StatusCode != http.StatusForbidden {
		t.Fatalf("confined token tested a channel: %d", res.StatusCode)
	}
	admin := createPAT(t, handler, cookies, csrf, []string{"notify:admin"}, nil)
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/notify/deliveries", "", admin); res.StatusCode != http.StatusOK {
		t.Fatalf("notify:admin read the Sent log: %d", res.StatusCode)
	}
}

// A rule's fallback round-trips, is kept when absent, cleared when empty,
// refused when it names one of the rule's own channels or nothing, and
// dropped when its channel is deleted.
func TestNotifyRuleFallbackRoundTrip(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-fb", "Telegram")

	type rule struct {
		ID                string   `json:"id"`
		ChannelIDs        []string `json:"channel_ids"`
		FallbackChannelID string   `json:"fallback_channel_id"`
	}
	post := func(body string) *http.Response {
		return doJSON(t, handler, http.MethodPost, "/api/notify/rules", body, cookies, csrf)
	}
	got := decodeBody[rule](t, post(`{"id":"r-1","name":"Urgent","event_types":["node.offline"],"channel_ids":["nc-a"],"fallback_channel_id":"nc-fb"}`))
	if got.FallbackChannelID != "nc-fb" || len(got.ChannelIDs) != 1 {
		t.Fatalf("saved = %+v", got)
	}
	got = decodeBody[rule](t, post(`{"id":"r-1","name":"Urgent renamed","event_types":["node.offline"],"channel_ids":["nc-a"]}`))
	if got.FallbackChannelID != "nc-fb" {
		t.Fatalf("an edit without the field dropped the fallback: %+v", got)
	}
	list := decodeBody[struct {
		Rules []rule `json:"rules"`
	}](t, doJSON(t, handler, http.MethodGet, "/api/notify/rules", "", cookies, ""))
	if len(list.Rules) != 1 || list.Rules[0].FallbackChannelID != "nc-fb" {
		t.Fatalf("list = %+v", list)
	}
	for _, bad := range []string{
		`{"id":"r-1","name":"U","channel_ids":["nc-a"],"fallback_channel_id":"nc-a"}`,
		`{"id":"r-1","name":"U","channel_ids":["nc-a"],"fallback_channel_id":"nc-nope"}`,
	} {
		if res := post(bad); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, res.StatusCode)
		}
	}
	if st.NotifyRuleOptionsByRule()["r-1"].FallbackChannelID != "nc-fb" {
		t.Fatal("a refused edit changed the fallback")
	}
	if res := doJSON(t, handler, http.MethodPost, "/api/notify/channels/delete", `{"id":"nc-fb"}`, cookies, csrf); res.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", res.StatusCode)
	}
	if _, ok := st.NotifyRuleOptionsByRule()["r-1"]; ok {
		t.Fatal("the deleted channel is still a fallback")
	}
	got = decodeBody[rule](t, post(`{"id":"r-1","name":"U","channel_ids":["nc-a"],"fallback_channel_id":""}`))
	if got.FallbackChannelID != "" {
		t.Fatalf("clear = %+v", got)
	}
}

// A plugin's message goes through the outbox, named by its plugin, to every
// enabled channel as before, whatever the rules say; nothing about a channel
// failure goes back to the plugin.
func TestPluginMessageGoesThroughTheOutbox(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-b", "Bark info")
	if err := st.UpsertNotifyRule(model.NotifyRule{ID: "r-1", Name: "Urgent", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-a"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-b" {
			return upstream(401)
		}
		return nil
	})
	host := &pluginHost{server: srv}
	if err := host.Send(context.Background(), "latticenet.sub-store", "Sync failed", "upstream 503"); err != nil {
		t.Fatalf("a channel failure reached the plugin: %v", err)
	}
	waitOutboxSettled(t, srv)
	rows := st.NotifyDeliveries(store.NotifyDeliveryFilter{Source: store.NotifySourcePlugin, SourceID: "latticenet.sub-store"})
	if len(rows) != 2 {
		t.Fatalf("plugin rows = %+v", rows)
	}
	for _, r := range rows {
		if r.EventType != "plugin.latticenet.sub-store.message" || r.RuleID != "" {
			t.Fatalf("row = %+v", r)
		}
	}
}

// An inbound webhook's own record is settled by the outbox once the event's
// deliveries settle, so the webhook page reports what was actually sent.
func TestWebhookRecordSettlesFromTheOutbox(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-b", "Bark info")
	hook := store.NotifyWebhook{ID: "nwh-deploy", Name: "Deploy", EventType: "deploy.finished", TitleTemplate: "Deploy of {{data.service}}", Enabled: true}
	if err := st.UpsertNotifyWebhook(hook); err != nil {
		t.Fatal(err)
	}
	fake := installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-b" {
			return upstream(401)
		}
		return nil
	})
	record := srv.fireNotifyWebhook(hook, map[string]string{"service": "api"}, "203.0.113.9", 10, false)
	if record.Channels != 2 || record.Outcome != store.NotifyWebhookAccepted {
		t.Fatalf("record = %+v", record)
	}
	waitOutboxSettled(t, srv)
	settled := webhookRecord(t, st, hook.ID, record.ID)
	if settled.Outcome != store.NotifyWebhookPartial || settled.Delivered != 1 || settled.Reason != "1 of 2 channel sends failed" {
		t.Fatalf("settled = %+v", settled)
	}
	rows := st.NotifyDeliveries(store.NotifyDeliveryFilter{Source: store.NotifySourceWebhook, SourceID: hook.ID})
	if len(rows) != 2 || rows[0].SourceRef != record.ID {
		t.Fatalf("rows = %+v", rows)
	}

	fake.setAnswer(func(string, int) error { return upstream(401) })
	record = srv.fireNotifyWebhook(hook, map[string]string{"service": "api"}, "203.0.113.9", 10, false)
	waitOutboxSettled(t, srv)
	if settled := webhookRecord(t, st, hook.ID, record.ID); settled.Outcome != store.NotifyWebhookFailed || settled.Delivered != 0 {
		t.Fatalf("all failed = %+v", settled)
	}
}

func webhookRecord(t *testing.T, st *store.Store, hookID, recordID string) store.NotifyWebhookDelivery {
	t.Helper()
	for _, d := range st.NotifyWebhookDeliveries(hookID, 0) {
		if d.ID == recordID {
			return d
		}
	}
	t.Fatalf("no webhook record %s", recordID)
	return store.NotifyWebhookDelivery{}
}

// The channel view still carries no config, health included.
func TestNotifyChannelViewWithHealthHidesSecret(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, _ := loginSession(t, handler)
	if err := st.UpsertNotifyChannel(model.NotifyChannel{ID: "nc-tg", Name: "Telegram", Kind: "telegram", Enabled: true, Config: map[string]string{"token": "SECRET-TOKEN", "chat_id": "1"}}); err != nil {
		t.Fatal(err)
	}
	installFakeNotifySender(srv, func(string, int) error { return upstream(401) })
	srv.notifyEventTyped(EventNodeOffline, "Node offline: alpha", "b")
	waitOutboxSettled(t, srv)
	body := readAll(t, doJSON(t, handler, http.MethodGet, "/api/notify/channels", "", cookies, ""))
	if strings.Contains(body, "SECRET-TOKEN") || strings.Contains(body, `"config"`) {
		t.Fatalf("channel list leaks config: %s", body)
	}
	if !bytes.Contains([]byte(body), []byte(`"last_failure_kind":"upstream_4xx"`)) {
		t.Fatalf("channel list lacks health: %s", body)
	}
}

// notify.send answers a plugin with fixed text only: nil once the message is
// stored for every enabled channel, a no-channel error when there is none
// (the message is still in the Sent log), and a backlog error, with nothing
// stored, once the plugin already has its bound of deliveries owed.
func TestPluginNotifySendAnswers(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	installFakeNotifySender(srv, nil)
	host := &pluginHost{server: srv}
	if err := host.Send(context.Background(), "latticenet.sub-store", "Sync failed", "b"); !errors.Is(err, errPluginNotifyNoChannel) {
		t.Fatalf("no channel: err = %v", err)
	}
	if rows := st.NotifyDeliveries(store.NotifyDeliveryFilter{Source: store.NotifySourcePlugin}); len(rows) != 1 || rows[0].Outcome != store.NotifyOutcomeNoRoute {
		t.Fatalf("no-channel rows = %+v", rows)
	}

	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	now := time.Now().UTC()
	owed := make([]store.NotifyDelivery, store.MaxNotifyUnsettledPerSource)
	for i := range owed {
		owed[i] = store.NotifyDelivery{ID: fmt.Sprintf("nd-owed-%03d", i), EventID: fmt.Sprintf("evt-%03d", i), EventType: "plugin.latticenet.sub-store.message",
			Source: store.NotifySourcePlugin, SourceID: "latticenet.sub-store", ChannelID: "nc-a", Role: store.NotifyRolePrimary,
			Outcome: store.NotifyOutcomePlanned, CreatedAt: now, NextAttemptAt: now.Add(time.Hour)}
	}
	if err := st.RecordNotifyDeliveries(owed); err != nil {
		t.Fatal(err)
	}
	before := st.NotifyDeliveryCount()
	if err := host.Send(context.Background(), "latticenet.sub-store", "Sync failed", "b"); !errors.Is(err, errPluginNotifyBacklog) {
		t.Fatalf("backlog: err = %v", err)
	}
	if st.NotifyDeliveryCount() != before {
		t.Fatal("a refused message was stored")
	}
	// Another plugin is not held back by this one's backlog.
	if err := host.Send(context.Background(), "latticenet.netguard", "Applied", "b"); err != nil {
		t.Fatalf("another plugin: err = %v", err)
	}
}
