package server

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func setChannelFallback(t *testing.T, st *store.Store, channelID, fallbackID string) {
	t.Helper()
	for _, c := range st.NotifyChannels() {
		if c.ID == channelID {
			if err := st.UpsertNotifyChannelWithOptions(c, store.NotifyChannelOptions{FallbackChannelID: fallbackID}); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("no channel %s", channelID)
}

func upsertRule(t *testing.T, st *store.Store, rule model.NotifyRule, fallbackID string) {
	t.Helper()
	rule.Enabled = true
	if err := st.UpsertNotifyRuleWithOptions(rule, store.NotifyRuleOptions{FallbackChannelID: fallbackID}); err != nil {
		t.Fatal(err)
	}
}

var errDialRefused = &url.Error{Op: "Post", URL: "https://bark.example.com/push", Err: errors.New("dial tcp: connection refused")}

// A critical message that fails on a channel goes to that channel's fallback
// at the first failed attempt, while the primary keeps retrying; the Sent log
// keeps both rows, linked, and the failing channel's health records the
// hand-off.
func TestCriticalMessageGoesToTheChannelFallbackAtTheFirstFailure(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-fb", "Bark relay")
	setChannelFallback(t, st, "nc-a", "nc-fb")
	upsertRule(t, st, model.NotifyRule{ID: "r-urgent", Name: "Urgent", EventTypes: []string{EventServiceDown, EventMonitorDown}, ChannelIDs: []string{"nc-a"}}, "")
	fake := installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-a" {
			return errDialRefused
		}
		return nil
	})

	srv.notifyEventTyped(EventServiceDown, "Service down: sing-box on alpha", "sing-box stopped answering")
	waitOutboxSettled(t, srv)

	primary := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-a"})
	if len(primary) != 1 || primary[0].Outcome != store.NotifyOutcomeFailed || len(primary[0].Attempts) != 4 {
		t.Fatalf("primary = %+v", primary)
	}
	fb := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-fb"})
	if len(fb) != 1 || fb[0].Role != store.NotifyRoleFallback || fb[0].Outcome != store.NotifyOutcomeSent ||
		fb[0].FallbackOf != primary[0].ID || fb[0].FallbackFor != "Bark urgent" || fb[0].EventID != primary[0].EventID || fb[0].RuleName != "Urgent" {
		t.Fatalf("fallback = %+v", fb)
	}
	sent := fake.sentTo("nc-fb")
	if len(sent) != 1 || sent[0].title != "Service down: sing-box on alpha" || !strings.Contains(sent[0].body, "Bark urgent failed to deliver this critical alert and is still retrying") {
		t.Fatalf("fallback message = %+v", sent)
	}
	h, _ := st.NotifyChannelHealth("nc-a")
	if h.Fallbacks != 1 || h.LastFallbackChannelID != "nc-fb" || h.LastFallbackAt.IsZero() {
		t.Fatalf("health = %+v", h)
	}

	// Not critical: the channel fallback stays out of it.
	srv.notifyEventTyped(EventMonitorDown, "Monitor down: web", "web is down")
	waitOutboxSettled(t, srv)
	if got := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-fb"}); len(got) != 1 {
		t.Fatalf("a warning went to the critical fallback: %+v", got)
	}
}

// The fallback channel is not sent an event it already receives, a fallback
// delivery never falls back again, and a disabled fallback is skipped.
func TestChannelFallbackNeverDuplicatesOrChains(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-fb", "Bark relay")
	addNotifyChannel(t, st, "nc-c", "Telegram")
	setChannelFallback(t, st, "nc-a", "nc-fb")
	setChannelFallback(t, st, "nc-fb", "nc-c")
	fake := installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-a" {
			return upstream(401)
		}
		return nil
	})

	// The rule already sends to the fallback channel.
	upsertRule(t, st, model.NotifyRule{ID: "r-1", Name: "Both", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-a", "nc-fb"}}, "")
	srv.notifyEventTyped(EventNodeOffline, "Node offline: alpha", "a")
	waitOutboxSettled(t, srv)
	if got := fake.sentTo("nc-fb"); len(got) != 1 {
		t.Fatalf("the fallback channel got the event %d times", len(got))
	}

	// A failed fallback delivery does not hand on to the fallback's fallback.
	upsertRule(t, st, model.NotifyRule{ID: "r-1", Name: "Urgent", EventTypes: []string{EventNodeOffline}, ChannelIDs: []string{"nc-a"}}, "")
	fake.setAnswer(func(id string, _ int) error {
		if id == "nc-a" || id == "nc-fb" {
			return upstream(401)
		}
		return nil
	})
	srv.notifyEventTyped(EventNodeOffline, "Node offline: bravo", "b")
	waitOutboxSettled(t, srv)
	if got := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-c"}); len(got) != 0 {
		t.Fatalf("a fallback chained on: %+v", got)
	}

	// A disabled fallback channel takes nothing.
	for _, c := range st.NotifyChannels() {
		if c.ID == "nc-fb" {
			c.Enabled = false
			if err := st.UpsertNotifyChannelWithOptions(c, store.NotifyChannelOptions{FallbackChannelID: "nc-c"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	before := len(deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-fb"}))
	srv.notifyEventTyped(EventNodeOffline, "Node offline: charlie", "c")
	waitOutboxSettled(t, srv)
	if got := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-fb"}); len(got) != before {
		t.Fatalf("a disabled fallback was used: %+v", got)
	}
}

// The rule fallback and the channel fallback answer different failures: when
// they name the same channel it gets the message once, and a channel's
// critical fallback does not stop the rule's own fallback when every primary
// failed.
func TestRuleAndChannelFallbacksTogether(t *testing.T) {
	srv, _, st := newInventoryServer(t)
	addNotifyChannel(t, st, "nc-a", "Bark urgent")
	addNotifyChannel(t, st, "nc-b", "Discord")
	addNotifyChannel(t, st, "nc-fb", "Bark relay")
	addNotifyChannel(t, st, "nc-r", "Telegram")
	setChannelFallback(t, st, "nc-a", "nc-fb")
	fake := installFakeNotifySender(srv, func(id string, _ int) error {
		if id == "nc-a" || id == "nc-b" {
			return upstream(403)
		}
		return nil
	})

	upsertRule(t, st, model.NotifyRule{ID: "r-1", Name: "Urgent", EventTypes: []string{EventSSHCompromiseSuspected}, ChannelIDs: []string{"nc-a"}}, "nc-fb")
	srv.notifyEventTyped(EventSSHCompromiseSuspected, "SSH compromise suspected on alpha", "a")
	waitOutboxSettled(t, srv)
	if got := fake.sentTo("nc-fb"); len(got) != 1 {
		t.Fatalf("one fallback channel named twice got the message %d times", len(got))
	}

	upsertRule(t, st, model.NotifyRule{ID: "r-1", Name: "Urgent", EventTypes: []string{EventSSHCompromiseSuspected}, ChannelIDs: []string{"nc-a", "nc-b"}}, "nc-r")
	srv.notifyEventTyped(EventSSHCompromiseSuspected, "SSH compromise suspected on bravo", "b")
	waitOutboxSettled(t, srv)
	if got := fake.sentTo("nc-fb"); len(got) != 2 {
		t.Fatalf("channel fallback sends = %d, want 2", len(got))
	}
	rule := deliveriesOf(st, store.NotifyDeliveryFilter{ChannelID: "nc-r"})
	if len(rule) != 1 || rule[0].FallbackOf != "" || rule[0].FallbackFor != "Bark urgent, Discord" || rule[0].Outcome != store.NotifyOutcomeSent {
		t.Fatalf("rule fallback = %+v", rule)
	}
}

// A channel's critical fallback round-trips through the channel API, is kept
// when the field is absent, cleared when empty, refused when it names the
// channel itself or nothing, and the view names the events it carries.
func TestNotifyChannelFallbackRoundTrip(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	addNotifyChannel(t, st, "nc-fb", "Bark relay")

	type channel struct {
		ID                 string   `json:"id"`
		FallbackChannelID  string   `json:"fallback_channel_id"`
		CriticalEventTypes []string `json:"critical_event_types"`
		Health             struct {
			Fallbacks int `json:"fallbacks"`
		} `json:"health"`
	}
	post := func(body string) *http.Response {
		return doJSON(t, handler, http.MethodPost, "/api/notify/channels", body, cookies, csrf)
	}
	const bark = `"kind":"bark","config":{"base_url":"https://bark.example.com","key":"k-a"}`
	got := decodeBody[channel](t, post(`{"id":"nc-a","name":"Bark urgent",`+bark+`,"fallback_channel_id":"nc-fb"}`))
	if got.FallbackChannelID != "nc-fb" || !slices.Equal(got.CriticalEventTypes, []string{EventNodeOffline, EventServiceDown, EventSSHCompromiseSuspected}) {
		t.Fatalf("saved = %+v", got)
	}
	got = decodeBody[channel](t, post(`{"id":"nc-a","name":"Bark urgent renamed",`+bark+`}`))
	if got.FallbackChannelID != "nc-fb" {
		t.Fatalf("an edit without the field dropped the fallback: %+v", got)
	}
	list := decodeBody[[]channel](t, doJSON(t, handler, http.MethodGet, "/api/notify/channels", "", cookies, ""))
	found := false
	for _, c := range list {
		found = found || (c.ID == "nc-a" && c.FallbackChannelID == "nc-fb")
	}
	if !found {
		t.Fatalf("list = %+v", list)
	}
	for _, bad := range []string{
		`{"id":"nc-a","name":"U",` + bark + `,"fallback_channel_id":"nc-a"}`,
		`{"id":"nc-a","name":"U",` + bark + `,"fallback_channel_id":"nc-nope"}`,
		`{"name":"New",` + bark + `,"fallback_channel_id":"nc-nope"}`,
	} {
		if res := post(bad); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, res.StatusCode)
		}
	}
	if st.NotifyChannelOptionsByChannel()["nc-a"].FallbackChannelID != "nc-fb" {
		t.Fatal("a refused edit changed the fallback")
	}
	got = decodeBody[channel](t, post(`{"id":"nc-a","name":"U",`+bark+`,"fallback_channel_id":""}`))
	if got.FallbackChannelID != "" {
		t.Fatalf("clear = %+v", got)
	}
	if _, ok := st.NotifyChannelOptionsByChannel()["nc-a"]; ok {
		t.Fatal("clearing left an options row")
	}
}
