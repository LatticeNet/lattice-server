package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// notifyEventNeverNotified are event-named constants that are not notification
// types, with the reason.
var notifyEventNeverNotified = map[string]string{
	"EventSSHPressureWindow": "recorded in the audit log, never notified (server_ssh_pressure.go)",
}

// notifyEmitFuncs are the entry points whose first argument is an event type.
var notifyEmitFuncs = map[string]bool{
	"emitNotifyTyped":      true,
	"notifyEventTyped":     true,
	"enqueueNotifyEvent":   true,
	"planNotifyEvent":      true,
	"notifyIncidentEvent":  true,
	"sendIncidentMessages": true,
	"sendRecoveries":       true,
}

var notifyEventConstName = regexp.MustCompile(`^[Ee]vent[A-Z]`)

// emittedNotifyEventTypes reads every event type the server can emit from the
// package's own source and runtime tables, each with where it was found: the
// Event* and event* string constants, every value classifyNotifyEvent
// returns, every string literal or constant a notify entry point is called
// with, and the incident and critical-fallback tables.
//
// It sees types written as literals or named constants. A type built at run
// time (fmt.Sprintf, a variable, a new entry point not in notifyEmitFuncs) is
// out of its reach: declare a new type as an Event constant, as the existing
// emitters do, and it is covered.
func emittedNotifyEventTypes(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	dir, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range dir {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	consts := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil {
							consts[name.Name] = v
						}
					}
				}
			}
		}
	}
	value := func(e ast.Expr) (string, bool) {
		switch x := e.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				v, err := strconv.Unquote(x.Value)
				return v, err == nil
			}
		case *ast.Ident:
			v, ok := consts[x.Name]
			return v, ok
		}
		return "", false
	}

	out := map[string]string{}
	add := func(eventType, where string) {
		if _, seen := out[eventType]; !seen {
			out[eventType] = where
		}
	}
	for name, v := range consts {
		if notifyEventConstName.MatchString(name) && notifyEventNeverNotified[name] == "" {
			add(v, "const "+name)
		}
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if x.Name.Name == "classifyNotifyEvent" && x.Recv == nil {
					ast.Inspect(x.Body, func(n ast.Node) bool {
						if ret, ok := n.(*ast.ReturnStmt); ok {
							for _, r := range ret.Results {
								if v, ok := value(r); ok {
									add(v, "classifyNotifyEvent")
								}
							}
						}
						return true
					})
				}
			case *ast.CallExpr:
				var fn string
				switch callee := x.Fun.(type) {
				case *ast.SelectorExpr:
					fn = callee.Sel.Name
				case *ast.Ident:
					fn = callee.Name
				}
				if notifyEmitFuncs[fn] && len(x.Args) > 0 {
					if v, ok := value(x.Args[0]); ok {
						add(v, fn+" at "+fset.Position(x.Pos()).String())
					}
				}
			}
			return true
		})
	}
	for open, k := range incidentKinds {
		add(open, "incidentKinds")
		add(k.recovery, "incidentKinds recovery")
	}
	for eventType := range notifyCriticalEventTypes {
		add(eventType, "notifyCriticalEventTypes")
	}
	return out
}

// Every event type the server can emit has an exact catalogue entry, or is a
// plugin's message and maps to plugins.
func TestNotifyCatalogueCoversEveryEmittedType(t *testing.T) {
	emitted := emittedNotifyEventTypes(t)
	// The source walk must actually see each kind of emitter, or an empty
	// result would pass.
	for _, known := range []string{EventNodeOffline, EventAgentStalled, eventNotifyTest, "ssh.login", "auth.2fa_limit", "generic", "inventory.renewal"} {
		if _, ok := emitted[known]; !ok {
			t.Fatalf("the source walk did not find %q; found %v", known, emitted)
		}
	}
	var missing []string
	for eventType, where := range emitted {
		if isNotifyPluginMessageType(eventType) {
			if got := notifyCatalogueLookup(eventType, false).Category; got != notifyCategoryPlugins {
				t.Errorf("%s (%s) maps to %s, want plugins", eventType, where, got)
			}
			continue
		}
		if _, ok := notifyCatalogueByType[eventType]; !ok {
			missing = append(missing, eventType+" ("+where+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("event types the server emits without a catalogue entry in notify_catalogue.go:\n  %s", strings.Join(missing, "\n  "))
	}
}

func TestNotifyCatalogueLookup(t *testing.T) {
	cases := []struct {
		eventType string
		webhook   bool
		category  string
		icon      string
	}{
		{"plugin.latticenet.sub-store.message", false, notifyCategoryPlugins, "puzzle"},
		{"plugin.message", false, notifyCategoryPlugins, "puzzle"},
		{"deploy.finished", true, notifyCategoryWebhooks, "webhook"},
		{"no.such.type", false, notifyCategoryGeneral, "bell"},
		{"plugin..message", false, notifyCategoryGeneral, "bell"},
		{"plugin.latticenet.sub-store.sync_failed", false, notifyCategoryGeneral, "bell"},
		// An exact type and a plugin's message win over a webhook raising
		// the same type.
		{EventNodeOffline, true, notifyCategoryNodes, "server-off"},
		{"plugin.latticenet.vpn-core.message", true, notifyCategoryPlugins, "puzzle"},
	}
	for _, c := range cases {
		got := notifyCatalogueLookup(c.eventType, c.webhook)
		if got.Category != c.category || got.Icon != c.icon || got.Type != c.eventType || got.Description == "" {
			t.Errorf("lookup(%q, webhook=%t) = %+v, want category %s icon %s", c.eventType, c.webhook, got, c.category, c.icon)
		}
	}
}

// The catalogue's critical types are the ones routing already treats as
// critical: notifyEventSeverity (quiet hours and escalation) and
// notifyCriticalEventTypes (the channel fallback). Recoveries are judged
// apart: routing gives a recovery its open's severity, the catalogue gives it
// recovery.
func TestNotifyCatalogueCriticalMatchesRouting(t *testing.T) {
	domain := map[string]bool{}
	for _, e := range notifyCatalogueTypes {
		domain[e.Type] = true
	}
	for eventType := range emittedNotifyEventTypes(t) {
		domain[eventType] = true
	}
	var catalogue, severity, fallback []string
	for eventType := range domain {
		e := notifyCatalogueLookup(eventType, false)
		if e.Recovery {
			continue
		}
		if e.Severity == notifySeverityCritical {
			catalogue = append(catalogue, eventType)
		}
		if notifyEventSeverity(eventType) == incidentSeverityCritical {
			severity = append(severity, eventType)
		}
		if notifyCriticalEventTypes[eventType] {
			fallback = append(fallback, eventType)
		}
	}
	sort.Strings(catalogue)
	sort.Strings(severity)
	sort.Strings(fallback)
	if !slices.Equal(catalogue, severity) {
		t.Errorf("catalogue critical types %v differ from notifyEventSeverity's critical types %v", catalogue, severity)
	}
	if !slices.Equal(catalogue, fallback) {
		t.Errorf("catalogue critical types %v differ from notifyCriticalEventTypes %v", catalogue, fallback)
	}
	for recovery := range incidentRecoveryOf {
		if !notifyCatalogueLookup(recovery, false).Recovery {
			t.Errorf("%s ends an incident but the catalogue does not mark it a recovery", recovery)
		}
	}
}

var notifyIconName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Every entry names a known category, a severity from the closed set, a
// kebab-case icon and a description, and no type is listed twice.
func TestNotifyCatalogueEntriesAreWellFormed(t *testing.T) {
	categories := map[string]bool{}
	for _, c := range notifyCategories {
		if c.ID == "" || c.Label == "" || categories[c.ID] {
			t.Fatalf("bad or repeated category %+v", c)
		}
		categories[c.ID] = true
	}
	severities := map[string]bool{notifySeverityInfo: true, notifySeverityNotice: true, notifySeverityWarning: true, notifySeverityCritical: true}
	check := func(name string, p notifyPresentation, description string) {
		if !categories[p.Category] || !severities[p.Severity] || !notifyIconName.MatchString(p.Icon) || description == "" {
			t.Errorf("%s: malformed entry %+v %q", name, p, description)
		}
		if p.Recovery && p.Severity != notifySeverityInfo {
			t.Errorf("%s: a recovery is info with recovery set, got %s", name, p.Severity)
		}
	}
	seen := map[string]bool{}
	for _, e := range notifyCatalogueTypes {
		if e.Type == "" || seen[e.Type] {
			t.Errorf("empty or repeated type %q", e.Type)
		}
		seen[e.Type] = true
		check(e.Type, e.notifyPresentation, e.Description)
	}
	check("plugin pattern", notifyPluginMessagePattern.notifyPresentation, notifyPluginMessagePattern.Description)
	check("webhook entry", notifyWebhookEntry.notifyPresentation, notifyWebhookEntry.Description)
	if _, ok := notifyCatalogueByType[eventGeneric]; !ok {
		t.Fatal("the generic entry is what lookup falls back to; it must exist")
	}
}

func TestNotifyTone(t *testing.T) {
	cases := []struct {
		severity string
		recovery bool
		want     string
	}{
		{notifySeverityCritical, false, notifyToneCritical},
		{notifySeverityWarning, false, notifyToneWarning},
		{notifySeverityNotice, false, notifyToneNotice},
		{notifySeverityInfo, false, notifyToneQuiet},
		{notifySeverityInfo, true, notifyToneRecovered},
		// Recovery wins over any severity.
		{notifySeverityCritical, true, notifyToneRecovered},
	}
	for _, c := range cases {
		if got := (notifyPresentation{Severity: c.severity, Recovery: c.recovery}).tone(); got != c.want {
			t.Errorf("tone(%s, recovery=%t) = %s, want %s", c.severity, c.recovery, got, c.want)
		}
	}
}

type catalogueAnswer struct {
	Categories   []notifyCategory         `json:"categories"`
	Types        []notifyCatalogueEntry   `json:"types"`
	Patterns     []notifyCataloguePattern `json:"patterns"`
	WebhookTypes []notifyCatalogueEntry   `json:"webhook_types"`
}

// GET /api/notify/catalogue returns the four lists, with the operator's
// webhook types that nothing else claims; it needs notify:admin and refuses a
// node-confined token with an audited deny.
func TestNotifyCatalogueRoute(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	for _, h := range []store.NotifyWebhook{
		{ID: "wh-deploy", Name: "Deploys", EventType: "deploy.finished", TitleTemplate: "t", Enabled: true},
		{ID: "wh-deploy-2", Name: "Deploys again", EventType: "deploy.finished", TitleTemplate: "t", Enabled: false},
		{ID: "wh-backup", Name: "Backups", EventType: "backup.failed", TitleTemplate: "t", Enabled: true},
		{ID: "wh-shadow", Name: "Shadows a server type", EventType: EventNodeOffline, TitleTemplate: "t", Enabled: true},
	} {
		if err := st.UpsertNotifyWebhook(h); err != nil {
			t.Fatal(err)
		}
	}

	got := decodeBody[catalogueAnswer](t, doJSON(t, handler, http.MethodGet, "/api/notify/catalogue", "", cookies, ""))
	if len(got.Categories) != len(notifyCategories) || got.Categories[0] != (notifyCategory{ID: "nodes", Label: "Nodes"}) {
		t.Fatalf("categories = %+v", got.Categories)
	}
	if len(got.Types) != len(notifyCatalogueTypes) {
		t.Fatalf("types = %d entries, want %d", len(got.Types), len(notifyCatalogueTypes))
	}
	byType := map[string]notifyCatalogueEntry{}
	for _, e := range got.Types {
		byType[e.Type] = e
	}
	if e := byType[EventNodeOffline]; e.Category != "nodes" || e.Severity != "critical" || e.Recovery || e.Icon != "server-off" || e.Description == "" {
		t.Fatalf("node.offline = %+v", e)
	}
	if e := byType[EventNodeOnline]; !e.Recovery || e.Severity != "info" || e.Icon != "server" {
		t.Fatalf("node.online = %+v", e)
	}
	for _, want := range []string{EventAgentStalled, EventAgentRecovered, eventGeneric} {
		if _, ok := byType[want]; !ok {
			t.Fatalf("types miss %s", want)
		}
	}
	if len(got.Patterns) != 1 || got.Patterns[0].Pattern != "plugin.<id>.message" || got.Patterns[0].Type != "plugin.<id>.message" || got.Patterns[0].Category != "plugins" || got.Patterns[0].Icon != "puzzle" {
		t.Fatalf("patterns = %+v", got.Patterns)
	}
	var webhookTypes []string
	for _, e := range got.WebhookTypes {
		webhookTypes = append(webhookTypes, e.Type)
		if e.Category != "webhooks" || e.Severity != "info" || e.Recovery || e.Icon != "webhook" || e.Description == "" {
			t.Fatalf("webhook type %+v lacks the webhook entry's fields", e)
		}
	}
	if !slices.Equal(webhookTypes, []string{"backup.failed", "deploy.finished"}) {
		t.Fatalf("webhook types = %v, want each operator type once, sorted, without the one an exact entry claims", webhookTypes)
	}

	if res := doJSON(t, handler, http.MethodPost, "/api/notify/catalogue", `{}`, cookies, csrf); res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", res.StatusCode)
	}
	sendOnly := createPAT(t, handler, cookies, csrf, []string{"notify:send"}, nil)
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/notify/catalogue", "", sendOnly); res.StatusCode != http.StatusForbidden {
		t.Fatalf("notify:send read the catalogue: %d", res.StatusCode)
	}
	confined := createPAT(t, handler, cookies, csrf, []string{"notify:admin"}, []string{"node-a"})
	res := doBearerJSON(t, handler, http.MethodGet, "/api/notify/catalogue", "", confined)
	body := readAll(t, res)
	if res.StatusCode != http.StatusForbidden || strings.Contains(body, "deploy.finished") {
		t.Fatalf("confined token read the catalogue: %d %s", res.StatusCode, body)
	}
	denied := false
	for _, ev := range st.AuditEvents() {
		if ev.Action == "notify.catalogue.read" && ev.Decision == "deny" && ev.Scope == "notify:admin" {
			denied = true
		}
	}
	if !denied {
		t.Fatal("the confined read was refused without an audited deny")
	}
	admin := createPAT(t, handler, cookies, csrf, []string{"notify:admin"}, nil)
	if res := doBearerJSON(t, handler, http.MethodGet, "/api/notify/catalogue", "", admin); res.StatusCode != http.StatusOK {
		t.Fatalf("notify:admin read the catalogue: %d", res.StatusCode)
	}
}

// Sent log rows carry category, severity, recovery and icon, computed from
// the event type when read.
func TestNotifyDeliveriesCarryPresentation(t *testing.T) {
	_, handler, st := newInventoryServer(t)
	cookies, _ := loginSession(t, handler)
	if err := st.UpsertNotifyWebhook(store.NotifyWebhook{ID: "wh-deploy", Name: "Deploys", EventType: "deploy.finished", TitleTemplate: "t", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 15, 6, 0, 0, 0, time.UTC)
	rows := []struct{ id, eventType, source string }{
		{"nd-offline", EventNodeOffline, store.NotifySourceServer},
		{"nd-online", EventNodeOnline, store.NotifySourceServer},
		{"nd-login", "ssh.login", store.NotifySourceServer},
		{"nd-plugin", "plugin.latticenet.sub-store.message", store.NotifySourcePlugin},
		{"nd-hook", "deploy.finished", store.NotifySourceWebhook},
		// The webhook that raised this was deleted; the row still reads as
		// a webhook event.
		{"nd-gone", "gone.away", store.NotifySourceWebhook},
		{"nd-unknown", "no.such.type", store.NotifySourceServer},
	}
	var records []store.NotifyDelivery
	for i, r := range rows {
		records = append(records, store.NotifyDelivery{
			ID: r.id, EventID: "evt-" + r.id, EventType: r.eventType, Source: r.source,
			ChannelID: "nc-a", ChannelKind: "bark", Role: store.NotifyRolePrimary,
			Outcome: store.NotifyOutcomeSent, Title: "t", CreatedAt: at.Add(time.Duration(i) * time.Second), SettledAt: at,
		})
	}
	if err := st.RecordNotifyDeliveries(records); err != nil {
		t.Fatal(err)
	}

	type row struct {
		ID        string `json:"id"`
		EventType string `json:"event_type"`
		Category  string `json:"category"`
		Severity  string `json:"severity"`
		Recovery  *bool  `json:"recovery"`
		Icon      string `json:"icon"`
	}
	page := decodeBody[struct {
		Deliveries []row `json:"deliveries"`
	}](t, doJSON(t, handler, http.MethodGet, "/api/notify/deliveries", "", cookies, ""))
	got := map[string]row{}
	for _, r := range page.Deliveries {
		if r.Recovery == nil {
			t.Fatalf("row %s has no recovery field; it must always be present", r.ID)
		}
		got[r.ID] = r
	}
	want := map[string]struct {
		category, severity string
		recovery           bool
		icon               string
	}{
		"nd-offline": {"nodes", "critical", false, "server-off"},
		"nd-online":  {"nodes", "info", true, "server"},
		"nd-login":   {"ssh", "notice", false, "key-round"},
		"nd-plugin":  {"plugins", "info", false, "puzzle"},
		"nd-hook":    {"webhooks", "info", false, "webhook"},
		"nd-gone":    {"webhooks", "info", false, "webhook"},
		"nd-unknown": {"general", "info", false, "bell"},
	}
	for id, w := range want {
		r, ok := got[id]
		if !ok {
			t.Fatalf("row %s missing from %+v", id, page.Deliveries)
		}
		if r.Category != w.category || r.Severity != w.severity || *r.Recovery != w.recovery || r.Icon != w.icon {
			t.Errorf("%s (%s) = %s/%s/%t/%s, want %s/%s/%t/%s", id, r.EventType, r.Category, r.Severity, *r.Recovery, r.Icon, w.category, w.severity, w.recovery, w.icon)
		}
	}
}

// A stored channel's test answer carries the same presentation as its Sent
// log row.
func TestStoredChannelTestCarriesPresentation(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	cookies, csrf := loginSession(t, handler)
	addNotifyChannel(t, st, "nc-a", "Bark")
	installFakeNotifySender(srv, nil)
	res := doJSON(t, handler, http.MethodPost, "/api/notify/channels/test", `{"id":"nc-a"}`, cookies, csrf)
	answer := decodeBody[struct {
		Delivery struct {
			EventType string `json:"event_type"`
			notifyPresentation
		} `json:"delivery"`
	}](t, res)
	if answer.Delivery.EventType != eventNotifyTest || answer.Delivery.Category != "notify" || answer.Delivery.Icon != "flask-conical" {
		t.Fatalf("test delivery = %+v", answer.Delivery)
	}
}
