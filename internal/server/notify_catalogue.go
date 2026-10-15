package server

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-server/internal/store"
)

// The notification presentation catalogue (design-notify-abstraction section
// 13, slice P).
//
// One static table says, for every event type the server emits, which
// category it belongs to, how bad it is, whether it ends a condition another
// type opened, and which lucide glyph shows it. The console's Sent log and
// every Bark push are drawn from it, so a node going down no longer looks
// like a routine SSH login on either surface. Colour (the tone) comes from
// severity and recovery, never from the category: colour says how bad, the
// glyph says what.
//
// It changes no routing. notifyEventSeverity (incidents.go) and
// notifyCriticalEventTypes (notify_channel_fallback.go) still decide quiet
// hours, escalation and the channel fallback, and a test pins the
// catalogue's critical types to both until slice A makes this table the
// routing input.
//
// Lookup never fails: an exact type, then a plugin's message
// (plugin.<id>.message), then an operator webhook's type, then generic.

// Categories, in the order the console groups them.
const (
	notifyCategoryNodes     = "nodes"
	notifyCategoryServices  = "services"
	notifyCategoryMonitors  = "monitors"
	notifyCategoryAgents    = "agents"
	notifyCategorySSH       = "ssh"
	notifyCategoryAuth      = "auth"
	notifyCategoryQuota     = "quota"
	notifyCategoryInventory = "inventory"
	notifyCategoryNotify    = "notify"
	notifyCategoryPlugins   = "plugins"
	notifyCategoryWebhooks  = "webhooks"
	notifyCategoryGeneral   = "general"
)

// Severities: the notify design's closed set (section 3). A recovery is info
// with recovery set rather than a fifth value.
const (
	notifySeverityInfo     = incidentSeverityInfo
	notifySeverityNotice   = "notice"
	notifySeverityWarning  = incidentSeverityWarning
	notifySeverityCritical = incidentSeverityCritical
)

// Tones: what the console's disc and a push's icon are filled with. They are
// part of the icon file name, so they are wire values.
const (
	notifyToneCritical  = "critical"
	notifyToneWarning   = "warning"
	notifyToneNotice    = "notice"
	notifyToneQuiet     = "quiet"
	notifyToneRecovered = "recovered"
)

// Event types the server emits without a declared constant. classifyNotifyEvent
// (server.go) derives them from titles and the renewal sweep names one
// directly; the catalogue test reads both, so a new one cannot go unlisted.
const (
	eventSSHLogin         = "ssh.login"
	eventAuth2FALimit     = "auth.2fa_limit"
	eventProxyQuota       = "proxy.quota"
	eventProxyExpiry      = "proxy.expiry"
	eventInventoryRenewal = "inventory.renewal"
	eventGeneric          = "generic"
)

// notifyCategory is a category as the catalogue endpoint lists it. Label is
// also the Bark group a push goes out under.
type notifyCategory struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

var notifyCategories = []notifyCategory{
	{notifyCategoryNodes, "Nodes"},
	{notifyCategoryServices, "Services"},
	{notifyCategoryMonitors, "Monitors"},
	{notifyCategoryAgents, "Agents"},
	{notifyCategorySSH, "SSH"},
	{notifyCategoryAuth, "Sign-in"},
	{notifyCategoryQuota, "Quota"},
	{notifyCategoryInventory, "Inventory"},
	{notifyCategoryNotify, "Notifications"},
	{notifyCategoryPlugins, "Plugins"},
	{notifyCategoryWebhooks, "Webhooks"},
	{notifyCategoryGeneral, "General"},
}

// notifyCategoryLabel is the English label of a category id.
func notifyCategoryLabel(id string) string {
	for _, c := range notifyCategories {
		if c.ID == id {
			return c.Label
		}
	}
	return id
}

// notifyPresentation is what the catalogue decides about one event type. It
// is also the four fields a Sent log row gains.
type notifyPresentation struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Recovery bool   `json:"recovery"`
	// Icon is a lucide icon name in kebab case.
	Icon string `json:"icon"`
}

// tone derives the fill from severity and recovery: a recovery is recovered
// whatever its severity, then critical, warning and notice name themselves,
// and everything else is quiet.
func (p notifyPresentation) tone() string {
	switch {
	case p.Recovery:
		return notifyToneRecovered
	case p.Severity == notifySeverityCritical:
		return notifyToneCritical
	case p.Severity == notifySeverityWarning:
		return notifyToneWarning
	case p.Severity == notifySeverityNotice:
		return notifyToneNotice
	default:
		return notifyToneQuiet
	}
}

// notifyCatalogueEntry is one event type. Description is one English line,
// the console's fallback label.
type notifyCatalogueEntry struct {
	Type string `json:"type"`
	notifyPresentation
	Description string `json:"description"`
}

// notifyCataloguePattern is an entry for a family of types: today only a
// plugin's messages. Its type repeats the pattern, so every list the
// catalogue endpoint returns has the entry's shape.
type notifyCataloguePattern struct {
	Pattern string `json:"pattern"`
	notifyCatalogueEntry
}

func notifyEntry(eventType, category, severity string, recovery bool, icon, description string) notifyCatalogueEntry {
	return notifyCatalogueEntry{
		Type:               eventType,
		notifyPresentation: notifyPresentation{Category: category, Severity: severity, Recovery: recovery, Icon: icon},
		Description:        description,
	}
}

// notifyCatalogueTypes is every exact type, in the console's order. Two
// choices differ from the section 3 table on purpose: node.offline is
// critical, because routing already treats it so and the console must not
// show a calmer colour than the page it caused; recoveries are info with
// recovery set, so the severity set stays four values.
var notifyCatalogueTypes = []notifyCatalogueEntry{
	notifyEntry(EventNodeOffline, notifyCategoryNodes, notifySeverityCritical, false, "server-off", "Node offline"),
	notifyEntry(EventNodeOnline, notifyCategoryNodes, notifySeverityInfo, true, "server", "Node back online"),
	notifyEntry(EventServiceDown, notifyCategoryServices, notifySeverityCritical, false, "power-off", "Proxy core down"),
	notifyEntry(EventServiceRecovered, notifyCategoryServices, notifySeverityInfo, true, "power", "Proxy core recovered"),
	notifyEntry(EventMonitorDown, notifyCategoryMonitors, notifySeverityWarning, false, "activity", "Monitor failing"),
	notifyEntry(EventMonitorRecovered, notifyCategoryMonitors, notifySeverityInfo, true, "heart-pulse", "Monitor recovered"),
	notifyEntry(EventAgentStalled, notifyCategoryAgents, notifySeverityWarning, false, "hourglass", "Agent loop stalled"),
	notifyEntry(EventAgentRecovered, notifyCategoryAgents, notifySeverityInfo, true, "bot", "Agent loop recovered"),
	notifyEntry(eventSSHLogin, notifyCategorySSH, notifySeverityNotice, false, "key-round", "SSH login"),
	notifyEntry(EventSSHCompromiseSuspected, notifyCategorySSH, notifySeverityCritical, false, "shield-alert", "SSH login after repeated failures"),
	notifyEntry(eventAuth2FALimit, notifyCategoryAuth, notifySeverityWarning, false, "lock-keyhole", "Two-factor attempt limit reached"),
	notifyEntry(eventProxyQuota, notifyCategoryQuota, notifySeverityNotice, false, "gauge", "Proxy user quota"),
	notifyEntry(eventProxyExpiry, notifyCategoryQuota, notifySeverityNotice, false, "calendar-clock", "Proxy user expiry"),
	notifyEntry(eventInventoryRenewal, notifyCategoryInventory, notifySeverityNotice, false, "receipt", "Server renewal due"),
	notifyEntry(EventNotifyChannelFailing, notifyCategoryNotify, notifySeverityWarning, false, "bell-off", "Notification channel failing"),
	notifyEntry(EventNotifyChannelOK, notifyCategoryNotify, notifySeverityInfo, true, "bell-ring", "Notification channel recovered"),
	notifyEntry(eventNotifyTest, notifyCategoryNotify, notifySeverityInfo, false, "flask-conical", "Channel test"),
	notifyEntry(eventGeneric, notifyCategoryGeneral, notifySeverityInfo, false, "bell", "Notification"),
}

// notifyPluginMessagePattern presents a plugin's notify.send
// (pluginNotifyEventType).
var notifyPluginMessagePattern = notifyCataloguePattern{
	Pattern:              "plugin.<id>.message",
	notifyCatalogueEntry: notifyEntry("plugin.<id>.message", notifyCategoryPlugins, notifySeverityInfo, false, "puzzle", "Plugin message"),
}

// notifyWebhookEntry presents an event an operator-defined inbound webhook
// raises; its type is the webhook's own.
var notifyWebhookEntry = notifyEntry("", notifyCategoryWebhooks, notifySeverityInfo, false, "webhook", "Inbound webhook event")

var notifyCatalogueByType = func() map[string]notifyCatalogueEntry {
	out := make(map[string]notifyCatalogueEntry, len(notifyCatalogueTypes))
	for _, e := range notifyCatalogueTypes {
		out[e.Type] = e
	}
	return out
}()

// isNotifyPluginMessageType reports a plugin's message type:
// plugin.<id>.message, or plugin.message from a host call without a plugin
// id.
func isNotifyPluginMessageType(eventType string) bool {
	if eventType == eventPluginMessage {
		return true
	}
	rest, ok := strings.CutPrefix(eventType, "plugin.")
	if !ok {
		return false
	}
	pluginID, ok := strings.CutSuffix(rest, ".message")
	return ok && pluginID != ""
}

// notifyCatalogueLookup presents an event type. webhookType says the type is
// one an operator webhook raises; an exact type or a plugin's message still
// wins over it. The entry's Type is the type looked up.
func notifyCatalogueLookup(eventType string, webhookType bool) notifyCatalogueEntry {
	if e, ok := notifyCatalogueByType[eventType]; ok {
		return e
	}
	var e notifyCatalogueEntry
	switch {
	case isNotifyPluginMessageType(eventType):
		e = notifyPluginMessagePattern.notifyCatalogueEntry
	case webhookType:
		e = notifyWebhookEntry
	default:
		e = notifyCatalogueByType[eventGeneric]
	}
	e.Type = eventType
	return e
}

// notifyWebhookTypes is the set of event types the operator's inbound
// webhooks raise, enabled or not: a disabled webhook still has history.
func (s *Server) notifyWebhookTypes() map[string]bool {
	out := map[string]bool{}
	for _, h := range s.store.NotifyWebhooks() {
		out[h.EventType] = true
	}
	return out
}

// notifyCatalogueEntryOf presents an event the outbox planned or sent. A
// delivery whose source is a webhook is a webhook type even after its
// webhook was deleted. The webhooks are read only for a type no exact entry
// or pattern claims, since nothing else can be a webhook's.
func (s *Server) notifyCatalogueEntryOf(eventType, source string) notifyCatalogueEntry {
	webhook := source == store.NotifySourceWebhook
	if _, exact := notifyCatalogueByType[eventType]; !webhook && !exact && !isNotifyPluginMessageType(eventType) {
		webhook = s.notifyWebhookTypes()[eventType]
	}
	return notifyCatalogueLookup(eventType, webhook)
}

// notifyDeliveryView is a Sent log row with its presentation, computed from
// the event type at read time: nothing is migrated, and a catalogue change
// applies to history.
type notifyDeliveryView struct {
	store.NotifyDelivery
	notifyPresentation
}

func toNotifyDeliveryView(row store.NotifyDelivery, webhookTypes map[string]bool) notifyDeliveryView {
	webhook := row.Source == store.NotifySourceWebhook || webhookTypes[row.EventType]
	return notifyDeliveryView{NotifyDelivery: row, notifyPresentation: notifyCatalogueLookup(row.EventType, webhook).notifyPresentation}
}

func toNotifyDeliveryViews(rows []store.NotifyDelivery, webhookTypes map[string]bool) []notifyDeliveryView {
	out := make([]notifyDeliveryView, len(rows))
	for i, row := range rows {
		out[i] = toNotifyDeliveryView(row, webhookTypes)
	}
	return out
}

// notifyCatalogueView is GET /api/notify/catalogue.
type notifyCatalogueView struct {
	Categories []notifyCategory         `json:"categories"`
	Types      []notifyCatalogueEntry   `json:"types"`
	Patterns   []notifyCataloguePattern `json:"patterns"`
	// WebhookTypes are the operator's webhook types that no exact entry or
	// pattern claims, each with the webhook entry's fields.
	WebhookTypes []notifyCatalogueEntry `json:"webhook_types"`
}

func (s *Server) notifyCatalogueView() notifyCatalogueView {
	webhookTypes := []notifyCatalogueEntry{}
	for eventType := range s.notifyWebhookTypes() {
		if e := notifyCatalogueLookup(eventType, true); e.Category == notifyCategoryWebhooks {
			webhookTypes = append(webhookTypes, e)
		}
	}
	sort.Slice(webhookTypes, func(i, j int) bool { return webhookTypes[i].Type < webhookTypes[j].Type })
	return notifyCatalogueView{
		Categories:   notifyCategories,
		Types:        notifyCatalogueTypes,
		Patterns:     []notifyCataloguePattern{notifyPluginMessagePattern},
		WebhookTypes: webhookTypes,
	}
}

// handleNotifyCatalogue returns the presentation catalogue. It sits on the
// notify read surface and is refused to a node-confined token like the rest
// of it: the webhook types are fleet-wide operator configuration with no node
// to confine them to.
func (s *Server) handleNotifyCatalogue(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if s.refuseConfinedNotifyRead(w, p, "notify.catalogue.read") {
		return
	}
	writeJSON(w, http.StatusOK, s.notifyCatalogueView())
}
