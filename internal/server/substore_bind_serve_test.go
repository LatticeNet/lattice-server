package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
)

// bindShareEnv is a bind fixture whose Sub-Store record "fleet-1" renders a
// typed-node plan over every line, "fleet-doc" a document plan, and whose
// convert is a hook that records what core sent it.
type bindShareEnv struct {
	*bindEnv
	renders  atomic.Int64
	mu       sync.Mutex
	converts []model.ConvertRequest
	// tamper, when set, edits every node of the next plans.
	tamper map[string]any
	// headers, when set, are the response headers every render asks for.
	headers map[string]string
	// chain, when set, is every plan's response chain. A convert that runs
	// it rewrites the body and answers chainHeaders, or fails with chainErr.
	chain        []model.ResponseTransformerStep
	chainHeaders map[string]string
	chainErr     error
}

const (
	// bindProviderUserinfo is a quota header a fleet snapshot must never
	// put on the wire: a fleet share's figures are its identity's.
	bindProviderUserinfo = "upload=9; download=9; total=9; expire=0"

	bindShareToken      = "ffffffffffffffffffffffffffffffff"
	bindShareNoIDTok    = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	bindShareDocToken   = "dddddddddddddddddddddddddddddddd"
	bindSharePlainTok   = "cccccccccccccccccccccccccccccccc"
	bindShareForeignTok = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func bindShareFixture(t *testing.T) *bindShareEnv {
	t.Helper()
	env := &bindShareEnv{bindEnv: bindFixture(t, 2, 2)}
	s := env.srv
	page := env.read(t, "")
	selection, err := json.Marshal(map[string]any{"catalogue_version": page.CatalogueVersion, "rows": page.Rows})
	if err != nil {
		t.Fatal(err)
	}
	// "fleet-foreign" is a record whose snapshot is not a catalogue document,
	// so it says nothing about which lines were selected.
	raws := map[string]string{"fleet-1": string(selection), "fleet-doc": string(selection), "plain-1": "vless://provider",
		"fleet-foreign": `{"members":[` + string(selection) + `]}`}
	for record, raw := range raws {
		if err := env.st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: subStorePluginID, SubscriptionID: record,
			Raw: raw, Userinfo: bindProviderUserinfo, FetchedAt: env.now}); err != nil {
			t.Fatal(err)
		}
	}
	s.subscriptionFetch = func(_ context.Context, _, record string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{Raw: raws[record], Userinfo: bindProviderUserinfo, FetchedAt: env.now}, nil
	}
	s.subscriptionRender = func(_ context.Context, share model.SubscriptionShare, _, _ string, _ shareRenderVariant, snap model.SubscriptionSnapshot) (renderedSubscription, error) {
		env.renders.Add(1)
		epoch, _ := s.subscriptionSnapshotEpoch(share.Source.PluginID, share.Source.SubscriptionID, snap)
		plan := model.SelectionPlan{Kind: model.SelectionPlanKindNodes, ResponseChain: env.chain}
		for _, row := range env.rows {
			plan.Nodes = append(plan.Nodes, bindNode(t, row, bindPlaceholder(t, row.LineUUID, "uuid"), env.tamper))
		}
		switch share.Source.SubscriptionID {
		case "fleet-doc":
			plan.Kind = model.SelectionPlanKindDocument
			plan.Document = bindDocument(t, plan.Nodes, nil)
		case "plain-1":
			// A provider record: a document, no plan, the provider's quota.
			return renderedSubscription{Body: []byte("plain document"), Userinfo: snap.Userinfo, SourceEpoch: epoch, FetchedAt: snap.FetchedAt,
				RevalidationVersion: subscriptionRevalidationVersion(snap), Headers: env.headers}, nil
		}
		return renderedSubscription{Plan: &plan, SourceEpoch: epoch, FetchedAt: snap.FetchedAt, RevalidationVersion: subscriptionRevalidationVersion(snap),
			Headers: env.headers}, nil
	}
	s.substoreCatalogue.bind.convert = func(_ context.Context, pluginID string, req model.ConvertRequest) (model.ConvertReply, error) {
		if pluginID != subStorePluginID {
			t.Errorf("convert called on %s", pluginID)
		}
		env.mu.Lock()
		env.converts = append(env.converts, req)
		n := len(env.converts)
		env.mu.Unlock()
		if len(req.ResponseChain) > 0 {
			if env.chainErr != nil {
				return model.ConvertReply{}, env.chainErr
			}
			return model.ConvertReply{Content: "rewritten by the response chain", ContentType: "text/plain", Target: req.Target, NodeCount: len(req.Nodes),
				Headers: env.chainHeaders, Log: []model.ConvertLogEntry{{Level: model.ConvertLogInfo, Message: "set headers"}}}, nil
		}
		return model.ConvertReply{Content: "converted " + strings.Repeat("#", n), ContentType: "text/plain", Target: req.Target, NodeCount: len(req.Nodes)}, nil
	}
	for _, share := range []model.SubscriptionShare{
		{ID: "sh-fleet", Slug: "fleet", Token: bindShareToken, Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "fleet-1", IdentityID: bindIdentityID}},
		{ID: "sh-noid", Slug: "noid", Token: bindShareNoIDTok, Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "fleet-1"}},
		{ID: "sh-doc", Slug: "doc", Token: bindShareDocToken, Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "fleet-doc", IdentityID: bindIdentityID}},
		{ID: "sh-plain", Slug: "plain", Token: bindSharePlainTok, Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "plain-1", IdentityID: bindIdentityID}},
		{ID: "sh-foreign", Slug: "foreign", Token: bindShareForeignTok, Enabled: true,
			Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: "fleet-foreign", IdentityID: bindIdentityID}},
	} {
		mustUpsertShare(t, env.st, share)
	}
	return env
}

func (env *bindShareEnv) get(path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	env.srv.handleSubscriptionShare(rec, shareRequest(path, "curl/8"))
	return rec
}

func (env *bindShareEnv) lastConvert(t *testing.T) model.ConvertRequest {
	t.Helper()
	env.mu.Lock()
	defer env.mu.Unlock()
	if len(env.converts) == 0 {
		t.Fatal("convert was never called")
	}
	return env.converts[len(env.converts)-1]
}

// shareRefusals returns the refusal reasons audited for one share.
func (env *bindShareEnv) shareRefusals(shareID string) []string {
	env.srv.shareRefusalAudits.Wait()
	var out []string
	for _, ev := range env.st.AuditEvents() {
		if ev.Action == auditActionShareFetch && ev.Decision == "deny" && ev.Metadata["share_id"] == shareID {
			out = append(out, ev.Reason)
		}
	}
	return out
}

func (env *bindShareEnv) nodeUUIDs(t *testing.T, req model.ConvertRequest) []string {
	t.Helper()
	var out []string
	for _, node := range req.Nodes {
		obj, err := parseSubstoreNodeObject(node)
		if err != nil {
			t.Fatal(err)
		}
		uuid, _ := obj.string("uuid")
		out = append(out, uuid)
	}
	return out
}

// A share on a fleet-bound record serves the convert of the plan with the
// share's identity bound in core, and its quota header from that identity's
// policy.
func TestSubstoreBindShareServesTheBoundPlan(t *testing.T) {
	env := bindShareFixture(t)
	rec := env.get("/sub/fleet/" + bindShareToken)
	if rec.Code != http.StatusOK || rec.Body.String() != "converted #" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	req := env.lastConvert(t)
	if req.Target != "URI" || req.Document != nil || len(req.Nodes) != len(env.rows) {
		t.Fatalf("convert request: target %q, document %v, %d nodes", req.Target, req.Document != nil, len(req.Nodes))
	}
	for i, uuid := range env.nodeUUIDs(t, req) {
		if uuid != bindIdentityUUID {
			t.Fatalf("convert node %d carries uuid %q", i, uuid)
		}
	}
	raw, _ := json.Marshal(req)
	if strings.Contains(string(raw), model.PlanPlaceholderPrefix) {
		t.Fatal("convert received a placeholder")
	}
	u, _ := env.srv.getVpnUser(bindIdentityID)
	if got, want := rec.Header().Get("Subscription-Userinfo"), identityLinkUserinfo(env.srv.vpnUserPolicyAt(u, env.now), false); got != want {
		t.Fatalf("quota header %q, want the identity's %q", got, want)
	}

	// The body is cached: a second fetch renders nothing.
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusOK || env.renders.Load() != 1 {
		t.Fatalf("a repeat fetch: status %d, renders %d", rec.Code, env.renders.Load())
	}
	// A body revalidated against an unmoved snapshot is extended, and its
	// quota header is still the identity's, not the snapshot's.
	later := env.now.Add(subscriptionCacheTTL + time.Minute)
	env.srv.now = func() time.Time { return later }
	env.srv.singboxInvMu.Lock()
	for nodeID, inv := range env.srv.singboxInv {
		inv.At = later
		env.srv.singboxInv[nodeID] = inv
	}
	env.srv.singboxInvMu.Unlock()
	env.srv.invalidateLineReadModel()
	rec = env.get("/sub/fleet/" + bindShareToken)
	if got, want := rec.Header().Get("Subscription-Userinfo"), identityLinkUserinfo(env.srv.vpnUserPolicyAt(u, later), false); rec.Code != http.StatusOK ||
		env.renders.Load() != 1 || got != want {
		t.Fatalf("a revalidated fetch: status %d, renders %d, quota %q, want %q", rec.Code, env.renders.Load(), got, want)
	}

	// The snapshot is identity-free, so it cannot see a rotation. The bind
	// state in the cache key does: the next fetch binds the new credential.
	const rotated = "0f1e2d3c-4b5a-4968-8776-655443322110"
	u.Credentials[0].UUID = rotated
	for i, row := range env.rows {
		u.Bindings[i].AppliedCredentialSHA256 = bindAppliedSHA(t, u, row.LineUUID)
	}
	if err := env.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	rec = env.get("/sub/fleet/" + bindShareToken)
	if rec.Code != http.StatusOK || env.renders.Load() != 2 || rec.Body.String() != "converted ##" {
		t.Fatalf("after a rotation: status %d, renders %d, body %q", rec.Code, env.renders.Load(), rec.Body.String())
	}
	for i, uuid := range env.nodeUUIDs(t, env.lastConvert(t)) {
		if uuid != rotated {
			t.Fatalf("after a rotation convert node %d carries %q", i, uuid)
		}
	}
}

// A document plan reaches convert as the document with one substitution per
// placeholder.
func TestSubstoreBindShareConvertsADocumentPlan(t *testing.T) {
	env := bindShareFixture(t)
	if rec := env.get("/sub/doc/" + bindShareDocToken); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	req := env.lastConvert(t)
	if req.Document == nil || len(req.Nodes) != 0 || len(req.Document.Substitutions) != len(env.rows) {
		t.Fatalf("convert request: %+v", req)
	}
	for placeholder, credential := range req.Document.Substitutions {
		if !strings.Contains(req.Document.Content, placeholder) || credential != bindIdentityUUID {
			t.Fatalf("substitution %s -> %s", placeholder, credential)
		}
	}
}

// Every refusal of the bind step is the decoy, audited with its reason, and
// none reaches convert.
func TestSubstoreBindShareRefusals(t *testing.T) {
	env := bindShareFixture(t)

	// A share that names no identity cannot serve a fleet-bound record.
	if rec := env.get("/sub/noid/" + bindShareNoIDTok); rec.Code != http.StatusNotFound {
		t.Fatalf("a share without an identity: status %d", rec.Code)
	}
	if got := env.shareRefusals("sh-noid"); len(got) != 1 || got[0] != substoreBindDenyNoIdentity {
		t.Fatalf("refusals %v", got)
	}

	// A plan whose every node a script moved binds nothing.
	env.tamper = map[string]any{"server": "relay.attacker.example"}
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusNotFound {
		t.Fatalf("a tampered plan: status %d", rec.Code)
	}
	if got := env.shareRefusals("sh-fleet"); len(got) != 1 || got[0] != substoreBindDenyPrefix+substoreBindRefusedNoLine {
		t.Fatalf("refusals %v", got)
	}
	env.tamper = nil

	// A record whose snapshot does not say which lines it selected binds
	// nothing, rather than every line the identity holds.
	if rec := env.get("/sub/foreign/" + bindShareForeignTok); rec.Code != http.StatusNotFound {
		t.Fatalf("a plan without a selection: status %d", rec.Code)
	}
	if got := env.shareRefusals("sh-foreign"); len(got) != 1 || got[0] != substoreBindDenyPrefix+substoreBindRefusedSelection {
		t.Fatalf("refusals %v", got)
	}

	// An identity that is not in service never reaches the bind step. The
	// handler refuses it before the cache, and a render that raced the
	// change refuses it too. (A share placeholder for a known token in a
	// policy state may answer first; either way no bound document leaves.)
	u, _ := env.srv.getVpnUser(bindIdentityID)
	u.Enabled = false
	if err := env.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	if rec := env.get("/sub/doc/" + bindShareDocToken); strings.HasPrefix(rec.Body.String(), "converted") {
		t.Fatalf("a disabled identity was served its bound document: status %d", rec.Code)
	}
	share, _ := env.st.SubscriptionShare("sh-doc")
	want := substoreBindDenyIdentityPrefix + vpnSuspendReasonDisabled
	if _, _, refusal := env.srv.substoreBindServeState(share, env.now); refusal != want {
		t.Fatalf("serve state refusal %q, want %q", refusal, want)
	}
	plan := bindNodesPlan(t, env.rows)
	_, err := env.srv.substoreBindRendered(context.Background(), share, "plain", shareRenderVariant{}, model.SubscriptionSnapshot{}, renderedSubscription{Plan: &plan})
	var refusal substoreBindRefusal
	if !errors.As(err, &refusal) || refusal.reason != want {
		t.Fatalf("a render for a disabled identity: %v", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if len(env.converts) != 0 {
		t.Fatalf("a refused plan reached convert %d time(s)", len(env.converts))
	}
}

// A share that names an identity on a record that renders a plain document
// binds nothing, so its quota header stays the record's own.
func TestSubstoreBindSharePlainDocumentKeepsItsQuota(t *testing.T) {
	env := bindShareFixture(t)
	rec := env.get("/sub/plain/" + bindSharePlainTok)
	if rec.Code != http.StatusOK || rec.Body.String() != "plain document" {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if got, want := rec.Header().Get("Subscription-Userinfo"), subscriptionUserinfoForResponse(bindProviderUserinfo); got != want {
		t.Fatalf("quota header %q, want the record's %q", got, want)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if len(env.converts) != 0 {
		t.Fatal("a plain document reached convert")
	}
}

// A bound plan reaches convert only when the plugin's signed manifest holds
// convert to zero host calls; the runtime enforces that budget, so the one
// method that holds a credential can reach no host function.
func TestSubstoreBindConvertNeedsAZeroHostCallBudget(t *testing.T) {
	env := bindShareFixture(t)
	s := env.srv
	s.substoreCatalogue.bind.convert = nil
	install := func(budget *plugin.InvokeBudgetSpec) {
		s.plugins = []plugin.Loaded{{Manifest: plugin.Manifest{ID: subStorePluginID, Schema: plugin.ManifestSchemaV2,
			Interfaces: []plugin.InterfaceContract{{Service: subStorePluginID + "/subscription",
				MethodSpecs: []plugin.InterfaceMethod{{Name: "convert", Effect: plugin.InterfaceEffectRead, Scopes: []string{"substore:admin"}, Budget: budget}}}}}}}
	}
	req := model.ConvertRequest{Target: "URI", Format: "plain", Nodes: []json.RawMessage{json.RawMessage(`{"name":"a"}`)}}
	for name, budget := range map[string]*plugin.InvokeBudgetSpec{
		"no budget":       nil,
		"one host call":   {TimeoutMS: 1000, StdoutBytes: 1024, StderrBytes: 1024, HostCalls: 1},
		"the default cap": {TimeoutMS: 1000, StdoutBytes: 1024, StderrBytes: 1024, HostCalls: plugin.DefaultInvokeHostCalls},
	} {
		install(budget)
		var refusal substoreBindRefusal
		if _, err := s.substoreBindConvert(context.Background(), subStorePluginID, req); !errors.As(err, &refusal) || refusal.reason != substoreBindDenyConvertUnsealed {
			t.Fatalf("%s: convert was called or failed otherwise: %v", name, err)
		}
	}
	s.plugins = nil
	var refusal substoreBindRefusal
	if _, err := s.substoreBindConvert(context.Background(), subStorePluginID, req); !errors.As(err, &refusal) {
		t.Fatalf("a plugin that is not loaded: %v", err)
	}
	// A sealed convert gets past the check to the runtime (none in this
	// fixture).
	install(&plugin.InvokeBudgetSpec{TimeoutMS: 1000, StdoutBytes: 1024, StderrBytes: 1024, HostCalls: 0})
	if _, err := s.substoreBindConvert(context.Background(), subStorePluginID, req); err == nil || errors.As(err, &refusal) {
		t.Fatalf("a sealed convert: %v", err)
	}
	// Through the share, an unsealed convert answers the decoy, audited.
	install(nil)
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusNotFound {
		t.Fatalf("an unsealed convert: status %d", rec.Code)
	}
	if got := env.shareRefusals("sh-fleet"); len(got) != 1 || got[0] != substoreBindDenyConvertUnsealed {
		t.Fatalf("refusals %v", got)
	}
}

// A render reply's plan is decoded strictly, and a reply cannot carry both a
// document and a plan.
func TestSubstoreDecodeRenderPlan(t *testing.T) {
	if plan, err := substoreDecodeRenderPlan("doc", nil); plan != nil || err != nil {
		t.Fatalf("a document reply: %v %v", plan, err)
	}
	valid := `{"kind":"nodes","nodes":[{"node":{"name":"p"},"provider":true}]}`
	if plan, err := substoreDecodeRenderPlan("", json.RawMessage(valid)); err != nil || plan == nil || len(plan.Nodes) != 1 {
		t.Fatalf("a plan reply: %v %v", plan, err)
	}
	for name, raw := range map[string]string{
		"an unknown field":  `{"kind":"nodes","nodes":[],"bind_anyway":true}`,
		"a duplicate key":   `{"kind":"nodes","nodes":[{"node":{"server":"a","server":"b"},"provider":true}]}`,
		"an unknown kind":   `{"kind":"raw","nodes":[]}`,
		"a node not object": `{"kind":"nodes","nodes":[{"node":"x","provider":true}]}`,
	} {
		if _, err := substoreDecodeRenderPlan("", json.RawMessage(raw)); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, err := substoreDecodeRenderPlan("doc", json.RawMessage(valid)); err == nil {
		t.Fatal("a reply with a document and a plan was accepted")
	}
}

// fetchPlain renders the plain record afresh with headers as its render's
// and returns the response headers. The body serves whatever the headers
// are.
func (env *bindShareEnv) fetchPlain(t *testing.T, headers map[string]string) http.Header {
	t.Helper()
	env.headers = headers
	env.srv.subscriptionCache.InvalidateShare("sh-plain")
	rec := env.get("/sub/plain/" + bindSharePlainTok)
	if rec.Code != http.StatusOK || rec.Body.String() != "plain document" {
		t.Fatalf("headers %q: status %d body %q", headers, rec.Code, rec.Body.String())
	}
	return rec.Header()
}

// A record's response headers reach the client through the allow-list only:
// each of the four passes, whatever the case of its name; a value that fails
// its check drops the header and never the body; any other name is dropped.
func TestShareRecordHeadersPassTheAllowListOnly(t *testing.T) {
	env := bindShareFixture(t)
	core := env.fetchPlain(t, nil)
	if core.Get("Content-Disposition") == "" || core.Get("Profile-Update-Interval") != "2" {
		t.Fatalf("the link's own headers: %v", core)
	}

	allowed := map[string]string{
		"Content-Disposition":     `attachment; filename*=UTF-8''Fleet%20Tokyo`,
		"PROFILE-UPDATE-INTERVAL": "12",
		"profile-web-page-url":    "https://panel.example.com/account",
		"Plan-Name":               "Fleet Pro",
	}
	got := env.fetchPlain(t, allowed)
	for name, value := range allowed {
		if got.Get(name) != value {
			t.Fatalf("%s = %q, want %q", name, got.Get(name), value)
		}
	}
	// The headers are cached with the body: a hit carries them too.
	renders := env.renders.Load()
	if rec := env.get("/sub/plain/" + bindSharePlainTok); env.renders.Load() != renders || rec.Header().Get("Plan-Name") != "Fleet Pro" {
		t.Fatalf("a cached body: renders %d then %d, plan-name %q", renders, env.renders.Load(), rec.Header().Get("Plan-Name"))
	}
	// Only the web page URL may exceed the short bound.
	longURL := "https://panel.example.com/" + strings.Repeat("a", 1000)
	if got := env.fetchPlain(t, map[string]string{"Profile-Web-Page-URL": longURL}); got.Get("Profile-Web-Page-URL") != longURL {
		t.Fatalf("a 1 KiB web page url was dropped")
	}

	long := strings.Repeat("a", recordHeaderValueBytes+1)
	for name, header := range map[string][2]string{
		"a CR":                       {"Plan-Name", "Pro\rX-Injected: 1"},
		"a LF":                       {"Plan-Name", "Pro\nSet-Cookie: a=b"},
		"a NUL":                      {"Content-Disposition", "attachment\x00"},
		"an escape":                  {"Plan-Name", "Pro\x1b[0m"},
		"a DEL":                      {"Plan-Name", "Pro\x7f"},
		"an empty value":             {"Plan-Name", ""},
		"a plan name over the bound": {"Plan-Name", long},
		"a disposition over bound":   {"Content-Disposition", "attachment; filename=" + long},
		"an interval of 0":           {"Profile-Update-Interval", "0"},
		"an interval over a week":    {"Profile-Update-Interval", "169"},
		"an interval with a unit":    {"Profile-Update-Interval", "12h"},
		"an http url":                {"Profile-Web-Page-URL", "http://panel.example.com/"},
		"a url with userinfo":        {"Profile-Web-Page-URL", "https://user:pass@panel.example.com/"},
		"a private address":          {"Profile-Web-Page-URL", "https://10.0.0.8/"},
		"another private address":    {"Profile-Web-Page-URL", "https://192.168.1.1/admin"},
		"a loopback address":         {"Profile-Web-Page-URL", "https://127.0.0.1/"},
		"a loopback v6 address":      {"Profile-Web-Page-URL", "https://[::1]/"},
		"a link-local address":       {"Profile-Web-Page-URL", "https://169.254.169.254/latest/meta-data"},
		"a link-local v6 address":    {"Profile-Web-Page-URL", "https://[fe80::1]/"},
		"localhost":                  {"Profile-Web-Page-URL", "https://localhost/"},
		"a local name":               {"Profile-Web-Page-URL", "https://router.local/"},
		"a url over 2 KiB":           {"Profile-Web-Page-URL", "https://panel.example.com/" + strings.Repeat("a", model.MaxSubscriptionResponseHeaderBytes)},
		// The share names an identity, so a value carrying its credential,
		// raw or encoded, is dropped.
		"the identity's uuid":          {"Plan-Name", "Fleet " + bindIdentityUUID},
		"the identity's uuid dashless": {"Profile-Web-Page-URL", "https://panel.example.com/?u=" + strings.ReplaceAll(bindIdentityUUID, "-", "")},
	} {
		got := env.fetchPlain(t, map[string]string{header[0]: header[1]})
		if got.Get(header[0]) != core.Get(header[0]) {
			t.Errorf("%s: %s = %q, want %q", name, header[0], got.Get(header[0]), core.Get(header[0]))
		}
	}

	// Every other name is dropped: core's own headers stand, and nothing the
	// record named is added.
	got = env.fetchPlain(t, map[string]string{
		"Subscription-Userinfo":        "upload=0; download=0; total=1; expire=0",
		"Content-Type":                 "text/html",
		"Cache-Control":                "public, max-age=86400",
		"Set-Cookie":                   "session=1",
		"Location":                     "https://panel.example.com/",
		"X-Lattice-Subscription-Stale": "true",
	})
	if got.Get("Subscription-Userinfo") != subscriptionUserinfoForResponse(bindProviderUserinfo) || got.Get("Content-Type") != core.Get("Content-Type") ||
		got.Get("Cache-Control") != "no-store" || got.Get("Set-Cookie") != "" || got.Get("Location") != "" || got.Get("X-Lattice-Subscription-Stale") != "" {
		t.Fatalf("a header off the allow-list reached the response: %v", got)
	}

	// An update interval the operator set on the share wins over the
	// record's; the record's other headers still apply.
	share, _ := env.st.SubscriptionShare("sh-plain")
	share, err := withShareUpdateIntervalHours(share, 6)
	if err != nil {
		t.Fatal(err)
	}
	mustUpsertShare(t, env.st, share)
	got = env.fetchPlain(t, allowed)
	if got.Get("Profile-Update-Interval") != "6" || got.Get("Plan-Name") != "Fleet Pro" {
		t.Fatalf("a share interval of 6 under a record interval of 12: %v", got)
	}
}

// On a fleet-bound record the response chain sets headers and nothing else:
// convert runs it a second time over the same bound nodes and its body is
// discarded, so the share serves the body no script touched after binding.
// Its headers pass the allow-list and the identity's credential screen.
func TestSubstoreBindShareResponseChainSetsOnlyHeaders(t *testing.T) {
	env := bindShareFixture(t)
	env.headers = map[string]string{"Plan-Name": "from the render"}
	env.chain = []model.ResponseTransformerStep{{Name: "headers", Source: "$options._res.headers['plan-name'] = 'Fleet Pro'", Enabled: true}}
	env.chainHeaders = map[string]string{
		"Plan-Name":               "Fleet Pro",
		"Profile-Update-Interval": "24",
		"Content-Disposition":     "attachment; filename=" + bindIdentityUUID,
		"Profile-Web-Page-URL":    "https://panel.example.com/?u=" + strings.ReplaceAll(bindIdentityUUID, "-", ""),
		"Subscription-Userinfo":   "upload=0; download=0; total=1; expire=0",
	}
	rec := env.get("/sub/fleet/" + bindShareToken)
	if rec.Code != http.StatusOK || rec.Body.String() != "converted #" {
		t.Fatalf("status %d body %q, want the body convert produced before the chain", rec.Code, rec.Body.String())
	}
	env.mu.Lock()
	converts := append([]model.ConvertRequest(nil), env.converts...)
	env.mu.Unlock()
	if len(converts) != 2 || converts[0].ResponseChain != nil || len(converts[1].ResponseChain) != 1 {
		t.Fatalf("converts: %d, chains %v", len(converts), converts)
	}
	first, second := env.nodeUUIDs(t, converts[0]), env.nodeUUIDs(t, converts[1])
	if len(first) != len(env.rows) || strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("the chain ran over other nodes: %v then %v", first, second)
	}
	u, _ := env.srv.getVpnUser(bindIdentityID)
	h := rec.Header()
	if h.Get("Plan-Name") != "Fleet Pro" || h.Get("Profile-Update-Interval") != "24" || h.Get("Profile-Web-Page-URL") != "" ||
		h.Get("Content-Disposition") != `attachment; filename="fleet"; filename*=UTF-8''fleet` ||
		h.Get("Subscription-Userinfo") != identityLinkUserinfo(env.srv.vpnUserPolicyAt(u, env.now), false) {
		t.Fatalf("headers %v", h)
	}

	// A chain that fails leaves the body served with the render's headers.
	env.chainErr = errors.New("the transformer threw")
	env.srv.subscriptionCache.InvalidateShare("sh-fleet")
	rec = env.get("/sub/fleet/" + bindShareToken)
	if rec.Code != http.StatusOK || rec.Body.String() != "converted ###" || rec.Header().Get("Plan-Name") != "from the render" {
		t.Fatalf("a failed chain: status %d body %q plan-name %q", rec.Code, rec.Body.String(), rec.Header().Get("Plan-Name"))
	}
}
