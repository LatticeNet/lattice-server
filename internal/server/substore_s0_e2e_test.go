package server

// Scratch-only joined check of the four Sub-Store S0 server lanes (host,
// catalogue, bind, services). A fake Sub-Store plugin runs behind the real
// plugin runtime manager, so every core path below is the production one:
// the plugin gateway, the share endpoint, the runtime call for fetch,
// render, convert, apply_revision and a scheduled method, the broker's
// rpc.call for the catalogue and claim_apply, and the approval endpoint.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	e2eAliceID   = "vu-alice"
	e2eAliceUUID = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	e2eBobID     = "vu-bob"
	e2eBobUUID   = "1b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e"
	e2eFleet     = "fleet-1"
	e2eDoc       = "doc-1"
	e2eNodes     = 25
	e2ePerNode   = 2 // 50 lines
	e2eDropped   = 5 // rev-2 drops the last five lines and renames the first
)

var e2eOperator = principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{
	"proxy:admin", "substore:admin", "substore:read", "vpncore:read", "vpncore:admin", "network:plan", "network:apply"}}}

var e2eApprover = principal{Principal: rbac.Principal{ActorID: "approver", Scopes: []string{"network:apply", "network:plan", "proxy:admin"}}}

// e2eSubStore is the fake Sub-Store plugin: a runtime runner that answers
// the subscription service the way S1/S2 are specified to.
type e2eSubStore struct {
	t          testing.TB
	reportLive bool

	mu        sync.Mutex
	broker    *plugin.Broker
	live      string
	calls     []string
	converts  []model.ConvertRequest
	claims    []string
	scheduled []string
}

func (f *e2eSubStore) Name() string { return "e2e-substore" }
func (f *e2eSubStore) Start(_ context.Context, req plugin.RunnerStartRequest) (plugin.RunnerStartResult, error) {
	f.mu.Lock()
	f.broker = req.Broker
	f.mu.Unlock()
	return plugin.RunnerStartResult{}, nil
}
func (f *e2eSubStore) Stop(context.Context, plugin.RunnerStopRequest) error { return nil }

func (f *e2eSubStore) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == method {
			n++
		}
	}
	return n
}

func (f *e2eSubStore) Invoke(ctx context.Context, req plugin.InvokeRequest) (plugin.InvokeResponse, error) {
	var call struct {
		Service string          `json:"service"`
		Method  string          `json:"method"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(req.Payload, &call); err != nil {
		return plugin.InvokeResponse{OK: false, Message: "bad call"}, err
	}
	f.mu.Lock()
	f.calls = append(f.calls, call.Method)
	broker, live := f.broker, f.live
	f.mu.Unlock()
	out, err := f.serve(ctx, broker, live, call.Service, call.Method, call.Payload)
	if err != nil {
		f.t.Logf("fake sub-store %s/%s: %v", call.Service, call.Method, err)
		return plugin.InvokeResponse{OK: false, Message: err.Error()}, err
	}
	return plugin.InvokeResponse{OK: true, Result: out}, nil
}

func (f *e2eSubStore) serve(ctx context.Context, broker *plugin.Broker, live, service, method string, payload json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "fetch":
		var req struct {
			SubscriptionID string `json:"subscription_id"`
		}
		_ = json.Unmarshal(payload, &req)
		if req.SubscriptionID == e2eDoc {
			return json.Marshal(map[string]string{"raw": "vless://provider-document"})
		}
		// A fleet record's snapshot is the catalogue rows it selected, read
		// through the plugin's own rpc.call grant.
		raw, err := e2eReadCatalogue(ctx, broker)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"raw": raw})
	case "render":
		var req struct {
			SubscriptionID string `json:"subscription_id"`
			Revision       string `json:"revision"`
			Raw            string `json:"raw"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		revision := req.Revision
		if revision == "" {
			revision = live
		}
		reply := map[string]any{}
		if f.reportLive {
			reply["live_revision"] = live
		}
		if req.SubscriptionID == e2eDoc {
			reply["content"] = "vless://provider-document#" + revision
			return json.Marshal(reply)
		}
		var snap struct {
			Rows []model.LineCatalogueRow `json:"rows"`
		}
		if err := json.Unmarshal([]byte(req.Raw), &snap); err != nil {
			return nil, fmt.Errorf("render: snapshot: %w", err)
		}
		rows := snap.Rows
		var rename map[string]any
		if revision == "rev-2" {
			rows = rows[:len(rows)-e2eDropped]
			rename = map[string]any{"name": "renamed in rev-2"}
		}
		plan := model.SelectionPlan{Kind: model.SelectionPlanKindNodes}
		for i, row := range rows {
			var edit map[string]any
			if i == 0 {
				edit = rename
			}
			plan.Nodes = append(plan.Nodes, bindNode(f.t, row, bindPlaceholder(f.t, row.LineUUID, "uuid"), edit))
		}
		reply["plan"] = plan
		return json.Marshal(reply)
	case "convert":
		req, err := model.DecodeConvertRequest(payload)
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.converts = append(f.converts, req)
		f.mu.Unlock()
		var b strings.Builder
		for _, node := range req.Nodes {
			b.Write(node)
			b.WriteByte('\n')
		}
		return json.Marshal(model.ConvertReply{Content: b.String(), ContentType: "text/plain; charset=utf-8", Target: req.Target, NodeCount: len(req.Nodes)})
	case "depends_on":
		return json.Marshal(map[string]any{"records": []map[string]string{{"id": e2eFleet, "revision": live}}})
	case subStoreApplyRevisionMethod:
		var req subStoreApplyRevisionRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		granted, err := broker.RPCCall(ctx, subStorePlansService, "claim_apply", payload)
		f.mu.Lock()
		f.claims = append(f.claims, string(granted))
		f.mu.Unlock()
		if err != nil || string(granted) != `{"granted":true}` {
			return nil, fmt.Errorf("claim_apply refused: %v %s", err, granted)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.live != req.ExpectedRevision {
			return nil, errors.New("expected_revision is not live")
		}
		f.live = req.Revision
		return json.Marshal(subStoreApplyRevisionReply{SubscriptionID: req.SubscriptionID, Revision: req.Revision})
	case "refresh_all":
		f.mu.Lock()
		f.scheduled = append(f.scheduled, string(payload))
		f.mu.Unlock()
		return json.RawMessage(`{}`), nil
	}
	return nil, fmt.Errorf("unknown method %s/%s", service, method)
}

// e2eReadCatalogue reads every catalogue page through the broker.
func e2eReadCatalogue(ctx context.Context, broker *plugin.Broker) (string, error) {
	var rows []json.RawMessage
	version, cursor := "", ""
	for {
		req := map[string]any{"limit": 20}
		if cursor != "" {
			req["cursor"] = cursor
		}
		body, _ := json.Marshal(req)
		out, err := broker.RPCCall(ctx, "latticenet.vpn-core/lines", "catalogue", body)
		if err != nil {
			return "", err
		}
		var page struct {
			CatalogueVersion string            `json:"catalogue_version"`
			Rows             []json.RawMessage `json:"rows"`
			Cursor           string            `json:"cursor"`
		}
		if err := json.Unmarshal(out, &page); err != nil {
			return "", err
		}
		version = page.CatalogueVersion
		rows = append(rows, page.Rows...)
		if page.Cursor == "" {
			break
		}
		cursor = page.Cursor
	}
	raw, err := json.Marshal(map[string]any{"catalogue_version": version, "rows": rows})
	return string(raw), err
}

// e2eRealManifest is a copy of the Sub-Store plugin's signed 0.16.0-alpha.4 manifest
// (lattice-plugin-sub-store/manifest.json), read as the server reads it.
const e2eRealManifest = "testdata/substore_manifest_0.16.0-alpha.4.json"

// e2eManifest is the current manifest plus what S2 is specified to add:
// task:schedule, rpc.call on the catalogue and on plans/claim_apply, the
// subscription methods depends_on, apply_revision and one scheduled method,
// and the core-backed shares, plans and bind methods the UI calls.
func e2eManifest(t testing.TB) plugin.Manifest {
	t.Helper()
	raw, err := os.ReadFile(e2eRealManifest)
	if err != nil {
		t.Fatal(err)
	}
	var m plugin.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	read := func(name string, scopes ...string) plugin.InterfaceMethod {
		return plugin.InterfaceMethod{Name: name, Effect: plugin.InterfaceEffectRead, Scopes: scopes}
	}
	write := func(name string, scopes ...string) plugin.InterfaceMethod {
		return plugin.InterfaceMethod{Name: name, Effect: plugin.InterfaceEffectWrite, Scopes: scopes}
	}
	m.Version = "0.17.0-alpha.0"
	m.Capabilities = append(m.Capabilities, "task:schedule")
	m.HostAccess.RPC = append(m.HostAccess.RPC,
		plugin.RPCDependency{Service: "latticenet.vpn-core/lines", Methods: []string{"catalogue"}},
		plugin.RPCDependency{Service: subStorePlansService, Methods: []string{"claim_apply"}})
	sawConvert := false
	for i := range m.Interfaces {
		c := &m.Interfaces[i]
		switch c.Service {
		case subStorePluginID + "/subscription":
			for _, method := range c.MethodSpecs {
				if method.Name == "convert" {
					sawConvert = method.Budget != nil && method.Budget.HostCalls == 0
				}
			}
			c.MethodSpecs = append(c.MethodSpecs, read("depends_on", "substore:read"),
				write(subStoreApplyRevisionMethod, "substore:admin"), write("refresh_all", "substore:admin"))
		case subStoreSharesService:
			c.MethodSpecs = append(c.MethodSpecs, write("create", "proxy:admin"), write("archive", "proxy:admin"))
		}
	}
	if !sawConvert {
		t.Fatal("the current manifest does not hold convert to zero host calls")
	}
	m.Interfaces = append(m.Interfaces,
		plugin.InterfaceContract{Service: subStorePlansService, Backing: plugin.BackingCore, MethodSpecs: []plugin.InterfaceMethod{
			write("propose", "proxy:admin"), read("status", "substore:read")}},
		plugin.InterfaceContract{Service: substoreBindService, Backing: plugin.BackingCore, MethodSpecs: []plugin.InterfaceMethod{
			read("preview", "vpncore:read", "substore:read")}})
	if err := plugin.ValidateManifest(m); err != nil {
		t.Fatalf("the extended manifest does not validate: %v", err)
	}
	return m
}

type e2eEnv struct {
	*catalogueEnv
	fake  *e2eSubStore
	rows  []model.LineCatalogueRow
	creds map[string]string
}

func newE2EEnv(t *testing.T, reportLive bool) *e2eEnv {
	t.Helper()
	cat := catalogueFixture(t, e2eNodes, e2ePerNode)
	s := cat.srv
	rows := cat.read(t, "").Rows
	env := &e2eEnv{catalogueEnv: cat, rows: rows, creds: map[string]string{e2eAliceID: e2eAliceUUID, e2eBobID: e2eBobUUID}}
	if len(rows) != e2eNodes*e2ePerNode {
		// The first page holds them all at this size; a smaller page bound
		// would only change how the plugin reads them.
		t.Logf("first catalogue page has %d rows", len(rows))
	}
	all, _, _ := cat.readAll(t, "", 100)
	env.rows = all
	if len(all) != 50 {
		t.Fatalf("catalogue has %d lines, want 50", len(all))
	}
	for _, id := range []string{e2eAliceID, e2eBobID} {
		u := VpnUser{ID: id, Email: id + "@example.com", Name: id, Enabled: true, CreatedAt: cat.now, UpdatedAt: cat.now,
			Credentials: []VpnCredential{{Protocol: "vless", UUID: env.creds[id], Flow: bindIdentityFlow}}}
		for _, row := range all {
			u.Bindings = append(u.Bindings, LineBinding{LineHashID: row.LineHashID, Enabled: true, AppliedCredentialSHA256: bindAppliedSHA(t, u, row.LineUUID)})
		}
		if err := s.putVpnUser(u); err != nil {
			t.Fatal(err)
		}
	}

	env.fake = &e2eSubStore{t: t, reportLive: reportLive, live: "rev-1"}
	manifest := e2eManifest(t)
	// A verified v2 load carries the bundle digest as its artifact digest.
	loaded := plugin.Loaded{Manifest: manifest, Capabilities: manifest.Capabilities, BundlePath: t.TempDir(), ArtifactDigest: manifest.Bundle.DigestSHA256}
	s.plugins = []plugin.Loaded{loaded}
	if err := cat.st.UpsertPluginInstallation(model.PluginInstallation{ID: subStorePluginID, Name: "Sub-Store", Type: plugin.TypeSystem,
		Status: model.PluginStatusActive, Version: loaded.Manifest.Version}); err != nil {
		t.Fatal(err)
	}
	// vpn-core owns the catalogue service the plugin reads.
	if err := cat.st.UpsertPluginInstallation(model.PluginInstallation{ID: vpnCorePluginID, Name: "vpn-core", Type: plugin.TypeSystem,
		Status: model.PluginStatusActive}); err != nil {
		t.Fatal(err)
	}
	s.pluginRuntime = plugin.NewRuntimeManagerWithOptions(plugin.RuntimeManagerOptions{
		Services: s.pluginHostServices(), Runners: map[string]plugin.Runner{plugin.TypeSystem: env.fake},
	})
	if _, err := s.pluginRuntime.Start(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	s.applyPluginHostAccess(loaded)
	return env
}

// gateway is the dashboard's call through the plugin gateway.
func (e *e2eEnv) gateway(t *testing.T, p principal, service, method string, payload any) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"id": subStorePluginID, "service": service, "method": method, "payload": payload})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/call", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	e.srv.handlePluginCall(rec, req, p)
	return rec.Code, rec.Body.Bytes()
}

func (e *e2eEnv) mustGateway(t *testing.T, service, method string, payload any) []byte {
	t.Helper()
	code, body := e.gateway(t, e2eOperator, service, method, payload)
	if code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", service, method, code, body)
	}
	return body
}

func (e *e2eEnv) createShare(t *testing.T, record, slug, identity string) model.SubscriptionShare {
	t.Helper()
	var reply subStoreSvcShareReply
	if err := json.Unmarshal(e.mustGateway(t, subStoreSharesService, "create",
		map[string]any{"subscription_id": record, "slug": slug, "identity_id": identity}), &reply); err != nil {
		t.Fatal(err)
	}
	share, ok := e.st.SubscriptionShare(reply.Share.ShareID)
	if !ok || share.Token == "" {
		t.Fatalf("share %s not stored", slug)
	}
	return share
}

func (e *e2eEnv) fetch(share model.SubscriptionShare) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.srv.handleSubscriptionShare(rec, shareRequest("/sub/"+share.Slug+"/"+share.Token, "curl/8"))
	return rec
}

// checkBody holds a served body to one identity's credentials.
func (e *e2eEnv) checkBody(t *testing.T, who, body string, lines int) {
	t.Helper()
	own := e.creds[who]
	if got := strings.Count(body, own); got != lines {
		t.Fatalf("%s's body carries its credential %d times, want %d", who, got, lines)
	}
	for id, cred := range e.creds {
		if id != who && strings.Contains(body, cred) {
			t.Fatalf("%s's body carries %s's credential", who, id)
		}
	}
	if strings.Contains(body, catalogueOwnerUUID) || strings.Contains(body, model.PlanPlaceholderPrefix) {
		t.Fatalf("%s's body carries the line owner's credential or a placeholder", who)
	}
	if got := strings.Count(body, "\n"); got != lines {
		t.Fatalf("%s's body has %d entries, want %d", who, got, lines)
	}
}

func TestS0JoinedFlow(t *testing.T) {
	env := newE2EEnv(t, true)
	s := env.srv

	// 1. Shares, made through the gateway as the Sub-Store UI makes them.
	alice := env.createShare(t, e2eFleet, "alice", e2eAliceID)
	bob := env.createShare(t, e2eFleet, "bob", e2eBobID)

	// 2. Validate-and-bind for one identity, as the Fleet view previews it.
	var preview substoreBindPreviewReply
	if err := json.Unmarshal(env.mustGateway(t, substoreBindService, "preview",
		map[string]any{"subscription_id": e2eFleet, "identity_id": e2eAliceID}), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Kind != model.SelectionPlanKindNodes || preview.FleetNodes != 50 || len(preview.Entries) != 50 || len(preview.Excluded) != 0 || preview.Refused != "" {
		t.Fatalf("preview: kind %s fleet %d entries %d excluded %+v refused %q", preview.Kind, preview.FleetNodes, len(preview.Entries), preview.Excluded, preview.Refused)
	}
	if raw, _ := json.Marshal(preview); strings.Contains(string(raw), e2eAliceUUID) {
		t.Fatal("the preview carries the identity's credential")
	}

	// 3. Render a plan for 50 lines, bind, convert, serve.
	for _, c := range []struct {
		who   string
		share model.SubscriptionShare
	}{{e2eAliceID, alice}, {e2eBobID, bob}} {
		rec := env.fetch(c.share)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s's share: %d %s refusals=%v", c.who, rec.Code, rec.Body.String(), env.refusals(c.share.ID))
		}
		env.checkBody(t, c.who, rec.Body.String(), 50)
	}
	env.fake.mu.Lock()
	converts := len(env.fake.converts)
	nodes := len(env.fake.converts[converts-1].Nodes)
	env.fake.mu.Unlock()
	if converts != 2 || nodes != 50 {
		t.Fatalf("convert called %d times, last with %d nodes", converts, nodes)
	}

	// 4. A plan proposal: rev-1 to rev-2 drops five lines and renames one.
	code, body := env.gateway(t, e2eOperator, subStorePlansService, "propose",
		map[string]any{"subscription_id": e2eFleet, "from_revision": "rev-1", "to_revision": "rev-2"})
	if code != http.StatusOK {
		t.Fatalf("propose: %d %s", code, body)
	}
	var reply subStorePlansProposeReply
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(reply.Plan))
	if !reply.Required || reply.Status != model.ApprovalPending || reply.PlanSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("propose reply: %+v", reply)
	}
	var plan subStorePlan
	if err := json.Unmarshal([]byte(reply.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reply.Plan, e2eAliceUUID) || strings.Contains(reply.Plan, e2eBobUUID) {
		t.Fatal("the plan carries a credential")
	}
	if len(plan.Identities) != 2 {
		t.Fatalf("plan identities: %+v", plan.Identities)
	}
	for _, id := range plan.Identities {
		if len(id.Removed) != e2eDropped || len(id.Changed) != 1 || len(id.Added) != 0 || len(id.Excluded) != 0 || id.Unchanged != 50-e2eDropped-1 {
			t.Fatalf("%s's diff: removed %d changed %d added %d excluded %d unchanged %d", id.IdentityID,
				len(id.Removed), len(id.Changed), len(id.Added), len(id.Excluded), id.Unchanged)
		}
	}
	if plan.Totals.Shares != 2 || plan.Totals.Removed != 2*e2eDropped || plan.Totals.Changed != 2 {
		t.Fatalf("plan totals: %+v", plan.Totals)
	}
	if env.fake.count(subStoreApplyRevisionMethod) != 0 {
		t.Fatal("propose applied")
	}

	// 5. Approval: the decision previews again, apply_revision claims its
	// grant through the broker, and the shares re-render from rev-2.
	approveBody, _ := json.Marshal(map[string]any{"approval_id": reply.ApprovalID, "plan_sha256": reply.PlanSHA256, "queue_apply": true})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/network/approvals/approve", strings.NewReader(string(approveBody)))
	req.Header.Set("Content-Type", "application/json")
	s.handleApprove(rec, req, e2eApprover)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	env.fake.mu.Lock()
	live, claims := env.fake.live, append([]string(nil), env.fake.claims...)
	env.fake.mu.Unlock()
	if live != "rev-2" || len(claims) != 1 || claims[0] != `{"granted":true}` {
		t.Fatalf("after approve: live %s claims %v", live, claims)
	}
	if got, _ := env.st.Approval(reply.ApprovalID); got.Status != model.ApprovalApplied {
		t.Fatalf("approval status %s", got.Status)
	}
	rec = env.fetch(alice)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice after apply: %d refusals=%v", rec.Code, env.refusals(alice.ID))
	}
	env.checkBody(t, e2eAliceID, rec.Body.String(), 50-e2eDropped)
	if !strings.Contains(rec.Body.String(), "renamed in rev-2") {
		t.Fatal("alice's body after apply is not rev-2's")
	}

	// 6. A scheduled task fires once.
	env.fake.mu.Lock()
	broker := env.fake.broker
	env.fake.mu.Unlock()
	if err := broker.TaskSchedule(context.Background(), sdkplugin.TaskSchedule{ID: "refresh", Cron: "*/15 * * * *",
		Service: subStorePluginID + "/subscription", Method: "refresh_all", Payload: json.RawMessage(`{"all":true}`)}); err != nil {
		t.Fatal(err)
	}
	tick := time.Date(2026, 10, 8, 12, 15, 7, 0, time.UTC)
	s.runDuePluginTaskSchedules(tick)
	s.pluginSchedules.runs.Wait()
	s.runDuePluginTaskSchedules(tick.Add(30 * time.Second))
	s.runDuePluginTaskSchedules(tick.Add(5 * time.Minute))
	s.pluginSchedules.runs.Wait()
	env.fake.mu.Lock()
	scheduled := append([]string(nil), env.fake.scheduled...)
	env.fake.mu.Unlock()
	if len(scheduled) != 1 || scheduled[0] != `{"all":true}` {
		t.Fatalf("scheduled runs: %v", scheduled)
	}
	// 7. A fleet write: bob is suspended. core asks depends_on off the write
	// path, bob's share refuses at once, alice's revalidates and still
	// serves her own 45 lines.
	fetchesBefore := env.fake.count("fetch")
	u, _ := s.getVpnUser(e2eBobID)
	u.Enabled = false
	if err := s.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	s.triggerVPNCoreMutation()
	s.substoreCatalogue.deps.wg.Wait()
	if n := env.fake.count("depends_on"); n != 1 {
		t.Fatalf("depends_on asked %d times after the fleet write", n)
	}
	// The host lane answers a known share in a policy state with one
	// placeholder entry; no bound line may leave.
	if rec := env.fetch(bob); strings.Contains(rec.Body.String(), e2eBobUUID) || strings.Contains(rec.Body.String(), catalogueNodeIP(0)) {
		t.Fatalf("bob's suspended share served a bound line: %d", rec.Code)
	} else {
		t.Logf("bob suspended: status %d, %d bytes, audited %v", rec.Code, rec.Body.Len(), env.refusals(bob.ID))
	}
	rec = env.fetch(alice)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice after the fleet write: %d", rec.Code)
	}
	env.checkBody(t, e2eAliceID, rec.Body.String(), 50-e2eDropped)
	if env.fake.count("fetch") == fetchesBefore {
		t.Fatal("alice's record did not revalidate after the fleet write")
	}

	t.Logf("plugin calls: fetch=%d render=%d convert=%d depends_on=%d apply_revision=%d refresh_all=%d",
		env.fake.count("fetch"), env.fake.count("render"), env.fake.count("convert"), env.fake.count("depends_on"),
		env.fake.count(subStoreApplyRevisionMethod), env.fake.count("refresh_all"))
}

// The adapter as posted on #177 leaves LiveRevision empty, so propose
// cannot pass the services lane's live-revision check.
func TestS0JoinedProposeWithoutLiveRevision(t *testing.T) {
	env := newE2EEnv(t, false)
	env.createShare(t, e2eFleet, "alice", e2eAliceID)
	code, body := env.gateway(t, e2eOperator, subStorePlansService, "propose",
		map[string]any{"subscription_id": e2eFleet, "from_revision": "rev-1", "to_revision": "rev-2"})
	t.Logf("propose without a live revision from the plugin: %d %s", code, body)
	if code != http.StatusConflict {
		t.Fatalf("propose: %d %s", code, body)
	}
}

// A share that names an identity on a record that renders a document needs
// a plan (services lane), but the bind preview refuses a document record.
func TestS0JoinedProposeOnADocumentRecord(t *testing.T) {
	env := newE2EEnv(t, true)
	share := env.createShare(t, e2eDoc, "alice-doc", e2eAliceID)
	if rec := env.fetch(share); rec.Code != http.StatusOK {
		t.Fatalf("document share: %d", rec.Code)
	}
	code, body := env.gateway(t, e2eOperator, subStorePlansService, "propose",
		map[string]any{"subscription_id": e2eDoc, "from_revision": "rev-1", "to_revision": "rev-2"})
	t.Logf("propose on a document record with an identity share: %d %s", code, body)
	if code != http.StatusOK {
		t.Fatalf("propose: %d %s", code, body)
	}
	var reply subStorePlansProposeReply
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatal(err)
	}
	var plan subStorePlan
	if err := json.Unmarshal([]byte(reply.Plan), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Identities) != 1 || plan.Totals.Added+plan.Totals.Removed+plan.Totals.Changed+plan.Totals.Excluded != 0 {
		t.Fatalf("document record plan: %s", reply.Plan)
	}
}

func (e *e2eEnv) refusals(shareID string) []string {
	e.srv.shareRefusalAudits.Wait()
	var out []string
	for _, ev := range e.st.AuditEvents() {
		if ev.Action == auditActionShareFetch && ev.Decision == "deny" && ev.Metadata["share_id"] == shareID {
			out = append(out, ev.Reason)
		}
	}
	return out
}

// TestS0JoinedSelectionIsBoundedByTheIdentity pins the trust rule design 28
// states for fleet records: the selected line set is the plugin's own fetch
// output, and core bounds it by the share identity's enabled bindings, not by
// the record. A selection naming every catalogue line serves an identity only
// the lines it is bound to, and never another identity's credential.
func TestS0JoinedSelectionIsBoundedByTheIdentity(t *testing.T) {
	env := newE2EEnv(t, true)
	s := env.srv
	const keep = 20
	u := VpnUser{ID: e2eAliceID, Email: e2eAliceID + "@example.com", Name: e2eAliceID, Enabled: true, CreatedAt: env.now, UpdatedAt: env.now,
		Credentials: []VpnCredential{{Protocol: "vless", UUID: e2eAliceUUID, Flow: bindIdentityFlow}}}
	for _, row := range env.rows[:keep] {
		u.Bindings = append(u.Bindings, LineBinding{LineHashID: row.LineHashID, Enabled: true, AppliedCredentialSHA256: bindAppliedSHA(t, u, row.LineUUID)})
	}
	if err := s.putVpnUser(u); err != nil {
		t.Fatal(err)
	}

	alice := env.createShare(t, e2eFleet, "alice-narrow", e2eAliceID)
	rec := env.fetch(alice)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice's share: %d %s refusals=%v", rec.Code, rec.Body.String(), env.refusals(alice.ID))
	}
	env.checkBody(t, e2eAliceID, rec.Body.String(), keep)
	for _, row := range env.rows[keep:] {
		if strings.Contains(rec.Body.String(), row.LineUUID) {
			t.Fatalf("alice's body names line %s, which she is not bound to", row.LineUUID)
		}
	}
	// The same selection still serves Bob every line he is bound to.
	bob := env.createShare(t, e2eFleet, "bob-wide", e2eBobID)
	if rec := env.fetch(bob); rec.Code != http.StatusOK {
		t.Fatalf("bob's share: %d %s", rec.Code, rec.Body.String())
	} else {
		env.checkBody(t, e2eBobID, rec.Body.String(), 50)
	}
}
