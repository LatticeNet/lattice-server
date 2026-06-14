package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/auth"
)

func TestBoltStateRoundTripBucketizedAndEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	st := emptyState()
	st.Users["u1"] = model.User{ID: "u1", Username: "admin", TOTPSecret: totpPlain, CreatedAt: now}
	st.Nodes["n1"] = model.Node{ID: "n1", Name: "node one", TokenHash: "node-token-hash", CreatedAt: now}
	st.KV["cfg/hello"] = model.KVEntry{Bucket: "cfg", Key: "hello", Value: "world", UpdatedAt: now}
	st.Results = []model.TaskResult{{TaskID: "task-1", NodeID: "n1", Stdout: "ok", StartedAt: now, FinishedAt: now}}
	st.Audit = []model.AuditEvent{{ID: "audit-1", At: now, Action: "test.audit", Decision: "allow"}}
	st.DDNS["d1"] = model.DDNSProfile{ID: "d1", Name: "dns", Provider: "cloudflare", CFAPIToken: cfTokenPlain, WebhookHeaders: webhookHdrPlain}
	st.NotifyChannels["ch1"] = model.NotifyChannel{ID: "ch1", Name: "tg", Kind: "telegram", Config: map[string]string{"bot_token": botTokenPlain, "chat_id": chatIDPlain}}
	st.MachineProfiles["mp1"] = model.MachineProfile{ID: "mp1", NodeID: "n1", Vendor: "DMIT", ConsoleURL: consoleURLPlain, DetailURL: detailURLPlain}
	st.NFTInputs["n1"] = model.NFTInputs{ID: "n1", NodeID: "n1", InterfaceName: "ens3", WireGuardCIDR: "10.66.0.0/24", PublicTCP: []int{80, 443}, PublicUDP: []int{53}}
	st.DNSDeployments["dns1"] = model.DNSDeployment{ID: "dns1", Name: "private dns", NodeID: "n1", Engine: model.DNSEngineCoreDNS, ListenPort: 53, EnableUDP: true, Exposure: model.DNSExposureMesh, Zones: []model.DNSZone{{Suffix: ".", Mode: model.DNSZoneForward, Upstreams: []string{"1.1.1.1"}}}, Hostname: "n1.dns.example.com", CFAPIToken: dnsCFTokenPlain, Status: model.DNSStatusPending, CreatedAt: now}
	st.NetPolicies["n1"] = model.NetPolicy{ID: "n1", TargetNodeID: "n1", Enabled: true, Rules: []model.NetRule{{ID: "r1", Action: model.NetRuleDeny, Direction: model.NetDirEgress, Protocol: model.NetProtoTCP, Ports: []int{1234}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}}}
	st.MonResults["m1"] = []model.MonitorResult{{MonitorID: "m1", NodeID: "n1", Success: true, At: now}}
	st.TOTPChallenges["tc1"] = auth.TOTPChallenge{ID: "tc1", UserID: "u1", ClientIP: "198.51.100.1", ExpiresAt: now.Add(time.Minute)}
	st.OIDCProviders["google"] = model.OIDCProvider{ID: "google", DisplayName: "Google", Issuer: "https://accounts.google.com", ClientID: "cid", ClientSecret: "oidc-client-secret", Enabled: true, CreatedAt: now}

	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	if err := bs.ImportState(st); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := string(raw)
	for _, leak := range []string{totpPlain, cfTokenPlain, webhookHdrPlain, dnsCFTokenPlain, botTokenPlain, chatIDPlain, consoleURLPlain, detailURLPlain, "oidc-client-secret"} {
		if strings.Contains(disk, leak) {
			t.Fatalf("plaintext secret leaked into bbolt file: %q", leak)
		}
	}
	for _, plain := range []string{"admin", "node one", "cloudflare", "Google", "DMIT"} {
		if !strings.Contains(disk, plain) {
			t.Fatalf("expected non-secret field %q to remain inspectable in bucketized storage", plain)
		}
	}
	if strings.Contains(disk, `"users"`) && strings.Contains(disk, `"oidc_providers"`) {
		t.Fatal("bbolt storage should not persist the entire State as one JSON blob")
	}

	got, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if got.Users["u1"].TOTPSecret != totpPlain {
		t.Fatalf("totp secret did not decrypt: %+v", got.Users["u1"])
	}
	if got.DDNS["d1"].CFAPIToken != cfTokenPlain || got.DDNS["d1"].WebhookHeaders != webhookHdrPlain {
		t.Fatalf("ddns secrets did not decrypt: %+v", got.DDNS["d1"])
	}
	if got.NotifyChannels["ch1"].Config["bot_token"] != botTokenPlain {
		t.Fatalf("notify secret did not decrypt: %+v", got.NotifyChannels["ch1"])
	}
	if got.MachineProfiles["mp1"].ConsoleURL != consoleURLPlain || got.MachineProfiles["mp1"].DetailURL != detailURLPlain {
		t.Fatalf("machine profile links did not decrypt: %+v", got.MachineProfiles["mp1"])
	}
	if got.NFTInputs["n1"].InterfaceName != "ens3" || got.NFTInputs["n1"].PublicUDP[0] != 53 {
		t.Fatalf("nft inputs not recovered: %+v", got.NFTInputs["n1"])
	}
	if got.DNSDeployments["dns1"].CFAPIToken != dnsCFTokenPlain || got.DNSDeployments["dns1"].ListenPort != 53 {
		t.Fatalf("dns deployment not recovered/decrypted: %+v", got.DNSDeployments["dns1"])
	}
	if got.NetPolicies["n1"].Rules[0].Ports[0] != 1234 {
		t.Fatalf("net policy not recovered: %+v", got.NetPolicies["n1"])
	}
	if got.OIDCProviders["google"].ClientSecret != "oidc-client-secret" {
		t.Fatalf("oidc secret did not decrypt: %+v", got.OIDCProviders["google"])
	}
	if len(got.Results) != 1 || got.Results[0].TaskID != "task-1" {
		t.Fatalf("results not recovered: %+v", got.Results)
	}
	if len(got.Audit) != 1 || got.Audit[0].ID != "audit-1" {
		t.Fatalf("audit events not recovered: %+v", got.Audit)
	}
	if len(got.MonResults["m1"]) != 1 || got.MonResults["m1"][0].MonitorID != "m1" {
		t.Fatalf("monitor results not recovered: %+v", got.MonResults)
	}
}

func TestBoltStateExportEmptyDatabaseReturnsInitializedState(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	got, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if got.Users == nil || got.Nodes == nil || got.OIDCAuthStates == nil {
		t.Fatalf("exported state maps must be initialized: %+v", got)
	}
}

func TestBoltStateRecordLevelNodeKVAndAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	now := time.Unix(1_700_000_100, 0).UTC()
	st := emptyState()
	st.Users["u1"] = model.User{ID: "u1", Username: "admin", CreatedAt: now}
	st.Nodes["n0"] = model.Node{ID: "n0", Name: "imported", CreatedAt: now}
	st.Audit = []model.AuditEvent{{ID: "audit-0", At: now.Add(-time.Minute), Action: "imported"}}

	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.ImportState(st); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertNode(model.Node{ID: "n2", Name: "node two"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertNode(model.Node{ID: "n1", Name: "node one"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.PutKV(model.KVEntry{Bucket: "cfg", Key: "z", Value: "last"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.PutKV(model.KVEntry{Bucket: "cfg", Key: "a", Value: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.AppendAudit(model.AuditEvent{ID: "audit-1", At: now, Action: "record.write"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.AppendAudit(model.AuditEvent{ID: "audit-2", At: now.Add(time.Minute), Action: "record.write"}); err != nil {
		t.Fatal(err)
	}

	n, ok, err := bs.Node("n2")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || n.Name != "node two" || n.CreatedAt.IsZero() {
		t.Fatalf("record-level node not recovered or timestamped: ok=%v node=%+v", ok, n)
	}
	geo := &model.NodeGeo{Country: "JP", City: "Tokyo", Lat: 35.6762, Lon: 139.6503, ASN: 2516, UpdatedAt: now}
	n, ok, err = bs.UpdateNodeGeo("n2", geo)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || n.Geo == nil || n.Geo.Country != "JP" || n.Geo.City != "Tokyo" {
		t.Fatalf("node geo not updated: ok=%v node=%+v", ok, n)
	}
	nodes, err := bs.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{nodes[0].ID, nodes[1].ID, nodes[2].ID}; strings.Join(got, ",") != "n0,n1,n2" {
		t.Fatalf("nodes not sorted by id: %+v", nodes)
	}
	kv, err := bs.KV("cfg")
	if err != nil {
		t.Fatal(err)
	}
	if len(kv) != 2 || kv[0].Key != "a" || kv[0].UpdatedAt.IsZero() || kv[1].Key != "z" {
		t.Fatalf("kv entries not sorted/timestamped: %+v", kv)
	}
	events, err := bs.AuditEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].ID != "audit-2" || events[1].ID != "audit-1" || events[2].ID != "audit-0" {
		t.Fatalf("audit events not appended/sorted newest-first: %+v", events)
	}
	exported, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if exported.Users["u1"].Username != "admin" {
		t.Fatalf("record-level writes reset unrelated buckets: %+v", exported.Users)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBoltStateRecordLevelOpsPersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertNode(model.Node{ID: "n1", Name: "node one"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.PutKV(model.KVEntry{Bucket: "cfg", Key: "hello", Value: "world"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.AppendAudit(model.AuditEvent{ID: "audit-1", At: time.Unix(1_700_000_200, 0).UTC(), Action: "persist"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	node, ok, err := reopened.Node("n1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || node.Name != "node one" {
		t.Fatalf("node did not persist across reopen: ok=%v node=%+v", ok, node)
	}
	kv, err := reopened.KV("cfg")
	if err != nil {
		t.Fatal(err)
	}
	if len(kv) != 1 || kv[0].Value != "world" {
		t.Fatalf("kv did not persist across reopen: %+v", kv)
	}
	events, err := reopened.AuditEvents()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "audit-1" {
		t.Fatalf("audit did not persist across reopen: %+v", events)
	}
}

func TestBoltStateRecordLevelDNSDeployment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	dep := model.DNSDeployment{
		ID: "dns1", Name: "private dns", NodeID: "n1", Engine: model.DNSEngineCoreDNS,
		ListenPort: 53, EnableUDP: true, Exposure: model.DNSExposureMesh,
		Zones:            []model.DNSZone{{Suffix: ".", Mode: model.DNSZoneForward, Upstreams: []string{"1.1.1.1"}}},
		CFAPIToken:       dnsCFTokenPlain,
		LastPublishedAt:  time.Unix(1_700_000_300, 0).UTC(),
		LastPublishError: "cloudflare throttled",
	}
	if err := bs.UpsertDNSDeployment(dep); err != nil {
		t.Fatal(err)
	}
	got, ok, err := bs.DNSDeployment("dns1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.CFAPIToken != dnsCFTokenPlain || got.UpdatedAt.IsZero() ||
		got.LastPublishedAt.IsZero() || got.LastPublishError != "cloudflare throttled" {
		t.Fatalf("dns deployment not recovered: ok=%v dep=%+v", ok, got)
	}
	list, err := bs.DNSDeploymentsForNode("n1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "dns1" {
		t.Fatalf("dns deployments for node not recovered: %+v", list)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), dnsCFTokenPlain) {
		t.Fatal("dns deployment cf token leaked into bbolt file")
	}
	if err := bs.DeleteDNSDeployment("dns1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := bs.DNSDeployment("dns1"); err != nil || ok {
		t.Fatalf("dns deployment should be deleted: ok=%v err=%v", ok, err)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBoltStateRecordLevelStaticWorkerPluginAndApproval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	now := time.Unix(1_700_000_300, 0).UTC()
	st := emptyState()
	st.Nodes["n1"] = model.Node{ID: "n1", Name: "keep me", CreatedAt: now}

	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.ImportState(st); err != nil {
		t.Fatal(err)
	}

	if err := bs.PutStatic(model.StaticObject{Bucket: "site", Path: "z.html", Content: "last", ContentType: "text/html"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.PutStatic(model.StaticObject{Bucket: "site", Path: "a.html", Content: "first", ContentType: "text/html"}); err != nil {
		t.Fatal(err)
	}
	static, err := bs.Static("site")
	if err != nil {
		t.Fatal(err)
	}
	if len(static) != 2 || static[0].Path != "a.html" || static[0].Size != len("first") || static[0].UpdatedAt.IsZero() || static[1].Path != "z.html" {
		t.Fatalf("static entries not sorted/sized/timestamped: %+v", static)
	}

	if err := bs.UpsertWorker(model.WorkerScript{ID: "w2", Name: "Zulu", Source: "return 2"}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertWorker(model.WorkerScript{ID: "w1", Name: "Alpha", Source: "return 1"}); err != nil {
		t.Fatal(err)
	}
	workers, err := bs.Workers()
	if err != nil {
		t.Fatal(err)
	}
	if len(workers) != 2 || workers[0].Name != "Alpha" || workers[0].UpdatedAt.IsZero() || workers[1].Name != "Zulu" {
		t.Fatalf("workers not sorted/timestamped: %+v", workers)
	}

	plugin := model.PluginInstallation{ID: "plug.b", Name: "Plugin B", Capabilities: []string{"kv:read"}}
	if err := bs.UpsertPluginInstallation(plugin); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertPluginInstallation(model.PluginInstallation{ID: "plug.a", Name: "Plugin A", Capabilities: []string{"log:write"}}); err != nil {
		t.Fatal(err)
	}
	if err := bs.SetPluginStatus("plug.b", model.PluginStatusInstalled); err != nil {
		t.Fatal(err)
	}
	if err := bs.SetPluginStatus("plug.b", model.PluginStatusActive); err != nil {
		t.Fatal(err)
	}
	if err := bs.SetPluginStatus("plug.b", model.PluginStatusInstalled); err == nil {
		t.Fatal("expected invalid active -> installed plugin transition to fail")
	}
	gotPlugin, ok, err := bs.PluginInstallation("plug.b")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || gotPlugin.Status != model.PluginStatusActive || gotPlugin.CreatedAt.IsZero() || gotPlugin.ActivatedAt.IsZero() {
		t.Fatalf("plugin lifecycle state not stamped correctly: ok=%v plugin=%+v", ok, gotPlugin)
	}
	gotPlugin.Capabilities[0] = "mutated"
	gotPluginAgain, ok, err := bs.PluginInstallation("plug.b")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || gotPluginAgain.Capabilities[0] != "kv:read" {
		t.Fatalf("plugin capabilities should be cloned on read: ok=%v plugin=%+v", ok, gotPluginAgain)
	}
	plugins, err := bs.PluginInstallations()
	if err != nil {
		t.Fatal(err)
	}
	if len(plugins) != 2 || plugins[0].ID != "plug.a" || plugins[1].ID != "plug.b" {
		t.Fatalf("plugin installations not sorted by id: %+v", plugins)
	}

	if err := bs.UpsertApproval(model.Approval{ID: "ap-old", NodeID: "n1", Plugin: "nft", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertApproval(model.Approval{ID: "ap-new", NodeID: "n1", Plugin: "wireguard", CreatedAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	approval, ok, err := bs.Approval("ap-new")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || approval.Plugin != "wireguard" || approval.UpdatedAt.IsZero() {
		t.Fatalf("approval not recovered/timestamped: ok=%v approval=%+v", ok, approval)
	}
	approvals, err := bs.Approvals()
	if err != nil {
		t.Fatal(err)
	}
	if len(approvals) != 2 || approvals[0].ID != "ap-new" || approvals[1].ID != "ap-old" {
		t.Fatalf("approvals not sorted newest-first: %+v", approvals)
	}

	exported, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if exported.Nodes["n1"].Name != "keep me" {
		t.Fatalf("record-level writes reset unrelated node bucket: %+v", exported.Nodes)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	static, err = reopened.Static("site")
	if err != nil {
		t.Fatal(err)
	}
	plugins, err = reopened.PluginInstallations()
	if err != nil {
		t.Fatal(err)
	}
	approvals, err = reopened.Approvals()
	if err != nil {
		t.Fatal(err)
	}
	if len(static) != 2 || len(plugins) != 2 || len(approvals) != 2 {
		t.Fatalf("record-level static/plugin/approval writes did not persist: static=%+v plugins=%+v approvals=%+v", static, plugins, approvals)
	}
}

func TestBoltStateRecordLevelTaskLifecycleAndResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	now := time.Unix(1_700_000_400, 0).UTC()
	st := emptyState()
	st.KV["cfg/keep"] = model.KVEntry{Bucket: "cfg", Key: "keep", Value: "me", UpdatedAt: now}

	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.ImportState(st); err != nil {
		t.Fatal(err)
	}

	if err := bs.CreateTask(model.Task{ID: "task-old", Targets: []string{"n1"}, Interpreter: "sh", Script: "echo old", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := bs.CreateTask(model.Task{ID: "task-new", Targets: []string{"n1"}, Interpreter: "sh", Script: "echo new", CreatedAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := bs.CreateTask(model.Task{ID: "task-other", Targets: []string{"n2"}, Interpreter: "sh", Script: "echo other", CreatedAt: now.Add(2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := bs.CreateTask(model.Task{ID: "task-auto", Targets: []string{"n3"}}); err != nil {
		t.Fatal(err)
	}

	auto, ok, err := bs.Task("task-auto")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || auto.Status != model.TaskQueued || auto.CreatedAt.IsZero() {
		t.Fatalf("task defaults not applied: ok=%v task=%+v", ok, auto)
	}

	tasks, err := bs.Tasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 4 || tasks[len(tasks)-1].ID != "task-old" || tasks[len(tasks)-2].ID != "task-new" {
		t.Fatalf("tasks not sorted newest-first: %+v", tasks)
	}

	leased, err := bs.LeaseTasks("n1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 || leased[0].ID != "task-old" || leased[0].Status != model.TaskLeased || leased[0].LeasedBy != "n1" || !strings.HasPrefix(leased[0].LeaseID, "lease_") || leased[0].StartedAt.IsZero() {
		t.Fatalf("oldest matching task was not leased correctly: %+v", leased)
	}
	again, err := bs.LeaseTasks("n1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 1 || again[0].ID != "task-new" {
		t.Fatalf("leased task should not be leased again, next queued task should lease: %+v", again)
	}
	none, err := bs.LeaseTasks("missing-node", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("unexpected leases for missing node: %+v", none)
	}

	if err := bs.AddTaskResult(model.TaskResult{TaskID: "task-old", LeaseID: leased[0].LeaseID, NodeID: "n1", ExitCode: 0, Stdout: "ok", FinishedAt: now.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := bs.AddTaskResult(model.TaskResult{TaskID: "task-new", LeaseID: again[0].LeaseID, NodeID: "n1", ExitCode: 2, Stderr: "bad", FinishedAt: now.Add(4 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	oldTask, ok, err := bs.Task("task-old")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || oldTask.Status != model.TaskFinished || !oldTask.FinishedAt.Equal(now.Add(3*time.Minute)) {
		t.Fatalf("successful result did not finish task: ok=%v task=%+v", ok, oldTask)
	}
	newTask, ok, err := bs.Task("task-new")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || newTask.Status != model.TaskFailed || !newTask.FinishedAt.Equal(now.Add(4*time.Minute)) {
		t.Fatalf("failed result did not fail task: ok=%v task=%+v", ok, newTask)
	}
	results, err := bs.Results()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].TaskID != "task-new" || results[1].TaskID != "task-old" {
		t.Fatalf("task results not appended/sorted newest-first: %+v", results)
	}
	exported, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if exported.KV["cfg/keep"].Value != "me" {
		t.Fatalf("task record-level writes reset unrelated KV bucket: %+v", exported.KV)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persistedTask, ok, err := reopened.Task("task-new")
	if err != nil {
		t.Fatal(err)
	}
	persistedResults, err := reopened.Results()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || persistedTask.Status != model.TaskFailed || len(persistedResults) != 2 || persistedResults[0].TaskID != "task-new" {
		t.Fatalf("task lifecycle did not persist across reopen: ok=%v task=%+v results=%+v", ok, persistedTask, persistedResults)
	}
}

func TestBoltStateRecordLevelMonitorResultsAndTunnels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	now := time.Unix(1_700_000_500, 0).UTC()
	st := emptyState()
	st.Nodes["n1"] = model.Node{ID: "n1", Name: "keep me", CreatedAt: now}

	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.ImportState(st); err != nil {
		t.Fatal(err)
	}

	if err := bs.UpsertMonitor(model.Monitor{ID: "m-z", Name: "node tcp", Type: model.MonitorTypeTCP, Target: "10.0.0.1:443", NodeIDs: []string{"n1"}, Enabled: true, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertMonitor(model.Monitor{ID: "m-a", Name: "all http", Type: model.MonitorTypeHTTP, Target: "https://example.com", AssignAll: true, Enabled: true, CreatedAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertMonitor(model.Monitor{ID: "m-b", Name: "disabled", Type: model.MonitorTypeTCP, Target: "10.0.0.2:22", NodeIDs: []string{"n1"}, Enabled: false, CreatedAt: now.Add(2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}

	monitor, ok, err := bs.Monitor("m-z")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || monitor.Name != "node tcp" || monitor.UpdatedAt.IsZero() {
		t.Fatalf("monitor not recovered/timestamped: ok=%v monitor=%+v", ok, monitor)
	}
	monitors, err := bs.Monitors()
	if err != nil {
		t.Fatal(err)
	}
	if len(monitors) != 3 || monitors[0].ID != "m-z" || monitors[1].ID != "m-a" || monitors[2].ID != "m-b" {
		t.Fatalf("monitors not sorted oldest-first: %+v", monitors)
	}
	assigned, err := bs.MonitorsForNode("n1")
	if err != nil {
		t.Fatal(err)
	}
	if len(assigned) != 2 || assigned[0].ID != "m-a" || assigned[1].ID != "m-z" {
		t.Fatalf("assigned monitors not filtered/sorted by id: %+v", assigned)
	}

	for i := 0; i < maxMonitorResults+3; i++ {
		nodeID := "n1"
		if i == maxMonitorResults+2 {
			nodeID = "n2"
		}
		if err := bs.AddMonitorResult(model.MonitorResult{MonitorID: "m-z", NodeID: nodeID, At: now.Add(time.Duration(i) * time.Second), Success: i%2 == 0, LatencyMs: float64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	series, err := bs.MonitorResults("m-z")
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != maxMonitorResults || series[0].LatencyMs != 3 || series[len(series)-1].LatencyMs != float64(maxMonitorResults+2) {
		t.Fatalf("monitor result cap/order not preserved: len=%d first=%+v last=%+v", len(series), series[0], series[len(series)-1])
	}
	lastN1, ok, err := bs.LastMonitorResultForNode("m-z", "n1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || lastN1.LatencyMs != float64(maxMonitorResults+1) {
		t.Fatalf("latest monitor result for node not found: ok=%v result=%+v", ok, lastN1)
	}

	if err := bs.UpsertTunnel(model.TunnelProfile{ID: "tun-old", Name: "old", NodeID: "n1", TunnelID: "cf-old", CredentialsFile: "/etc/cloudflared/old.json", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertTunnel(model.TunnelProfile{ID: "tun-new", Name: "new", NodeID: "n1", TunnelID: "cf-new", Ingress: []model.TunnelIngress{{Hostname: "app.example.com", Service: "http://localhost:8080"}}, CreatedAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	tunnel, ok, err := bs.Tunnel("tun-old")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || tunnel.CredentialsFile != "/etc/cloudflared/old.json" || tunnel.UpdatedAt.IsZero() {
		t.Fatalf("tunnel not recovered/timestamped: ok=%v tunnel=%+v", ok, tunnel)
	}
	tunnels, err := bs.Tunnels()
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels) != 2 || tunnels[0].ID != "tun-old" || tunnels[1].ID != "tun-new" {
		t.Fatalf("tunnels not sorted oldest-first: %+v", tunnels)
	}
	if err := bs.DeleteTunnel("tun-old"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := bs.Tunnel("tun-old"); err != nil || ok {
		t.Fatalf("tunnel delete failed: ok=%v err=%v", ok, err)
	}

	if err := bs.DeleteMonitor("m-z"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := bs.Monitor("m-z"); err != nil || ok {
		t.Fatalf("monitor delete failed: ok=%v err=%v", ok, err)
	}
	series, err = bs.MonitorResults("m-z")
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 0 {
		t.Fatalf("monitor delete should remove result history: %+v", series)
	}
	exported, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if exported.Nodes["n1"].Name != "keep me" {
		t.Fatalf("monitor/tunnel writes reset unrelated node bucket: %+v", exported.Nodes)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	tunnels, err = reopened.Tunnels()
	if err != nil {
		t.Fatal(err)
	}
	monitors, err = reopened.Monitors()
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels) != 1 || tunnels[0].ID != "tun-new" || len(monitors) != 2 {
		t.Fatalf("monitor/tunnel lifecycle did not persist across reopen: tunnels=%+v monitors=%+v", tunnels, monitors)
	}
}

func TestBoltStateRecordLevelSecretBucketsEncryptedAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	now := time.Unix(1_700_000_600, 0).UTC()

	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}

	recoveryCode := "rescue-code-1"
	recoveryHash := auth.HashRecoveryCode(recoveryCode)
	if err := bs.UpsertUser(model.User{
		ID:                 "u1",
		Username:           "Admin@Example.com",
		TOTPSecret:         totpPlain,
		RecoveryCodeHashes: []string{recoveryHash},
		CreatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertToken(model.Token{ID: "tok1", Name: "automation", TokenHash: "hash-only", ActorID: "u1", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session, err := auth.NewSession("u1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.PutSession(session); err != nil {
		t.Fatal(err)
	}
	challenge, err := auth.NewTOTPChallenge("u1", "198.51.100.2", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.PutTOTPChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertDDNSProfile(model.DDNSProfile{
		ID: "d1", Name: "dns", NodeID: "n1", Provider: model.DDNSProviderCloudflare,
		CFAPIToken: cfTokenPlain, WebhookHeaders: webhookHdrPlain, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertNotifyChannel(model.NotifyChannel{
		ID: "ch1", Name: "telegram", Kind: "telegram", Enabled: true, CreatedAt: now,
		Config: map[string]string{"bot_token": botTokenPlain, "chat_id": chatIDPlain},
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertMachineProfile(model.MachineProfile{
		ID: "mp1", NodeID: "n1", Vendor: "DMIT", ConsoleURL: consoleURLPlain, DetailURL: detailURLPlain, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertNFTInputs(model.NFTInputs{
		NodeID: "n1", InterfaceName: "ens3", WireGuardCIDR: "10.66.0.0/24", PublicTCP: []int{80, 443}, PublicUDP: []int{53}, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertNetPolicy(model.NetPolicy{
		TargetNodeID: "n1",
		Enabled:      true,
		Rules: []model.NetRule{{
			ID: "r1", Action: model.NetRuleDeny, Direction: model.NetDirEgress,
			Protocol: model.NetProtoTCP, Ports: []int{1234}, Remote: model.NetEndpoint{Kind: model.NetRefAny},
		}},
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertOIDCProvider(model.OIDCProvider{
		ID: "google", DisplayName: "Google", Issuer: "https://accounts.google.com",
		ClientID: "cid", ClientSecret: "oidc-client-secret", Enabled: true, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	idn := model.OIDCIdentity{ProviderID: "google", Issuer: "https://accounts.google.com", Subject: "sub-1", UserID: "u1", Email: "admin@example.com", CreatedAt: now}
	if err := bs.PutOIDCIdentity(idn); err != nil {
		t.Fatal(err)
	}
	oidcState, err := auth.NewOIDCAuthState("google", "198.51.100.2", "/", "pkce-verifier-secret", "browser-binding-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.PutOIDCAuthState(oidcState); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := string(raw)
	for _, leak := range []string{
		totpPlain,
		session.ID,
		session.CSRFToken,
		challenge.ID,
		cfTokenPlain,
		webhookHdrPlain,
		botTokenPlain,
		chatIDPlain,
		consoleURLPlain,
		detailURLPlain,
		"oidc-client-secret",
		oidcState.State,
		oidcState.CodeVerifier,
	} {
		if strings.Contains(disk, leak) {
			t.Fatalf("secret leaked into bbolt file: %q", leak)
		}
	}
	for _, plain := range []string{"Admin@Example.com", "automation", "cloudflare", "Google", "DMIT"} {
		if !strings.Contains(disk, plain) {
			t.Fatalf("expected non-secret field %q to remain readable", plain)
		}
	}

	user, ok, err := bs.User("u1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || user.TOTPSecret != totpPlain {
		t.Fatalf("user secret not decrypted: ok=%v user=%+v", ok, user)
	}
	userByName, ok, err := bs.UserByUsername("admin@example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || userByName.ID != "u1" {
		t.Fatalf("case-insensitive username lookup failed: ok=%v user=%+v", ok, userByName)
	}
	consumed, err := bs.ConsumeRecoveryCode("u1", recoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("expected recovery code to be consumed")
	}
	consumedAgain, err := bs.ConsumeRecoveryCode("u1", recoveryCode)
	if err != nil {
		t.Fatal(err)
	}
	if consumedAgain {
		t.Fatal("recovery code should be single-use")
	}

	token, ok, err := bs.Token("tok1")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := bs.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || token.TokenHash != "hash-only" || len(tokens) != 1 {
		t.Fatalf("token record not recovered: ok=%v token=%+v tokens=%+v", ok, token, tokens)
	}
	gotSession, ok, err := bs.Session(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || gotSession.CSRFToken != session.CSRFToken {
		t.Fatalf("session not decrypted: ok=%v session=%+v", ok, gotSession)
	}
	gotChallenge, ok, err := bs.TOTPChallenge(challenge.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || gotChallenge.UserID != "u1" {
		t.Fatalf("totp challenge not recovered: ok=%v challenge=%+v", ok, gotChallenge)
	}
	if err := bs.FailTOTPChallenge(challenge.ID, 2); err != nil {
		t.Fatal(err)
	}
	gotChallenge, ok, err = bs.TOTPChallenge(challenge.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || gotChallenge.Attempts != 1 {
		t.Fatalf("totp challenge failure was not recorded: ok=%v challenge=%+v", ok, gotChallenge)
	}
	if err := bs.FailTOTPChallenge(challenge.ID, 2); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := bs.TOTPChallenge(challenge.ID); err != nil || ok {
		t.Fatalf("totp challenge should be burned at attempt cap: ok=%v err=%v", ok, err)
	}

	ddns, ok, err := bs.DDNSProfile("d1")
	if err != nil {
		t.Fatal(err)
	}
	ddnsForNode, err := bs.DDNSProfilesForNode("n1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || ddns.CFAPIToken != cfTokenPlain || len(ddnsForNode) != 1 || ddnsForNode[0].WebhookHeaders != webhookHdrPlain {
		t.Fatalf("ddns profile not decrypted: ok=%v profile=%+v node=%+v", ok, ddns, ddnsForNode)
	}
	notify, err := bs.NotifyChannels()
	if err != nil {
		t.Fatal(err)
	}
	enabledNotify, err := bs.EnabledNotifyChannels()
	if err != nil {
		t.Fatal(err)
	}
	if len(notify) != 1 || notify[0].Config["bot_token"] != botTokenPlain || len(enabledNotify) != 1 || enabledNotify[0].Config["chat_id"] != chatIDPlain {
		t.Fatalf("notify channel not decrypted: all=%+v enabled=%+v", notify, enabledNotify)
	}
	machine, ok, err := bs.MachineProfile("mp1")
	if err != nil {
		t.Fatal(err)
	}
	machines, err := bs.MachineProfiles()
	if err != nil {
		t.Fatal(err)
	}
	machineByNode, okByNode, err := bs.MachineProfileForNode("n1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !okByNode || len(machines) != 1 || machine.ConsoleURL != consoleURLPlain || machineByNode.DetailURL != detailURLPlain {
		t.Fatalf("machine profile not decrypted: ok=%v byNode=%v machine=%+v machines=%+v", ok, okByNode, machine, machines)
	}
	nftInputs, ok, err := bs.NFTInputs("n1")
	if err != nil {
		t.Fatal(err)
	}
	allNFTInputs, err := bs.AllNFTInputs()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || nftInputs.ID != "n1" || nftInputs.InterfaceName != "ens3" || len(allNFTInputs) != 1 || allNFTInputs[0].PublicUDP[0] != 53 {
		t.Fatalf("nft inputs not recovered: ok=%v inputs=%+v all=%+v", ok, nftInputs, allNFTInputs)
	}
	netPolicy, ok, err := bs.NetPolicy("n1")
	if err != nil {
		t.Fatal(err)
	}
	allNetPolicies, err := bs.NetPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || netPolicy.ID != "n1" || len(allNetPolicies) != 1 || allNetPolicies[0].Rules[0].Ports[0] != 1234 {
		t.Fatalf("net policy not recovered: ok=%v policy=%+v all=%+v", ok, netPolicy, allNetPolicies)
	}
	provider, ok, err := bs.OIDCProvider("google")
	if err != nil {
		t.Fatal(err)
	}
	enabledProviders, err := bs.EnabledOIDCProviders()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || provider.ClientSecret != "oidc-client-secret" || len(enabledProviders) != 1 {
		t.Fatalf("oidc provider not decrypted: ok=%v provider=%+v enabled=%+v", ok, provider, enabledProviders)
	}
	gotIDN, ok, err := bs.OIDCIdentity("google", "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || gotIDN.UserID != "u1" {
		t.Fatalf("oidc identity not recovered: ok=%v identity=%+v", ok, gotIDN)
	}
	gotOIDCState, ok, err := bs.ConsumeOIDCAuthState(oidcState.State)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || gotOIDCState.CodeVerifier != oidcState.CodeVerifier {
		t.Fatalf("oidc auth state not decrypted/consumed: ok=%v state=%+v", ok, gotOIDCState)
	}
	if _, ok, err := bs.ConsumeOIDCAuthState(oidcState.State); err != nil || ok {
		t.Fatalf("oidc auth state should be single-use: ok=%v err=%v", ok, err)
	}
	if err := bs.DeleteDDNSProfile("d1"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteNotifyChannel("ch1"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteMachineProfile("mp1"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteNFTInputs("n1"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteNetPolicy("n1"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteOIDCProvider("google"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteSession(session.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := bs.Session(session.ID); err != nil || ok {
		t.Fatalf("session should be deleted: ok=%v err=%v", ok, err)
	}
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := reopened.User("u1"); err != nil || !ok {
		t.Fatalf("user did not persist across reopen: ok=%v err=%v", ok, err)
	}
	if _, ok, err := reopened.OIDCProvider("google"); err != nil || ok {
		t.Fatalf("deleted provider should stay deleted across reopen: ok=%v err=%v", ok, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	wrongKey, err := OpenBoltState(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	defer wrongKey.Close()
	if _, _, err := wrongKey.User("u1"); err == nil {
		t.Fatal("expected wrong key to fail record-level user decrypt")
	}
	if _, err := wrongKey.ExportState(); err == nil {
		t.Fatal("expected wrong key to fail full bbolt export")
	}
}

func TestBoltStateDisabledCipherExportNormalizesOpaqueAuthKeys(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()

	session, err := auth.NewSession("u1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.PutSession(session); err != nil {
		t.Fatal(err)
	}
	challenge, err := auth.NewTOTPChallenge("u1", "198.51.100.3", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.PutTOTPChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	oidcState, err := auth.NewOIDCAuthState("google", "198.51.100.3", "/", "verifier", "binding", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.PutOIDCAuthState(oidcState); err != nil {
		t.Fatal(err)
	}

	exported, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := exported.Sessions[session.ID]; !ok {
		t.Fatalf("session export should be keyed by plaintext id, got keys: %+v", exported.Sessions)
	}
	if _, ok := exported.TOTPChallenges[challenge.ID]; !ok {
		t.Fatalf("totp challenge export should be keyed by plaintext id, got keys: %+v", exported.TOTPChallenges)
	}
	if _, ok := exported.OIDCAuthStates[oidcState.State]; !ok {
		t.Fatalf("oidc auth state export should be keyed by plaintext state, got keys: %+v", exported.OIDCAuthStates)
	}
}
