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
	for _, leak := range []string{totpPlain, cfTokenPlain, webhookHdrPlain, botTokenPlain, chatIDPlain, "oidc-client-secret"} {
		if strings.Contains(disk, leak) {
			t.Fatalf("plaintext secret leaked into bbolt file: %q", leak)
		}
	}
	for _, plain := range []string{"admin", "node one", "cloudflare", "Google"} {
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
