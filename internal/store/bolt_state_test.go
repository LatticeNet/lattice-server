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
