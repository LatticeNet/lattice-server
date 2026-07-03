package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func seedMigrationState(now time.Time) State {
	st := emptyState()
	st.Users["u1"] = model.User{ID: "u1", Username: "admin", TOTPSecret: totpPlain, CreatedAt: now}
	st.Nodes["node-a"] = model.Node{ID: "node-a", Name: "Node A", TokenHash: "node-token-hash", CreatedAt: now}
	st.DDNS["d1"] = model.DDNSProfile{ID: "d1", Name: "dns", Provider: "cloudflare", CFAPIToken: cfTokenPlain}
	st.NotifyChannels["ch1"] = model.NotifyChannel{ID: "ch1", Name: "tg", Kind: "telegram", Config: map[string]string{"bot_token": botTokenPlain}}
	st.OIDCProviders["oidc"] = model.OIDCProvider{ID: "oidc", DisplayName: "OIDC", ClientID: "client-id", ClientSecret: "oidc-secret", CreatedAt: now}
	st.Groups["grp1"] = model.Group{ID: "grp1", Name: "Edge", Slug: "edge", Color: "sky", Members: []string{"node-a"}, CreatedAt: now}
	st.GroupPolicies["gnp1"] = model.GroupNetPolicy{ID: "gnp1", ScopeGroupID: "grp1", Enabled: true, Priority: 10, Rules: []model.GroupNetRule{{ID: "rule1", Action: model.NetRuleAllow, Direction: model.NetDirIngress, Protocol: model.NetProtoTCP, Ports: []int{443}, Remote: model.NetEndpoint{Kind: model.NetRefAny}}}, CreatedAt: now}
	st.Audit = []model.AuditEvent{{ID: "audit-1", At: now, Action: "migration.test", Decision: "allow"}}
	return st
}

func TestMigrateJSONToBoltAndExportBack(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state.db")
	exportPath := filepath.Join(dir, "state.export.json")
	c := testCipher(t)
	now := time.Unix(1_700_000_001, 0).UTC()

	if err := WriteJSONState(jsonPath, seedMigrationState(now), c, MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	rawJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawJSON), cfTokenPlain) || !strings.Contains(string(rawJSON), "lat$1$") {
		t.Fatal("precondition: JSON state must be encrypted at rest")
	}

	if err := MigrateJSONToBolt(jsonPath, boltPath, c, MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	rawBolt, err := os.ReadFile(boltPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawBolt), cfTokenPlain) || strings.Contains(string(rawBolt), "oidc-secret") {
		t.Fatal("migrated bbolt state leaked plaintext secrets")
	}

	bs, err := OpenBoltState(boltPath, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := bs.ExportState()
	if cerr := bs.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if got.Users["u1"].TOTPSecret != totpPlain || got.DDNS["d1"].CFAPIToken != cfTokenPlain || got.OIDCProviders["oidc"].ClientSecret != "oidc-secret" {
		t.Fatalf("migrated state did not decrypt correctly: %+v %+v %+v", got.Users["u1"], got.DDNS["d1"], got.OIDCProviders["oidc"])
	}
	if got.Groups["grp1"].Members[0] != "node-a" || got.GroupPolicies["gnp1"].Rules[0].Ports[0] != 443 {
		t.Fatalf("migrated group state did not recover: %+v %+v", got.Groups["grp1"], got.GroupPolicies["gnp1"])
	}

	if err := ExportBoltToJSON(boltPath, exportPath, c, MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	rawExport, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawExport), cfTokenPlain) || strings.Contains(string(rawExport), "oidc-secret") {
		t.Fatal("exported JSON leaked plaintext secrets")
	}
	back, err := LoadJSONState(exportPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if back.Nodes["node-a"].Name != "Node A" || len(back.Audit) != 1 || back.NotifyChannels["ch1"].Config["bot_token"] != botTokenPlain || back.Groups["grp1"].Name != "Edge" || back.GroupPolicies["gnp1"].ScopeGroupID != "grp1" {
		t.Fatalf("exported JSON did not round-trip: %+v", back)
	}
}

func TestMigrationRefusesToOverwriteTargets(t *testing.T) {
	dir := t.TempDir()
	c := testCipher(t)
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state.db")
	exportPath := filepath.Join(dir, "export.json")

	if err := WriteJSONState(jsonPath, seedMigrationState(time.Now().UTC()), c, MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boltPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateJSONToBolt(jsonPath, boltPath, c, MigrationOptions{}); err == nil {
		t.Fatal("expected JSON->bbolt migration to refuse an existing target")
	}
	if err := MigrateJSONToBolt(jsonPath, boltPath, c, MigrationOptions{Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	if backups, err := filepath.Glob(filepath.Join(dir, "state.db.backup-*")); err != nil || len(backups) != 0 {
		t.Fatalf("expected overwrite migration to clean backups, backups=%v err=%v", backups, err)
	}

	if err := os.WriteFile(exportPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ExportBoltToJSON(boltPath, exportPath, c, MigrationOptions{}); err == nil {
		t.Fatal("expected bbolt->JSON export to refuse an existing target")
	}
	if err := ExportBoltToJSON(boltPath, exportPath, c, MigrationOptions{Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	if backups, err := filepath.Glob(filepath.Join(dir, "export.json.backup-*")); err != nil || len(backups) != 0 {
		t.Fatalf("expected overwrite export to clean backups, backups=%v err=%v", backups, err)
	}
}

func TestMigrationFailsClosedWithWrongKey(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state.db")
	if err := WriteJSONState(jsonPath, seedMigrationState(time.Now().UTC()), testCipher(t), MigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := MigrateJSONToBolt(jsonPath, boltPath, testCipher(t), MigrationOptions{}); err == nil {
		t.Fatal("expected migration with the wrong key to fail")
	}
	if _, err := os.Stat(boltPath); err == nil {
		t.Fatal("failed migration should not leave a target bbolt file")
	}
}

func TestExportBoltToJSONRequiresExistingSource(t *testing.T) {
	dir := t.TempDir()
	missingBoltPath := filepath.Join(dir, "missing.db")
	exportPath := filepath.Join(dir, "export.json")

	if err := ExportBoltToJSON(missingBoltPath, exportPath, testCipher(t), MigrationOptions{}); err == nil {
		t.Fatal("expected bbolt export to fail when the source database does not exist")
	}
	if _, err := os.Stat(exportPath); err == nil {
		t.Fatal("failed export should not leave a JSON target file")
	}
}
