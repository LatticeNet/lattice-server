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

func TestProxyCollectionsJSONStoreCRUDAndEncryption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	c := testCipher(t)
	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_001_000, 0).UTC()

	if err := s.UpsertProxyInbound(model.ProxyInbound{
		ID: "in-b", Name: "beta", Core: model.ProxyCoreSingbox,
		Protocol: model.ProxyProtocolTrojan, Transport: model.ProxyTransportTCP,
		Security: model.ProxySecurityTLS, Port: 8443, CreatedAt: now.Add(time.Second),
		Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertProxyInbound(model.ProxyInbound{
		ID: "in-a", Name: "alpha", Core: model.ProxyCoreSingbox,
		Protocol: model.ProxyProtocolVLESS, Transport: model.ProxyTransportTCP,
		Security: model.ProxySecurityReality, Port: 443, CreatedAt: now,
		RealityPrivateKey: proxyRealityPrivateKeyPlain, RealityPublicKey: "pub", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertProxyUser(model.ProxyUser{
		ID: "u-a", Name: "alice", Enabled: true, UUID: proxyUUIDPlain,
		Password: proxyPasswordPlain, SubToken: proxySubTokenPlain,
		InboundIDs: []string{"in-a"}, Status: model.ProxyUserStatusActive, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertProxyUser(model.ProxyUser{
		ID: "u-all", Name: "all", Enabled: true, Status: model.ProxyUserStatusActive, CreatedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertProxyNodeProfile(model.ProxyNodeProfile{
		NodeID: "node-b", Core: model.ProxyCoreSingbox, InboundIDs: []string{"in-a"},
		Hostname: "node-b.dns.example.com", ConfigPath: "/etc/sing-box/config.json",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertProxyUsageSnapshot(model.ProxyUsageSnapshot{
		NodeID: "node-b", At: now, CoreUptimeSec: 12, UserBytes: map[string]int64{"u-a": 1024},
	}); err != nil {
		t.Fatal(err)
	}

	inbounds := s.ProxyInbounds()
	if len(inbounds) != 2 || inbounds[0].ID != "in-a" || inbounds[1].ID != "in-b" {
		t.Fatalf("inbounds not sorted by creation time: %+v", inbounds)
	}
	usersForB := s.ProxyUsersForInbound("in-b")
	if len(usersForB) != 1 || usersForB[0].ID != "u-all" {
		t.Fatalf("empty inbound membership should mean all inbounds: %+v", usersForB)
	}
	profile, ok := s.ProxyNodeProfile("node-b")
	if !ok || profile.ID != "node-b" || profile.Hostname == "" {
		t.Fatalf("proxy node profile not recovered: ok=%v profile=%+v", ok, profile)
	}
	usage, ok := s.ProxyUsageSnapshot("node-b")
	if !ok || usage.UserBytes["u-a"] != 1024 {
		t.Fatalf("proxy usage snapshot not recovered: ok=%v usage=%+v", ok, usage)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := string(raw)
	for _, leak := range []string{proxyRealityPrivateKeyPlain, proxyUUIDPlain, proxyPasswordPlain, proxySubTokenPlain} {
		if strings.Contains(disk, leak) {
			t.Fatalf("proxy secret leaked to JSON store: %q", leak)
		}
	}

	reopened, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	in, ok := reopened.ProxyInbound("in-a")
	if !ok || in.RealityPrivateKey != proxyRealityPrivateKeyPlain {
		t.Fatalf("proxy inbound secret did not decrypt: ok=%v inbound=%+v", ok, in)
	}
	user, ok := reopened.ProxyUser("u-a")
	if !ok || user.UUID != proxyUUIDPlain || user.Password != proxyPasswordPlain || user.SubToken != proxySubTokenPlain {
		t.Fatalf("proxy user secrets did not decrypt: ok=%v user=%+v", ok, user)
	}

	if err := reopened.DeleteProxyInbound("in-b"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteProxyUser("u-all"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteProxyNodeProfile("node-b"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteProxyUsageSnapshot("node-b"); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.ProxyInbound("in-b"); ok {
		t.Fatal("proxy inbound should be deleted")
	}
	if _, ok := reopened.ProxyUser("u-all"); ok {
		t.Fatal("proxy user should be deleted")
	}
	if _, ok := reopened.ProxyNodeProfile("node-b"); ok {
		t.Fatal("proxy node profile should be deleted")
	}
	if _, ok := reopened.ProxyUsageSnapshot("node-b"); ok {
		t.Fatal("proxy usage snapshot should be deleted")
	}
}

func TestApplyProxyUsageUpdateJSONStorePersistsReportAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	c := testCipher(t)
	s, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_002_000, 0).UTC()

	if err := s.ApplyProxyUsageUpdate(
		[]model.ProxyUser{
			{ID: "u-a", Name: "alice", Enabled: true, UUID: proxyUUIDPlain, Password: proxyPasswordPlain, SubToken: proxySubTokenPlain},
			{ID: "u-b", Name: "bob", Enabled: true, UsedBytes: 4096},
		},
		&model.ProxyNodeProfile{NodeID: "node-a", Core: model.ProxyCoreSingbox, Hostname: "node-a.example.com"},
		&model.ProxyUsageSnapshot{NodeID: "node-a", At: now, CoreUptimeSec: 30, UserBytes: map[string]int64{"u-a": 1024, "u-b": 4096}},
	); err != nil {
		t.Fatal(err)
	}

	user, ok := s.ProxyUser("u-a")
	if !ok || user.UUID != proxyUUIDPlain || user.Password != proxyPasswordPlain || user.SubToken != proxySubTokenPlain || user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() {
		t.Fatalf("proxy user not stored with normalized timestamps/secrets: ok=%v user=%+v", ok, user)
	}
	profile, ok := s.ProxyNodeProfile("node-a")
	if !ok || profile.ID != "node-a" || profile.Hostname != "node-a.example.com" || profile.UpdatedAt.IsZero() {
		t.Fatalf("proxy profile not stored with normalized id/timestamps: ok=%v profile=%+v", ok, profile)
	}
	usage, ok := s.ProxyUsageSnapshot("node-a")
	if !ok || usage.UserBytes["u-a"] != 1024 || usage.UserBytes["u-b"] != 4096 {
		t.Fatalf("proxy usage not stored: ok=%v usage=%+v", ok, usage)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	disk := string(raw)
	for _, leak := range []string{proxyUUIDPlain, proxyPasswordPlain, proxySubTokenPlain} {
		if strings.Contains(disk, leak) {
			t.Fatalf("batched proxy usage update leaked secret to JSON store: %q", leak)
		}
	}

	reopened, err := OpenWithCipher(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedUser, ok := reopened.ProxyUser("u-a"); !ok || reopenedUser.UUID != proxyUUIDPlain {
		t.Fatalf("batched proxy user did not decrypt after reopen: ok=%v user=%+v", ok, reopenedUser)
	}
	if reopenedUsage, ok := reopened.ProxyUsageSnapshot("node-a"); !ok || reopenedUsage.CoreUptimeSec != 30 {
		t.Fatalf("batched usage did not persist after reopen: ok=%v usage=%+v", ok, reopenedUsage)
	}
}

func TestRuntimeBoltHotStoreKeepsHighChurnDomainsOutOfJSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "state.json")
	boltPath := filepath.Join(dir, "state-hot.db")
	c := testCipher(t)
	now := time.Now().UTC()

	s, err := OpenWithCipher(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertNode(model.Node{ID: "node-hot", Name: "Hot Node"}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyProxyUsageUpdate(
		[]model.ProxyUser{{ID: "runtime-proxy-user", Name: "runtime user", Enabled: true, UsedBytes: 4096}},
		&model.ProxyNodeProfile{NodeID: "node-hot", Hostname: "runtime-hot.example.com"},
		&model.ProxyUsageSnapshot{NodeID: "node-hot", At: now, CoreUptimeSec: 42, UserBytes: map[string]int64{"runtime-proxy-user": 4096}},
	); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSession(auth.Session{ID: "runtime-session", ActorID: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit(model.AuditEvent{ID: "runtime-audit", At: now, Action: "runtime.hot", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}

	jsonState, err := LoadJSONState(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := jsonState.ProxyUsers["runtime-proxy-user"]; ok {
		t.Fatal("proxy user should live in runtime bbolt hot store, not JSON state")
	}
	if _, ok := jsonState.ProxyProfiles["node-hot"]; ok {
		t.Fatal("proxy node profile should live in runtime bbolt hot store, not JSON state")
	}
	if _, ok := jsonState.ProxyUsage["node-hot"]; ok {
		t.Fatal("proxy usage should live in runtime bbolt hot store, not JSON state")
	}
	if _, ok := jsonState.Sessions["runtime-session"]; ok {
		t.Fatal("session should live in runtime bbolt hot store, not JSON state")
	}
	for _, ev := range jsonState.Audit {
		if ev.ID == "runtime-audit" {
			t.Fatal("audit event should live in runtime bbolt hot store, not JSON state")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithCipher(jsonPath, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.EnableRuntimeBoltHotStore(boltPath); err != nil {
		t.Fatal(err)
	}
	if user, ok := reopened.ProxyUser("runtime-proxy-user"); !ok || user.UsedBytes != 4096 {
		t.Fatalf("proxy user not recovered from runtime bbolt hot store: ok=%v user=%+v", ok, user)
	}
	if profile, ok := reopened.ProxyNodeProfile("node-hot"); !ok || profile.Hostname != "runtime-hot.example.com" {
		t.Fatalf("proxy node profile not recovered from runtime bbolt hot store: ok=%v profile=%+v", ok, profile)
	}
	if usage, ok := reopened.ProxyUsageSnapshot("node-hot"); !ok || usage.CoreUptimeSec != 42 {
		t.Fatalf("proxy usage not recovered from runtime bbolt hot store: ok=%v usage=%+v", ok, usage)
	}
	if sess, ok := reopened.Session("runtime-session"); !ok || sess.ActorID != "admin" {
		t.Fatalf("session not recovered from runtime bbolt hot store: ok=%v session=%+v", ok, sess)
	}
	events := reopened.AuditEvents()
	foundAudit := false
	for _, ev := range events {
		if ev.ID == "runtime-audit" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("audit event not recovered from runtime bbolt hot store: %+v", events)
	}
}

func TestBoltStateRecordLevelProxyCollections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	c := testCipher(t)
	bs, err := OpenBoltState(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	now := time.Unix(1_700_001_200, 0).UTC()

	if err := bs.UpsertProxyInbound(model.ProxyInbound{
		ID: "in-a", Name: "alpha", Core: model.ProxyCoreSingbox,
		Protocol: model.ProxyProtocolVLESS, Transport: model.ProxyTransportTCP,
		Security: model.ProxySecurityReality, Port: 443, CreatedAt: now,
		RealityPrivateKey: proxyRealityPrivateKeyPlain, RealityPublicKey: "pub", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertProxyUser(model.ProxyUser{
		ID: "u-a", Name: "alice", Enabled: true, UUID: proxyUUIDPlain,
		Password: proxyPasswordPlain, SubToken: proxySubTokenPlain,
		InboundIDs: []string{"in-a"}, Status: model.ProxyUserStatusActive, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertProxyUser(model.ProxyUser{
		ID: "u-all", Name: "all", Enabled: true, Status: model.ProxyUserStatusActive, CreatedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertProxyNodeProfile(model.ProxyNodeProfile{
		NodeID: "node-a", Core: model.ProxyCoreSingbox, InboundIDs: []string{"in-a"},
		Hostname: "node-a.dns.example.com", StatsAPI: "127.0.0.1:9090",
	}); err != nil {
		t.Fatal(err)
	}
	if err := bs.UpsertProxyUsageSnapshot(model.ProxyUsageSnapshot{
		NodeID: "node-a", At: now, CoreUptimeSec: 99, UserBytes: map[string]int64{"u-a": 2048},
	}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{proxyRealityPrivateKeyPlain, proxyUUIDPlain, proxyPasswordPlain, proxySubTokenPlain} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("proxy secret leaked to bbolt store: %q", leak)
		}
	}

	in, ok, err := bs.ProxyInbound("in-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || in.RealityPrivateKey != proxyRealityPrivateKeyPlain || in.Port != 443 {
		t.Fatalf("proxy inbound not recovered: ok=%v inbound=%+v", ok, in)
	}
	user, ok, err := bs.ProxyUser("u-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || user.UUID != proxyUUIDPlain || user.Password != proxyPasswordPlain || user.SubToken != proxySubTokenPlain {
		t.Fatalf("proxy user secrets not recovered: ok=%v user=%+v", ok, user)
	}
	usersForB, err := bs.ProxyUsersForInbound("in-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(usersForB) != 1 || usersForB[0].ID != "u-all" {
		t.Fatalf("empty inbound membership should mean all inbounds: %+v", usersForB)
	}
	profile, ok, err := bs.ProxyNodeProfile("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || profile.ID != "node-a" || profile.Hostname == "" {
		t.Fatalf("proxy node profile not recovered: ok=%v profile=%+v", ok, profile)
	}
	usage, ok, err := bs.ProxyUsageSnapshot("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || usage.UserBytes["u-a"] != 2048 {
		t.Fatalf("proxy usage snapshot not recovered: ok=%v usage=%+v", ok, usage)
	}
	batchProfile := model.ProxyNodeProfile{
		NodeID: "node-b", Core: model.ProxyCoreSingbox, InboundIDs: []string{"in-a"},
		Hostname: "node-b.dns.example.com", StatsAPI: "127.0.0.1:9191",
	}
	batchSnapshot := model.ProxyUsageSnapshot{
		NodeID: "node-b", At: now.Add(time.Minute), CoreUptimeSec: 101, UserBytes: map[string]int64{"u-b": 4096},
	}
	if err := bs.ApplyProxyUsageUpdate([]model.ProxyUser{{
		ID: "u-b", Name: "bob", Enabled: true, UUID: proxyUUIDPlain,
		Password: proxyPasswordPlain, SubToken: proxySubTokenPlain,
		InboundIDs: []string{"in-a"}, Status: model.ProxyUserStatusActive, CreatedAt: now.Add(time.Minute),
	}}, &batchProfile, &batchSnapshot); err != nil {
		t.Fatal(err)
	}
	batchUser, ok, err := bs.ProxyUser("u-b")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || batchUser.Password != proxyPasswordPlain || batchUser.SubToken != proxySubTokenPlain || batchUser.UpdatedAt.IsZero() {
		t.Fatalf("batched proxy user not recovered: ok=%v user=%+v", ok, batchUser)
	}
	batchedProfile, ok, err := bs.ProxyNodeProfile("node-b")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || batchedProfile.ID != "node-b" || batchedProfile.StatsAPI != "127.0.0.1:9191" {
		t.Fatalf("batched proxy profile not recovered: ok=%v profile=%+v", ok, batchedProfile)
	}
	batchedUsage, ok, err := bs.ProxyUsageSnapshot("node-b")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || batchedUsage.CoreUptimeSec != 101 || batchedUsage.UserBytes["u-b"] != 4096 {
		t.Fatalf("batched proxy usage not recovered: ok=%v usage=%+v", ok, batchedUsage)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{proxyUUIDPlain, proxyPasswordPlain, proxySubTokenPlain} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("batched proxy secret leaked to bbolt store: %q", leak)
		}
	}
	exported, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if exported.ProxyUsers["u-a"].SubToken != proxySubTokenPlain || exported.ProxyUsers["u-b"].SubToken != proxySubTokenPlain || exported.ProxyInbounds["in-a"].RealityPrivateKey != proxyRealityPrivateKeyPlain {
		t.Fatalf("proxy records did not export/decrypt: %+v %+v", exported.ProxyUsers["u-a"], exported.ProxyInbounds["in-a"])
	}

	if err := bs.DeleteProxyInbound("in-a"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteProxyUser("u-a"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteProxyNodeProfile("node-a"); err != nil {
		t.Fatal(err)
	}
	if err := bs.DeleteProxyUsageSnapshot("node-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := bs.ProxyInbound("in-a"); err != nil || ok {
		t.Fatalf("proxy inbound should be deleted: ok=%v err=%v", ok, err)
	}
	if _, ok, err := bs.ProxyUser("u-a"); err != nil || ok {
		t.Fatalf("proxy user should be deleted: ok=%v err=%v", ok, err)
	}
	if _, ok, err := bs.ProxyNodeProfile("node-a"); err != nil || ok {
		t.Fatalf("proxy profile should be deleted: ok=%v err=%v", ok, err)
	}
	if _, ok, err := bs.ProxyUsageSnapshot("node-a"); err != nil || ok {
		t.Fatalf("proxy usage should be deleted: ok=%v err=%v", ok, err)
	}
}
