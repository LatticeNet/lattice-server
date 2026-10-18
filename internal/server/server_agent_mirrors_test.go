package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Design 31, S5: the mirror registry, the source order it produces, and the
// reviewed agent.mirrors plan that is the only way to change it.

const mirrorTestBase = "https://dl.example.org"

// seedAgentMirrors writes the registry directly, as an approved plan would.
func seedAgentMirrors(t *testing.T, st *store.Store, mirrors ...model.AgentMirror) {
	t.Helper()
	if _, err := st.ReplaceAgentMirrors(mirrors); err != nil {
		t.Fatal(err)
	}
}

func sourceLabels(sources []model.AgentUpdateSource) []string {
	out := make([]string, 0, len(sources))
	for _, src := range sources {
		out = append(out, agentUpdateSourceLabel(src))
	}
	return out
}

// Order computation, table-tested over preferred, global and upstream,
// static group members, duplicates and the cap.
func TestAgentUpdateSourceOrder(t *testing.T) {
	const object = "0.3.4/linux/amd64/" + "aa" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const cp = artifactTestPublicURL + agentBinaryPathPrefix + object
	const up = "https://github.com/LatticeNet/lattice-node-agent/releases/download/v0.3.4/lattice-agent-linux-amd64"
	mirror := func(id string, priority int, global bool, prefer ...string) model.AgentMirror {
		return model.AgentMirror{ID: id, BaseURL: "https://" + id + ".example.org/agents", PreferFor: prefer, Global: global, Priority: priority, Enabled: true}
	}
	groups := []model.Group{
		{ID: "grp-static", Members: []string{"node-a", "node-c"}},
		// A selector is never a stable input: the node matches it today and
		// the plan would change when its facts do.
		{ID: "grp-smart", Selector: &model.GroupSelector{MatchTagsAny: []string{"cn"}}},
	}
	for _, tc := range []struct {
		name    string
		node    string
		mirrors []model.AgentMirror
		cp, up  string
		want    []string
	}{
		{"no mirrors", "node-a", nil, cp, up, []string{"control-plane", "upstream"}},
		{"preferred before the control plane, global after, upstream last", "node-a",
			[]model.AgentMirror{mirror("g", 1, true), mirror("p", 1, false, "node-a")}, cp, up,
			[]string{"mirror:p", "control-plane", "mirror:g", "upstream"}},
		{"a mirror preferred for another node is not listed", "node-b",
			[]model.AgentMirror{mirror("p", 1, false, "node-a")}, cp, up, []string{"control-plane", "upstream"}},
		{"a static group member is preferred", "node-c",
			[]model.AgentMirror{mirror("p", 1, false, "grp-static")}, cp, up, []string{"mirror:p", "control-plane", "upstream"}},
		{"a group selector does not count", "node-a",
			[]model.AgentMirror{mirror("p", 1, false, "grp-smart")}, cp, up, []string{"control-plane", "upstream"}},
		{"a mirror preferred and global is listed once, where it is preferred", "node-a",
			[]model.AgentMirror{mirror("both", 1, true, "node-a", "node-a", "grp-static")}, cp, up,
			[]string{"mirror:both", "control-plane", "upstream"}},
		{"priority then id", "node-a",
			[]model.AgentMirror{mirror("zz", 5, true), mirror("aa", 5, true), mirror("first", 1, true)}, "", up,
			[]string{"mirror:first", "mirror:aa", "mirror:zz", "upstream"}},
		{"a disabled mirror is never listed", "node-a",
			[]model.AgentMirror{{ID: "off", BaseURL: "https://off.example.org", Global: true, Priority: 1}}, cp, up,
			[]string{"control-plane", "upstream"}},
		{"the cap drops global mirrors first", "node-a",
			[]model.AgentMirror{mirror("p1", 1, false, "node-a"), mirror("p2", 2, false, "node-a"), mirror("g1", 1, true), mirror("g2", 2, true)}, cp, up,
			[]string{"mirror:p1", "mirror:p2", "control-plane", "upstream"}},
		{"the cap then drops the last preferred mirrors", "node-a",
			[]model.AgentMirror{mirror("p1", 1, false, "node-a"), mirror("p2", 2, false, "node-a"), mirror("p3", 3, false, "node-a")}, cp, up,
			[]string{"mirror:p1", "mirror:p2", "control-plane", "upstream"}},
		{"without the control plane the mirrors keep four places", "node-a",
			[]model.AgentMirror{mirror("p1", 1, false, "node-a"), mirror("g1", 1, true), mirror("g2", 2, true), mirror("g3", 3, true)}, "", up,
			[]string{"mirror:p1", "mirror:g1", "mirror:g2", "upstream"}},
		{"a plan with no upstream ends at the control plane", "node-a",
			[]model.AgentMirror{mirror("g", 1, true)}, cp, "", []string{"control-plane", "mirror:g"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := agentUpdateSourceOrder(agentSourceOrderInput{
				NodeID: tc.node, Groups: groups, Mirrors: tc.mirrors, ObjectPath: object,
				ControlPlaneURL: tc.cp, UpstreamURL: tc.up, UpstreamReason: "the release this version names",
			})
			if labels := sourceLabels(got); !slices.Equal(labels, tc.want) {
				t.Fatalf("order %q, want %q", labels, tc.want)
			}
			for _, src := range got {
				if src.Reason == "" {
					t.Fatalf("every source says why it is listed: %+v", src)
				}
				switch src.Kind {
				case model.AgentSourceKindMirror:
					if !strings.HasSuffix(src.URL, "/agents/"+object) {
						t.Fatalf("a mirror URL is its base followed by the control plane's object path: %s", src.URL)
					}
				case model.AgentSourceKindControlPlane:
					if src.URL != cp {
						t.Fatalf("the control plane entry is the URL given: %s", src.URL)
					}
				case model.AgentSourceKindUpstream:
					if src.URL != up {
						t.Fatalf("the upstream entry is the URL given: %s", src.URL)
					}
				}
			}
		})
	}
}

// Registry validation refuses each class in D4: plain HTTP, userinfo, a
// query or fragment, loopback, unspecified, link-local and multicast
// addresses, localhost, the control plane's own host, and non-canonical
// numeric hosts, which some resolvers read as one of the others.
func TestAgentMirrorRegistryValidation(t *testing.T) {
	valid := model.AgentMirror{ID: "r2", Name: "Cloudflare R2", BaseURL: "https://dl.example.org/agents/", Global: true, Priority: 10, Enabled: true}
	got, err := validateAgentMirror(valid, artifactTestPublicURL)
	if err != nil {
		t.Fatalf("a plain HTTPS base is a mirror: %v", err)
	}
	if got.BaseURL != "https://dl.example.org/agents" {
		t.Fatalf("the base is kept without its trailing slash, got %q", got.BaseURL)
	}
	for _, ok := range []string{"https://203.0.113.7", "https://[2001:db8::1]:8443/x", "https://DL.Example.ORG"} {
		m := valid
		m.BaseURL = ok
		if _, err := validateAgentMirror(m, artifactTestPublicURL); err != nil {
			t.Fatalf("%s must be accepted: %v", ok, err)
		}
	}
	for _, tc := range []struct{ name, base string }{
		{"plain http", "http://dl.example.org"},
		{"no scheme", "dl.example.org"},
		{"userinfo", "https://user:pass@dl.example.org"},
		{"query", "https://dl.example.org/?x=1"},
		{"empty query", "https://dl.example.org/?"},
		{"fragment", "https://dl.example.org/#x"},
		{"no host", "https:///agents"},
		{"loopback", "https://127.0.0.1"},
		{"loopback v6", "https://[::1]"},
		{"mapped loopback", "https://[::ffff:127.0.0.1]"},
		{"unspecified", "https://0.0.0.0"},
		{"unspecified v6", "https://[::]"},
		{"link-local", "https://169.254.169.254"},
		{"link-local v6", "https://[fe80::1]"},
		{"multicast", "https://224.0.0.1"},
		{"multicast v6", "https://[ff02::1]"},
		{"localhost", "https://localhost"},
		{"localhost subdomain", "https://a.localhost"},
		{"localhost trailing dot", "https://localhost."},
		{"the control plane", "https://lattice.example"},
		{"the control plane on another port", "https://lattice.example:8443"},
		{"the control plane in capitals", "https://LATTICE.example"},
		{"decimal address", "https://2130706433"},
		{"hex address", "https://0x7f000001"},
		{"hex octet", "https://0x7f.0.0.1"},
		{"octal octet", "https://0177.0.0.1"},
		{"short form", "https://127.1"},
		{"leading zero", "https://203.0.113.07"},
		{"numeric last label", "https://example.123"},
		{"shell syntax in the path", "https://dl.example.org/$(reboot)"},
		{"quote in the path", "https://dl.example.org/it's"},
		{"space", "https://dl.example.org/a b"},
		{"percent escape", "https://dl.example.org/a%20b"},
		{"non-ascii host", "https://dl.exämple.org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := valid
			m.BaseURL = tc.base
			if got, err := validateAgentMirror(m, artifactTestPublicURL); err == nil {
				t.Fatalf("%q must be refused, got %+v", tc.base, got)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(m *model.AgentMirror)
	}{
		{"empty id", func(m *model.AgentMirror) { m.ID = "" }},
		{"capital id", func(m *model.AgentMirror) { m.ID = "R2" }},
		{"id with shell syntax", func(m *model.AgentMirror) { m.ID = "r2;reboot" }},
		{"id starting with a hyphen", func(m *model.AgentMirror) { m.ID = "-r2" }},
		{"id too long", func(m *model.AgentMirror) { m.ID = strings.Repeat("a", 32) }},
		{"control character in the name", func(m *model.AgentMirror) { m.Name = "R2\nSafety: fine" }},
		{"name too long", func(m *model.AgentMirror) { m.Name = strings.Repeat("n", 81) }},
		{"preferred for something that is not an id", func(m *model.AgentMirror) { m.PreferFor = []string{"node a"} }},
		{"preferred for too many", func(m *model.AgentMirror) {
			for i := 0; i < 65; i++ {
				m.PreferFor = append(m.PreferFor, "node-"+strings.Repeat("x", i%5+1)+string(rune('a'+i%26)))
			}
		}},
		{"negative priority", func(m *model.AgentMirror) { m.Priority = -1 }},
		{"priority too large", func(m *model.AgentMirror) { m.Priority = 1_000_001 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := valid
			tc.mutate(&m)
			if got, err := validateAgentMirror(m, artifactTestPublicURL); err == nil {
				t.Fatalf("must be refused, got %+v", got)
			}
		})
	}
}

// A mirror is listed only for bytes the control plane has a chunk manifest
// for, and the plan then carries that manifest.
func TestAgentUpdatePlanListsAMirrorOnlyWithAManifest(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", 3*agentChunkSize+100)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true})
	_, approval, _ := seedWalkUpdate(t, srv, st, data, false)
	payload, err := agentUpdatePayloadFromApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"control-plane", "mirror:r2", "upstream"}; !slices.Equal(sourceLabels(payload.Sources), want) {
		t.Fatalf("sources %q, want %q", sourceLabels(payload.Sources), want)
	}
	if payload.ChunkManifest == nil || *payload.ChunkManifest != computeAgentChunkManifest(data) {
		t.Fatalf("a plan that lists a mirror carries the manifest of the pinned bytes: %+v", payload.ChunkManifest)
	}
	if want := mirrorTestBase + "/0.3.4/linux/amd64/" + payload.SHA256; payload.Sources[1].URL != want {
		t.Fatalf("mirror URL %q, want %q", payload.Sources[1].URL, want)
	}
	if !strings.Contains(approval.Plan, "chunk manifest sha256 "+payload.ChunkManifest.digest()) {
		t.Fatalf("the plan prints the manifest's own digest:\n%s", approval.Plan)
	}

	// Bytes the control plane never saw have no manifest, so a plan for
	// them lists no mirror.
	srv2, _, st2 := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st2)
	seedAgentMirrors(t, st2, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true})
	sum := sha256.Sum256([]byte("bytes nobody imported"))
	if err := st2.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, TargetVersion: "0.3.4", BinaryURL: fallbackTestReleaseURL, SHA256: hex.EncodeToString(sum[:]),
		InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	other, err := srv2.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := agentUpdatePayloadFromApproval(other)
	if want := []string{"upstream"}; !slices.Equal(sourceLabels(p2.Sources), want) || p2.ChunkManifest != nil {
		t.Fatalf("without a manifest no mirror is listed: sources %q manifest %v", sourceLabels(p2.Sources), p2.ChunkManifest)
	}
}

// An import that does not fit the store still verifies the release and
// records its digest and manifest, so a mirror can serve an architecture
// the control plane has no room for, and a plan for it needs no GitHub
// fetch to pin it.
func TestAgentArtifactImportRecordsTheManifestWhenTheStoreIsFull(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st)
	if err := st.PutStatic(model.StaticObject{
		Bucket: agentArtifactBucket, Path: "0.3.1/linux/arm64/" + strings.Repeat("a", 64),
		Content: strings.Repeat("A", maxAgentArtifactStoreBytes-1024), ContentType: agentArtifactContentType,
	}); err != nil {
		t.Fatal(err)
	}
	data, digest := walkTestBinary("0.3.4", 2*agentChunkSize+7)
	ref := agentArtifactRef{Version: "0.3.4", OS: "linux", Arch: "amd64", SHA256: digest}
	result, err := srv.importAgentArtifact(ref, data)
	if err != nil {
		t.Fatalf("an import that does not fit is recorded, not refused: %v", err)
	}
	if result.Stored || !result.Recorded {
		t.Fatalf("result %+v, want recorded and not stored", result)
	}
	if _, ok := srv.storedAgentArtifact("0.3.4", "linux", "amd64"); ok {
		t.Fatal("bytes that do not fit must not be stored")
	}
	manifest, ok := srv.agentArtifactManifest("0.3.4", "linux", "amd64", digest)
	if !ok || manifest != computeAgentChunkManifest(data) {
		t.Fatalf("the manifest must be recorded: %+v %t", manifest, ok)
	}
	// A wrong digest records nothing.
	if _, err := srv.importAgentArtifact(agentArtifactRef{Version: "0.3.5", OS: "linux", Arch: "amd64", SHA256: strings.Repeat("b", 64)}, data); err == nil {
		t.Fatal("bytes that fail their digest must not be recorded")
	}
	if _, ok := srv.agentArtifactManifest("0.3.5", "linux", "amd64", strings.Repeat("b", 64)); ok {
		t.Fatal("a failed import recorded a manifest")
	}

	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true})
	if err := st.UpsertAgentUpdatePolicy(model.AgentUpdatePolicy{
		NodeID: "node-a", Enabled: true, TargetVersion: "0.3.4",
		InstallPath: defaultAgentInstallPath, ServiceName: defaultAgentServiceName,
	}); err != nil {
		t.Fatal(err)
	}
	approval, err := srv.createAgentUpdateApproval(context.Background(), "node-a", "admin", false, "manual", time.Now().UTC())
	if err != nil {
		t.Fatalf("the recorded digest pins the plan without a fetch: %v", err)
	}
	payload, _ := agentUpdatePayloadFromApproval(approval)
	if payload.SHA256 != digest || !slices.Equal(sourceLabels(payload.Sources), []string{"mirror:r2", "upstream"}) {
		t.Fatalf("payload sha %s sources %q, want the recorded digest from the mirror, then the release", payload.SHA256, sourceLabels(payload.Sources))
	}
}

// The plan an operator approves for a registry change shows the diff and
// every node whose order changes; only its approval changes the registry,
// and a plan made against an older registry is stale.
func TestAgentMirrorPlanIsReviewedThenApplied(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st)
	if err := st.UpsertNode(model.Node{ID: "node-b", Name: "Node B", HostFacts: model.HostFacts{OS: "linux", Arch: "arm64"}}); err != nil {
		t.Fatal(err)
	}
	admin := principal{Principal: rbac.Principal{ActorID: "admin", Scopes: []string{"*"}}}
	plan := func(req model.AgentMirrorPlanRequest) (int, model.AgentMirrorPlanResponse, string) {
		t.Helper()
		raw, _ := json.Marshal(req)
		r := httptest.NewRequest(http.MethodPost, "/api/nodes/agent-updates/mirrors/plan", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.handleAgentMirrorPlan(w, r, admin)
		var resp model.AgentMirrorPlanResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp, w.Body.String()
	}
	code, resp, body := plan(model.AgentMirrorPlanRequest{Action: model.AgentMirrorActionCreate, Mirror: model.AgentMirror{
		ID: "r2", Name: "Cloudflare R2", BaseURL: mirrorTestBase, PreferFor: []string{"node-a"}, Priority: 1, Enabled: true,
	}})
	if code != http.StatusOK {
		t.Fatalf("plan: %d %s", code, body)
	}
	if resp.Approval.Plugin != model.AgentMirrorsApprovalPlugin || resp.Approval.Status != model.ApprovalPending || resp.Approval.NodeID != "" {
		t.Fatalf("approval %+v", resp.Approval)
	}
	if len(st.AgentMirrorRegistry().Mirrors) != 0 {
		t.Fatal("a plan alone must not change the registry")
	}
	if len(resp.Plan.Changes) != 1 || resp.Plan.Changes[0].NodeID != "node-a" ||
		!slices.Equal(resp.Plan.Changes[0].After, []string{"mirror:r2", "control-plane", "upstream"}) {
		t.Fatalf("the plan names every node whose order changes, and only those: %+v", resp.Plan.Changes)
	}
	if len(resp.Plan.Diff) == 0 || !strings.Contains(strings.Join(resp.Plan.Diff, "\n"), "base_url: - -> "+mirrorTestBase) {
		t.Fatalf("the plan shows the diff: %q", resp.Plan.Diff)
	}

	// A second plan against the same registry, then the first approved: the
	// second was made against a registry that no longer exists.
	_, stale, _ := plan(model.AgentMirrorPlanRequest{Action: model.AgentMirrorActionCreate, Mirror: model.AgentMirror{
		ID: "other", BaseURL: "https://other.example.org", Global: true, Priority: 2, Enabled: true,
	}})
	sum := sha256.Sum256([]byte(resp.Approval.Plan))
	approved, err := srv.approveApprovalCore(context.Background(), admin, resp.Approval, true, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.Status != model.ApprovalApplied {
		t.Fatalf("a registry change takes effect as it is decided, status %s", approved.Status)
	}
	reg := st.AgentMirrorRegistry()
	if len(reg.Mirrors) != 1 || reg.Mirrors[0].ID != "r2" || reg.Revision != 1 {
		t.Fatalf("registry %+v", reg)
	}
	sum = sha256.Sum256([]byte(stale.Approval.Plan))
	if _, err := srv.approveApprovalCore(context.Background(), admin, stale.Approval, true, hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("a plan made against an older registry must be refused")
	}
	if len(st.AgentMirrorRegistry().Mirrors) != 1 {
		t.Fatal("a stale plan changed the registry")
	}

	// Change and delete need the entry to exist, and delete takes the id.
	if code, _, body := plan(model.AgentMirrorPlanRequest{Action: model.AgentMirrorActionChange, Mirror: model.AgentMirror{ID: "nope", BaseURL: mirrorTestBase, Enabled: true}}); code != http.StatusNotFound {
		t.Fatalf("change of a missing mirror: %d %s", code, body)
	}
	code, del, body := plan(model.AgentMirrorPlanRequest{Action: model.AgentMirrorActionDelete, Mirror: model.AgentMirror{ID: "r2"}})
	if code != http.StatusOK || del.Plan.Previous == nil || len(del.Plan.Changes) != 1 ||
		!slices.Equal(del.Plan.Changes[0].Before, []string{"mirror:r2", "control-plane", "upstream"}) {
		t.Fatalf("delete plan: %d %s", code, body)
	}

	// The registry steers every node, so a principal confined to some nodes
	// may neither plan nor decide a change.
	confined := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"*"}, ServerAllowlist: []string{"node-a"}}}
	raw, _ := json.Marshal(model.AgentMirrorPlanRequest{Action: model.AgentMirrorActionCreate, Mirror: model.AgentMirror{ID: "x", BaseURL: mirrorTestBase, Enabled: true}})
	w := httptest.NewRecorder()
	srv.handleAgentMirrorPlan(w, httptest.NewRequest(http.MethodPost, "/api/nodes/agent-updates/mirrors/plan", strings.NewReader(string(raw))), confined)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a confined principal planned a registry change: %d %s", w.Code, w.Body.String())
	}
	sum = sha256.Sum256([]byte(del.Approval.Plan))
	if _, err := srv.approveApprovalCore(context.Background(), confined, del.Approval, true, hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("a confined principal decided a registry change")
	}
	if !srv.approvalVisibleToPrincipal(admin, del.Approval) || srv.approvalVisibleToPrincipal(confined, del.Approval) {
		t.Fatal("an agent.mirrors plan is readable by a fleet agent admin only")
	}
}

// The first time a mirror appears in any plan, the notify path says so,
// once.
func TestAgentMirrorFirstPlanNotifies(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	installFakeNotifySender(srv, nil)
	addNotifyChannel(t, st, "nc-a", "Ops")
	data, _ := walkTestBinary("0.3.4", agentChunkSize+10)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true})
	seedWalkUpdate(t, srv, st, data, false)
	count := func() int {
		return len(st.NotifyDeliveries(store.NotifyDeliveryFilter{EventType: eventAgentMirrorFirstPlan}))
	}
	if count() != 1 {
		t.Fatalf("the first plan that lists r2 must notify once, got %d", count())
	}
	if _, ok := st.AgentMirrorRegistry().FirstPlanned["r2"]; !ok {
		t.Fatal("the first plan must be recorded")
	}
	// Another plan listing the same mirror says nothing new.
	if err := st.UpsertNode(model.Node{ID: "node-b", AgentVersion: "0.1.0", HostFacts: model.HostFacts{OS: "linux", Arch: "amd64"}}); err != nil {
		t.Fatal(err)
	}
	policy, _ := st.AgentUpdatePolicy("node-a")
	policy.NodeID = "node-b"
	if err := st.UpsertAgentUpdatePolicy(policy); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.createAgentUpdateApproval(context.Background(), "node-b", "admin", false, "manual", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatalf("a mirror's first plan notifies once, got %d", count())
	}
}

// The registry view lists the entries and every readable node's order, and
// flags a mirror whose fetches wrote chunks that failed the manifest.
func TestAgentMirrorsViewShowsOrderAndChunkFailures(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true})
	if _, err := st.MutateAgentUpdatePolicy("node-a", true, func(p *model.AgentUpdatePolicy) bool {
		p.LastFetch = &model.AgentUpdateFetch{ApprovalID: "approval_1", Fetches: []model.AgentUpdateFetchAttempt{
			{Source: 1, Kind: "m.r2", ExitCode: 28, Bytes: 0, BadChunks: 1},
			{Source: 2, Kind: "cp", ExitCode: 0, Bytes: 10},
		}, Stage: model.AgentFetchStageDone}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srv.handleAgentMirrors(w, httptest.NewRequest(http.MethodGet, "/api/nodes/agent-updates/mirrors", nil),
		principal{Principal: rbac.Principal{ActorID: "admin", Scopes: []string{"*"}}})
	var view model.AgentMirrorsView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if len(view.Mirrors) != 1 || len(view.Order) != 1 || !slices.Equal(view.Order[0].Sources, []string{"control-plane", "mirror:r2", "upstream"}) {
		t.Fatalf("view %+v", view)
	}
	if len(view.Health) != 1 || view.Health[0].Mirror != "r2" || view.Health[0].Fetches != 1 || view.Health[0].ChunkFailures != 1 {
		t.Fatalf("health %+v", view.Health)
	}
}

// The console's path: plan over HTTP, find the plan in the approvals list,
// approve it with the hash of the plan it read, and read the registry back.
func TestAgentMirrorPlanOverHTTP(t *testing.T) {
	_, handler, st := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st)
	cookies, csrf := loginSession(t, handler)
	res := doJSON(t, handler, http.MethodPost, "/api/nodes/agent-updates/mirrors/plan",
		`{"action":"create","mirror":{"id":"r2","name":"Cloudflare R2","base_url":"`+mirrorTestBase+`","global":true,"priority":1,"enabled":true}}`, cookies, csrf)
	var planned model.AgentMirrorPlanResponse
	if err := json.NewDecoder(res.Body).Decode(&planned); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("plan: %d %v", res.StatusCode, err)
	}
	res.Body.Close()
	res = doJSON(t, handler, http.MethodGet, "/api/network/approvals", "", cookies, csrf)
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(raw), planned.Approval.ID) {
		t.Fatalf("the approvals list must show the registry plan: %d %s", res.StatusCode, raw)
	}
	res = doJSON(t, handler, http.MethodPost, "/api/network/approvals/approve",
		string(mustJSON(t, map[string]any{"approval_id": planned.Approval.ID, "queue_apply": true, "plan_sha256": planSHA256(planned.Approval.Plan)})),
		cookies, csrf)
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"status":"applied"`) {
		t.Fatalf("approve: %d %s", res.StatusCode, raw)
	}
	res = doJSON(t, handler, http.MethodGet, "/api/nodes/agent-updates/mirrors", "", cookies, csrf)
	var view model.AgentMirrorsView
	if err := json.NewDecoder(res.Body).Decode(&view); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("view: %d %v", res.StatusCode, err)
	}
	res.Body.Close()
	if len(view.Mirrors) != 1 || view.Mirrors[0].ID != "r2" || view.Revision != 1 || len(view.Pending) != 0 {
		t.Fatalf("view %+v", view)
	}
}

// A reader confined to some nodes sees which of them an entry prefers, not
// the rest of the fleet or its groups; the registry itself is unchanged.
func TestAgentMirrorsViewHidesOtherNodesFromAConfinedReader(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, PreferFor: []string{"node-a", "node-z", "grp-x"}, Priority: 1, Enabled: true})
	read := func(p rbac.Principal) model.AgentMirrorsView {
		w := httptest.NewRecorder()
		srv.handleAgentMirrors(w, httptest.NewRequest(http.MethodGet, "/api/nodes/agent-updates/mirrors", nil), principal{Principal: p})
		var view model.AgentMirrorsView
		if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || w.Code != http.StatusOK || len(view.Mirrors) != 1 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		return view
	}
	if got := read(rbac.Principal{ActorID: "ops", Scopes: []string{"node:read"}, ServerAllowlist: []string{"node-a"}}).Mirrors[0].PreferFor; !slices.Equal(got, []string{"node-a"}) {
		t.Fatalf("a confined reader sees prefer_for %q, want only node-a", got)
	}
	if got := read(rbac.Principal{ActorID: "admin", Scopes: []string{"*"}}).Mirrors[0].PreferFor; len(got) != 3 {
		t.Fatalf("the fleet reader sees prefer_for %q, want all three", got)
	}
}

// The first-plan alert is about a host: an id deleted and created again, or
// pointed at another host, alerts again; a change that keeps the host does
// not.
func TestAgentMirrorFirstPlanForgottenWhenTheIDMovesHost(t *testing.T) {
	_, _, st := newAgentArtifactServer(t)
	mirror := model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true}
	mark := func() []string {
		t.Helper()
		fresh, err := st.MarkAgentMirrorsPlanned([]string{"r2"}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return fresh
	}
	seedAgentMirrors(t, st, mirror)
	if got := mark(); !slices.Equal(got, []string{"r2"}) {
		t.Fatalf("first plan %q", got)
	}
	mirror.Priority = 2
	seedAgentMirrors(t, st, mirror)
	if got := mark(); len(got) != 0 {
		t.Fatalf("a change that keeps the host must not alert again: %q", got)
	}
	mirror.BaseURL = "https://other.example.org"
	seedAgentMirrors(t, st, mirror)
	if got := mark(); !slices.Equal(got, []string{"r2"}) {
		t.Fatalf("the same id on another host must alert: %q", got)
	}
	seedAgentMirrors(t, st)
	seedAgentMirrors(t, st, mirror)
	if got := mark(); !slices.Equal(got, []string{"r2"}) {
		t.Fatalf("an id deleted and created again must alert: %q", got)
	}
}

// A release whose assets were replaced and imported again pins the latest
// import, whatever order the digests sort in.
func TestAgentImportedDigestIsTheLatestImport(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	older, newer := strings.Repeat("a", 64), strings.Repeat("f", 64)
	at := time.Now().UTC()
	for _, rec := range []store.AgentArtifactManifest{
		{Version: "0.3.9", OS: "linux", Arch: "amd64", SHA256: older, Source: "import", RecordedAt: at.Add(-time.Hour)},
		{Version: "0.3.9", OS: "linux", Arch: "amd64", SHA256: newer, Source: "import", RecordedAt: at},
	} {
		if err := st.PutAgentArtifactManifest(rec); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := srv.importedAgentArtifactDigest("0.3.9", "linux", "amd64"); !ok || got != newer {
		t.Fatalf("imported digest %q (%t), want the latest import", got, ok)
	}
}

// A version a mirror URL cannot carry gets no mirror, rather than a payload
// the validator refuses; the same bytes under a plain version get one.
func TestAgentUpdateSourcesSkipMirrorsForAVersionAURLCannotCarry(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	seedLinuxAgentNode(t, st)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true})
	data, _ := walkTestBinary("0.3.4", agentChunkSize+10)
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	m := computeAgentChunkManifest(data)
	node, _ := st.Node("node-a")
	for _, tc := range []struct {
		version string
		mirror  bool
	}{{"1:0.3.4", false}, {"0.3.4", true}} {
		if err := st.PutAgentArtifactManifest(store.AgentArtifactManifest{
			Version: tc.version, OS: "linux", Arch: "amd64", SHA256: sha, Size: m.Size, ChunkSize: m.ChunkSize, Chunks: m.Chunks,
			Source: "import", RecordedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		sources, manifest := srv.agentUpdateSourcesFor(node, agentUpdatePayload{TargetVersion: tc.version, SHA256: sha, BinaryURL: fallbackTestReleaseURL})
		listed := slices.ContainsFunc(sources, func(src model.AgentUpdateSource) bool { return src.Kind == model.AgentSourceKindMirror })
		if listed != tc.mirror || (manifest != nil) != tc.mirror {
			t.Fatalf("version %s: sources %q manifest %v, want a mirror %t", tc.version, sourceLabels(sources), manifest != nil, tc.mirror)
		}
	}
}

// An update whose task already ran is awaiting confirmation of that run, and
// a registry change after it is no reason to record it as rejected; a plan
// still pending is re-planned.
func TestAgentMirrorChangeDoesNotRejectAnUpdateThatRan(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	data, _ := walkTestBinary("0.3.4", agentChunkSize+10)
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true})
	_, approval, _ := seedWalkUpdate(t, srv, st, data, false)
	seedAgentMirrors(t, st)
	if stale, reason := srv.agentUpdateApprovalLocalStaleness(approval); stale {
		t.Fatalf("an update whose task ran was found stale: %s", reason)
	}
	pending := approval
	pending.Status = model.ApprovalPending
	if stale, reason := srv.agentUpdateApprovalLocalStaleness(pending); !stale || !strings.Contains(reason, "sources") {
		t.Fatalf("a pending plan whose sources changed must be re-planned: %t %q", stale, reason)
	}
}

// agentUpdatePayloadEqual is hand-listed; a field added to the payload and
// not to it would be ignored by every staleness check.
func TestAgentUpdatePayloadEqualSeesEveryField(t *testing.T) {
	typ := reflect.TypeOf(agentUpdatePayload{})
	for i := 0; i < typ.NumField(); i++ {
		var changed agentUpdatePayload
		f := reflect.ValueOf(&changed).Elem().Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString("x")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int:
			f.SetInt(1)
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		default:
			t.Fatalf("field %s has kind %s, which this test cannot set; teach it", typ.Field(i).Name, f.Kind())
		}
		if agentUpdatePayloadEqual(agentUpdatePayload{}, changed) {
			t.Errorf("agentUpdatePayloadEqual ignores %s", typ.Field(i).Name)
		}
	}
}
