package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/store"
)

type guardRealitySummaryTest struct {
	NodeID            string     `json:"node_id"`
	SnapshotStatus    string     `json:"snapshot_status"`
	CollectedAt       *time.Time `json:"collected_at,omitempty"`
	ReceivedAt        *time.Time `json:"received_at,omitempty"`
	StaleAfter        *time.Time `json:"stale_after,omitempty"`
	ManagedSHA        string     `json:"managed_sha,omitempty"`
	ListenerCount     *int       `json:"listener_count,omitempty"`
	InterfaceCount    *int       `json:"interface_count,omitempty"`
	ForeignTableCount *int       `json:"foreign_table_count,omitempty"`
}

type guardRealityListTest struct {
	Nodes      []guardRealitySummaryTest `json:"nodes"`
	NextCursor string                    `json:"next_cursor,omitempty"`
}

type guardRealityDetailTest struct {
	Node struct {
		NodeID         string                  `json:"node_id"`
		SnapshotStatus string                  `json:"snapshot_status"`
		Reality        *model.GuardNodeReality `json:"reality"`
		ReceivedAt     *time.Time              `json:"received_at"`
		StaleAfter     *time.Time              `json:"stale_after"`
	} `json:"node"`
}

// guardRealityTestClock is the clock these tests install on the server.
//
// It is locked because the server under test is a running server: New starts
// background goroutines, and the terminal reaper calls s.now() on a ticker.
// Tests used to advance time by assigning to a shared time.Time and to
// srv.now while those goroutines were reading both, which the race detector
// caught intermittently. Set is the only safe way to move the clock.
type guardRealityTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newGuardRealityTestClock(at time.Time) *guardRealityTestClock {
	return &guardRealityTestClock{now: at}
}

func (c *guardRealityTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.UTC()
}

func (c *guardRealityTestClock) Set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = at
}

func newGuardRealityServerForTest(t *testing.T, clock *guardRealityTestClock) (*Server, http.Handler, *store.Store, []*http.Cookie, string) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv, err := New(Options{
		Store:                   st,
		AdminPassword:           testAdminPass,
		DisableRenewalScheduler: true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.now = clock.Now
	handler := srv.Handler()
	cookies, csrf := loginSession(t, handler)
	return srv, handler, st, cookies, csrf
}

func guardRealityFixture(nodeID string, collectedAt time.Time) model.GuardNodeReality {
	return model.GuardNodeReality{
		NodeID: nodeID,
		Listeners: []model.GuardListener{{
			Protocol: "tcp",
			Port:     22,
			Address:  "2001:db8::10",
			Process:  "sshd",
		}},
		Interfaces: []model.GuardInterface{{
			Name:      "ens3",
			Addresses: []string{"2001:db8::10/128"},
			Up:        true,
		}},
		ManagedSHA:    strings.Repeat("a", 64),
		ForeignTables: []string{"inet docker"},
		NFTVersion:    "nftables v1.0.9",
		CollectedAt:   collectedAt,
	}
}

func postGuardRealityForTest(t *testing.T, handler http.Handler, token, nodeID string, reality model.GuardNodeReality) *httptestResponse {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"node_id": nodeID,
		"reality": reality,
		"future_agent_field": map[string]any{
			"ignored": true,
		},
	})
	if err != nil {
		t.Fatalf("marshal guard reality body: %v", err)
	}
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/guard-reality", string(body), token)
	return &httptestResponse{code: rec.Code, body: rec.Body.String()}
}

type httptestResponse struct {
	code int
	body string
}

func assertAPIErrorCodeFromBody(t *testing.T, body string, want string) {
	t.Helper()
	var out model.APIErrorResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode error body %q: %v", body, err)
	}
	if out.Error.Code != want {
		t.Fatalf("error code = %q, want %q; body=%s", out.Error.Code, want, body)
	}
}

func TestNetGuardRealityAgentWriteAndReadContract(t *testing.T) {
	now := time.Date(2026, 7, 31, 13, 0, 1, 0, time.UTC)
	clock := newGuardRealityTestClock(now)
	_, handler, st, cookies, csrf := newGuardRealityServerForTest(t, clock)

	tokenA := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")

	collectedAt := now.Add(-time.Second)
	reality := guardRealityFixture("node-a", collectedAt)
	resp := postGuardRealityForTest(t, handler, tokenA, "node-a", reality)
	if resp.code != http.StatusOK {
		t.Fatalf("agent write status = %d, body=%s", resp.code, resp.body)
	}
	var accepted struct {
		OK                 bool      `json:"ok"`
		NodeID             string    `json:"node_id"`
		CollectedAt        time.Time `json:"collected_at"`
		ReceivedAt         time.Time `json:"received_at"`
		CollectedAtClamped bool      `json:"collected_at_clamped"`
	}
	if err := json.Unmarshal([]byte(resp.body), &accepted); err != nil {
		t.Fatalf("decode accepted response: %v", err)
	}
	if !accepted.OK || accepted.NodeID != "node-a" {
		t.Fatalf("unexpected accepted response: %+v", accepted)
	}
	if !accepted.CollectedAt.Equal(collectedAt) || !accepted.ReceivedAt.Equal(now) || accepted.CollectedAtClamped {
		t.Fatalf("unexpected accepted timestamps: %+v", accepted)
	}
	stored, ok := st.GuardRealitySnapshot("node-a")
	if !ok {
		t.Fatalf("snapshot not persisted")
	}
	if stored.Reality.NodeID != "node-a" || stored.Reality.Listeners[0].Process != "sshd" {
		t.Fatalf("unexpected persisted snapshot: %+v", stored.Reality)
	}
	foundAudit := false
	for _, ev := range st.AuditEvents() {
		if ev.Action != "netguard.reality.report" {
			continue
		}
		foundAudit = true
		if ev.NodeID != "node-a" {
			t.Fatalf("reality audit node_id = %q, want node-a", ev.NodeID)
		}
		// Counts plus the request-path source_ip stamp; never raw reality
		// payload fields.
		wantMetadata := map[string]string{
			"listener_count":      "1",
			"interface_count":     "1",
			"foreign_table_count": "1",
			"source_ip":           "192.0.2.1",
		}
		if len(ev.Metadata) != len(wantMetadata) {
			t.Fatalf("reality audit metadata = %+v, want counts and source_ip only", ev.Metadata)
		}
		for key, want := range wantMetadata {
			if ev.Metadata[key] != want {
				t.Fatalf("reality audit metadata[%s] = %q, want %q", key, ev.Metadata[key], want)
			}
		}
	}
	if !foundAudit {
		t.Fatalf("missing netguard.reality.report audit: %+v", st.AuditEvents())
	}

	listRes := doJSON(t, handler, http.MethodGet, "/api/netguard/reality", "", cookies, csrf)
	defer listRes.Body.Close()
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", listRes.StatusCode)
	}
	listRaw, err := io.ReadAll(listRes.Body)
	if err != nil {
		t.Fatalf("read list body: %v", err)
	}
	for _, forbidden := range []string{"sshd", "2001:db8::10", "2001:db8::10/128", "inet docker"} {
		if strings.Contains(string(listRaw), forbidden) {
			t.Fatalf("summary response leaked detail %q: %s", forbidden, string(listRaw))
		}
	}
	var list guardRealityListTest
	if err := json.Unmarshal(listRaw, &list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(list.Nodes) != 2 {
		t.Fatalf("list node count = %d, want 2: %s", len(list.Nodes), string(listRaw))
	}
	if list.Nodes[0].NodeID != "node-a" || list.Nodes[0].SnapshotStatus != "fresh" {
		t.Fatalf("node-a summary = %+v", list.Nodes[0])
	}
	if list.Nodes[0].ListenerCount == nil || *list.Nodes[0].ListenerCount != 1 {
		t.Fatalf("node-a listener_count = %+v", list.Nodes[0].ListenerCount)
	}
	if list.Nodes[0].InterfaceCount == nil || *list.Nodes[0].InterfaceCount != 1 {
		t.Fatalf("node-a interface_count = %+v", list.Nodes[0].InterfaceCount)
	}
	if list.Nodes[0].ForeignTableCount == nil || *list.Nodes[0].ForeignTableCount != 1 {
		t.Fatalf("node-a foreign_table_count = %+v", list.Nodes[0].ForeignTableCount)
	}
	if list.Nodes[1].NodeID != "node-b" || list.Nodes[1].SnapshotStatus != "unknown" {
		t.Fatalf("node-b summary = %+v", list.Nodes[1])
	}
	if list.Nodes[1].CollectedAt != nil || list.Nodes[1].ListenerCount != nil {
		t.Fatalf("unknown node exposed snapshot-derived fields: %+v", list.Nodes[1])
	}

	clock.Set(collectedAt.Add(30 * time.Hour))
	detailRes := doJSON(t, handler, http.MethodGet, "/api/netguard/reality?node_id=node-a", "", cookies, csrf)
	defer detailRes.Body.Close()
	if detailRes.StatusCode != http.StatusOK {
		t.Fatalf("detail status = %d", detailRes.StatusCode)
	}
	var detail guardRealityDetailTest
	if err := json.NewDecoder(detailRes.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail.Node.NodeID != "node-a" || detail.Node.SnapshotStatus != "stale" {
		t.Fatalf("detail status = %+v", detail.Node)
	}
	if detail.Node.Reality == nil || detail.Node.Reality.Listeners[0].Process != "sshd" {
		t.Fatalf("detail did not include full normalized reality: %+v", detail.Node.Reality)
	}
	if detail.Node.StaleAfter == nil || !detail.Node.StaleAfter.Equal(collectedAt.Add(30*time.Hour)) {
		t.Fatalf("stale_after = %+v, want %s", detail.Node.StaleAfter, collectedAt.Add(30*time.Hour))
	}
}

func TestNetGuardRealityValidationAndStaleConflicts(t *testing.T) {
	now := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	_, handler, _, cookies, csrf := newGuardRealityServerForTest(t, newGuardRealityTestClock(now))
	tokenA := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	tokenB := enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")
	tokenC := enrollNamedNodeToken(t, handler, cookies, csrf, "node-c", "Node C")

	missingNodeID := string(mustJSON(t, map[string]any{"reality": guardRealityFixture("node-a", now)}))
	rec := doAgentRaw(t, handler, http.MethodPost, "/api/agent/guard-reality", missingNodeID, tokenA)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing node_id status = %d, body=%s", rec.Code, rec.Body.String())
	}
	assertAPIErrorCodeFromBody(t, rec.Body.String(), model.APIErrorBadRequest)

	mismatch := guardRealityFixture("other-node", now)
	body, err := json.Marshal(map[string]any{"node_id": "node-a", "reality": mismatch})
	if err != nil {
		t.Fatalf("marshal mismatch: %v", err)
	}
	rec = doAgentRaw(t, handler, http.MethodPost, "/api/agent/guard-reality", string(body), tokenA)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched node status = %d, body=%s", rec.Code, rec.Body.String())
	}
	assertAPIErrorCodeFromBody(t, rec.Body.String(), model.APIErrorBadRequest)

	rawWithToken := `{"node_id":"node-a","token":"` + tokenA + `","reality":` + string(mustJSON(t, guardRealityFixture("node-a", now))) + `}`
	rec = doAgentRaw(t, handler, http.MethodPost, "/api/agent/guard-reality", rawWithToken, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("body token auth status = %d, body=%s", rec.Code, rec.Body.String())
	}
	assertAPIErrorCodeFromBody(t, rec.Body.String(), model.APIErrorInvalidNodeToken)

	valid := guardRealityFixture("node-a", now)
	rec = doAgentRaw(t, handler, http.MethodPost, "/api/agent/guard-reality", string(mustJSON(t, map[string]any{"node_id": "node-a", "reality": valid}))+" {}", tokenA)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON status = %d, body=%s", rec.Code, rec.Body.String())
	}
	assertAPIErrorCodeFromBody(t, rec.Body.String(), model.APIErrorBadRequest)

	resp := postGuardRealityForTest(t, handler, tokenA, "node-a", valid)
	if resp.code != http.StatusOK {
		t.Fatalf("valid seed status = %d, body=%s", resp.code, resp.body)
	}
	older := guardRealityFixture("node-a", now.Add(-time.Second))
	resp = postGuardRealityForTest(t, handler, tokenA, "node-a", older)
	if resp.code != http.StatusConflict {
		t.Fatalf("older status = %d, body=%s", resp.code, resp.body)
	}
	assertAPIErrorCodeFromBody(t, resp.body, "guard_reality_stale")

	diffSameTime := guardRealityFixture("node-a", now)
	diffSameTime.ManagedSHA = strings.Repeat("b", 64)
	resp = postGuardRealityForTest(t, handler, tokenA, "node-a", diffSameTime)
	if resp.code != http.StatusConflict {
		t.Fatalf("same-time diff status = %d, body=%s", resp.code, resp.body)
	}
	assertAPIErrorCodeFromBody(t, resp.body, "guard_reality_stale")

	omittedEmpty := model.GuardNodeReality{
		NodeID:      "node-c",
		Interfaces:  []model.GuardInterface{{Name: "lo"}},
		CollectedAt: now,
	}
	resp = postGuardRealityForTest(t, handler, tokenC, "node-c", omittedEmpty)
	if resp.code != http.StatusOK {
		t.Fatalf("omitted-empty seed status = %d, body=%s", resp.code, resp.body)
	}
	explicitEmpty := omittedEmpty
	explicitEmpty.Listeners = []model.GuardListener{}
	explicitEmpty.Interfaces[0].Addresses = []string{}
	explicitEmpty.ForeignTables = []string{}
	resp = postGuardRealityForTest(t, handler, tokenC, "node-c", explicitEmpty)
	if resp.code != http.StatusOK {
		t.Fatalf("explicit-empty retry status = %d, body=%s", resp.code, resp.body)
	}

	future := guardRealityFixture("node-b", now.Add(10*time.Minute))
	resp = postGuardRealityForTest(t, handler, tokenB, "node-b", future)
	if resp.code != http.StatusOK {
		t.Fatalf("future-clamp status = %d, body=%s", resp.code, resp.body)
	}
	var accepted struct {
		CollectedAt        time.Time `json:"collected_at"`
		CollectedAtClamped bool      `json:"collected_at_clamped"`
	}
	if err := json.Unmarshal([]byte(resp.body), &accepted); err != nil {
		t.Fatalf("decode future response: %v", err)
	}
	if !accepted.CollectedAt.Equal(now) || !accepted.CollectedAtClamped {
		t.Fatalf("future clamp response = %+v, want collected_at=%s clamped=true", accepted, now)
	}

	badProtocol := guardRealityFixture("node-b", now.Add(time.Minute))
	badProtocol.Listeners[0].Protocol = "icmp"
	resp = postGuardRealityForTest(t, handler, tokenB, "node-b", badProtocol)
	if resp.code != http.StatusBadRequest {
		t.Fatalf("bad protocol status = %d, body=%s", resp.code, resp.body)
	}
	assertAPIErrorCodeFromBody(t, resp.body, model.APIErrorBadRequest)

	tooManyListeners := guardRealityFixture("node-b", now.Add(time.Minute))
	tooManyListeners.Listeners = make([]model.GuardListener, 4097)
	for i := range tooManyListeners.Listeners {
		tooManyListeners.Listeners[i] = model.GuardListener{Protocol: "tcp", Port: 1024 + i%1000}
	}
	resp = postGuardRealityForTest(t, handler, tokenB, "node-b", tooManyListeners)
	if resp.code != http.StatusBadRequest {
		t.Fatalf("too many listeners status = %d, body=%s", resp.code, resp.body)
	}
	assertAPIErrorCodeFromBody(t, resp.body, model.APIErrorBadRequest)
}

func TestNetGuardRealityReadVisibilityAndPagination(t *testing.T) {
	now := time.Date(2026, 7, 31, 13, 0, 0, 0, time.UTC)
	_, handler, _, cookies, csrf := newGuardRealityServerForTest(t, newGuardRealityTestClock(now))
	tokenA := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-b", "Node B")
	tokenC := enrollNamedNodeToken(t, handler, cookies, csrf, "node-c", "Node C")

	if resp := postGuardRealityForTest(t, handler, tokenA, "node-a", guardRealityFixture("node-a", now)); resp.code != http.StatusOK {
		t.Fatalf("seed node-a status=%d body=%s", resp.code, resp.body)
	}
	if resp := postGuardRealityForTest(t, handler, tokenC, "node-c", guardRealityFixture("node-c", now)); resp.code != http.StatusOK {
		t.Fatalf("seed node-c status=%d body=%s", resp.code, resp.body)
	}

	pat := createPAT(t, handler, cookies, csrf, []string{"netguard:read"}, []string{"node-b", "node-c"})
	first := doBearerJSON(t, handler, http.MethodGet, "/api/netguard/reality?limit=1", "", pat)
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first page status = %d", first.StatusCode)
	}
	var firstPage guardRealityListTest
	if err := json.NewDecoder(first.Body).Decode(&firstPage); err != nil {
		t.Fatalf("decode first page: %v", err)
	}
	if len(firstPage.Nodes) != 1 || firstPage.Nodes[0].NodeID != "node-b" || firstPage.Nodes[0].SnapshotStatus != "unknown" {
		t.Fatalf("first page = %+v", firstPage)
	}
	if firstPage.NextCursor == "" {
		t.Fatalf("first page missing next_cursor")
	}

	second := doBearerJSON(t, handler, http.MethodGet, "/api/netguard/reality?cursor="+firstPage.NextCursor+"&limit=1", "", pat)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second page status = %d", second.StatusCode)
	}
	var secondPage guardRealityListTest
	if err := json.NewDecoder(second.Body).Decode(&secondPage); err != nil {
		t.Fatalf("decode second page: %v", err)
	}
	if len(secondPage.Nodes) != 1 || secondPage.Nodes[0].NodeID != "node-c" || secondPage.Nodes[0].SnapshotStatus != "fresh" {
		t.Fatalf("second page = %+v", secondPage)
	}
	if secondPage.NextCursor != "" {
		t.Fatalf("final page next_cursor = %q, want empty", secondPage.NextCursor)
	}

	hidden := doBearerJSON(t, handler, http.MethodGet, "/api/netguard/reality?node_id=node-a", "", pat)
	defer hidden.Body.Close()
	if hidden.StatusCode != http.StatusNotFound {
		t.Fatalf("hidden detail status = %d", hidden.StatusCode)
	}
	body, err := io.ReadAll(hidden.Body)
	if err != nil {
		t.Fatalf("read hidden detail: %v", err)
	}
	assertAPIErrorCodeFromBody(t, string(body), model.APIErrorNotFound)

	unknown := doBearerJSON(t, handler, http.MethodGet, "/api/netguard/reality?node_id=node-b", "", pat)
	defer unknown.Body.Close()
	if unknown.StatusCode != http.StatusOK {
		t.Fatalf("unknown detail status = %d", unknown.StatusCode)
	}
	var unknownDetail guardRealityDetailTest
	if err := json.NewDecoder(unknown.Body).Decode(&unknownDetail); err != nil {
		t.Fatalf("decode unknown detail: %v", err)
	}
	if unknownDetail.Node.NodeID != "node-b" || unknownDetail.Node.SnapshotStatus != "unknown" || unknownDetail.Node.Reality != nil || unknownDetail.Node.ReceivedAt != nil {
		t.Fatalf("unknown detail = %+v", unknownDetail.Node)
	}

	for _, path := range []string{
		"/api/netguard/reality?node_id=node-b&limit=1",
		"/api/netguard/reality?cursor=not-base64",
		"/api/netguard/reality?limit=501",
	} {
		res := doBearerJSON(t, handler, http.MethodGet, path, "", pat)
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatalf("read %s body: %v", path, err)
		}
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status = %d, body=%s", path, res.StatusCode, string(body))
		}
		assertAPIErrorCodeFromBody(t, string(body), model.APIErrorBadRequest)
	}
}

// The SSH Guard page prints PASSWORD and PORTS from these facts, so the
// contract is: a current agent's facts come back on the per-node detail
// canonicalized, a current agent's refusal comes back as the note alone, and
// an agent that predates the field keeps reporting exactly as before.
func TestNetGuardRealitySSHDFactsRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 2, 7, 0, 1, 0, time.UTC)
	clock := newGuardRealityTestClock(now)
	_, handler, st, cookies, csrf := newGuardRealityServerForTest(t, clock)
	token := enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	readDetail := func() (model.GuardNodeReality, map[string]any) {
		t.Helper()
		res := doJSON(t, handler, http.MethodGet, "/api/netguard/reality?node_id=node-a", "", cookies, csrf)
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("read detail body: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("detail status = %d: %s", res.StatusCode, raw)
		}
		var typed guardRealityDetailTest
		if err := json.Unmarshal(raw, &typed); err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		var generic struct {
			Node struct {
				Reality map[string]any `json:"reality"`
			} `json:"node"`
		}
		if err := json.Unmarshal(raw, &generic); err != nil {
			t.Fatalf("decode generic detail: %v", err)
		}
		if typed.Node.Reality == nil {
			t.Fatalf("detail has no reality: %s", raw)
		}
		return *typed.Node.Reality, generic.Node.Reality
	}
	asJSON := func(v any) string {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	collectedAt := now.Add(-time.Second)
	observedAt := now.Add(-2 * time.Second)
	withFacts := guardRealityFixture("node-a", collectedAt)
	withFacts.SSHD = &model.GuardSSHDFacts{
		PubkeyAuthentication: true,
		PermitRootLogin:      "prohibit-password",
		MaxAuthTries:         3,
		// Configuration order with a duplicate, as a node with two Port
		// lines and an Include could produce; the read side must be a set.
		Ports:           []int{58394, 22, 58394},
		ListenAddresses: []string{"[::]:58394", "0.0.0.0:58394"},
		ObservedAt:      observedAt,
	}
	if resp := postGuardRealityForTest(t, handler, token, "node-a", withFacts); resp.code != http.StatusOK {
		t.Fatalf("post with sshd facts = %d: %s", resp.code, resp.body)
	}
	reality, generic := readDetail()
	if reality.SSHD == nil {
		t.Fatalf("sshd facts missing from detail: %v", generic)
	}
	got := *reality.SSHD
	if got.PasswordAuthentication || !got.PubkeyAuthentication || got.PermitRootLogin != "prohibit-password" || got.MaxAuthTries != 3 || !got.ObservedAt.Equal(observedAt) {
		t.Fatalf("sshd facts = %+v", got)
	}
	if asJSON(got.Ports) != "[22,58394]" || asJSON(got.ListenAddresses) != `["0.0.0.0:58394","[::]:58394"]` {
		t.Fatalf("sshd ports/listen addresses not canonical: %+v", got)
	}
	if _, ok := generic["sshd_note"]; ok || reality.SSHDNote != "" {
		t.Fatalf("sshd_note must be absent when the facts were read: %v", generic)
	}
	if len(reality.Listeners) != 1 || reality.Listeners[0].Process != "sshd" {
		t.Fatalf("listeners changed alongside sshd facts: %+v", reality.Listeners)
	}

	refused := guardRealityFixture("node-a", collectedAt.Add(time.Second))
	refused.SSHDNote = "sshd -T needs root to read the effective configuration; agent runs as uid 1000"
	if resp := postGuardRealityForTest(t, handler, token, "node-a", refused); resp.code != http.StatusOK {
		t.Fatalf("post refusal = %d: %s", resp.code, resp.body)
	}
	reality, generic = readDetail()
	if _, ok := generic["sshd"]; ok || reality.SSHD != nil {
		t.Fatalf("a refusal must not carry facts: %v", generic)
	}
	if reality.SSHDNote != refused.SSHDNote {
		t.Fatalf("sshd_note = %q, want the agent's reason", reality.SSHDNote)
	}

	older := guardRealityFixture("node-a", collectedAt.Add(2*time.Second))
	if resp := postGuardRealityForTest(t, handler, token, "node-a", older); resp.code != http.StatusOK {
		t.Fatalf("post from an older agent = %d: %s", resp.code, resp.body)
	}
	reality, generic = readDetail()
	for _, key := range []string{"sshd", "sshd_note"} {
		if _, ok := generic[key]; ok {
			t.Fatalf("older agent report must not grow %q: %v", key, generic)
		}
	}
	if asJSON(reality) != asJSON(older) {
		t.Fatalf("older agent report changed on the way through:\n got %s\nwant %s", asJSON(reality), asJSON(older))
	}

	// The audit gate fires on a changed reality. observed_at changes on every
	// poll, so it must be invisible to the fingerprint while a real change
	// (password authentication turned on) must not be.
	same := withFacts
	sameSSHD := *withFacts.SSHD
	sameSSHD.ObservedAt = observedAt.Add(time.Hour)
	same.SSHD = &sameSSHD
	if guardRealityFingerprint(withFacts) != guardRealityFingerprint(same) {
		t.Fatal("sshd observed_at must not change the audit fingerprint")
	}
	changed := withFacts
	changedSSHD := *withFacts.SSHD
	changedSSHD.PasswordAuthentication = true
	changed.SSHD = &changedSSHD
	if guardRealityFingerprint(withFacts) == guardRealityFingerprint(changed) {
		t.Fatal("password authentication flipping must change the audit fingerprint")
	}

	stored, ok := st.GuardRealitySnapshot("node-a")
	if !ok {
		t.Fatal("snapshot missing before validation cases")
	}
	invalid := []struct {
		name   string
		mutate func(*model.GuardNodeReality)
	}{
		{"port out of range", func(r *model.GuardNodeReality) {
			r.SSHD = &model.GuardSSHDFacts{Ports: []int{70000}, PermitRootLogin: "no", ObservedAt: now}
		}},
		{"no ports", func(r *model.GuardNodeReality) {
			r.SSHD = &model.GuardSSHDFacts{PermitRootLogin: "no", ObservedAt: now}
		}},
		{"missing observed_at", func(r *model.GuardNodeReality) {
			r.SSHD = &model.GuardSSHDFacts{Ports: []int{22}, PermitRootLogin: "no"}
		}},
		{"empty permit_root_login", func(r *model.GuardNodeReality) {
			r.SSHD = &model.GuardSSHDFacts{Ports: []int{22}, ObservedAt: now}
		}},
		{"control characters in the note", func(r *model.GuardNodeReality) {
			r.SSHDNote = "refused\x1b[31m"
		}},
		{"note over the byte bound", func(r *model.GuardNodeReality) {
			r.SSHDNote = strings.Repeat("x", guardRealityMaxSSHDNoteBytes+1)
		}},
	}
	for _, tc := range invalid {
		bad := guardRealityFixture("node-a", collectedAt.Add(time.Hour))
		tc.mutate(&bad)
		resp := postGuardRealityForTest(t, handler, token, "node-a", bad)
		if resp.code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400: %s", tc.name, resp.code, resp.body)
		}
		assertAPIErrorCodeFromBody(t, resp.body, model.APIErrorBadRequest)
	}
	after, _ := st.GuardRealitySnapshot("node-a")
	if !after.Reality.CollectedAt.Equal(stored.Reality.CollectedAt) {
		t.Fatal("a rejected sshd report must not replace the stored snapshot")
	}
}
