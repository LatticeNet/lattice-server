package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The S2 plans harness: records with their own live revisions, a fake
// depends_on graph over them, a previewer that answers per record, revision
// and member revisions, and an apply_revision that moves the graph the way
// the plugin's promotion does.

const (
	s2Alice = "vpnuser_alice"
	s2Bob   = "vpnuser_bob"
	s2Carol = "vpnuser_carol"
)

// s2Lines are distinct line uuids the tests hand out by index.
var s2Lines = []string{
	"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333",
	"44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666",
}

// s2Result is a bind result that includes the given lines, named after them.
func s2Result(lines ...int) subStoreBindResult {
	out := subStoreBindResult{}
	for _, i := range lines {
		out.Included = append(out.Included, subStoreBindLine{LineUUID: s2Lines[i], Name: "line " + s2Lines[i][:4], Digest: "d" + s2Lines[i][:4]})
	}
	return out
}

// s2Previewer answers PreviewBind per record, revision and member
// revisions; every identity receives the same result unless the test names
// one. The live revision it reports is the record's in the graph.
type s2Previewer struct {
	mu      sync.Mutex
	graph   *subStoreFakeGraph
	results map[string]subStoreBindResult
	calls   []subStoreBindQuery
	err     error
	fail    map[string]error // by record
	// live overrides the live revision a preview of the record reports.
	live   map[string]string
	onCall func(subStoreBindQuery)
}

// s2Key names a result: record, revision, the member revisions in a stable
// order, and optionally an identity.
func s2Key(record, revision string, members map[string]string, identity string) string {
	parts := []string{record, revision}
	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, "m:"+k+"="+members[k])
	}
	if identity != "" {
		parts = append(parts, "i:"+identity)
	}
	return strings.Join(parts, "|")
}

func (p *s2Previewer) set(record, revision string, members map[string]string, result subStoreBindResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.results[s2Key(record, revision, members, "")] = result
}

func (p *s2Previewer) setFor(record, revision string, members map[string]string, identity string, result subStoreBindResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.results[s2Key(record, revision, members, identity)] = result
}

func (p *s2Previewer) PreviewBind(_ context.Context, q subStoreBindQuery) (map[string]subStoreBindResult, error) {
	p.mu.Lock()
	hook := p.onCall
	p.mu.Unlock()
	if hook != nil {
		hook(q)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, q)
	if p.err != nil {
		return nil, p.err
	}
	if err := p.fail[q.SubscriptionID]; err != nil {
		return nil, err
	}
	p.graph.mu.Lock()
	facts := p.graph.records[q.SubscriptionID]
	p.graph.mu.Unlock()
	if q.Revision != facts.Revision && q.Revision != facts.StagedRevision {
		return nil, errors.New("revision_unknown: " + q.Revision)
	}
	out := map[string]subStoreBindResult{}
	for _, identity := range q.IdentityIDs {
		result, ok := p.results[s2Key(q.SubscriptionID, q.Revision, q.MemberRevisions, identity)]
		if !ok {
			result = p.results[s2Key(q.SubscriptionID, q.Revision, q.MemberRevisions, "")]
		}
		result.LiveRevision = facts.Revision
		if live, ok := p.live[q.SubscriptionID]; ok {
			result.LiveRevision = live
		}
		out[identity] = result
	}
	return out, nil
}

func (p *s2Previewer) queries() []subStoreBindQuery {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]subStoreBindQuery(nil), p.calls...)
}

// s2PlanEnv is the harness.
type s2PlanEnv struct {
	*subStoreSvcHarness
	graph     *subStoreFakeGraph
	previewer *s2Previewer
	mu        sync.Mutex
	applied   []subStoreApplyRevisionRequest
	applyErr  map[string]error
	onApply   func(context.Context, subStoreApplyRevisionRequest)
}

func newS2PlanEnv(t testing.TB) *s2PlanEnv {
	t.Helper()
	e := &s2PlanEnv{subStoreSvcHarness: newSubStoreSvcHarness(t), applyErr: map[string]error{}}
	for _, id := range []string{s2Alice, s2Bob, s2Carol} {
		if err := e.srv.putVpnUser(VpnUser{ID: id, Email: id + "@example.com", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	e.graph = installSubStoreFakeGraph(t, e.srv)
	e.previewer = &s2Previewer{graph: e.graph, results: map[string]subStoreBindResult{}, fail: map[string]error{}, live: map[string]string{}}
	e.srv.subStoreSvc.previewer = e.previewer
	e.srv.subStoreSvc.applyRevision = func(ctx context.Context, req subStoreApplyRevisionRequest) (subStoreApplyRevisionReply, error) {
		e.mu.Lock()
		e.applied = append(e.applied, req)
		err, hook := e.applyErr[req.SubscriptionID], e.onApply
		e.mu.Unlock()
		if hook != nil {
			hook(ctx, req)
		}
		if err != nil {
			return subStoreApplyRevisionReply{}, err
		}
		if req.Action == subStorePlanActionDelete {
			e.graph.mu.Lock()
			delete(e.graph.records, req.SubscriptionID)
			e.graph.mu.Unlock()
			return subStoreApplyRevisionReply{SubscriptionID: req.SubscriptionID, Revision: req.Revision}, nil
		}
		e.graph.update(req.SubscriptionID, func(f *fleetDependsFacts) {
			f.Revision, f.StagedRevision, f.StagedMigrated = req.Revision, "", false
			if f.StagedSource != "" {
				f.Source = f.StagedSource
			}
			f.StagedSource = ""
			if f.Source == subStoreSourceFleet {
				f.FleetBound, f.OwnerCredentials = true, false
			}
		})
		return subStoreApplyRevisionReply{SubscriptionID: req.SubscriptionID, Revision: req.Revision}, nil
	}
	return e
}

// record states a record in the graph and gives it a fresh snapshot.
func (e *s2PlanEnv) record(t testing.TB, facts fleetDependsFacts) {
	t.Helper()
	if facts.Kind == "" {
		facts.Kind = "sub"
	}
	e.graph.put(facts)
	if facts.Revision != "" {
		if err := e.st.UpsertSubscriptionSnapshot(model.SubscriptionSnapshot{PluginID: subStorePluginID, SubscriptionID: facts.ID, Raw: "snap-" + facts.ID,
			FetchedAt: e.srv.now()}); err != nil {
			t.Fatal(err)
		}
	}
}

// share stores a live share directly, so a test can give a share an
// identity on any record.
func (e *s2PlanEnv) share(t testing.TB, id, record, identity string) {
	t.Helper()
	if err := e.st.UpsertSubscriptionShare(model.SubscriptionShare{ID: id, Slug: id, Token: strings.Repeat(string(rune('a'+len(id)%26)), 40) + id, Enabled: true,
		Source: model.ShareSource{Kind: model.ShareSourcePlugin, PluginID: subStorePluginID, SubscriptionID: record, IdentityID: identity}}); err != nil {
		t.Fatal(err)
	}
}

func (e *s2PlanEnv) appliedRequests() []subStoreApplyRevisionRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]subStoreApplyRevisionRequest(nil), e.applied...)
}

func (e *s2PlanEnv) failApply(record string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applyErr[record] = err
}

// propose calls plans.propose; it fails the test on an error.
func (e *s2PlanEnv) propose(t *testing.T, body string) (subStorePlansProposeReply, subStorePlan) {
	t.Helper()
	var reply subStorePlansProposeReply
	if err := json.Unmarshal(e.mustCall(t, subStorePlansService, "propose", body), &reply); err != nil {
		t.Fatal(err)
	}
	var plan subStorePlan
	if reply.Plan != "" {
		if err := json.Unmarshal([]byte(reply.Plan), &plan); err != nil {
			t.Fatal(err)
		}
	}
	return reply, plan
}

// proposeErr calls plans.propose and returns the refusal's status and body.
func (e *s2PlanEnv) proposeErr(body string) (int, string) {
	_, err := e.call(subStoreSvcAdmin, subStorePlansService, "propose", body)
	return subStoreSvcErrStatus(err), subStoreSvcErrBody(err)
}

func (e *s2PlanEnv) publish(body string) ([]byte, int, string) {
	out, err := e.call(subStoreSvcAdmin, subStorePlansService, "publish", body)
	return out, subStoreSvcErrStatus(err), subStoreSvcErrBody(err)
}

// approve drives the real approve endpoint.
func (e *s2PlanEnv) approve(reply subStorePlansProposeReply) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"approval_id": reply.ApprovalID, "plan_sha256": reply.PlanSHA256, "queue_apply": true})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/network/approvals/approve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	e.srv.handleApprove(rec, req, subStorePlanApprover)
	return rec
}

func (e *s2PlanEnv) approval(id string) model.Approval {
	a, _ := e.st.Approval(id)
	return a
}

func (e *s2PlanEnv) shareIdentity(t *testing.T, id string) (string, bool) {
	t.Helper()
	share, ok := e.st.SubscriptionShare(id)
	if !ok {
		t.Fatalf("share %s is gone", id)
	}
	return share.Source.IdentityID, share.ArchivedAt != nil
}

func (e *s2PlanEnv) snapshot(id string) (model.SubscriptionSnapshot, bool) {
	return e.st.SubscriptionSnapshot(subStorePluginID, id)
}

// section finds a record's section in a plan.
func s2Section(t *testing.T, plan subStorePlan, id string) subStorePlanRecord {
	t.Helper()
	for _, section := range plan.sections() {
		if section.SubscriptionID == id {
			return section
		}
	}
	t.Fatalf("the plan has no section for %s: %v", id, plan.Closure)
	return subStorePlanRecord{}
}

func s2Identity(section subStorePlanRecord, id string) (subStorePlanIdentity, bool) {
	for _, diff := range section.Identities {
		if diff.IdentityID == id {
			return diff, true
		}
	}
	return subStorePlanIdentity{}, false
}

// s2Deadline fails a test that has not finished in time, so a lock or gate
// deadlock fails it instead of hanging the run.
func s2Deadline(t *testing.T, d time.Duration) func() {
	t.Helper()
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-time.After(d):
			panic("test " + t.Name() + " did not finish within " + d.String() + ": a lock or the plugin gate is held")
		}
	}()
	return func() { close(done) }
}
