package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/rbac"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// Design 28 slice S2, lane 5a: the plan's selection and policy in bind, the
// two policy reasons, the NAT rule, the policy memo in the cache digest, the
// decoy for a plan-less document on an identity share, and the preview's
// snapshot fallback.

// bindRunInputs builds a fresh catalogue, round-trips the plan through the
// SDK's strict codec and binds it with in, after edit has changed the build.
func (e *bindEnv) bindRunInputs(t testing.TB, plan model.SelectionPlan, in substoreBindInputs, edit func(*lineCatalogue)) substoreBindResult {
	t.Helper()
	raw, err := model.EncodeSelectionPlan(plan)
	if err != nil {
		t.Fatalf("plan does not encode: %v", err)
	}
	decoded, err := model.DecodeSelectionPlan(raw)
	if err != nil {
		t.Fatalf("plan does not decode: %v", err)
	}
	catalogue, err := e.srv.buildLineCatalogue("")
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(catalogue)
	}
	u, ok := e.srv.getVpnUser(bindIdentityID)
	if !ok {
		t.Fatal("bind identity missing")
	}
	return substoreBindPlan(decoded, u, catalogue, in)
}

// planSelection is a selection over rows at version.
func planSelection(version string, rows ...model.LineCatalogueRow) *model.PlanSelection {
	out := &model.PlanSelection{CatalogueVersion: version, LineUUIDs: []string{}}
	for _, row := range rows {
		out.LineUUIDs = append(out.LineUUIDs, row.LineUUID)
	}
	return out
}

// Core's carried set is the SDK's list, so the plugin's plan encoder,
// convert's strip and core cannot drift; and no carried key is also compared
// or mutable.
func TestCoreCarriedSetIsTheSDKList(t *testing.T) {
	want := map[string]bool{}
	for _, field := range model.SelectionPlanCarriedFields {
		want[field] = true
	}
	if !maps.Equal(substoreBindCarriedFields, want) {
		t.Fatalf("core carries %v, the SDK lists %v", slices.Sorted(maps.Keys(substoreBindCarriedFields)), model.SelectionPlanCarriedFields)
	}
	for field := range substoreBindCarriedFields {
		if substoreBindComparedFields[field] || substoreBindMutableFields[field] {
			t.Fatalf("%s is carried and also compared or mutable", field)
		}
	}
	if !substoreBindComparedFields["line_uuid"] || substoreBindCarriedFields["line_uuid"] || substoreBindCarriedFields["_lattice"] {
		t.Fatal("line_uuid is compared, never carried, and _lattice is no plan key")
	}
	for _, field := range model.SelectionPlanStrippedFields {
		if !substoreBindCarriedFields[field] && !substoreBindComparedFields[field] {
			t.Fatalf("convert strips %s, which core would refuse on a plan node", field)
		}
	}
}

// A plan that states its selection is checked against it, not against the
// snapshot: a line the snapshot selected but the plan's selection did not is
// plan_rejected:line_uuid, and a line the staged selection added binds. A
// plan from a plugin that states none falls back to the snapshot.
func TestBindTakesSelectionFromPlan(t *testing.T) {
	e := bindFixture(t, 2, 2)
	plan := bindNodesPlan(t, e.rows)
	plan.Selection = planSelection("lcv1-staged", e.rows[0], e.rows[1], e.rows[3])
	snapshotSelected := map[string]bool{e.rows[0].LineUUID: true, e.rows[1].LineUUID: true, e.rows[2].LineUUID: true}
	result := e.bindRunInputs(t, plan, substoreBindInputs{selected: snapshotSelected}, nil)
	if got := result.reasons(); fmt.Sprint(got) != fmt.Sprint(map[int]string{2: "plan_rejected:line_uuid"}) {
		t.Fatalf("exclusions %v", got)
	}
	if len(result.nodes) != 3 || result.Refused != "" {
		t.Fatalf("%d nodes, refused %q", len(result.nodes), result.Refused)
	}
	// With no snapshot selection at all, the plan's own still binds.
	if result := e.bindRunInputs(t, plan, substoreBindInputs{}, nil); result.Refused != "" || len(result.nodes) != 3 {
		t.Fatalf("no snapshot selection: refused %q, %d nodes", result.Refused, len(result.nodes))
	}
	// An S1 plan reads the snapshot's selection.
	plan.Selection = nil
	result = e.bindRunInputs(t, plan, substoreBindInputs{selected: snapshotSelected}, nil)
	if got := result.reasons(); fmt.Sprint(got) != fmt.Sprint(map[int]string{3: "plan_rejected:line_uuid"}) {
		t.Fatalf("S1 plan exclusions %v", got)
	}
	if result := e.bindRunInputs(t, plan, substoreBindInputs{}, nil); result.Refused != substoreBindRefusedSelection {
		t.Fatalf("an S1 plan with no snapshot selection: refused %q", result.Refused)
	}
	// An empty stated selection selects nothing.
	plan.Selection = planSelection("lcv1-staged")
	if result := e.bindRunInputs(t, plan, substoreBindInputs{selected: snapshotSelected}, nil); result.Refused != substoreBindRefusedNoLine {
		t.Fatalf("an empty selection: refused %q", result.Refused)
	}
}

// On the serve path the plan's selection must name the snapshot's catalogue
// version and only lines the snapshot's rows hold; otherwise the share
// answers the decoy, audited as selection_mismatch.
func TestBindRefusesSelectionMismatchOnServePath(t *testing.T) {
	env := bindShareFixture(t)
	env.selection = planSelection(env.catalogueVersion, env.rows...)
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusOK {
		t.Fatalf("a matching selection: status %d", rec.Code)
	}
	cases := map[string]*model.PlanSelection{
		"another version": planSelection("lcv1-0000", env.rows...),
		"a line the snapshot lacks": {CatalogueVersion: env.catalogueVersion,
			LineUUIDs: append(planSelection("", env.rows...).LineUUIDs, "abcdef01-2345-4678-89ab-cdef01234567")},
	}
	share, _ := env.st.SubscriptionShare("sh-fleet")
	snap, _ := env.st.SubscriptionSnapshot(subStorePluginID, "fleet-1")
	for name, selection := range cases {
		env.selection = selection
		env.srv.subscriptionCache.InvalidateShare("sh-fleet")
		if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
		// The audit throttle folds repeats per share, so the reason is read
		// from the bind step itself.
		plan := bindNodesPlan(t, env.rows)
		plan.Selection = selection
		_, err := env.srv.substoreBindRendered(context.Background(), share, "plain", shareRenderVariant{}, snap, renderedSubscription{Plan: &plan})
		var refusal substoreBindRefusal
		if !errors.As(err, &refusal) || refusal.reason != substoreBindDenyPrefix+substoreBindRefusedSelectionMismatch {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if got := env.shareRefusals("sh-fleet"); len(got) == 0 || got[0] != substoreBindDenyPrefix+substoreBindRefusedSelectionMismatch {
		t.Fatalf("refusals %v", got)
	}
	// A selection narrower than the snapshot is fine: it is a subset.
	env.selection = planSelection(env.catalogueVersion, env.rows[0])
	env.srv.subscriptionCache.InvalidateShare("sh-fleet")
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusOK || len(env.lastConvert(t).Nodes) != 1 {
		t.Fatalf("a narrower selection: status %d", rec.Code)
	}
	// A record whose snapshot states no selection refuses a plan that does.
	share, _ = env.st.SubscriptionShare("sh-foreign")
	plan := bindNodesPlan(t, env.rows)
	plan.Selection = planSelection(env.catalogueVersion, env.rows...)
	snap, _ = env.st.SubscriptionSnapshot(subStorePluginID, "fleet-foreign")
	_, err := env.srv.substoreBindRendered(context.Background(), share, "plain", shareRenderVariant{}, snap, renderedSubscription{Plan: &plan})
	var refusal substoreBindRefusal
	if !errors.As(err, &refusal) || refusal.reason != substoreBindDenyPrefix+substoreBindRefusedSelectionMismatch {
		t.Fatalf("a selection over a snapshot without one: %v", err)
	}
}

// bind.preview of a named revision uses that revision's own selection as it
// is, since a staged selection may legitimately differ from the live
// snapshot; a preview of the live revision with nothing named is checked as
// the serve path checks it.
func TestBindPreviewSkipsMismatchForNamedRevision(t *testing.T) {
	env := bindShareFixture(t)
	staged := planSelection("lcv1-staged", env.rows[0], env.rows[1])
	env.srv.substoreCatalogue.bind.renderPlan = func(_ context.Context, q substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
		plan := bindNodesPlan(t, env.rows)
		plan.Selection = staged
		return &plan, "rev-live", nil
	}
	reader := principal{Principal: rbac.Principal{ActorID: "op", Scopes: []string{"vpncore:read", "substore:read"}}}
	preview := func(request string) substoreBindPreviewReply {
		t.Helper()
		out, err := env.srv.substoreBindRPC(bindOperatorCtx(reader), "preview", []byte(request))
		if err != nil {
			t.Fatal(err)
		}
		var reply substoreBindPreviewReply
		if err := json.Unmarshal(out, &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	named := preview(`{"subscription_id":"fleet-1","revision":"rev-staged","identity_id":"` + bindIdentityID + `"}`)
	if named.Refused != "" || len(named.Entries) != 2 || len(named.Excluded) != len(env.rows)-2 || named.Excluded[0].Reason != "plan_rejected:line_uuid" {
		t.Fatalf("a named revision: %+v", named)
	}
	live := preview(`{"subscription_id":"fleet-1","identity_id":"` + bindIdentityID + `"}`)
	if live.Refused != substoreBindRefusedSelectionMismatch || len(live.Entries) != 0 || live.FleetNodes != len(env.rows) {
		t.Fatalf("the live revision with a mismatched selection: %+v", live)
	}
	staged.CatalogueVersion = env.catalogueVersion
	if live := preview(`{"subscription_id":"fleet-1","identity_id":"` + bindIdentityID + `"}`); live.Refused != "" || len(live.Entries) != 2 {
		t.Fatalf("the live revision with a matching selection: %+v", live)
	}
}

// The probe rule (acceptance): a record that opts in excludes a line whose
// probe failed at least N times in a row, for every N from 1 to 10, from a
// synthetic probe history in the catalogue fixture; a record that does not
// opt in excludes nothing; a pass never excludes.
func TestBindProbeRuleExcludesAfterNConsecutiveFailures(t *testing.T) {
	e := bindFixture(t, 3, 4)
	// Line i failed i times in a row; the last line passed.
	history := func(c *lineCatalogue) {
		for i := range e.rows {
			row := &c.rows[c.index[e.rows[i].LineUUID]]
			row.Probe = &model.LineCatalogueProbe{Verdict: model.LineProbeVerdictFail, At: e.now, ConsecutiveFailures: i}
			if i == len(e.rows)-1 {
				row.Probe = &model.LineCatalogueProbe{Verdict: model.LineProbeVerdictPass, At: e.now}
			}
		}
	}
	plan := bindNodesPlan(t, e.rows)
	if result := e.bindRunInputs(t, plan, substoreBindInputs{selected: e.selection()}, history); len(result.Excluded) != 0 {
		t.Fatalf("without the opt-in: %v", result.reasons())
	}
	for n := 1; n <= model.MaxBindProbeConsecutiveFailures; n++ {
		plan.Policy = &model.BindPolicy{Probe: &model.ProbeExclusionPolicy{ConsecutiveFailures: n}}
		result := e.bindRunInputs(t, plan, substoreBindInputs{selected: e.selection()}, history)
		want := map[int]string{}
		for i := n; i < len(e.rows)-1; i++ {
			want[i] = substoreBindReasonProbeFailed
		}
		if got := result.reasons(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("N=%d: exclusions %v, want %v", n, got, want)
		}
		if len(result.nodes) != len(e.rows)-len(want) {
			t.Fatalf("N=%d: %d nodes", n, len(result.nodes))
		}
	}
	// probe_failed is operational: a document keeps the line's text inert.
	if !substoreBindOperationalReasons[substoreBindReasonProbeFailed] || !substoreBindOperationalReasons[substoreBindReasonUsageExceeded] {
		t.Fatal("the policy reasons must be operational")
	}
}

// A null probe block never excludes, whatever the threshold.
func TestBindProbeRuleNullNeverExcludes(t *testing.T) {
	e := bindFixture(t, 2, 2)
	plan := bindNodesPlan(t, e.rows)
	plan.Policy = &model.BindPolicy{Probe: &model.ProbeExclusionPolicy{ConsecutiveFailures: 1}}
	result := e.bindRunInputs(t, plan, substoreBindInputs{selected: e.selection()}, func(c *lineCatalogue) {
		for i := range c.rows {
			c.rows[i].Probe = nil
		}
	})
	if len(result.Excluded) != 0 || len(result.nodes) != len(e.rows) {
		t.Fatalf("a null probe excluded: %v", result.reasons())
	}
}

// The usage rule excludes a line on which the identity used strictly more
// than the threshold this period, and only when the record opts in.
func TestBindUsageRuleExcludesOverThreshold(t *testing.T) {
	e := bindFixture(t, 2, 2)
	const threshold = 10 << 30
	usage := map[string]int64{e.rows[0].LineHashID: threshold + 1, e.rows[1].LineHashID: threshold, e.rows[2].LineHashID: 1}
	plan := bindNodesPlan(t, e.rows)
	if result := e.bindRunInputs(t, plan, substoreBindInputs{selected: e.selection(), usage: usage}, nil); len(result.Excluded) != 0 {
		t.Fatalf("without the opt-in: %v", result.reasons())
	}
	plan.Policy = &model.BindPolicy{Usage: &model.UsageExclusionPolicy{MaxBytesPerLine: threshold}}
	result := e.bindRunInputs(t, plan, substoreBindInputs{selected: e.selection(), usage: usage}, nil)
	if got := result.reasons(); fmt.Sprint(got) != fmt.Sprint(map[int]string{0: substoreBindReasonUsageExceeded}) {
		t.Fatalf("exclusions %v", got)
	}
}

// The S0 acceptance exclusions hold under a plan that states its selection
// and a snapshot that states none: a line whose service is down is excluded
// with service_down.
func TestBindServiceDownExcluded(t *testing.T) {
	e := bindFixture(t, 1, 2)
	if _, _, err := e.st.UpsertSingBoxLiveness(store.SingBoxLiveness{NodeID: "node-000", State: serviceStateRunning, ReceivedAt: e.now}); err != nil {
		t.Fatal(err)
	}
	unbound := false
	editSingBoxLine(t, e.srv, "node-000", "vless-20000", func(n *model.SingBoxNode) { n.PortBound = &unbound })
	plan := bindNodesPlan(t, e.rows)
	plan.Selection = planSelection("lcv1-any", e.rows...)
	result := e.bindRunInputs(t, plan, substoreBindInputs{}, nil)
	if got := result.reasons(); fmt.Sprint(got) != fmt.Sprint(map[int]string{0: identityLineServiceDown}) || len(result.nodes) != 1 {
		t.Fatalf("exclusions %v, %d nodes", got, len(result.nodes))
	}
}

// A committed chain root whose path is drifted is excluded with
// graph_drifted under a plan that states its selection.
func TestBindGraphDriftedExcluded(t *testing.T) {
	e := bindFixture(t, 1, 2)
	plan := bindNodesPlan(t, e.rows)
	plan.Selection = planSelection("lcv1-any", e.rows...)
	result := e.bindRunInputs(t, plan, substoreBindInputs{}, func(c *lineCatalogue) {
		c.rows[c.index[e.rows[1].LineUUID]].Chain = model.LineCatalogueChain{Role: model.LineChainRoleEntry, Root: true, PathState: model.LinePathDrifted}
	})
	if got := result.reasons(); fmt.Sprint(got) != fmt.Sprint(map[int]string{1: substoreBindReasonGraphDrifted}) || len(result.nodes) != 1 {
		t.Fatalf("exclusions %v, %d nodes", got, len(result.nodes))
	}
}

// A line behind NAT (its template host is its provider edge) may be dialled
// at the edge, at the edge's own addresses and at a verified name whose
// Target is the edge, and not at the node's own public addresses or an A
// record name, which point at the provider's shared egress.
func TestBindNATLineAdmitsEdgeAndCNAMEOnly(t *testing.T) {
	const edge = "edge.provider.example"
	nat := store.LineClientTemplate{Host: edge, Port: 443}
	row := model.LineCatalogueRow{ProviderEdge: edge, Addresses: []string{"203.0.114.7", "46.1.2.3"},
		DDNSNames: []model.LineCatalogueDDNSName{
			{Name: "a-record.ddns.example", Verified: true},
			{Name: "cname.ddns.example", Verified: true, Target: edge},
			{Name: "other-cname.ddns.example", Verified: true, Target: "elsewhere.example"},
			{Name: "stale-cname.ddns.example", Target: edge},
		}}
	edgeAddrs := []string{"46.1.2.3"}
	for server, want := range map[string]bool{
		edge: true, "EDGE.provider.example": true, "46.1.2.3": true, "cname.ddns.example": true,
		"203.0.114.7": false, "a-record.ddns.example": false, "other-cname.ddns.example": false, "stale-cname.ddns.example": false,
	} {
		if got := substoreBindServerAllowed(server, nat, row, edgeAddrs); got != want {
			t.Errorf("NAT server %q allowed = %v, want %v", server, got, want)
		}
	}
	// The same row with a template that dials the node directly keeps the
	// full set: the flat addresses and every verified name.
	direct := store.LineClientTemplate{Host: "203.0.114.7", Port: 443}
	for _, server := range []string{"203.0.114.7", "46.1.2.3", "a-record.ddns.example", "cname.ddns.example", edge} {
		if !substoreBindServerAllowed(server, direct, row, nil) {
			t.Errorf("direct server %q refused", server)
		}
	}

	// Through the binder: the edge's addresses come from the names the
	// catalogue resolved, and a plan node at the node's own address is
	// refused.
	e := bindFixture(t, 1, 1)
	nodeIP := e.rows[0].Template.Host
	natRow := func(c *lineCatalogue) {
		i := c.index[e.rows[0].LineUUID]
		c.rows[i].ProviderEdge = edge
		c.rows[i].Addresses = []string{"46.1.2.3", nodeIP}
		c.rows[i].Template.Host = edge
		t := *c.templates[i]
		t.Host = edge
		c.templates[i] = &t
	}
	names := map[string][]string{edge: {"46.1.2.3"}}
	for server, want := range map[string]string{edge: "", "46.1.2.3": "", nodeIP: "plan_rejected:server"} {
		row := e.rows[0]
		node := bindNode(t, row, bindPlaceholder(t, row.LineUUID, "uuid"), map[string]any{"server": server})
		plan := model.SelectionPlan{Kind: model.SelectionPlanKindNodes, Nodes: []model.SelectionPlanNode{node}}
		result := e.bindRunInputs(t, plan, substoreBindInputs{selected: e.selection(), names: names}, natRow)
		if got := result.reasons()[0]; got != want {
			t.Errorf("NAT line dialled at %s: reason %q, want %q", server, got, want)
		}
	}
}

// substoreBindTestPolicy turns every S2 rule on.
func substoreBindTestPolicy(threshold int64) *model.BindPolicy {
	return &model.BindPolicy{Probe: &model.ProbeExclusionPolicy{ConsecutiveFailures: 2},
		Usage: &model.UsageExclusionPolicy{MaxBytesPerLine: threshold}, DDNSDial: true}
}

// The digest covers each policy input: a probe flip, a usage crossing and a
// DDNS verification flip each change it when the policy names the rule, and
// none of them changes it when the policy does not.
func TestBindDigestCoversPolicyInputs(t *testing.T) {
	e := bindFixture(t, 1, 2)
	u, _ := e.srv.getVpnUser(bindIdentityID)
	const threshold = 1 << 20
	if err := e.st.UpsertDDNSProfile(model.DDNSProfile{ID: "d1", NodeID: "node-000", Domains: []string{"home.example.org"}}); err != nil {
		t.Fatal(err)
	}
	answers := map[string][]string{"home.example.org": {catalogueNodeIP(0)}}
	e.srv.substoreCatalogue.names.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		var out []net.IPAddr
		for _, a := range answers[host] {
			out = append(out, net.IPAddr{IP: net.ParseIP(a)})
		}
		if out == nil {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
	e.srv.refreshLineCatalogueNames(e.now)
	failures := 0
	e.srv.substoreCatalogue.bind.probe = func(lineUUID string) *model.LineCatalogueProbe {
		if lineUUID != e.rows[0].LineUUID {
			return nil
		}
		return &model.LineCatalogueProbe{Verdict: model.LineProbeVerdictFail, At: e.now, ConsecutiveFailures: failures}
	}
	usage := map[string]int64{e.rows[0].LineHashID: threshold}
	full := substoreBindTestPolicy(threshold)
	digest := func(policy *model.BindPolicy) string { return e.srv.substoreBindStateDigest(u, policy, usage) }
	type flip struct {
		name  string
		rule  *model.BindPolicy
		apply func()
		undo  func()
	}
	flips := []flip{
		{"probe", &model.BindPolicy{Probe: full.Probe}, func() { failures = 2 }, func() { failures = 0 }},
		{"usage", &model.BindPolicy{Usage: full.Usage}, func() { usage[e.rows[0].LineHashID] = threshold + 1 }, func() { usage[e.rows[0].LineHashID] = threshold }},
		{"ddns", &model.BindPolicy{DDNSDial: true}, func() {
			answers["home.example.org"] = []string{"46.9.9.9"}
			e.srv.refreshLineCatalogueNames(e.now)
		}, func() {
			answers["home.example.org"] = []string{catalogueNodeIP(0)}
			e.srv.refreshLineCatalogueNames(e.now)
		}},
	}
	for _, f := range flips {
		withRule, withAll, without := digest(f.rule), digest(full), digest(nil)
		f.apply()
		if digest(f.rule) == withRule {
			t.Errorf("%s: a flip did not move the digest under its rule", f.name)
		}
		if digest(full) == withAll {
			t.Errorf("%s: a flip did not move the digest under every rule", f.name)
		}
		if digest(nil) != without {
			t.Errorf("%s: a flip moved the digest with no policy", f.name)
		}
		for _, other := range flips {
			if other.name != f.name && digest(other.rule) != func() string { f.undo(); d := digest(other.rule); f.apply(); return d }() {
				t.Errorf("%s: a flip moved the digest under the %s rule alone", f.name, other.name)
			}
		}
		f.undo()
		if digest(f.rule) != withRule {
			t.Errorf("%s: undoing the flip did not restore the digest", f.name)
		}
	}
	if digest(nil) == digest(&model.BindPolicy{}) {
		t.Fatal("a known policy must key apart from no policy")
	}
}

// The usage input is the boolean used > threshold, so it moves exactly where
// the rule excludes: not between T-1 and T, and between T and T+1.
func TestBindDigestFlipsExactlyWhereUsageRuleDoes(t *testing.T) {
	e := bindFixture(t, 1, 1)
	u, _ := e.srv.getVpnUser(bindIdentityID)
	const threshold = 1000
	policy := &model.BindPolicy{Usage: &model.UsageExclusionPolicy{MaxBytesPerLine: threshold}}
	hash := e.rows[0].LineHashID
	digests := map[int64]string{}
	reasons := map[int64]string{}
	plan := bindNodesPlan(t, e.rows)
	plan.Policy = policy
	for _, used := range []int64{threshold - 1, threshold, threshold + 1} {
		usage := map[string]int64{hash: used}
		digests[used] = e.srv.substoreBindStateDigest(u, policy, usage)
		reasons[used] = e.bindRunInputs(t, plan, substoreBindInputs{selected: e.selection(), usage: usage}, nil).reasons()[0]
	}
	if digests[threshold-1] != digests[threshold] || digests[threshold] == digests[threshold+1] {
		t.Fatalf("digest steps T-1 %s T %s T+1 %s", digests[threshold-1], digests[threshold], digests[threshold+1])
	}
	if reasons[threshold-1] != "" || reasons[threshold] != "" || reasons[threshold+1] != substoreBindReasonUsageExceeded {
		t.Fatalf("rule steps %v", reasons)
	}
}

// bindKey is the cache-key fragment the serve path computes for sh-fleet.
func (env *bindShareEnv) bindKey(t *testing.T) string {
	t.Helper()
	share, _ := env.st.SubscriptionShare("sh-fleet")
	token, _, refusal := env.srv.substoreBindServeState(share, env.srv.now())
	if refusal != "" {
		t.Fatalf("serve state refused: %s", refusal)
	}
	return token
}

// Until a serve-path bind miss has filled the memo, the key carries no
// policy input; after it, it does; a restart empties the memo with the body
// cache, so the first request is a full miss again.
func TestBindDigestIgnoresPolicyUntilFirstMiss(t *testing.T) {
	env := bindShareFixture(t)
	const threshold = 1 << 20
	env.policy = &model.BindPolicy{Usage: &model.UsageExclusionPolicy{MaxBytesPerLine: threshold}}
	used := int64(0)
	env.srv.substoreCatalogue.bind.dayRows = func(userID string, from, to time.Time) []store.UsageDayUser {
		return []store.UsageDayUser{{UserID: userID, Day: store.UsageDay(to), ByLine: map[string]store.UsageDayUserLine{env.rows[0].LineHashID: {Uplink: used}}}}
	}
	before := env.bindKey(t)
	used = threshold + 1
	if env.bindKey(t) != before {
		t.Fatal("the key moved on a policy input before any miss filled the memo")
	}
	used = 0
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusOK {
		t.Fatalf("first fetch: %d", rec.Code)
	}
	if policy := env.srv.substoreBindPolicyFor(subStorePluginID, "fleet-1"); policy == nil || policy.Usage.MaxBytesPerLine != threshold {
		t.Fatalf("memo after the miss = %+v", policy)
	}
	filled := env.bindKey(t)
	if filled == before {
		t.Fatal("the memo's policy did not reach the key")
	}
	used = threshold + 1
	if env.bindKey(t) == filled {
		t.Fatal("a usage crossing did not move the key once the memo was filled")
	}
	// The crossing is a miss: the next fetch binds again and excludes the line.
	renders := env.renders.Load()
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusOK || env.renders.Load() != renders+1 ||
		len(env.lastConvert(t).Nodes) != len(env.rows)-1 {
		t.Fatalf("after the crossing: status %d, renders %d, nodes %d", rec.Code, env.renders.Load()-renders, len(env.lastConvert(t).Nodes))
	}
	// A restart: memo and body cache are both empty, and the key is the
	// policy-free one until the next miss.
	env.srv.substoreCatalogue.bind.memo = substoreBindPolicyMemo{}
	env.srv.subscriptionCache.InvalidateShare("sh-fleet")
	u, _ := env.srv.getVpnUser(bindIdentityID)
	if env.bindKey(t) != ";bind="+env.srv.substoreBindStateDigest(u, nil, nil) {
		t.Fatal("after a restart the key carries a policy no miss has stated")
	}
}

// A preview binds staged revisions, so it never writes the memo, whatever
// policy the previewed plan carries.
func TestBindPreviewLeavesPolicyMemoUnchanged(t *testing.T) {
	env := bindShareFixture(t)
	live := &model.BindPolicy{Usage: &model.UsageExclusionPolicy{MaxBytesPerLine: 1 << 30}}
	env.policy = live
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusOK {
		t.Fatalf("fetch: %d", rec.Code)
	}
	for _, staged := range []*model.BindPolicy{nil, {Probe: &model.ProbeExclusionPolicy{ConsecutiveFailures: 1}}} {
		env.srv.substoreCatalogue.bind.renderPlan = func(context.Context, substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
			plan := bindNodesPlan(t, env.rows)
			plan.Policy = staged
			return &plan, "rev-live", nil
		}
		if _, err := env.srv.substoreBindPreview(context.Background(), subStorePluginID, "fleet-1", "rev-staged", bindIdentityID); err != nil {
			t.Fatal(err)
		}
		if _, err := (substoreBindPlansPreviewer{env.srv}).PreviewBind(context.Background(), subStoreBindQuery{PluginID: subStorePluginID,
			SubscriptionID: "fleet-1", Revision: "rev-staged", IdentityIDs: []string{bindIdentityID}}); err != nil {
			t.Fatal(err)
		}
		if got := env.srv.substoreBindPolicyFor(subStorePluginID, "fleet-1"); !reflect.DeepEqual(got, live) {
			t.Fatalf("a preview of a plan with policy %+v left the memo at %+v", staged, got)
		}
	}
}

// A memo write carries the epoch its render read and the generation read
// before its bind; a plan apply in between drops it, and an apply also voids
// an entry written before it. Entries are never evicted.
func TestPolicyMemoDropsWriteAcrossApply(t *testing.T) {
	env := bindShareFixture(t)
	s := env.srv
	s.pluginRPC.SetOwnerActive(func(string) bool { return true })
	s.subStoreSvc.applyRevision = func(_ context.Context, req subStoreApplyRevisionRequest) (subStoreApplyRevisionReply, error) {
		return subStoreApplyRevisionReply{SubscriptionID: req.SubscriptionID, Revision: req.Revision}, nil
	}
	share, _ := env.st.SubscriptionShare("sh-fleet")
	snap, _ := env.st.SubscriptionSnapshot(subStorePluginID, "fleet-1")
	epoch, current := s.subscriptionSnapshotEpoch(subStorePluginID, "fleet-1", snap)
	if !current {
		t.Fatal("the fixture's snapshot is not current")
	}
	old := &model.BindPolicy{Usage: &model.UsageExclusionPolicy{MaxBytesPerLine: 1}}
	plan := bindNodesPlan(t, env.rows)
	plan.Policy = old
	apply := func() {
		t.Helper()
		if _, err := s.subStorePlanApply(context.Background(), subStoreApplyRevisionRequest{SubscriptionID: "fleet-1", Revision: "rev-2", ExpectedRevision: "rev-1"}); err != nil {
			t.Fatal(err)
		}
	}
	// A render that read its epoch before the apply binds after it: its
	// policy is not written.
	apply()
	if _, err := s.substoreBindRendered(context.Background(), share, "plain", shareRenderVariant{}, snap, renderedSubscription{Plan: &plan, SourceEpoch: epoch}); err != nil {
		t.Fatal(err)
	}
	if got := s.substoreBindPolicyFor(subStorePluginID, "fleet-1"); got != nil {
		t.Fatalf("a write from before the apply landed: %+v", got)
	}
	// A write at the current epoch lands, and the next apply voids it.
	key := subscriptionRefreshKey{pluginID: subStorePluginID, subscriptionID: "fleet-1"}
	publication := s.subscriptionPublicationStateFor(key)
	publication.mu.Lock()
	epoch = publication.epoch
	publication.mu.Unlock()
	generation := s.substoreBindPluginGeneration(subStorePluginID)
	s.substoreBindRememberPolicy(subStorePluginID, "fleet-1", epoch, generation, old)
	if got := s.substoreBindPolicyFor(subStorePluginID, "fleet-1"); !reflect.DeepEqual(got, old) {
		t.Fatalf("a current write did not land: %+v", got)
	}
	apply()
	if got := s.substoreBindPolicyFor(subStorePluginID, "fleet-1"); got != nil {
		t.Fatalf("an apply left the old policy in the memo: %+v", got)
	}
	// A generation that moved since the bind read it drops the write too.
	publication.mu.Lock()
	epoch = publication.epoch
	publication.mu.Unlock()
	s.substoreBindRememberPolicy(subStorePluginID, "fleet-1", epoch, generation, old)
	if got := s.substoreBindPolicyFor(subStorePluginID, "fleet-1"); got != nil {
		t.Fatalf("a write with a stale generation landed: %+v", got)
	}
	// Never evicted: many records keep their entries.
	generation = s.substoreBindPluginGeneration(subStorePluginID)
	for i := 0; i < 500; i++ {
		record := fmt.Sprintf("record-%03d", i)
		s.substoreBindRememberPolicy(subStorePluginID, record, 0, generation, old)
	}
	for i := 0; i < 500; i++ {
		if s.substoreBindPolicyFor(subStorePluginID, fmt.Sprintf("record-%03d", i)) == nil {
			t.Fatalf("record %d lost its entry", i)
		}
	}
	// The memo holds a copy: changing the plan's policy after the write does
	// not change it.
	old.Usage.MaxBytesPerLine = 99
	if got := s.substoreBindPolicyFor(subStorePluginID, "record-000"); got.Usage.MaxBytesPerLine != 1 {
		t.Fatal("the memo shares the plan's policy")
	}
}

// An identity-bound share that receives a plan-less document answers the
// decoy, whatever the record and its snapshot say: a provider record, and a
// record whose snapshot is a catalogue document. A share that names no
// identity still receives the document.
func TestBindRefusesPlanlessDocumentForIdentityShare(t *testing.T) {
	env := bindShareFixture(t)
	if rec := env.get("/sub/plain-id/" + bindSharePlainIDTok); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "plain document") {
		t.Fatalf("an identity share on a document record: status %d body %q", rec.Code, rec.Body.String())
	}
	if got := env.shareRefusals("sh-plain-id"); len(got) != 1 || got[0] != substoreBindDenyLegacyDocument {
		t.Fatalf("refusals %v", got)
	}
	if rec := env.get("/sub/plain/" + bindSharePlainTok); rec.Code != http.StatusOK || rec.Body.String() != "plain document" {
		t.Fatalf("a share without an identity: status %d", rec.Code)
	}
	share, _ := env.st.SubscriptionShare("sh-fleet")
	snap, _ := env.st.SubscriptionSnapshot(subStorePluginID, "fleet-1")
	_, err := env.srv.substoreBindRendered(context.Background(), share, "plain", shareRenderVariant{}, snap,
		renderedSubscription{Body: []byte("vless://owner-credential@node.example:443"), SourceVersion: env.catalogueVersion})
	var refusal substoreBindRefusal
	if !errors.As(err, &refusal) || refusal.reason != substoreBindDenyLegacyDocument {
		t.Fatalf("a document over a catalogue snapshot: %v", err)
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if len(env.converts) != 0 {
		t.Fatal("a plan-less document reached convert")
	}
}

// substoreBindCountRows routes the bind step's day-row reads through a
// counter.
func substoreBindCountRows(s *Server) *atomic.Int64 {
	var reads atomic.Int64
	s.substoreCatalogue.bind.dayRows = func(userID string, from, to time.Time) []store.UsageDayUser {
		reads.Add(1)
		return s.usageDayUserRows(userID, from, to)
	}
	return &reads
}

// The serve path reads the identity's day rows once per request at key time,
// for the quota and the usage rule together, and once more on a miss for the
// bind: the usage rule adds no read. An identity with no quota pays a read
// only once the memo names a usage rule.
func TestServePathReadsUsageRowsOnce(t *testing.T) {
	env := bindShareFixture(t)
	reads := substoreBindCountRows(env.srv)
	share, _ := env.st.SubscriptionShare("sh-fleet")
	if _, _, refusal := env.srv.substoreBindServeState(share, env.now); refusal != "" || reads.Load() != 0 {
		t.Fatalf("no quota, no usage rule: refusal %q, %d reads", refusal, reads.Load())
	}
	u, _ := env.srv.getVpnUser(bindIdentityID)
	u.QuotaBytes, u.QuotaPeriod, u.QuotaResetDay = 100<<30, vpnQuotaPeriodMonthly, 1
	if err := env.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	env.policy = &model.BindPolicy{Usage: &model.UsageExclusionPolicy{MaxBytesPerLine: 1 << 30}}
	count := func(name string, want int64) {
		t.Helper()
		reads.Store(0)
		if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
		if got := reads.Load(); got != want {
			t.Fatalf("%s: %d day-row reads, want %d", name, got, want)
		}
	}
	count("the first miss", 2)                  // key time (quota) and bind (quota and usage)
	count("the miss the memo's policy keys", 2) // the key now carries the usage inputs
	count("a hit", 1)                           // key time only: quota and usage from one read
	count("another hit", 1)

	// No quota and a usage rule in the memo: one read at key time.
	u.QuotaBytes = 0
	if err := env.srv.putVpnUser(u); err != nil {
		t.Fatal(err)
	}
	reads.Store(0)
	if _, _, refusal := env.srv.substoreBindServeState(share, env.now); refusal != "" || reads.Load() != 1 {
		t.Fatalf("no quota with a usage rule: refusal %q, %d reads", refusal, reads.Load())
	}
}

// substoreBindIdentityState decides the identity's policy exactly as
// vpnUserPolicyAt does and sums its per-line usage exactly as the catalogue
// does, for every quota shape.
func TestBindIdentityStateMatchesPolicyAndCatalogueUsage(t *testing.T) {
	e := bindFixture(t, 1, 2)
	reads := substoreBindCountRows(e.srv)
	base, _ := e.srv.getVpnUser(bindIdentityID)
	if err := e.st.ApplyProxyUsage(store.ProxyUsageUpdate{DayUsers: []store.UsageDayUser{
		{UserID: base.ID, Day: store.UsageDay(e.now), Uplink: 300, Downlink: 200, Proof: 100,
			ByLine: map[string]store.UsageDayUserLine{e.rows[0].LineHashID: {Uplink: 300, Downlink: 200}}},
		{UserID: base.ID, Day: store.UsageDay(e.now.AddDate(0, -2, 0)), Uplink: 7000,
			ByLine: map[string]store.UsageDayUserLine{e.rows[1].LineHashID: {Uplink: 7000}}},
	}}); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*VpnUser){
		"no quota":                func(*VpnUser) {},
		"monthly quota":           func(u *VpnUser) { u.QuotaBytes, u.QuotaPeriod, u.QuotaResetDay = 1<<30, vpnQuotaPeriodMonthly, 5 },
		"monthly quota exhausted": func(u *VpnUser) { u.QuotaBytes, u.QuotaPeriod, u.QuotaResetDay = 100, vpnQuotaPeriodMonthly, 1 },
		"lifetime quota":          func(u *VpnUser) { u.QuotaBytes = 1 << 30 },
		"lifetime quota exhausted": func(u *VpnUser) {
			u.QuotaBytes = 10
		},
	} {
		u := base
		edit(&u)
		if u.QuotaBytes > 0 && u.QuotaPeriod != vpnQuotaPeriodMonthly && u.QuotaBytes <= 10 {
			if err := e.st.ApplyProxyUsage(store.ProxyUsageUpdate{Users: []model.ProxyUser{{ID: u.ID, UsedBytes: 7500}}}); err != nil {
				t.Fatal(err)
			}
		}
		want := e.srv.vpnUserPolicyAt(u, e.now)
		wantUsage, _, _ := e.srv.lineCatalogueIdentityUsage(u, e.now)
		for _, wantRule := range []bool{false, true} {
			reads.Store(0)
			got, usage := e.srv.substoreBindIdentityState(u, e.now, wantRule)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s (usage rule %v): policy %+v, want %+v", name, wantRule, got, want)
			}
			if wantRule && !maps.Equal(usage, wantUsage) {
				t.Fatalf("%s: usage %v, want %v", name, usage, wantUsage)
			}
			if !wantRule && usage != nil {
				t.Fatalf("%s: usage read without the rule", name)
			}
			if reads.Load() > 1 {
				t.Fatalf("%s (usage rule %v): %d reads", name, wantRule, reads.Load())
			}
		}
	}
}

// The digest a poll computes reads nothing outside the identity's day rows
// and the in-memory read model: no DNS query, no fetch, no render, no
// convert, however many rules the memo names.
func TestServePathDigestCostIsBounded(t *testing.T) {
	env := bindShareFixture(t)
	s := env.srv
	reads := substoreBindCountRows(s)
	var lookups, fetches, probes atomic.Int64
	s.substoreCatalogue.names.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		lookups.Add(1)
		return nil, errors.New("no such host")
	}
	fetch := s.subscriptionFetch
	s.subscriptionFetch = func(ctx context.Context, pluginID, record string) (model.SubscriptionSnapshot, error) {
		fetches.Add(1)
		return fetch(ctx, pluginID, record)
	}
	s.substoreCatalogue.bind.probe = func(string) *model.LineCatalogueProbe {
		probes.Add(1)
		return nil
	}
	if err := env.st.UpsertDDNSProfile(model.DDNSProfile{ID: "d1", NodeID: "node-000", Domains: []string{"home.example.org"}, RecordType: "cname", CNAMETarget: "edge.example"}); err != nil {
		t.Fatal(err)
	}
	env.policy = substoreBindTestPolicy(1 << 30)
	if rec := env.get("/sub/fleet/" + bindShareToken); rec.Code != http.StatusOK {
		t.Fatalf("fetch: %d", rec.Code)
	}
	if s.substoreBindPolicyFor(subStorePluginID, "fleet-1") == nil {
		t.Fatal("the memo was not filled")
	}
	renders := env.renders.Load()
	env.mu.Lock()
	converts := len(env.converts)
	env.mu.Unlock()
	reads.Store(0)
	lookups.Store(0)
	fetches.Store(0)
	probes.Store(0)
	share, _ := env.st.SubscriptionShare("sh-fleet")
	for i := 0; i < 5; i++ {
		if _, _, refusal := s.substoreBindServeState(share, env.now); refusal != "" {
			t.Fatal(refusal)
		}
	}
	env.mu.Lock()
	defer env.mu.Unlock()
	if reads.Load() != 5 || lookups.Load() != 0 || fetches.Load() != 0 || env.renders.Load() != renders || len(env.converts) != converts ||
		probes.Load() != int64(5*len(env.rows)) {
		t.Fatalf("five polls: %d day-row reads, %d lookups, %d fetches, %d renders, %d converts, %d probe reads",
			reads.Load(), lookups.Load(), fetches.Load(), env.renders.Load()-renders, len(env.converts)-converts, probes.Load())
	}
}

// A staged preview of a record whose snapshot cannot be refreshed renders
// over an empty raw instead of failing; the live revision, named or not,
// still fails without a snapshot.
func TestBindPreviewOfNamedRevisionWithoutSnapshotRenders(t *testing.T) {
	env := bindShareFixture(t)
	s := env.srv
	if err := env.st.DeleteSubscriptionSnapshot(subStorePluginID, "fleet-1"); err != nil {
		t.Fatal(err)
	}
	s.subscriptionFetch = func(context.Context, string, string) (model.SubscriptionSnapshot, error) {
		return model.SubscriptionSnapshot{}, errors.New("provider down")
	}
	var raws []string
	s.substoreCatalogue.bind.renderPlan = func(_ context.Context, q substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
		raws = append(raws, q.Snapshot.Raw)
		plan := bindNodesPlan(t, env.rows)
		plan.Selection = planSelection("lcv1-staged", env.rows...)
		return &plan, "rev-live", nil
	}
	reply, err := s.substoreBindPreview(context.Background(), subStorePluginID, "fleet-1", "rev-staged", bindIdentityID)
	if err != nil {
		t.Fatalf("a staged preview without a snapshot: %v", err)
	}
	if len(raws) != 1 || raws[0] != "" || reply.Refused != "" || len(reply.Entries) != len(env.rows) || reply.LiveRevision != "rev-live" {
		t.Fatalf("raws %q, reply %+v", raws, reply)
	}
	// Member revisions make a render staged even at the live revision.
	if _, err := (substoreBindPlansPreviewer{s}).PreviewBind(context.Background(), subStoreBindQuery{PluginID: subStorePluginID, SubscriptionID: "fleet-1",
		Revision: "rev-live", MemberRevisions: map[string]string{"member": "staged-1"}, IdentityIDs: []string{bindIdentityID}}); err != nil {
		t.Fatalf("a collection preview over a staged member: %v", err)
	}
	for _, revision := range []string{"", "rev-live"} {
		if _, err := s.substoreBindPreview(context.Background(), subStorePluginID, "fleet-1", revision, bindIdentityID); err == nil {
			t.Fatalf("a live preview (revision %q) without a snapshot succeeded", revision)
		}
	}
}

// A plan apply leaves the record without a snapshot (the apply drops what it
// promoted), and the next propose runs at once, before any client poll: the
// preview refreshes the snapshot instead of failing on its absence.
func TestProposeRunsImmediatelyAfterApply(t *testing.T) {
	env := bindShareFixture(t)
	s := env.srv
	s.pluginRPC.SetOwnerActive(func(string) bool { return true })
	live := "rev-1"
	var fetches atomic.Int64
	fetch := s.subscriptionFetch
	s.subscriptionFetch = func(ctx context.Context, pluginID, record string) (model.SubscriptionSnapshot, error) {
		fetches.Add(1)
		return fetch(ctx, pluginID, record)
	}
	var raws []string
	s.substoreCatalogue.bind.renderPlan = func(_ context.Context, q substoreBindRenderQuery) (*model.SelectionPlan, string, error) {
		raws = append(raws, q.Snapshot.Raw)
		rows := env.rows
		if q.Revision != live {
			rows = rows[:len(rows)-1]
		}
		plan := bindNodesPlan(t, rows)
		return &plan, live, nil
	}
	s.subStoreSvc.applyRevision = func(_ context.Context, req subStoreApplyRevisionRequest) (subStoreApplyRevisionReply, error) {
		live = req.Revision
		// The apply drops the promoted record's snapshot.
		if err := env.st.DeleteSubscriptionSnapshot(subStorePluginID, req.SubscriptionID); err != nil {
			return subStoreApplyRevisionReply{}, err
		}
		return subStoreApplyRevisionReply{SubscriptionID: req.SubscriptionID, Revision: req.Revision}, nil
	}
	propose := func(from, to string) subStorePlansProposeReply {
		t.Helper()
		ctx := context.WithValue(context.Background(), pluginOperatorPrincipalKey{}, subStoreSvcAdmin)
		out, err := s.callCoreServiceForOperator(ctx, subStorePlansService, "propose",
			[]byte(`{"subscription_id":"fleet-1","from_revision":"`+from+`","to_revision":"`+to+`"}`))
		if err != nil {
			t.Fatalf("propose %s to %s: %v %s", from, to, err, subStoreSvcErrBody(err))
		}
		var reply subStorePlansProposeReply
		if err := json.Unmarshal(out, &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	first := propose("rev-1", "rev-2")
	if !first.Required || first.ApprovalID == "" {
		t.Fatalf("first propose: %+v", first)
	}
	body, _ := json.Marshal(map[string]any{"approval_id": first.ApprovalID, "plan_sha256": first.PlanSHA256, "queue_apply": true})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/network/approvals/approve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	s.handleApprove(rec, req, subStorePlanApprover)
	if rec.Code != http.StatusOK || live != "rev-2" {
		t.Fatalf("approve: %d %s, live %s", rec.Code, rec.Body.String(), live)
	}
	if _, ok := env.st.SubscriptionSnapshot(subStorePluginID, "fleet-1"); ok {
		t.Fatal("the apply left the snapshot")
	}
	fetches.Store(0)
	raws = nil
	second := propose("rev-2", "rev-3")
	if !second.Required || second.ApprovalID == "" {
		t.Fatalf("the propose right after the apply: %+v", second)
	}
	if fetches.Load() == 0 || len(raws) != 2 || raws[0] == "" || raws[1] == "" {
		t.Fatalf("the propose did not refresh the snapshot: %d fetches, raws %q", fetches.Load(), raws)
	}
}

// BenchmarkSubstoreBindPlan1000 binds a 1000-node plan that states its
// selection and turns every policy rule on, against a fresh 1000-line
// catalogue build: the core's share of a fleet-bound cache miss (target
// under 50 ms, design 28 S2 section 5).
func BenchmarkSubstoreBindPlan1000(b *testing.B) {
	e := bindFixture(b, 100, 10)
	plan := bindNodesPlan(b, e.rows)
	plan.Selection = planSelection("lcv1-bench", e.rows...)
	plan.Policy = substoreBindTestPolicy(1 << 40)
	raw, err := model.EncodeSelectionPlan(plan)
	if err != nil {
		b.Fatal(err)
	}
	if plan, err = model.DecodeSelectionPlan(raw); err != nil {
		b.Fatal(err)
	}
	u, _ := e.srv.getVpnUser(bindIdentityID)
	usage := map[string]int64{}
	for _, row := range e.rows {
		usage[row.LineHashID] = 1 << 30
	}
	names := e.srv.substoreCatalogue.names.snapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		catalogue, err := e.srv.buildLineCatalogue("")
		if err != nil {
			b.Fatal(err)
		}
		if result := substoreBindPlan(plan, u, catalogue, substoreBindInputs{usage: usage, names: names}); len(result.nodes) != len(e.rows) {
			b.Fatalf("%d of %d nodes bound", len(result.nodes), len(e.rows))
		}
	}
}

// bindRenderRunner is a Sub-Store runtime whose render answers a fixed plan
// and records every request payload.
type bindRenderRunner struct {
	mu       sync.Mutex
	payloads []json.RawMessage
	reply    json.RawMessage
}

func (r *bindRenderRunner) Name() string { return "bind-render" }
func (r *bindRenderRunner) Start(context.Context, plugin.RunnerStartRequest) (plugin.RunnerStartResult, error) {
	return plugin.RunnerStartResult{}, nil
}
func (r *bindRenderRunner) Stop(context.Context, plugin.RunnerStopRequest) error { return nil }
func (r *bindRenderRunner) Invoke(_ context.Context, req plugin.InvokeRequest) (plugin.InvokeResponse, error) {
	var call struct {
		Payload json.RawMessage `json:"payload"`
	}
	_ = json.Unmarshal(req.Payload, &call)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.payloads = append(r.payloads, call.Payload)
	return plugin.InvokeResponse{OK: true, Result: r.reply}, nil
}

// The bind step's render names the revision and, for a collection, the
// member revisions to the plugin, and reads the live revision back.
func TestBindPreviewForwardsMemberRevisions(t *testing.T) {
	env := bindShareFixture(t)
	s := env.srv
	plan := bindNodesPlan(t, env.rows)
	encoded, err := model.EncodeSelectionPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	runner := &bindRenderRunner{reply: json.RawMessage(`{"content":"","plan":` + string(encoded) + `,"live_revision":"rev-live"}`)}
	s.pluginRuntime = plugin.NewRuntimeManagerWithOptions(plugin.RuntimeManagerOptions{
		Services: s.pluginHostServices(), Runners: map[string]plugin.Runner{plugin.TypeSystem: runner},
	})
	if _, err := s.pluginRuntime.Start(context.Background(), plugin.Loaded{
		Manifest:     plugin.Manifest{ID: subStorePluginID, Name: "Sub-Store", Type: plugin.TypeSystem, Capabilities: []string{"kv:read"}},
		Capabilities: []string{"kv:read"}, BundlePath: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	snap, _ := env.st.SubscriptionSnapshot(subStorePluginID, "fleet-1")
	got, live, err := s.substoreBindRenderPlan(context.Background(), substoreBindRenderQuery{PluginID: subStorePluginID, SubscriptionID: "fleet-1",
		Revision: "rev-staged", MemberRevisions: map[string]string{"hk": "staged-1", "gone": ""}, Snapshot: snap})
	if err != nil || got == nil || live != "rev-live" || len(got.Nodes) != len(env.rows) {
		t.Fatalf("render: plan %v, live %q, err %v", got != nil, live, err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.payloads) != 1 {
		t.Fatalf("%d renders", len(runner.payloads))
	}
	var req struct {
		SubscriptionID  string            `json:"subscription_id"`
		Revision        string            `json:"revision"`
		MemberRevisions map[string]string `json:"member_revisions"`
		Raw             string            `json:"raw"`
	}
	if err := json.Unmarshal(runner.payloads[0], &req); err != nil {
		t.Fatal(err)
	}
	if req.SubscriptionID != "fleet-1" || req.Revision != "rev-staged" || req.Raw != snap.Raw ||
		!maps.Equal(req.MemberRevisions, map[string]string{"hk": "staged-1", "gone": ""}) {
		t.Fatalf("render request %+v", req)
	}
	// A render with nothing named sends neither field.
	runner.payloads = nil
	runner.mu.Unlock()
	_, _, err = s.substoreBindRenderPlan(context.Background(), substoreBindRenderQuery{PluginID: subStorePluginID, SubscriptionID: "fleet-1", Snapshot: snap})
	runner.mu.Lock()
	if err != nil || len(runner.payloads) != 1 || strings.Contains(string(runner.payloads[0]), "revision") {
		t.Fatalf("a live render: %v %s", err, runner.payloads)
	}
}
