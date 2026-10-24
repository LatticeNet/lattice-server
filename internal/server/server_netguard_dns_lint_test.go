package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/netguard"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// markDNSApplied records a deployment as its task result does when it
// applies: running, with an apply time.
func markDNSApplied(t *testing.T, st *store.Store, depID string) {
	t.Helper()
	dep, ok := st.DNSDeployment(depID)
	if !ok {
		t.Fatalf("deployment %s not found", depID)
	}
	dep.Status, dep.LastAppliedAt = model.DNSStatusRunning, time.Now().UTC()
	if err := st.UpsertDNSDeployment(dep); err != nil {
		t.Fatal(err)
	}
}

func netGuardPlanStatus(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf, nodeID string) (int, string, model.Approval) {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/netguard/plan", `{"node_id":"`+nodeID+`","accept_lockout_risk":true}`, cookies, csrf)
	body := readBody(t, res)
	var out struct {
		Approval model.Approval `json:"approval"`
	}
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, body, out.Approval
}

// KI-29 race 2: the DNS plan checks that NetGuard admits its listeners, and
// now NetGuard checks the DNS deployments back. A NetGuard plan that would
// close the ports of a deployment applied on the node is refused, naming the
// deployment and the two ways out, whatever lockout risk the operator
// accepts; the review shows the same finding; the approve checks again,
// since a deployment may apply after the plan; a disabled one does not count.
func TestNetGuardPlanRefusedWhileItClosesARunningDNSDeploymentsPorts(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	adoptNodeWithWebGroup(t, handler, st, cookies, csrf)
	depID := createDNSDeployment(t, handler, cookies, csrf)

	// Not applied yet: nothing listens, so nothing blocks.
	status, body, early := netGuardPlanStatus(t, handler, cookies, csrf, "n1")
	if status != http.StatusOK {
		t.Fatalf("netguard plan before the deployment applied = %d %s", status, body)
	}

	markDNSApplied(t, st, depID)
	approvals := len(st.Approvals())
	status, body, _ = netGuardPlanStatus(t, handler, cookies, csrf, "n1")
	for _, want := range []string{`self-host DNS deployment \"private dns\"`, "closes udp/53 and tcp/53 from the WireGuard range on tokyo-1",
		"open them in a security group on this node, or disable the deployment first"} {
		if status != http.StatusConflict || !strings.Contains(body, want) {
			t.Fatalf("netguard plan closing a running deployment's ports = %d %s, want 409 with %q", status, body, want)
		}
	}
	if len(st.Approvals()) != approvals {
		t.Fatal("a refused netguard plan recorded an approval")
	}

	review := doJSON(t, handler, http.MethodGet, "/api/netguard/review?node_id=n1", "", cookies, csrf)
	var reviewed netGuardReviewResponse
	if err := json.Unmarshal([]byte(readBody(t, review)), &reviewed); err != nil {
		t.Fatal(err)
	}
	if !hasFinding(reviewed.Review.Findings, netguard.FindingDNSListenerClosed) {
		t.Fatalf("the review must show what the plan refuses on: %+v", reviewed.Review.Findings)
	}

	// The plan made before the deployment applied is judged again.
	if status, body := approveStatus(t, handler, cookies, csrf, early); status != http.StatusConflict || !strings.Contains(body, `\"private dns\"`) {
		t.Fatalf("approving a plan that now closes a running deployment's ports = %d %s, want 409", status, body)
	}

	// Way out one: open the ports in a security group.
	openDNSPortsOnWebGroup(t, st)
	if status, body, _ := netGuardPlanStatus(t, handler, cookies, csrf, "n1"); status != http.StatusOK {
		t.Fatalf("netguard plan with the DNS ports open = %d %s", status, body)
	}

	// Way out two: disable the deployment.
	group, _ := st.SecurityGroup("sg-web")
	kept := group.Rules[:0]
	for _, rule := range group.Rules {
		if !strings.HasPrefix(rule.ID, "dns-") {
			kept = append(kept, rule)
		}
	}
	group.Rules = kept
	if _, err := st.UpsertSecurityGroup(group); err != nil {
		t.Fatal(err)
	}
	dep, _ := st.DNSDeployment(depID)
	dep.Disabled = true
	if err := st.UpsertDNSDeployment(dep); err != nil {
		t.Fatal(err)
	}
	if status, body, _ := netGuardPlanStatus(t, handler, cookies, csrf, "n1"); status != http.StatusOK {
		t.Fatalf("netguard plan with the deployment disabled = %d %s", status, body)
	}
}
