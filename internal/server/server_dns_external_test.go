package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// seedNodeListeners stores a reality snapshot whose listener set is exactly the
// one given, so an external DNS record can be checked against it.
func seedNodeListeners(t *testing.T, st *store.Store, nodeID string, listeners []model.GuardListener) {
	t.Helper()
	now := time.Now().UTC()
	node, ok := st.Node(nodeID)
	if !ok {
		t.Fatalf("seed listeners: missing node %s", nodeID)
	}
	if _, _, err := st.UpsertGuardRealitySnapshot(node.LatticeIdentityUUID, store.GuardRealitySnapshot{
		Reality: model.GuardNodeReality{
			NodeID:      nodeID,
			Listeners:   listeners,
			CollectedAt: now,
		},
		ReceivedAt: now,
	}); err != nil {
		t.Fatalf("seed listeners: %v", err)
	}
}

func dnsproxyListeners() []model.GuardListener {
	return []model.GuardListener{
		{Protocol: "tcp", Port: 22, Address: "0.0.0.0", Process: "sshd"},
		{Protocol: "tcp", Port: 53, Address: "0.0.0.0", Process: "dnsproxy"},
		{Protocol: "udp", Port: 53, Address: "0.0.0.0", Process: "dnsproxy"},
		{Protocol: "tcp", Port: 2053, Address: "0.0.0.0", Process: "dnsproxy"},
		{Protocol: "udp", Port: 2053, Address: "0.0.0.0", Process: "dnsproxy"},
		{Protocol: "tcp", Port: 8443, Address: "0.0.0.0", Process: "dnsproxy"},
	}
}

const externalDNSBody = `{
	"name":"operator dnsproxy",
	"node_id":"n1",
	"engine":"external",
	"hostname":"dns.roobli.org",
	"exposure":"public",
	"cert_not_after":"2026-11-17T00:00:00Z",
	"listeners":[
		{"protocol":"udp","port":53},
		{"protocol":"tcp","port":53},
		{"protocol":"udp","port":2053},
		{"protocol":"tcp","port":2053},
		{"protocol":"tcp","port":8443}
	]
}`

type externalDNSView struct {
	ID            string              `json:"id"`
	Engine        string              `json:"engine"`
	Status        string              `json:"status"`
	Hostname      string              `json:"hostname"`
	ListenPort    int                 `json:"listen_port"`
	EnableTCP     bool                `json:"enable_tcp"`
	EnableUDP     bool                `json:"enable_udp"`
	Zones         []model.DNSZone     `json:"zones"`
	Listeners     []model.DNSListener `json:"listeners"`
	CertNotAfter  time.Time           `json:"cert_not_after"`
	PublishIPv4   bool                `json:"publish_ipv4"`
	HasCredential bool                `json:"has_credential"`
	Drift         *dnsDriftView       `json:"drift"`
}

func createExternalDNS(t *testing.T, handler http.Handler, cookies []*http.Cookie, csrf string) externalDNSView {
	t.Helper()
	res := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", externalDNSBody, cookies, csrf)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create external deployment failed: %d", res.StatusCode)
	}
	var out externalDNSView
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExternalDNSDeploymentIsObservedOnly(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	seedNodeListeners(t, st, "n1", dnsproxyListeners())

	view := createExternalDNS(t, handler, cookies, csrf)
	if view.Engine != model.DNSEngineExternal {
		t.Fatalf("engine = %q, want external", view.Engine)
	}
	if view.Status != model.DNSStatusObserved {
		t.Fatalf("status = %q, want observed", view.Status)
	}
	if len(view.Zones) != 0 {
		t.Fatalf("an observed engine serves zones Lattice does not know: %+v", view.Zones)
	}
	if view.PublishIPv4 || view.HasCredential {
		t.Fatalf("an observed engine must never publish a record: %+v", view)
	}
	if !view.EnableTCP || !view.EnableUDP {
		t.Fatalf("protocol flags should follow the listener set: %+v", view)
	}
	if view.ListenPort != 53 {
		t.Fatalf("listen_port = %d, want the lowest recorded listener (53)", view.ListenPort)
	}
	if !view.CertNotAfter.Equal(time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("cert_not_after = %s, want the operator's value", view.CertNotAfter)
	}
	want := []model.DNSListener{
		{Protocol: "tcp", Port: 53, Process: "dnsproxy"},
		{Protocol: "udp", Port: 53, Process: "dnsproxy"},
		{Protocol: "tcp", Port: 2053, Process: "dnsproxy"},
		{Protocol: "udp", Port: 2053, Process: "dnsproxy"},
		{Protocol: "tcp", Port: 8443, Process: "dnsproxy"},
	}
	if len(view.Listeners) != len(want) {
		t.Fatalf("listeners = %+v, want %+v", view.Listeners, want)
	}
	for i, l := range want {
		if view.Listeners[i] != l {
			t.Fatalf("listener %d = %+v, want %+v", i, view.Listeners[i], l)
		}
	}
	if view.Drift == nil || view.Drift.Status != dnsDriftOK {
		t.Fatalf("a record matching reality should read ok: %+v", view.Drift)
	}
	if len(view.Drift.Findings) != 0 {
		t.Fatalf("no findings expected: %+v", view.Drift.Findings)
	}

	// Nothing is ever rendered or applied for it.
	plan := doJSON(t, handler, http.MethodPost, "/api/dns/plan", `{"id":"`+view.ID+`"}`, cookies, csrf)
	defer plan.Body.Close()
	if plan.StatusCode != http.StatusBadRequest {
		t.Fatalf("plan status = %d, want 400", plan.StatusCode)
	}
	planBody := new(strings.Builder)
	if _, err := io.Copy(planBody, plan.Body); err != nil {
		t.Fatal(err)
	}
	// The refusal must say why, not fall through to the renderer's generic
	// "unsupported engine": the operator asked for a record Lattice observes.
	if !strings.Contains(planBody.String(), "observed only") {
		t.Fatalf("plan refusal should name the reason: %s", planBody.String())
	}
	if len(st.Approvals()) != 0 {
		t.Fatalf("a refused plan must file no approval: %+v", st.Approvals())
	}
	publish := doJSON(t, handler, http.MethodPost, "/api/dns/publish", `{"id":"`+view.ID+`"}`, cookies, csrf)
	defer publish.Body.Close()
	if publish.StatusCode != http.StatusBadRequest {
		t.Fatalf("publish status = %d, want 400", publish.StatusCode)
	}
}

func TestExternalDNSDeploymentDriftNamesAMissingListener(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	seedNodeListeners(t, st, "n1", dnsproxyListeners())
	view := createExternalDNS(t, handler, cookies, csrf)

	// The DoH listener goes away and something else takes tcp/2053.
	next := []model.GuardListener{
		{Protocol: "tcp", Port: 53, Address: "0.0.0.0", Process: "dnsproxy"},
		{Protocol: "udp", Port: 53, Address: "0.0.0.0", Process: "dnsproxy"},
		{Protocol: "tcp", Port: 2053, Address: "0.0.0.0", Process: "nginx"},
		{Protocol: "udp", Port: 2053, Address: "0.0.0.0", Process: "dnsproxy"},
	}
	seedNodeListeners(t, st, "n1", next)

	list := doJSON(t, handler, http.MethodGet, "/api/dns/deployments", "", cookies, "")
	defer list.Body.Close()
	var out struct {
		Deployments []externalDNSView `json:"deployments"`
	}
	if err := json.NewDecoder(list.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Deployments) != 1 || out.Deployments[0].ID != view.ID {
		t.Fatalf("list did not return the external record: %+v", out.Deployments)
	}
	drift := out.Deployments[0].Drift
	if drift == nil || drift.Status != dnsDriftDrift {
		t.Fatalf("drift status = %+v, want drift", drift)
	}
	joined := strings.Join(drift.Findings, "\n")
	if !strings.Contains(joined, "tcp/8443 is not listening") {
		t.Fatalf("a missing listener should be a finding, got:\n%s", joined)
	}
	if !strings.Contains(joined, "owned by nginx") {
		t.Fatalf("a changed owner should be a finding, got:\n%s", joined)
	}
	if len(st.Approvals()) != 0 || len(st.Tasks()) != 0 {
		t.Fatalf("a drift finding must never become an action: approvals=%+v tasks=%+v", st.Approvals(), st.Tasks())
	}
}

func TestExternalDNSDeploymentRejectsPublishingIntent(t *testing.T) {
	_, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	seedNodeListeners(t, st, "n1", dnsproxyListeners())

	cases := map[string]string{
		"no listeners": `{"name":"x","node_id":"n1","engine":"external","hostname":"dns.roobli.org"}`,
		"no hostname":  `{"name":"x","node_id":"n1","engine":"external","listeners":[{"protocol":"tcp","port":53}]}`,
		"credential":   `{"name":"x","node_id":"n1","engine":"external","hostname":"dns.roobli.org","cf_api_token":"tok","listeners":[{"protocol":"tcp","port":53}]}`,
		"bad protocol": `{"name":"x","node_id":"n1","engine":"external","hostname":"dns.roobli.org","listeners":[{"protocol":"sctp","port":53}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			res := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", body, cookies, csrf)
			defer res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", res.StatusCode)
			}
		})
	}
	if len(st.DNSDeployments()) != 0 {
		t.Fatalf("no record should have been written: %+v", st.DNSDeployments())
	}
}

// A node whose IP moves must not drag the operator's own hostname with it.
func TestExternalDNSDeploymentIsNotRepublishedOnNodeIPChange(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	seedNodeListeners(t, st, "n1", dnsproxyListeners())
	created := createExternalDNS(t, handler, cookies, csrf)

	provider := &captureDNSProvider{ch: make(chan ddns.Record, 1)}
	srv.ddnsProvider = func(model.DDNSProfile) (ddns.Provider, error) { return provider, nil }
	srv.maybeTriggerDDNS("n1", "203.0.113.7", "", "203.0.113.8", "")
	select {
	case rec := <-provider.ch:
		t.Fatalf("an observed engine must never publish: %+v", rec)
	case <-time.After(150 * time.Millisecond):
	}
	stored, ok := st.DNSDeployment(created.ID)
	if !ok || !stored.LastPublishedAt.IsZero() || stored.LastIPv4 != "" || stored.LastPublishError != "" {
		t.Fatalf("record should carry no publish state, not even a failed attempt: %+v", stored)
	}
}
