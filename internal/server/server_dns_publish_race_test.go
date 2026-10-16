package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/ddns"
)

const raceDeploymentBody = `"node_id":"n1","hostname":"race.dns.example.com","cf_api_token":"t","publish_ipv4":true,` +
	`"zones":[{"suffix":".","mode":"forward","upstreams":["1.1.1.1"]}]`

// startGatedPublish creates a deployment, then presses "Publish" on it with a
// provider that holds the write, and returns once the write is held. The
// returned channel yields the publish's status after release is closed.
func startGatedPublish(t *testing.T, srv *Server, handler http.Handler, cookies []*http.Cookie, csrf string) (string, chan struct{}, <-chan int) {
	t.Helper()
	fp := &fakeProvider{}
	srv.ddnsProvider = func(model.DDNSProfile) (ddns.Provider, error) { return fp, nil }
	entered, release := gateDDNSProvider(srv)
	res := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{"name":"race dns",`+raceDeploymentBody+`}`, cookies, csrf)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %v", res.StatusCode, err)
	}
	res.Body.Close()

	published := make(chan int, 1)
	go func() {
		res := doJSON(t, handler, http.MethodPost, "/api/dns/publish", `{"id":"`+created.ID+`"}`, cookies, csrf)
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		published <- res.StatusCode
	}()
	waitEntered(t, entered)
	return created.ID, release, published
}

// An edit saved while a publish waits on Cloudflare survives the publish. The
// publish used to write back the whole deployment it started from, so the
// edit was lost; now only the publish-status fields land, on the deployment
// as stored when it ends.
func TestDNSPublishKeepsAnEditSavedWhileItRan(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	id, release, published := startGatedPublish(t, srv, handler, cookies, csrf)

	edit := doJSON(t, handler, http.MethodPost, "/api/dns/deployments", `{"id":"`+id+`","name":"renamed","record_ttl":300,`+raceDeploymentBody+`}`, cookies, csrf)
	edit.Body.Close()
	if edit.StatusCode != http.StatusOK {
		t.Fatalf("edit during the publish: %d", edit.StatusCode)
	}
	close(release)
	if code := <-published; code != http.StatusOK {
		t.Fatalf("publish: %d", code)
	}

	got, ok := st.DNSDeployment(id)
	if !ok || got.Name != "renamed" || got.RecordTTL != 300 {
		t.Fatalf("the publish undid the edit: %+v", got)
	}
	if got.LastIPv4 != "203.0.113.7" || got.LastPublishError != "" || got.LastPublishedAt.IsZero() {
		t.Fatalf("the publish's own outcome: %+v", got)
	}
}

// A deployment deleted while a publish waits on Cloudflare stays deleted.
func TestDNSPublishDoesNotBringBackADeletedDeployment(t *testing.T) {
	srv, handler, st := newDNSServer(t)
	cookies, csrf := loginSession(t, handler)
	id, release, published := startGatedPublish(t, srv, handler, cookies, csrf)

	del := doJSON(t, handler, http.MethodPost, "/api/dns/deployments/delete", `{"id":"`+id+`"}`, cookies, csrf)
	del.Body.Close()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete during the publish: %d", del.StatusCode)
	}
	close(release)
	<-published

	if got, ok := st.DNSDeployment(id); ok {
		t.Fatalf("the publish brought the deleted deployment back: %+v", got)
	}
}
