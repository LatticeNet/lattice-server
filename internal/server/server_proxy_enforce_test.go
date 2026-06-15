package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestProxyConfigDriftDetectionAndClear(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "gmami-jp1"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)

	inbound := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", `{
		"id":"in1",
		"name":"VLESS Reality 443",
		"core":"sing-box",
		"protocol":"vless",
		"port":443,
		"security":"reality",
		"reality_private_key":"private-reality-key-0001",
		"reality_public_key":"public-reality-key-0001",
		"reality_short_ids":["aa"],
		"reality_dest":"www.microsoft.com:443",
		"enabled":true
	}`, cookies, csrf)
	defer inbound.Body.Close()
	if inbound.StatusCode != http.StatusOK {
		t.Fatalf("create inbound: %d", inbound.StatusCode)
	}
	for _, uid := range []string{"alice", "bob"} {
		u := doJSON(t, handler, http.MethodPost, "/api/proxy/users",
			`{"id":"`+uid+`","name":"`+uid+`","inbound_ids":["in1"],"enabled":true}`, cookies, csrf)
		if u.StatusCode != http.StatusOK {
			t.Fatalf("create user %s: %d", uid, u.StatusCode)
		}
		u.Body.Close()
	}
	prof := doJSON(t, handler, http.MethodPost, "/api/proxy/profiles",
		`{"node_id":"node-a","inbound_ids":["in1"],"hostname":"gmami-jp1.example.com"}`, cookies, csrf)
	if prof.StatusCode != http.StatusOK {
		t.Fatalf("create profile: %d", prof.StatusCode)
	}
	prof.Body.Close()

	// Simulate a successful apply: pin AppliedSHA256 to the current render.
	_, _, artifact, err := srv.renderProxyCoreArtifact("node-a")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	profile, ok := st.ProxyNodeProfile("node-a")
	if !ok {
		t.Fatal("profile missing")
	}
	profile.AppliedSHA256 = artifact.ConfigSHA256
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	srv.evaluateProxyConfigDrift(now)
	if state, ok := srv.proxyDriftFor("node-a"); !ok || state.Stale {
		t.Fatalf("expected not stale right after apply, got %+v ok=%v", state, ok)
	}

	// Disable one user: the renderer now drops it, so the render diverges from
	// the applied config — that is the drift we must surface.
	bob, ok := st.ProxyUser("bob")
	if !ok {
		t.Fatal("bob missing")
	}
	bob.Enabled = false
	if err := st.UpsertProxyUser(bob); err != nil {
		t.Fatal(err)
	}

	srv.evaluateProxyConfigDrift(now)
	state, ok := srv.proxyDriftFor("node-a")
	if !ok || !state.Stale || state.IneligibleUsers != 1 {
		t.Fatalf("expected stale with 1 ineligible user, got %+v ok=%v", state, ok)
	}
	if state.PendingSHA256 == "" || state.PendingSHA256 == state.AppliedSHA256 {
		t.Fatalf("expected a distinct pending sha, got %+v", state)
	}

	view := srv.toProxyNodeProfileView(profile)
	if !view.ConfigStale || view.IneligibleUsers != 1 || view.PendingConfigSHA256 != state.PendingSHA256 {
		t.Fatalf("profile view should surface drift: %+v", view)
	}

	// Enforce via a (simulated) reviewed apply of the new render: drift clears.
	profile.AppliedSHA256 = state.PendingSHA256
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}
	srv.refreshProxyDriftFor("node-a", now)
	if state, _ := srv.proxyDriftFor("node-a"); state.Stale {
		t.Fatalf("expected drift cleared after enforcing apply, got %+v", state)
	}
}

func TestProxyConfigDriftWhenAllUsersIneligible(t *testing.T) {
	srv, handler, st := newInventoryServer(t)
	if err := st.UpsertNode(model.Node{ID: "node-a", Name: "node-a"}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := loginSession(t, handler)
	inbound := doJSON(t, handler, http.MethodPost, "/api/proxy/inbounds", `{
		"id":"in1","name":"in1","core":"sing-box","protocol":"vless","port":443,"security":"reality",
		"reality_private_key":"private-reality-key-0001","reality_public_key":"public-reality-key-0001",
		"reality_short_ids":["aa"],"reality_dest":"www.microsoft.com:443","enabled":true
	}`, cookies, csrf)
	if inbound.StatusCode != http.StatusOK {
		t.Fatalf("create inbound: %d", inbound.StatusCode)
	}
	inbound.Body.Close()
	u := doJSON(t, handler, http.MethodPost, "/api/proxy/users",
		`{"id":"alice","name":"alice","inbound_ids":["in1"],"enabled":true}`, cookies, csrf)
	if u.StatusCode != http.StatusOK {
		t.Fatalf("create user: %d", u.StatusCode)
	}
	u.Body.Close()
	prof := doJSON(t, handler, http.MethodPost, "/api/proxy/profiles",
		`{"node_id":"node-a","inbound_ids":["in1"],"hostname":"node-a.example.com"}`, cookies, csrf)
	if prof.StatusCode != http.StatusOK {
		t.Fatalf("create profile: %d", prof.StatusCode)
	}
	prof.Body.Close()

	profile, _ := st.ProxyNodeProfile("node-a")
	profile.AppliedSHA256 = "deadbeef" // any prior applied marker
	if err := st.UpsertProxyNodeProfile(profile); err != nil {
		t.Fatal(err)
	}
	// Disable the only user: the inbound now has zero eligible users, so a fresh
	// render fails. That render failure is itself drift (the live config still
	// serves the now-disabled user).
	alice, _ := st.ProxyUser("alice")
	alice.Enabled = false
	if err := st.UpsertProxyUser(alice); err != nil {
		t.Fatal(err)
	}
	srv.evaluateProxyConfigDrift(time.Now().UTC())
	state, ok := srv.proxyDriftFor("node-a")
	if !ok || !state.Stale || state.IneligibleUsers != 1 {
		t.Fatalf("expected stale render-failure drift, got %+v ok=%v", state, ok)
	}
}
