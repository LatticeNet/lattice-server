package server

import (
	"net/http"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

func TestValidateNodeIPConfig(t *testing.T) {
	cases := []struct {
		name         string
		mode, v4, v6 string
		resolvers    []string
		wantErr      bool
		wantNil      bool
	}{
		{"empty clears", "", "", "", nil, false, true},
		{"auto ok", "auto", "", "", nil, false, false},
		{"static needs an ip", "static", "", "", nil, true, false},
		{"static v4 ok", "static", "203.0.113.7", "", nil, false, false},
		{"unknown mode", "bogus", "", "", nil, true, false},
		{"bad v4", "auto", "not-an-ip", "", nil, true, false},
		{"v6 in the v4 slot", "auto", "2001:db8::1", "", nil, true, false},
		{"static v6 ok", "static", "", "2001:db8::1", nil, false, false},
		{"resolver must be a url", "resolver", "", "", []string{"1.1.1.1"}, true, false},
		{"resolver url ok", "resolver", "", "", []string{"https://api.ipify.org"}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := validateNodeIPConfig(c.mode, c.v4, c.v6, c.resolvers)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && (cfg == nil) != c.wantNil {
				t.Fatalf("cfg nil=%v wantNil=%v", cfg == nil, c.wantNil)
			}
		})
	}
}

// TestNodeIPConfigHTTP exercises setting, rejecting, and clearing a per-node IP
// override through the endpoint, asserting it is persisted on the node.
func TestNodeIPConfigHTTP(t *testing.T) {
	handler, st := newTestServer(t)
	cookies, csrf := loginSession(t, handler)
	enrollNamedNodeToken(t, handler, cookies, csrf, "node-a", "Node A")

	set := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"static","static_ipv4":"203.0.113.7","resolvers":["https://api.ipify.org"]}`,
		cookies, csrf)
	set.Body.Close()
	if set.StatusCode != http.StatusOK {
		t.Fatalf("set ip-config failed: %d", set.StatusCode)
	}
	n, _ := st.Node("node-a")
	if n.IPConfig == nil || n.IPConfig.Mode != model.NodeIPModeStatic || n.IPConfig.StaticIPv4 != "203.0.113.7" {
		t.Fatalf("ip-config not stored: %+v", n.IPConfig)
	}
	if len(n.IPConfig.Resolvers) != 1 || n.IPConfig.Resolvers[0] != "https://api.ipify.org" {
		t.Fatalf("resolvers not stored: %+v", n.IPConfig.Resolvers)
	}

	bad := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":"static"}`, cookies, csrf)
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("static without an ip should be 400, got %d", bad.StatusCode)
	}

	clr := doJSON(t, handler, http.MethodPost, "/api/nodes/ip-config",
		`{"node_id":"node-a","mode":""}`, cookies, csrf)
	clr.Body.Close()
	if clr.StatusCode != http.StatusOK {
		t.Fatalf("clear failed: %d", clr.StatusCode)
	}
	if n2, _ := st.Node("node-a"); n2.IPConfig != nil {
		t.Fatalf("override not cleared: %+v", n2.IPConfig)
	}
}
