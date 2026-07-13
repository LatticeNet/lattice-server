package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	netGuardPluginID         = "latticenet.netguard"
	netGuardFirewallService  = "latticenet.netguard/firewall"
	wireGuardPluginID        = "latticenet.wireguard"
	wireGuardNetworksService = "latticenet.wireguard/networks"
)

type pluginOperatorPrincipalKey struct{}

type pluginOperationError struct {
	StatusCode int
	Body       []byte
}

func (e *pluginOperationError) Error() string {
	return fmt.Sprintf("plugin operation returned HTTP %d", e.StatusCode)
}

type pluginOperationRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *pluginOperationRecorder) Header() http.Header {
	return r.header
}

func (r *pluginOperationRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *pluginOperationRecorder) Write(value []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(value)
}

func pluginOperatorPrincipal(ctx context.Context) (principal, error) {
	p, ok := ctx.Value(pluginOperatorPrincipalKey{}).(principal)
	if !ok {
		return principal{}, errors.New("plugin operator principal unavailable")
	}
	return p, nil
}

// invokePluginOperation lets sandbox interfaces share the exact validation,
// authorization, audit, and approval path used by the corresponding REST API.
// It intentionally does not run auth middleware: the gateway already supplied
// the authenticated principal, which is passed explicitly to the handler.
func invokePluginOperation(
	ctx context.Context,
	method string,
	payload []byte,
	handler func(http.ResponseWriter, *http.Request, principal),
) ([]byte, error) {
	p, err := pluginOperatorPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://plugin.operation/", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	recorder := &pluginOperationRecorder{header: make(http.Header)}
	handler(recorder, req, p)
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	body := append([]byte(nil), recorder.body.Bytes()...)
	if recorder.status < 200 || recorder.status >= 300 {
		return nil, &pluginOperationError{StatusCode: recorder.status, Body: body}
	}
	return body, nil
}

func (s *Server) registerNetworkPluginRPC() {
	if s.pluginRPC == nil {
		return
	}
	if err := s.pluginRPC.Register(netGuardPluginID, netGuardFirewallService, "v1", []string{
		"overview", "upsert_group", "delete_group", "upsert_zone", "delete_zone",
		"upsert_binding", "adopt", "plan",
	}, s.netGuardFirewallRPC); err != nil {
		s.logger.Printf("netguard: register %s failed: %v", netGuardFirewallService, err)
	}
	if err := s.pluginRPC.Register(wireGuardPluginID, wireGuardNetworksService, "v1", []string{
		"overview", "plan",
	}, s.wireGuardNetworksRPC); err != nil {
		s.logger.Printf("wireguard: register %s failed: %v", wireGuardNetworksService, err)
	}
}

func (s *Server) netGuardFirewallRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "overview":
		groups, err := invokePluginOperation(ctx, http.MethodGet, nil, s.handleNetGuardGroups)
		if err != nil {
			return nil, err
		}
		zones, err := invokePluginOperation(ctx, http.MethodGet, nil, s.handleNetGuardZones)
		if err != nil {
			return nil, err
		}
		nodes, err := invokePluginOperation(ctx, http.MethodGet, nil, s.handleNetGuardNodes)
		if err != nil {
			return nil, err
		}
		var groupResult, zoneResult, nodeResult map[string]json.RawMessage
		if err := json.Unmarshal(groups, &groupResult); err != nil {
			return nil, fmt.Errorf("decode netguard groups: %w", err)
		}
		if err := json.Unmarshal(zones, &zoneResult); err != nil {
			return nil, fmt.Errorf("decode netguard zones: %w", err)
		}
		if err := json.Unmarshal(nodes, &nodeResult); err != nil {
			return nil, fmt.Errorf("decode netguard nodes: %w", err)
		}
		return json.Marshal(map[string]json.RawMessage{
			"groups": groupResult["groups"],
			"zones":  zoneResult["zones"],
			"nodes":  nodeResult["nodes"],
		})
	case "upsert_group":
		return invokePluginOperation(ctx, http.MethodPost, request, s.handleNetGuardGroups)
	case "delete_group":
		return invokePluginOperation(ctx, http.MethodPost, request, s.handleDeleteSecurityGroup)
	case "upsert_zone":
		return invokePluginOperation(ctx, http.MethodPost, request, s.handleNetGuardZones)
	case "delete_zone":
		return invokePluginOperation(ctx, http.MethodPost, request, s.handleDeleteGuardZone)
	case "upsert_binding":
		return invokePluginOperation(ctx, http.MethodPost, request, s.handleNetGuardBindings)
	case "adopt":
		return invokePluginOperation(ctx, http.MethodPost, request, s.handleNetGuardAdopt)
	case "plan":
		return invokePluginOperation(ctx, http.MethodPost, request, s.handleNetGuardPlan)
	default:
		return nil, fmt.Errorf("netguard/firewall: unknown method %q", method)
	}
}

type wireGuardNetworkView struct {
	NodeID        string    `json:"node_id"`
	Name          string    `json:"name"`
	Address       string    `json:"address,omitempty"`
	PublicKey     string    `json:"public_key,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"`
	ListenPort    int       `json:"listen_port,omitempty"`
	PublicIP      string    `json:"public_ip,omitempty"`
	Online        bool      `json:"online"`
	Disabled      bool      `json:"disabled,omitempty"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
	Configuration string    `json:"configuration"`
}

func (s *Server) wireGuardNetworksRPC(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case "overview":
		p, err := pluginOperatorPrincipal(ctx)
		if err != nil {
			return nil, err
		}
		rows := make([]wireGuardNetworkView, 0)
		for _, node := range s.store.Nodes() {
			if !rbac.Allows(p.Principal, "node:read", node.ID) {
				continue
			}
			configuration := "missing"
			switch {
			case strings.TrimSpace(node.WireGuardIP) != "" && strings.TrimSpace(node.WireGuardPublicKey) != "":
				configuration = "ready"
			case strings.TrimSpace(node.WireGuardIP) != "" || strings.TrimSpace(node.WireGuardPublicKey) != "":
				configuration = "partial"
			}
			rows = append(rows, wireGuardNetworkView{
				NodeID: node.ID, Name: node.Name, Address: node.WireGuardIP,
				PublicKey: node.WireGuardPublicKey, Endpoint: node.WireGuardEndpoint,
				ListenPort: node.WireGuardPort, PublicIP: node.PublicIP,
				Online: node.Online, Disabled: node.Disabled, LastSeen: node.LastSeen,
				Configuration: configuration,
			})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Name == rows[j].Name {
				return rows[i].NodeID < rows[j].NodeID
			}
			return rows[i].Name < rows[j].Name
		})
		ready := 0
		for _, row := range rows {
			if row.Configuration == "ready" {
				ready++
			}
		}
		return json.Marshal(map[string]any{"nodes": rows, "count": len(rows), "ready": ready})
	case "plan":
		return invokePluginOperation(ctx, http.MethodPost, request, s.handleWireGuardPlan)
	default:
		return nil, fmt.Errorf("wireguard/networks: unknown method %q", method)
	}
}
