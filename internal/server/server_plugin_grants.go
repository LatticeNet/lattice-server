package server

import (
	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
)

// pluginIsActive is the lifecycle predicate the RPC bus consults before dispatching
// any service. It is the single answer to "may this plugin's backend run right now",
// and it applies whether the engine behind the service lives in the plugin's artifact
// or in core.
func (s *Server) pluginIsActive(pluginID string) bool {
	installation, ok := s.store.PluginInstallation(pluginID)
	return ok && installation.Status == model.PluginStatusActive
}

// applyPluginHostAccess materializes signed, method-bounded dependencies only
// for an active plugin runtime. The manifest remains the sole owner of these
// edges; core services do not pre-authorize specific plugin IDs.
func (s *Server) applyPluginHostAccess(loaded plugin.Loaded) {
	if s.pluginRPC == nil || loaded.Manifest.HostAccess == nil {
		return
	}
	for _, dependency := range loaded.Manifest.HostAccess.RPC {
		s.pluginRPC.AllowMethods(loaded.Manifest.ID, dependency.Service, dependency.Methods)
	}
}

func (s *Server) revokePluginHostAccess(loaded plugin.Loaded) {
	if s.pluginRPC == nil || loaded.Manifest.HostAccess == nil {
		return
	}
	for _, dependency := range loaded.Manifest.HostAccess.RPC {
		s.pluginRPC.Revoke(loaded.Manifest.ID, dependency.Service)
	}
}
