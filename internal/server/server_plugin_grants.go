package server

import "github.com/LatticeNet/lattice-server/internal/plugin"

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
