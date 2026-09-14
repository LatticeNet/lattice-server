package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-server/internal/knocktool"
)

// knockToolPathPrefix serves the lattice-knock client this release carries,
// for operators whose network cannot reach GitHub.
//
// Public on purpose, like /install.sh: the files hold no credential and hand
// none out. A knock sequence is only ever revealed in the console, behind a
// second factor. The client is the same bytes as the GitHub release, which the
// knocktool tests hold the vendored copy to.
const knockToolPathPrefix = "/tools/knock/"

func (s *Server) handleKnockTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var body []byte
	switch strings.TrimPrefix(r.URL.Path, knockToolPathPrefix) {
	case "knock":
		body = knocktool.Knock()
	case "SHA256SUMS":
		body = knocktool.Sums()
	case "install.sh":
		// With this control plane and the client's checksum rendered in, so
		// the one-liner needs no arguments. A server without a usable public
		// URL serves the script as released, and the operator passes --server.
		// That case is ordinary and stays quiet; drift between the vendored
		// script and the renderer is a build defect and is logged.
		script, err := knocktool.InstallScript(s.publicURL)
		if err != nil {
			if errors.Is(err, knocktool.ErrInstallScriptDrift) {
				s.logger.Printf("knock tool: serving install.sh unrendered: %v", err)
			}
			script = knocktool.UnrenderedInstallScript()
		}
		body = script
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}
