package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/agentinstall"
)

// Design 31, S6: install on new nodes from the same sources updates use.
//
// The control plane serves the installer it carries (agentinstall) at
// agentInstallerPath, as it serves the knock client at /tools/knock/, and
// renders into the enrollment command an ordered list of sources (the
// registry's global mirrors, then the GitHub release) and the digests it has
// verified for the installer's version. The installer holds the binary to the
// rendered digest, so a mirror never supplies the digest it is checked
// against; without a digest for its platform it skips the mirrors and checks
// the release's SHA256SUMS, as before. The binary route stays lease-only: the
// long-lived node token never fetches from it.
const agentInstallerPath = "/tools/agent/install.sh"

// agentInstallSourceRe is a source token as the installer accepts it.
var agentInstallSourceRe = regexp.MustCompile(`^[mr]=https://[A-Za-z0-9._~:/+-]+$`)

// handleAgentInstaller serves the vendored installer. It is public, like
// /install.sh and /tools/knock/: the file holds no credential and is the same
// bytes as lattice-node-agent's scripts/install.sh at agentinstall.Ref.
func (s *Server) handleAgentInstaller(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	body := agentinstall.Script()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// agentInstallMirrorBases are the registry's enabled global mirrors, in
// priority order: the install sources before the release. They are capped as
// an update plan's are, so the release stays within maxAgentUpdateSources and
// a run of dead mirrors costs a new node a bounded wait.
func (s *Server) agentInstallMirrorBases() []string {
	if s.store == nil {
		return nil
	}
	var mirrors []model.AgentMirror
	for _, m := range s.store.AgentMirrorRegistry().Mirrors {
		if m.Enabled && m.Global {
			mirrors = append(mirrors, m)
		}
	}
	slices.SortStableFunc(mirrors, func(a, b model.AgentMirror) int {
		if a.Priority != b.Priority {
			return a.Priority - b.Priority
		}
		return strings.Compare(a.ID, b.ID)
	})
	if len(mirrors) > maxAgentUpdateSources-1 {
		mirrors = mirrors[:maxAgentUpdateSources-1]
	}
	out := make([]string, 0, len(mirrors))
	for _, m := range mirrors {
		out = append(out, m.BaseURL)
	}
	return out
}

// agentInstallSources renders the ordered source list: m=<base> for each
// mirror, r=<release base> last. Mirrors are listed only when there is a
// digest to hold them to. A token that does not match the installer's own
// pattern is left out, so the rendered list is one the installer accepts.
func agentInstallSources(mirrors []string, releaseBase string, withMirrors bool) string {
	var tokens []string
	if withMirrors {
		for _, base := range mirrors {
			tokens = append(tokens, "m="+base)
		}
	}
	tokens = append(tokens, "r="+releaseBase)
	out := tokens[:0]
	for _, token := range tokens {
		if agentInstallSourceRe.MatchString(token) {
			out = append(out, token)
		}
	}
	return strings.Join(out, " ")
}

// agentInstallDigests is the os/arch=sha256 table the control plane has
// verified for an installer version: the binaries it stores or imported,
// which an import held to the release's SHA256SUMS. It is read from local
// state only, so rendering a command never waits on GitHub.
func (s *Server) agentInstallDigests(version string) string {
	if s.store == nil {
		return ""
	}
	var rows []string
	for _, arch := range []string{"amd64", "arm64"} {
		sha := ""
		if ref, ok := s.storedAgentArtifact(version, "linux", arch); ok {
			sha = ref.SHA256
		} else if digest, ok := s.importedAgentArtifactDigest(version, "linux", arch); ok {
			sha = digest
		}
		if agentSHA256Re.MatchString(sha) {
			rows = append(rows, "linux/"+arch+"="+sha)
		}
	}
	return strings.Join(rows, " ")
}

// agentInstallerDownload is the first half of an enroll or reconfigure
// command, which fetches the installer, and the environment the installer
// run takes from the control plane. A server without a usable public HTTPS
// URL has no address to serve the installer at, and hands out the GitHub one
// as before.
func (s *Server) agentInstallerDownload() (download, env string) {
	base := s.agentBinaryBaseURL()
	if base == "" {
		return agentInstallScriptDownloadCommand(), ""
	}
	download = fmt.Sprintf("curl -fsSL --proto '=https' --tlsv1.2 %s -o lattice-agent-install.sh", shellQuote(base+agentInstallerPath))
	digests := s.agentInstallDigests(strings.TrimPrefix(agentInstallerRef, "v"))
	release := "https://github.com/" + s.agentReleaseRepoOrDefault() + "/releases/download/" + agentInstallerRef
	env = " LATTICE_AGENT_SOURCES=" + shellQuote(agentInstallSources(s.agentInstallMirrorBases(), release, digests != ""))
	if digests != "" {
		env += " LATTICE_AGENT_SHA256=" + shellQuote(digests)
	}
	return download, env
}

func (s *Server) agentReleaseRepoOrDefault() string {
	if s.agentReleaseRepo == "" {
		return defaultAgentReleaseRepo
	}
	return s.agentReleaseRepo
}
