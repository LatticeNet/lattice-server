package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// The one-liner updater. `curl -fsSL https://<host>/install.sh | sh` on a node
// that already runs the agent replaces the binary with the current stable
// release and restarts the service.
//
// It updates; it does not enrol. A machine with no agent is turned away with an
// explanation rather than being half-provisioned, which keeps this route out of
// the enrolment path entirely: no token reaches it, so it can stay public and
// still hand out nothing an attacker could not read from the release page.
//
// The version and the checksums are rendered into the script rather than looked
// up by it. The client then verifies against bytes that arrived over the same
// TLS connection that served the script, instead of trusting a second fetch, and
// two runs a minute apart cannot land on different releases.
const agentInstallScriptPath = "/install.sh"

func (s *Server) handleAgentInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	version, tag, err := s.officialAgentTargetAndTag("")
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	sums, err := s.fetchAgentReleaseText(fmt.Sprintf(
		"https://github.com/%s/releases/download/%s/SHA256SUMS", s.agentReleaseRepo, tag))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	script, err := renderAgentInstallScript(s.agentReleaseRepo, version, tag, sums)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(script))
	}
}

// agentInstallScriptPlatforms is what the released workflow builds. A platform
// missing its checksum is left out of the table rather than silently shipped
// unverifiable, so an incomplete release degrades to "unsupported platform"
// instead of "installed something nobody checked".
var agentInstallScriptPlatforms = []struct{ OS, Arch string }{
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
}

func renderAgentInstallScript(repo, version, tag, sums string) (string, error) {
	type entry struct{ key, artifact, sha string }
	var rows []entry
	for _, p := range agentInstallScriptPlatforms {
		artifact := agentArtifactName(p.OS, p.Arch)
		sha, ok := shaFromSums(sums, artifact)
		if !ok {
			continue
		}
		rows = append(rows, entry{p.OS + "/" + p.Arch, artifact, sha})
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("release %s publishes no checksums", tag)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].key < rows[j].key })

	var table strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&table, "%s %s %s\n", row.key, row.artifact, row.sha)
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", repo, tag)

	return strings.NewReplacer(
		"@@VERSION@@", version,
		"@@TAG@@", tag,
		"@@BASE@@", base,
		"@@TABLE@@", strings.TrimRight(table.String(), "\n"),
	).Replace(agentInstallScriptTemplate), nil
}

// agentInstallScriptTemplate is POSIX sh: the nodes that need this most are the
// ones where nothing has been set up yet.
const agentInstallScriptTemplate = `#!/bin/sh
# Update the Lattice node agent to @@VERSION@@ (@@TAG@@).
#
#   curl -fsSL https://<control-plane>/install.sh | sudo sh
#
# This updates a node that already runs the agent. It does not enrol a new one:
# enrolment needs a token, and a public script is the wrong place to take one.
set -eu

BASE='@@BASE@@'
VERSION='@@VERSION@@'
AGENT=/opt/lattice/lattice-agent
# Written only after the service has actually been restarted onto this version.
# The binary on disk is not the question: it can be replaced by a run that then
# fails to restart, leaving the new bytes in place and the old process serving.
# Keying the short-circuit off the binary made that state look finished.
STATE=/opt/lattice/.installed-version

die() { echo "lattice: $*" >&2; exit 1; }

sha_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else die "no sha256 tool available; refusing to install unverified bytes"
    fi
}

[ "$(id -u)" = 0 ] || die "run as root: curl -fsSL <url> | sudo sh"
[ -x "$AGENT" ] || die "no agent at $AGENT. This script updates an enrolled node; enrol it first."

case "$(uname -s)" in
    Linux)  OS=linux ;;
    Darwin) OS=darwin ;;
    *)      die "unsupported system: $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *)             die "unsupported architecture: $(uname -m)" ;;
esac

ARTIFACT=''
EXPECTED=''
while read -r key artifact sha; do
    [ "$key" = "$OS/$ARCH" ] || continue
    ARTIFACT=$artifact
    EXPECTED=$sha
done <<TABLE
@@TABLE@@
TABLE
[ -n "$ARTIFACT" ] || die "release @@TAG@@ has no build for $OS/$ARCH"

if [ "$(cat "$STATE" 2>/dev/null || true)" = "$VERSION" ] && [ "$(sha_of "$AGENT")" = "$EXPECTED" ]; then
    echo "lattice: already on $VERSION"
    exit 0
fi

# Find the service by looking at what is actually installed, rather than
# assuming a name. Both the unit and the launchd label have differed from the
# obvious guess on real machines here.
UNIT=''
LABEL=''
if [ "$OS" = darwin ]; then
    for plist in /Library/LaunchDaemons/*.plist; do
        [ -f "$plist" ] || continue
        grep -q "$AGENT" "$plist" 2>/dev/null || continue
        LABEL=$(/usr/libexec/PlistBuddy -c 'Print :Label' "$plist" 2>/dev/null || true)
        [ -n "$LABEL" ] && break
    done
    [ -n "$LABEL" ] || die "no LaunchDaemon references $AGENT; cannot restart the service"
else
    PID=$(pgrep -x lattice-agent 2>/dev/null | head -1 || true)
    if [ -n "$PID" ] && [ -r "/proc/$PID/cgroup" ]; then
        UNIT=$(sed -n 's|.*/\([A-Za-z0-9@._-]*\.service\).*|\1|p' "/proc/$PID/cgroup" | head -1)
    fi
    [ -n "$UNIT" ] || UNIT=lattice-agent.service
fi

CURRENT=$("$AGENT" --version 2>/dev/null | head -1 || echo unknown)
echo "lattice: $CURRENT -> $VERSION ($OS/$ARCH, ${UNIT:-$LABEL})"

if [ "$(sha_of "$AGENT")" = "$EXPECTED" ]; then
    # A previous run already put these bytes in place and did not get as far as
    # restarting. Nothing to fetch; the restart below is the whole job.
    echo "lattice: binary already current, restarting onto it"
else
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT INT TERM
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time 300 "$BASE/$ARTIFACT" -o "$TMP/agent" || die "download failed"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 300 -O "$TMP/agent" "$BASE/$ARTIFACT" || die "download failed"
    else
        die "neither curl nor wget is available"
    fi
    GOT=$(sha_of "$TMP/agent")
    [ "$GOT" = "$EXPECTED" ] || die "checksum mismatch: got $GOT want $EXPECTED"
    cp -p "$AGENT" "$AGENT.bak-$CURRENT" 2>/dev/null || true
    # Overwrite in place and restart in one job. Never stop first: where this
    # runs as a child of the agent, stopping the agent kills this script too and
    # leaves the service down with nothing left to start it.
    install -m 0755 "$TMP/agent" "$AGENT" || die "install failed"
fi

if [ "$OS" = darwin ]; then
    launchctl kickstart -k "system/$LABEL" >/dev/null 2>&1 || die "launchctl kickstart system/$LABEL failed"
else
    systemctl restart "$UNIT" || die "systemctl restart $UNIT failed"
fi

sleep 3
NOW=$("$AGENT" --version 2>/dev/null | head -1 || echo unknown)
[ "$NOW" = "$VERSION" ] || die "still reporting $NOW after restart; previous binary kept at $AGENT.bak-$CURRENT"
printf '%s\n' "$VERSION" >"$STATE"
echo "lattice: now on $NOW"
`
