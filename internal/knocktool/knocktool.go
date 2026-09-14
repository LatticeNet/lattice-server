// Package knocktool carries the lattice-knock client this server release was
// built with, so an operator whose network cannot reach GitHub can install it
// from the control plane at /tools/knock/.
//
// The three files beside this one are copied byte for byte from the GitHub
// release named by Release: knock and install.sh are the release assets, and
// SHA256SUMS is the release's own checksum file. The tests hold the copy to
// that, so a vendored script that drifted from the release fails go test,
// which CI runs on every pull request, instead of reaching an operator's
// machine.
package knocktool

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Release is the lattice-knock tag the embedded files were copied from.
const Release = "v0.1.0-alpha.1"

// Repo is where the client is developed and released.
const Repo = "LatticeNet/lattice-knock"

var (
	//go:embed knock
	knockScript []byte
	//go:embed install.sh
	installScript []byte
	//go:embed SHA256SUMS
	releaseSums []byte
)

// Knock returns the client script.
func Knock() []byte {
	return append([]byte(nil), knockScript...)
}

// KnockSHA256 is the hex sha256 of the client script.
func KnockSHA256() string {
	sum := sha256.Sum256(knockScript)
	return hex.EncodeToString(sum[:])
}

// Sums is the checksum file the control plane serves. It lists the client
// only: the install.sh this server hands out has its defaults rendered in, so
// its bytes are not the release's, and a line claiming otherwise would fail
// anyone who checked it.
func Sums() []byte {
	return []byte(KnockSHA256() + "  knock\n")
}

// These are the two default lines InstallScript fills in. They are matched
// exactly, and the tests pin that each appears once, so a release that
// reworded either one fails the tests rather than serving an installer that
// quietly ignores the control plane.
const (
	serverDefaultLine = `server="${KNOCK_SERVER:-}"`
	pinDefaultLine    = `pin="${KNOCK_SHA256:-}"`
)

// ErrInstallScriptDrift means the embedded install.sh no longer carries the
// default lines InstallScript fills in. The tests stop that before a release.
// It is its own error so the server can log it if it ever gets past them: the
// fallback, the script as released, still installs but no longer names this
// control plane, and nothing else would say so.
var ErrInstallScriptDrift = errors.New("knocktool: install.sh no longer carries the default lines this server renders")

// InstallScript returns install.sh with this control plane and the client's
// sha256 rendered in as defaults, so `curl -fsSL <base>/tools/knock/install.sh
// | sh` installs from here and checks the bytes without further arguments. It
// is the same move the agent's /install.sh makes: the values the client
// verifies against arrive over the TLS connection that served the script.
// Both stay overridable from the environment and the command line.
func InstallScript(baseURL string) ([]byte, error) {
	base, err := CheckBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return renderInstallScript(installScript, base)
}

func renderInstallScript(src []byte, base string) ([]byte, error) {
	script := string(src)
	if strings.Count(script, serverDefaultLine) != 1 || strings.Count(script, pinDefaultLine) != 1 {
		return nil, ErrInstallScriptDrift
	}
	script = strings.Replace(script, serverDefaultLine, `server="${KNOCK_SERVER:-`+base+`}"`, 1)
	script = strings.Replace(script, pinDefaultLine, `pin="${KNOCK_SHA256:-`+KnockSHA256()+`}"`, 1)
	return []byte(script), nil
}

// UnrenderedInstallScript is install.sh exactly as released, for a server
// that has no usable public URL to render in.
func UnrenderedInstallScript() []byte {
	return append([]byte(nil), installScript...)
}

// CheckBaseURL accepts a plain https URL whose every character is inert in a
// double-quoted shell string, and returns it without a trailing slash. The URL
// is operator configuration, but it lands in a script people pipe into sh and
// in a command they paste, so it is checked rather than trusted.
func CheckBaseURL(raw string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("knocktool: %q is not a plain https URL", raw)
	}
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(":/.-_~", r):
		default:
			return "", fmt.Errorf("knocktool: %q has a character that is not safe in a shell command", raw)
		}
	}
	return base, nil
}

// ControlPlaneInstallCommand is the one-liner that installs the client from
// the control plane at base. It reports false when base is not usable.
func ControlPlaneInstallCommand(base string) (string, bool) {
	b, err := CheckBaseURL(base)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("curl -fsSL %s/tools/knock/install.sh | sh", b), true
}

// GitHubInstallCommand is the one-liner that installs the same release from
// GitHub, pinned to the sha256 this server carries. The pin is what makes the
// GitHub route as trustworthy as the console that shows it.
func GitHubInstallCommand() string {
	return fmt.Sprintf("curl -fsSL https://raw.githubusercontent.com/%s/%s/install.sh | sh -s -- --sha256 %s",
		Repo, Release, KnockSHA256())
}
