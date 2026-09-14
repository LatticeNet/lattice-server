package knocktool

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func sumOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func releaseSum(t *testing.T, name string) string {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(string(releaseSums)), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return f[0]
		}
	}
	t.Fatalf("SHA256SUMS has no line for %s", name)
	return ""
}

// The vendored files are the release's files. A copy edited in place, or a
// SHA256SUMS taken from a different release, fails here instead of reaching
// an operator's machine through /tools/knock/.
func TestVendoredFilesMatchTheReleaseChecksums(t *testing.T) {
	if got, want := sumOf(knockScript), releaseSum(t, "knock"); got != want {
		t.Fatalf("knock: vendored sha256 %s, release says %s", got, want)
	}
	if got, want := sumOf(installScript), releaseSum(t, "install.sh"); got != want {
		t.Fatalf("install.sh: vendored sha256 %s, release says %s", got, want)
	}
	if KnockSHA256() != releaseSum(t, "knock") {
		t.Fatal("KnockSHA256 disagrees with the release checksum")
	}
	if got, want := string(Sums()), releaseSum(t, "knock")+"  knock\n"; got != want {
		t.Fatalf("served SHA256SUMS:\n  got  %q\n  want %q", got, want)
	}
}

// Release names the tag the files came from; the scripts say which release
// they are. Bumping one without the other fails here.
func TestVendoredFilesNameTheRelease(t *testing.T) {
	if !strings.Contains(string(knockScript), "\nKNOCK_VERSION=\""+strings.TrimPrefix(Release, "v")+"\"\n") {
		t.Fatalf("knock does not say KNOCK_VERSION=%q", strings.TrimPrefix(Release, "v"))
	}
	if !strings.Contains(string(installScript), "\nKNOCK_RELEASE=\""+Release+"\"\n") {
		t.Fatalf("install.sh does not say KNOCK_RELEASE=%q", Release)
	}
}

// The control plane's install.sh differs from the release in exactly the two
// default lines, so what is served is the reviewed script with two values
// filled in, and nothing else.
func TestInstallScriptRendersOnlyTheTwoDefaults(t *testing.T) {
	script, err := InstallScript("https://lattice.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	server := `server="${KNOCK_SERVER:-https://lattice.example.com}"`
	pin := `pin="${KNOCK_SHA256:-` + KnockSHA256() + `}"`
	if strings.Count(s, server) != 1 || strings.Count(s, pin) != 1 {
		t.Fatalf("rendered install.sh lacks the control plane or the pin:\n%s", s)
	}
	restored := strings.Replace(strings.Replace(s, server, serverDefaultLine, 1), pin, pinDefaultLine, 1)
	if restored != string(installScript) {
		t.Fatal("rendering changed more than the two default lines")
	}
	if string(UnrenderedInstallScript()) != string(installScript) {
		t.Fatal("the unrendered script is not the release's install.sh")
	}
}

// A release that rewords a default line is drift, which the server logs. A
// missing public URL is ordinary, and must not be reported as drift.
func TestInstallScriptDriftIsItsOwnError(t *testing.T) {
	for name, src := range map[string]string{
		"reworded server line": strings.Replace(string(installScript), serverDefaultLine, `server="${LATTICE_SERVER:-}"`, 1),
		"reworded pin line":    strings.Replace(string(installScript), pinDefaultLine, `pin="${KNOCK_PIN:-}"`, 1),
		"duplicated pin line":  string(installScript) + "\n" + pinDefaultLine + "\n",
	} {
		if _, err := renderInstallScript([]byte(src), "https://lattice.example.com"); !errors.Is(err, ErrInstallScriptDrift) {
			t.Fatalf("%s: want ErrInstallScriptDrift, got %v", name, err)
		}
	}
	if _, err := InstallScript(""); err == nil || errors.Is(err, ErrInstallScriptDrift) {
		t.Fatalf("a missing public URL must fail without being drift, got %v", err)
	}
}

// The URL is operator configuration, but it lands in a script piped into sh
// and in a command pasted into a shell.
func TestCheckBaseURLRefusesWhatAShellWouldInterpret(t *testing.T) {
	for _, bad := range []string{
		"",
		"lattice.example.com",
		"http://lattice.example.com",
		"https://",
		"https://user@lattice.example.com",
		"https://lattice.example.com/?a=b",
		"https://lattice.example.com/#top",
		`https://lattice.example.com/"; id; "`,
		"https://lattice.example.com/$(id)",
		"https://lattice.example.com/`id`",
		"https://lattice.example.com/${HOME}",
		"https://lattice.example.com/a b",
		"https://lattice.example.com/\nid",
		"https://lattice.example.com/a'b",
	} {
		if _, err := CheckBaseURL(bad); err == nil {
			t.Fatalf("CheckBaseURL accepted %q", bad)
		}
		if _, ok := ControlPlaneInstallCommand(bad); ok {
			t.Fatalf("ControlPlaneInstallCommand accepted %q", bad)
		}
		if _, err := InstallScript(bad); err == nil {
			t.Fatalf("InstallScript accepted %q", bad)
		}
	}
	for _, good := range []string{
		"https://lattice.roobli.org",
		"https://lattice.example.com/",
		"https://example.com:8443/lattice",
	} {
		if _, err := CheckBaseURL(good); err != nil {
			t.Fatalf("CheckBaseURL refused %q: %v", good, err)
		}
	}
}

func TestInstallCommands(t *testing.T) {
	cmd, ok := ControlPlaneInstallCommand("https://lattice.example.com/")
	if !ok || cmd != "curl -fsSL https://lattice.example.com/tools/knock/install.sh | sh" {
		t.Fatalf("control plane install command: %q, %v", cmd, ok)
	}
	want := "curl -fsSL https://raw.githubusercontent.com/LatticeNet/lattice-knock/" + Release +
		"/install.sh | sh -s -- --sha256 " + KnockSHA256()
	if got := GitHubInstallCommand(); got != want {
		t.Fatalf("GitHub install command:\n  got  %s\n  want %s", got, want)
	}
}
