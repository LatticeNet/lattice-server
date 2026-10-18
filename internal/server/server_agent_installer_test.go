package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/agentinstall"
)

// Design 31, S6: new nodes install from the control plane's installer, with
// the sources and digests the control plane renders.

// The control plane serves the installer it carries, byte for byte.
func TestAgentInstallerRouteServesTheVendoredCopy(t *testing.T) {
	_, handler, _ := newAgentArtifactServer(t)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, agentInstallerPath, nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: %d %v", method, rec.Code, rec.Header())
		}
		if method == http.MethodGet && rec.Body.String() != string(agentinstall.Script()) {
			t.Fatal("the route must serve the vendored installer unchanged")
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, agentInstallerPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
}

// The enrollment command fetches the installer from the control plane and
// passes it the global mirrors, then the release, with the digests the
// control plane verified for the installer's version. Without a digest no
// mirror is listed; without a public URL the command is the GitHub one.
func TestAgentEnrollCommandRendersSourcesAndDigests(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	version := strings.TrimPrefix(agentInstallerRef, "v")
	release := "r=https://github.com/" + defaultAgentReleaseRepo + "/releases/download/" + agentInstallerRef
	seedAgentMirrors(t, st,
		model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 2, Enabled: true},
		model.AgentMirror{ID: "first", BaseURL: "https://first.example.org/a", Global: true, Priority: 1, Enabled: true},
		model.AgentMirror{ID: "off", BaseURL: "https://off.example.org", Global: true, Priority: 0},
		model.AgentMirror{ID: "pref", BaseURL: "https://pref.example.org", PreferFor: []string{"node-a"}, Priority: 0, Enabled: true},
	)
	cmd := srv.agentEnrollCommand(artifactTestPublicURL, "node-a", "tok")
	if !strings.HasPrefix(cmd, "curl -fsSL --proto '=https' --tlsv1.2 '"+artifactTestPublicURL+agentInstallerPath+"' -o lattice-agent-install.sh") {
		t.Fatalf("the installer must come from the control plane:\n%s", cmd)
	}
	if !strings.Contains(cmd, " LATTICE_AGENT_SOURCES='"+release+"' ") || strings.Contains(cmd, "LATTICE_AGENT_SHA256") {
		t.Fatalf("without a verified digest no mirror is listed and no table rendered:\n%s", cmd)
	}

	amd, digest := walkTestBinary(version, 4096)
	if _, err := srv.importAgentArtifact(agentArtifactRef{Version: version, OS: "linux", Arch: "amd64", SHA256: digest}, amd); err != nil {
		t.Fatal(err)
	}
	cmd = srv.agentEnrollCommand(artifactTestPublicURL, "node-a", "tok")
	want := " LATTICE_AGENT_SOURCES='m=https://first.example.org/a m=" + mirrorTestBase + " " + release + "' LATTICE_AGENT_SHA256='linux/amd64=" + digest + "' "
	if !strings.Contains(cmd, want) {
		t.Fatalf("command lacks %q:\n%s", want, cmd)
	}
	run := cmd[strings.LastIndex(cmd, " env "):]
	if !strings.Contains(run, "LATTICE_AGENT_SOURCES=") || !strings.HasSuffix(run, "./lattice-agent-install.sh") {
		t.Fatalf("the sources must ride the env that runs the installer:\n%s", cmd)
	}
	reconfigure := srv.agentReconfigureCommands(artifactTestPublicURL, "node-a", model.AgentLaunchConfig{})["linux"]
	if !strings.Contains(reconfigure, want) || !strings.Contains(reconfigure, artifactTestPublicURL+agentInstallerPath) {
		t.Fatalf("the reconfigure command must install the same way:\n%s", reconfigure)
	}

	// No public URL: no address to serve the installer at.
	bare := &Server{}
	if legacy := bare.agentEnrollCommand("https://lattice.example.com", "node-a", "tok"); !strings.Contains(legacy, agentInstallScriptURL()) ||
		strings.Contains(legacy, "LATTICE_AGENT_SOURCES") {
		t.Fatalf("a server without a public URL hands out the GitHub installer as before:\n%s", legacy)
	}
}

// Only tokens the installer accepts are rendered, whatever the registry
// holds.
func TestAgentInstallSourcesRenderOnlyWhatTheInstallerAccepts(t *testing.T) {
	got := agentInstallSources([]string{"https://ok.example.org/x", "https://bad.example.org/it's", "http://plain.example.org"}, "https://github.com/a/b/releases/download/v1.2.3", true)
	if got != "m=https://ok.example.org/x r=https://github.com/a/b/releases/download/v1.2.3" {
		t.Fatalf("sources %q", got)
	}
	if got := agentInstallSources([]string{"https://ok.example.org"}, "https://github.com/a/b/releases/download/v1.2.3", false); got != "r=https://github.com/a/b/releases/download/v1.2.3" {
		t.Fatalf("without digests mirrors are left out, got %q", got)
	}
}

// The /install.sh updater walks its sources: a mirror that serves wrong
// bytes is discarded and the release installs; a mirror that splices wrong
// bytes onto the release's is caught by the digest, and the second round
// fetches each source from zero.
func TestAgentUpdaterScriptWalksItsSources(t *testing.T) {
	newBinary := []byte("#!/bin/sh\necho 0.3.8\n# " + strings.Repeat("padding ", 2000) + "\n")
	sum := sha256.Sum256(newBinary)
	digest := hex.EncodeToString(sum[:])
	sums := digest + "  lattice-agent-linux-amd64\n"
	script, err := renderAgentInstallScript("LatticeNet/lattice-node-agent", "0.3.8", "v0.3.8", sums, []string{mirrorTestBase})
	if err != nil {
		t.Fatal(err)
	}
	mirrorURL := mirrorTestBase + "/0.3.8/linux/amd64/" + digest
	releaseURL := "https://github.com/LatticeNet/lattice-node-agent/releases/download/v0.3.8/lattice-agent-linux-amd64"
	wrong := corrupt(newBinary, 30)

	run := func(t *testing.T, mSteps, rSteps string, mBody []byte) (string, []string, int) {
		t.Helper()
		dir := t.TempDir()
		bin := filepath.Join(dir, "bin")
		if err := os.Mkdir(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, tool := range []string{"cat", "rm", "awk", "sha256sum", "shasum", "cut", "sed", "head", "tail", "wc", "cp", "mktemp", "grep", "true", "chmod"} {
			if path, err := exec.LookPath(tool); err == nil {
				if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
					t.Fatal(err)
				}
			}
		}
		stubs := map[string]string{
			"curl":      walkFetchStub,
			"id":        "#!/bin/sh\necho 0\n",
			"uname":     "#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n",
			"pgrep":     "#!/bin/sh\nexit 1\n",
			"systemctl": "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >>\"$STUB_CALLS\"\n",
			"sleep":     "#!/bin/sh\n",
			"install":   "#!/bin/sh\nif [ \"$1\" = -m ]; then shift 2; fi\ncp \"$1\" \"$2\"\nchmod 0755 \"$2\"\n",
			"date":      "#!/bin/sh\necho 1000\n",
		}
		for name, body := range stubs {
			if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		agent := filepath.Join(dir, "lattice-agent")
		if err := os.WriteFile(agent, []byte("#!/bin/sh\necho 0.3.7\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		mFile, rFile := filepath.Join(dir, "m-body"), filepath.Join(dir, "r-body")
		_ = os.WriteFile(mFile, mBody, 0o600)
		_ = os.WriteFile(rFile, newBinary, 0o600)
		_ = os.WriteFile(filepath.Join(dir, "clock"), []byte("1000\n"), 0o600)
		text := strings.Replace(script, "AGENT=/opt/lattice/lattice-agent\n", "AGENT="+shellQuote(agent)+"\n", 1)
		text = strings.Replace(text, "STATE=/opt/lattice/.installed-version\n", "STATE="+shellQuote(filepath.Join(dir, "state"))+"\n", 1)
		if err := os.WriteFile(filepath.Join(dir, "update.sh"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", filepath.Join(dir, "update.sh"))
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + bin, "TMPDIR=" + dir, "STUB_DIR=" + dir, "STUB_CALLS=" + filepath.Join(dir, "calls"),
			"STUB_CLOCK=" + filepath.Join(dir, "clock"),
			"STUB_CP_URL=" + mirrorURL, "STUB_CP_BODY=" + mFile, "STUB_CP_STEPS=" + mSteps,
			"STUB_FB_URL=" + releaseURL, "STUB_FB_BODY=" + rFile, "STUB_FB_STEPS=" + rSteps}
		out, err := cmd.CombinedOutput()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "calls"))
		var curls []string
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if strings.HasPrefix(line, "curl ") {
				curls = append(curls, line)
			}
		}
		installed, _ := os.ReadFile(agent)
		if code == 0 && string(installed) != string(newBinary) {
			t.Fatalf("exit 0 but the agent was not replaced:\n%s", out)
		}
		return string(out), curls, code
	}

	t.Run("a lying mirror is discarded and the release installs", func(t *testing.T) {
		out, curls, code := run(t, "0:0:1", "0:0:1", wrong)
		if code != 0 || len(curls) != 2 || !strings.Contains(out, "lattice: now on 0.3.8") {
			t.Fatalf("exit %d calls %q:\n%s", code, curls, out)
		}
		if !strings.HasSuffix(curls[0], mirrorURL) || strings.Contains(curls[0], " -fsSL ") || !strings.Contains(curls[0], " -C - ") {
			t.Fatalf("the mirror is fetched first, resumable, without following redirects: %s", curls[0])
		}
		if !strings.HasSuffix(curls[1], releaseURL) || !strings.Contains(curls[1], " -fsSL ") || !strings.Contains(curls[1], "--proto-redir =https") {
			t.Fatalf("the release follows redirects to HTTPS only: %s", curls[1])
		}
	})
	t.Run("a splice is caught and the second round fetches from zero", func(t *testing.T) {
		// The mirror sends 100 wrong bytes and fails; the release continues
		// them, so the result fails its digest. The second round asks the
		// mirror again (it fails at once) and the release from byte zero.
		out, curls, code := run(t, "18:100:1 7:-1:1", "0:0:1", wrong)
		if code != 0 || len(curls) != 4 || !strings.Contains(out, "lattice: now on 0.3.8") {
			t.Fatalf("exit %d calls %q:\n%s", code, curls, out)
		}
	})
	t.Run("nothing verifies", func(t *testing.T) {
		out, _, code := run(t, "0:0:1", "22:-1:1", wrong)
		if code == 0 || !strings.Contains(out, "no source delivered the pinned binary") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})
}

// The vendored installer accepts what the enrollment command renders: run on
// a node with neither curl nor wget, it gets past every check of the two
// variables, uses the mirrors, and stops only for want of a downloader. A
// hostile source is refused before anything runs.
func TestVendoredInstallerAcceptsWhatTheServerRenders(t *testing.T) {
	srv, _, st := newAgentArtifactServer(t)
	version := strings.TrimPrefix(agentInstallerRef, "v")
	seedAgentMirrors(t, st, model.AgentMirror{ID: "r2", BaseURL: mirrorTestBase, Global: true, Priority: 1, Enabled: true})
	amd, digest := walkTestBinary(version, 4096)
	if _, err := srv.importAgentArtifact(agentArtifactRef{Version: version, OS: "linux", Arch: "amd64", SHA256: digest}, amd); err != nil {
		t.Fatal(err)
	}
	cmd := srv.agentEnrollCommand(artifactTestPublicURL, "node-a", "tok")
	rendered := func(name string) string {
		_, rest, ok := strings.Cut(cmd, " "+name+"='")
		value, _, closed := strings.Cut(rest, "'")
		if !ok || !closed {
			t.Fatalf("the command renders no %s:\n%s", name, cmd)
		}
		return value
	}
	sources, table := rendered("LATTICE_AGENT_SOURCES"), rendered("LATTICE_AGENT_SHA256")

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"id":    "#!/bin/sh\nif [ \"$1\" = -u ]; then echo 0; else echo uid=0; fi\n",
		"uname": "#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"sh", "awk", "sed", "grep", "tr", "cut", "head", "tail", "cat", "mktemp", "rm", "mkdir", "chmod", "dirname", "basename", "env", "sort", "wc", "expr", "ls"} {
		if p, err := exec.LookPath(tool); err == nil {
			_ = os.Symlink(p, filepath.Join(bin, tool))
		}
	}
	script := filepath.Join(dir, "lattice-agent-install.sh")
	if err := os.WriteFile(script, agentinstall.Script(), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(sources string) (string, error) {
		c := exec.Command(filepath.Join(bin, "sh"), script)
		c.Env = []string{"PATH=" + bin, "HOME=" + dir, "LATTICE_HOME=" + filepath.Join(dir, "home"),
			"LATTICE_SERVER=" + artifactTestPublicURL, "LATTICE_NODE_ID=node-a", "LATTICE_NODE_TOKEN=tok",
			"LATTICE_AGENT_VERSION=" + agentInstallerRef, "LATTICE_AGENT_SOURCES=" + sources, "LATTICE_AGENT_SHA256=" + table}
		out, err := c.CombinedOutput()
		return string(out), err
	}
	out, err := run(sources)
	if err == nil || !strings.Contains(out, "need curl or wget to download the agent") ||
		strings.Contains(out, "LATTICE_AGENT_SOURCES:") || strings.Contains(out, "LATTICE_AGENT_SHA256 ") || strings.Contains(out, "skipping mirror") {
		t.Fatalf("the installer must accept %q and %q and stop only for want of a downloader, got %v:\n%s", sources, table, err, out)
	}
	pwned := filepath.Join(dir, "pwned")
	out, err = run("m=https://dl.example.org/$(touch " + pwned + ") " + sources)
	if _, statErr := os.Stat(pwned); err == nil || !strings.Contains(out, "LATTICE_AGENT_SOURCES: a base may hold only") || statErr == nil {
		t.Fatalf("a hostile source must be refused before anything runs, got %v:\n%s", err, out)
	}
}
