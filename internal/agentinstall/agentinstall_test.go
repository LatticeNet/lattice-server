package agentinstall

import (
	"strings"
	"testing"
)

// The embedded installer is the copy Ref names: a hand edit, or a refresh
// that forgot a constant, fails here.
func TestInstallerIsTheCopyRefNames(t *testing.T) {
	if got := ScriptSHA256(); got != SHA256 {
		t.Fatalf("install.sh hashes to %s, but SHA256 says %s; copy it from %s and update both constants", got, SHA256, Ref)
	}
}

// The server renders these into the enrollment command; an installer that
// does not read them would quietly ignore the mirrors and the digests.
func TestInstallerReadsWhatTheServerRenders(t *testing.T) {
	script := string(Script())
	for _, want := range []string{"LATTICE_AGENT_SOURCES", "LATTICE_AGENT_SHA256", "LATTICE_AGENT_VERSION"} {
		if !strings.Contains(script, want) {
			t.Fatalf("the vendored installer does not read %s", want)
		}
	}
}
