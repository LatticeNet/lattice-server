package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// sdk.ref and dashboard.ref are pointers this repo keeps to other repos. The
// container build checks the sdk out at sdk.ref and lays a go workspace over
// it, so that ref wins over go.mod entirely: if the two disagree, the image
// build fails on symbols the code uses and the checked-out sdk does not have.
//
// That is exactly what a31 would have done. sdk.ref still named the commit
// before model.User gained ServerAllowlist while go.mod already required the
// one after, and nothing anywhere checked. Neither ref is verified by anything
// until a tag turns it into a build, which is the worst moment to find out.
func TestSDKRefAgreesWithGoMod(t *testing.T) {
	ref, err := os.ReadFile("sdk.ref")
	if err != nil {
		t.Fatalf("read sdk.ref: %v", err)
	}
	pinned := strings.TrimSpace(string(ref))
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(pinned) {
		t.Fatalf("sdk.ref is not a full commit sha: %q", pinned)
	}

	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	// A go pseudo-version ends in the 12-character prefix of the commit it was
	// built from: v0.2.19-0.20260819134534-9ddc0d4e9490.
	m := regexp.MustCompile(`github\.com/LatticeNet/lattice-sdk v\S*-([0-9a-f]{12})`).FindSubmatch(mod)
	if m == nil {
		t.Skip("go.mod does not pin the sdk by pseudo-version, so there is nothing to compare")
	}
	if want := string(m[1]); !strings.HasPrefix(pinned, want) {
		t.Fatalf("sdk.ref %s does not match the commit go.mod requires (%s...); "+
			"the image build lays a workspace over sdk.ref, so it would compile the code "+
			"in this repo against a different sdk than the tests just used", pinned, want)
	}
}

// Weaker than the sdk check, because nothing in this repo depends on the
// dashboard at compile time, so a stale value cannot fail a build. It ships a
// console older than the server instead, which is how a31 nearly went out with
// the server half of a security fix and not the console half.
func TestDashboardRefIsAFullCommitSha(t *testing.T) {
	ref, err := os.ReadFile("dashboard.ref")
	if err != nil {
		t.Fatalf("read dashboard.ref: %v", err)
	}
	pinned := strings.TrimSpace(string(ref))
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(pinned) {
		t.Fatalf("dashboard.ref is not a full commit sha: %q", pinned)
	}
}
