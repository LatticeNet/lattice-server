package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func generateHere(t *testing.T, ref string) []byte {
	t.Helper()
	sdk, err := sdkModuleDir()
	if err != nil {
		t.Skipf("no go command to locate the sdk: %v", err)
	}
	out, err := generate(filepath.Join("..", "..", "internal", "server"), filepath.Join(sdk, "model"), ref)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// core-types.ts is the generator's output for this tree: a change to a reply
// type's JSON tags that is not regenerated fails here, before the UI's
// contract test sees it. Regenerate with: go run ./tools/tsgen -o tools/tsgen/core-types.ts
func TestCoreTypesAreGenerated(t *testing.T) {
	committed, err := os.ReadFile("core-types.ts")
	if err != nil {
		t.Fatal(err)
	}
	if got := generateHere(t, ""); !bytes.Equal(got, committed) {
		t.Fatalf("core-types.ts is stale; regenerate it with go run ./tools/tsgen -o tools/tsgen/core-types.ts")
	}
}

// The fields a hand copy lost are there, optional where the server omits
// them, and the ref lands in the header.
func TestCoreTypesFollowTheJSONTags(t *testing.T) {
	out := string(generateHere(t, "0123abc"))
	if !strings.Contains(out, "// Source: lattice-server 0123abc\n") {
		t.Fatal("the ref is not in the header")
	}
	for _, want := range []string{
		"export interface BindEntry {\n  index: number;\n  line_uuid?: string;\n  provider?: boolean;\n  name?: string;\n  label?: string;\n  node_id?: string;\n",
		"  clone?: number;\n  digest: string;\n}",
		"export interface BindPreviewReply {",
		"  entries: BindEntry[];\n  excluded: BindExclusion[];",
		"export interface PlanStatusRow {",
		"export interface ShareRow {",
		"  icon?: ShareIcon;",
		// An embedded struct's fields are inlined, as encoding/json does.
		"export interface PlanLine {\n  line_uuid: string;\n  names: string[];\n  digest: string;\n  reason?: string;\n}",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q", want)
		}
	}
	// A field tagged "-" never reaches the wire, so never the declaration.
	if !strings.Contains(out, "export interface BindLine {\n  line_uuid?: string;\n  name?: string;\n  reason?: string;\n}") {
		t.Fatal("BindLine is not its three wire fields")
	}
}

func TestTSNameDropsThePackagePrefix(t *testing.T) {
	for goName, want := range map[string]string{
		"substoreBindEntry": "BindEntry", "subStorePlanShare": "PlanShare", "ShareIcon": "ShareIcon", "lineRow": "LineRow",
	} {
		if got := tsName(goName); got != want {
			t.Fatalf("tsName(%q) = %q, want %q", goName, got, want)
		}
	}
}
