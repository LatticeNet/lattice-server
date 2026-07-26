package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAcceptsValidManifestAndPrintsBuildEvidence(t *testing.T) {
	manifestPath := writeManifest(t, "valid.json", `{
		"schema":"lattice.plugin.manifest.v2",
		"id":"test.valid",
		"name":"Valid Test Plugin",
		"type":"system",
		"capabilities":["kv:read"],
		"version":"0.1.0-alpha.1",
		"bundle":{"format":"tar+gzip","digest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"runtime":{"protocol":"stdio-json-v1","entrypoints":{"linux/amd64":"bin/plugin"}},
		"compatibility":{"server":">=0.2.0","dashboard_host":">=0.2.0","runtime_protocol":"stdio-json-v1"}
	}`)

	var stdout, stderr bytes.Buffer
	if code := run([]string{manifestPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("run exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if got := stdout.String(); !strings.Contains(got, "server_version=") ||
		!strings.Contains(got, "server_commit=") ||
		!strings.Contains(got, manifestPath+": ok id=test.valid version=0.1.0-alpha.1 schema=lattice.plugin.manifest.v2") {
		t.Fatalf("missing build evidence or ok line:\n%s", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestRunRejectsManifestTheServerValidatorRejects(t *testing.T) {
	manifestPath := writeManifest(t, "bad.json", `{
		"schema":"lattice.plugin.manifest.v2",
		"id":"test.bad",
		"name":"Bad Test Plugin",
		"type":"system",
		"capabilities":["not:a-capability"],
		"version":"0.1.0-alpha.1",
		"bundle":{"format":"tar+gzip","digest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"runtime":{"protocol":"stdio-json-v1","entrypoints":{"linux/amd64":"bin/plugin"}},
		"compatibility":{"server":">=0.2.0","dashboard_host":">=0.2.0","runtime_protocol":"stdio-json-v1"}
	}`)

	var stdout, stderr bytes.Buffer
	if code := run([]string{manifestPath}, &stdout, &stderr); code != 1 {
		t.Fatalf("run exit=%d, want 1; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "server_version=") {
		t.Fatalf("validator must still print build evidence on failure:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), `capability "not:a-capability" is not recognized`) {
		t.Fatalf("missing validator rejection in stderr:\n%s", stderr.String())
	}
}

func TestRunRejectsMissingBackingFixture(t *testing.T) {
	manifestPath := writeManifest(t, "missing-backing.json", `{
		"schema":"lattice.plugin.manifest.v2",
		"id":"test.backing",
		"name":"Missing Backing",
		"type":"system",
		"capabilities":["kv:read"],
		"version":"0.1.0-alpha.1",
		"bundle":{"format":"tar+gzip","digest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"runtime":{"protocol":"stdio-json-v1","entrypoints":{"linux/amd64":"bin/plugin"}},
		"compatibility":{"server":">=0.2.0","dashboard_host":">=0.2.0","runtime_protocol":"stdio-json-v1"},
		"interfaces":[{"service":"test.backing/items","methods":[{"name":"list","effect":"read"}]}]
	}`)

	var stdout, stderr bytes.Buffer
	if code := run([]string{manifestPath}, &stdout, &stderr); code != 1 {
		t.Fatalf("run exit=%d, want 1; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), `must declare backing ("runtime" or "core")`) {
		t.Fatalf("missing backing rejection in stderr:\n%s", stderr.String())
	}
}

func TestRunVersionOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "lattice-plugin-manifest-check server_module=") {
		t.Fatalf("missing version output:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func writeManifest(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}
