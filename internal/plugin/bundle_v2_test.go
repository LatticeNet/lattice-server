package plugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testArchiveEntry struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
}

func makeTestArchive(t *testing.T, entries ...testArchiveEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		size := int64(len(entry.body))
		if typeflag != tar.TypeReg && typeflag != tar.TypeRegA {
			size = 0
		}
		h := &tar.Header{Name: entry.name, Typeflag: typeflag, Mode: 0o777, Size: size, Linkname: entry.linkname}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := tw.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testManifestForArchive(archive []byte) Manifest {
	m := validManifestV2()
	m.Bundle.DigestSHA256 = DigestSHA256(archive)
	m.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(testV2PrivateKey(), SigningPayload(m)))
	return m
}

func testV2PrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

func testV2TrustPolicy() TrustPolicy {
	return TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{
		"latticenet": testV2PrivateKey().Public().(ed25519.PublicKey),
	}}
}

func resignTestManifestV2(m Manifest) Manifest {
	m.SignatureEd25519 = ""
	m.SignatureEd25519 = base64.RawStdEncoding.EncodeToString(ed25519.Sign(testV2PrivateKey(), SigningPayload(m)))
	return m
}

func TestExtractBundleV2ValidArchive(t *testing.T) {
	script := []byte("#!/bin/sh\necho ok\n")
	archive := makeTestArchive(t,
		testArchiveEntry{name: "bin/linux-amd64/plugin", body: script},
		testArchiveEntry{name: "ui/index.html", body: []byte("<main>Example</main>")},
		testArchiveEntry{name: "ui/assets/app.123.js", body: []byte("postMessage('ready')")},
	)
	m := testManifestForArchive(archive)
	cache := t.TempDir()
	got, err := ExtractBundleV2(cache, m, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != m.Bundle.DigestSHA256 || got.Root == "" || got.RuntimePath == "" || got.UIEntry == "" {
		t.Fatalf("incomplete extraction result: %+v", got)
	}
	if got.RuntimePath != filepath.Join(got.Root, "bin", "linux-amd64", "plugin") {
		t.Fatalf("runtime path escaped or was not selected: %q", got.RuntimePath)
	}
	if got.UIEntry != filepath.Join(got.Root, "ui", "index.html") || got.UIRoot != filepath.Join(got.Root, "ui") {
		t.Fatalf("unexpected UI paths: root=%q entry=%q", got.UIRoot, got.UIEntry)
	}
	if len(got.Inventory) != 3 || got.Inventory["ui/assets/app.123.js"].SHA256 == "" {
		t.Fatalf("unexpected inventory: %+v", got.Inventory)
	}
	for path, wantMode := range map[string]os.FileMode{
		got.RuntimePath: 0o700,
		got.UIEntry:     0o600,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != wantMode || !info.Mode().IsRegular() {
			t.Fatalf("%s mode=%v want regular %v", path, info.Mode(), wantMode)
		}
	}

	again, err := ExtractBundleV2(cache, m, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if again.Root != got.Root {
		t.Fatalf("content-addressed extraction was not reused: %q != %q", again.Root, got.Root)
	}
}

func TestExtractBundleV2ChecksDigestBeforeGzip(t *testing.T) {
	m := validManifestV2()
	m.Bundle.DigestSHA256 = strings.Repeat("0", 64)
	m = resignTestManifestV2(m)
	_, err := ExtractBundleV2(t.TempDir(), m, []byte("not gzip"), "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy())
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch before gzip error, got %v", err)
	}
}

func TestExtractBundleV2RejectsArchiveAttacks(t *testing.T) {
	limits := BundleLimits{
		MaxCompressedBytes: 1 << 20,
		MaxExpandedBytes:   20,
		MaxFileBytes:       12,
		MaxFiles:           2,
		MaxPathBytes:       40,
		MaxDepth:           3,
	}
	tests := []struct {
		name    string
		entries []testArchiveEntry
		edit    func(*BundleLimits)
		want    string
	}{
		{"parent traversal", []testArchiveEntry{{name: "../escape", body: []byte("x")}}, nil, "invalid path"},
		{"absolute path", []testArchiveEntry{{name: "/absolute", body: []byte("x")}}, nil, "invalid path"},
		{"nested traversal", []testArchiveEntry{{name: "a/../../escape", body: []byte("x")}}, nil, "invalid path"},
		{"windows separator", []testArchiveEntry{{name: `a\windows`, body: []byte("x")}}, nil, "invalid path"},
		{"control character", []testArchiveEntry{{name: "a\nb", body: []byte("x")}}, nil, "invalid path"},
		{"non-normal path", []testArchiveEntry{{name: "a//b", body: []byte("x")}}, nil, "invalid path"},
		{"duplicate path", []testArchiveEntry{{name: "a", body: []byte("x")}, {name: "a", body: []byte("y")}}, nil, "duplicate"},
		{"symlink", []testArchiveEntry{{name: "a", typeflag: tar.TypeSymlink, linkname: "b"}}, nil, "entry type"},
		{"hardlink", []testArchiveEntry{{name: "a", typeflag: tar.TypeLink, linkname: "b"}}, nil, "entry type"},
		{"fifo", []testArchiveEntry{{name: "a", typeflag: tar.TypeFifo}}, nil, "entry type"},
		{"device", []testArchiveEntry{{name: "a", typeflag: tar.TypeChar}}, nil, "entry type"},
		{"too many files", []testArchiveEntry{{name: "a", body: []byte("x")}, {name: "b", body: []byte("x")}, {name: "c", body: []byte("x")}}, nil, "file count"},
		{"too many directories", []testArchiveEntry{{name: "a/", typeflag: tar.TypeDir}, {name: "b/", typeflag: tar.TypeDir}, {name: "c/", typeflag: tar.TypeDir}}, nil, "file count"},
		{"file too large", []testArchiveEntry{{name: "a", body: []byte("0123456789abc")}}, nil, "file size"},
		{"expanded too large", []testArchiveEntry{{name: "a", body: []byte("0123456789a")}, {name: "b", body: []byte("0123456789a")}}, nil, "expanded size"},
		{"path too deep", []testArchiveEntry{{name: "a/b/c/d", body: []byte("x")}}, nil, "path depth"},
		{"path too long", []testArchiveEntry{{name: strings.Repeat("a", 41), body: []byte("x")}}, nil, "path length"},
		{"compressed too large", []testArchiveEntry{{name: "a", body: []byte("x")}}, func(l *BundleLimits) { l.MaxCompressedBytes = 1 }, "compressed size"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			archive := makeTestArchive(t, tc.entries...)
			m := testManifestForArchive(archive)
			gotLimits := limits
			if tc.edit != nil {
				tc.edit(&gotLimits)
			}
			cache := t.TempDir()
			_, err := ExtractBundleV2(cache, m, archive, "linux/amd64", gotLimits, testV2TrustPolicy())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
			entries, readErr := os.ReadDir(cache)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failed extraction left cache residue: %+v", entries)
			}
		})
	}
}

func TestExtractBundleV2RejectsMissingDeclaredFilesAndTamperedCache(t *testing.T) {
	archive := makeTestArchive(t,
		testArchiveEntry{name: "bin/linux-amd64/plugin", body: []byte("runtime")},
		testArchiveEntry{name: "ui/index.html", body: []byte("ui")},
	)
	m := testManifestForArchive(archive)

	missingRuntime := cloneManifestV2(t, m)
	missingRuntime.Runtime.Entrypoints["linux/amd64"] = "bin/linux-amd64/missing"
	missingRuntime = resignTestManifestV2(missingRuntime)
	if _, err := ExtractBundleV2(t.TempDir(), missingRuntime, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy()); err == nil || !strings.Contains(err.Error(), "runtime entrypoint") {
		t.Fatalf("expected missing runtime rejection, got %v", err)
	}

	missingUI := cloneManifestV2(t, m)
	missingUI.UIRuntime.Entrypoint = "ui/missing.html"
	missingUI = resignTestManifestV2(missingUI)
	if _, err := ExtractBundleV2(t.TempDir(), missingUI, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy()); err == nil || !strings.Contains(err.Error(), "ui entrypoint") {
		t.Fatalf("expected missing UI rejection, got %v", err)
	}

	cache := t.TempDir()
	got, err := ExtractBundleV2(cache, m, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(got.RuntimePath, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractBundleV2(cache, m, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy()); err == nil || !strings.Contains(err.Error(), "cached bundle") {
		t.Fatalf("expected tampered cache rejection, got %v", err)
	}
}

func TestExtractBundleV2RejectsTruncatedFileBody(t *testing.T) {
	// A hand-built tar header can claim more bytes than are present. The extractor
	// must surface the read failure instead of accepting a short file.
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "bin/linux-amd64/plugin", Typeflag: tar.TypeReg, Mode: 0o700, Size: 10}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(tw, "short")
	_ = zw.Close()
	archive := raw.Bytes()
	m := testManifestForArchive(archive)
	if _, err := ExtractBundleV2(t.TempDir(), m, archive, "linux/amd64", DefaultBundleLimits(), testV2TrustPolicy()); err == nil {
		t.Fatal("expected truncated archive rejection")
	}
}
