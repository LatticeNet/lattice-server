package plugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	defaultMaxCompressedBundleBytes = int64(64 << 20)
	defaultMaxExpandedBundleBytes   = int64(256 << 20)
	defaultMaxBundleFileBytes       = int64(32 << 20)
	defaultMaxBundleFiles           = 2048
	defaultMaxBundlePathBytes       = 240
	defaultMaxBundleDepth           = 16
)

type BundleLimits struct {
	MaxCompressedBytes int64
	MaxExpandedBytes   int64
	MaxFileBytes       int64
	MaxFiles           int
	MaxPathBytes       int
	MaxDepth           int
}

func DefaultBundleLimits() BundleLimits {
	return BundleLimits{
		MaxCompressedBytes: defaultMaxCompressedBundleBytes,
		MaxExpandedBytes:   defaultMaxExpandedBundleBytes,
		MaxFileBytes:       defaultMaxBundleFileBytes,
		MaxFiles:           defaultMaxBundleFiles,
		MaxPathBytes:       defaultMaxBundlePathBytes,
		MaxDepth:           defaultMaxBundleDepth,
	}
}

type BundleFile struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type ExtractedBundle struct {
	Root        string
	RuntimePath string
	UIRoot      string
	UIEntry     string
	Digest      string
	Inventory   map[string]BundleFile
}

// ExtractBundleV2 verifies the signed compressed bytes before parsing, expands
// into a fresh cache-local staging directory, and publishes a content-addressed
// immutable tree. Existing cache entries are reused only after byte-for-byte
// hash, size, type, mode, and tree membership validation against this extraction.
func ExtractBundleV2(cacheDir string, manifest Manifest, artifact []byte, platform string, limits BundleLimits, policy TrustPolicy) (ExtractedBundle, error) {
	if manifest.Schema != ManifestSchemaV2 {
		return ExtractedBundle{}, errors.New("bundle extraction requires manifest schema v2")
	}
	if cacheDir == "" {
		return ExtractedBundle{}, errors.New("bundle extraction requires a cache directory")
	}
	limits = normalizedBundleLimits(limits)
	if int64(len(artifact)) > limits.MaxCompressedBytes {
		return ExtractedBundle{}, fmt.Errorf("bundle compressed size %d exceeds limit %d", len(artifact), limits.MaxCompressedBytes)
	}
	// VerifyManifest checks the compressed digest and trusted publisher signature;
	// both complete before gzip.NewReader sees attacker-controlled bytes.
	if err := VerifyManifest(manifest, artifact, policy); err != nil {
		return ExtractedBundle{}, err
	}
	runtimeEntry, ok := manifest.Runtime.Entrypoints[platform]
	if !ok {
		return ExtractedBundle{}, fmt.Errorf("manifest has no runtime entrypoint for platform %q", platform)
	}

	resolvedCache, err := prepareBundleCache(cacheDir)
	if err != nil {
		return ExtractedBundle{}, err
	}
	staging, err := os.MkdirTemp(resolvedCache, ".bundle-v2-")
	if err != nil {
		return ExtractedBundle{}, fmt.Errorf("create bundle staging directory: %w", err)
	}
	if err := os.Chmod(staging, 0o700); err != nil {
		_ = os.RemoveAll(staging)
		return ExtractedBundle{}, fmt.Errorf("secure bundle staging directory: %w", err)
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = os.RemoveAll(staging)
		}
	}()

	inventory, err := extractBundleArchive(staging, artifact, runtimeEntry, limits)
	if err != nil {
		return ExtractedBundle{}, err
	}
	if _, ok := inventory[runtimeEntry]; !ok {
		return ExtractedBundle{}, fmt.Errorf("declared runtime entrypoint %q is missing from bundle", runtimeEntry)
	}
	if manifest.UIRuntime != nil {
		if _, ok := inventory[manifest.UIRuntime.Entrypoint]; !ok {
			return ExtractedBundle{}, fmt.Errorf("declared ui entrypoint %q is missing from bundle", manifest.UIRuntime.Entrypoint)
		}
	}
	if err := syncTree(staging); err != nil {
		return ExtractedBundle{}, fmt.Errorf("sync extracted bundle: %w", err)
	}

	target := filepath.Join(resolvedCache, manifest.ID, manifest.Version, strings.ToLower(manifest.Bundle.DigestSHA256))
	if info, statErr := os.Lstat(target); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ExtractedBundle{}, errors.New("cached bundle target is not a regular directory")
		}
		if err := validateCachedBundle(staging, target, inventory); err != nil {
			return ExtractedBundle{}, fmt.Errorf("cached bundle validation failed: %w", err)
		}
		return extractedBundleResult(target, runtimeEntry, manifest.UIRuntime, manifest.Bundle.DigestSHA256, inventory), nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ExtractedBundle{}, fmt.Errorf("inspect cached bundle: %w", statErr)
	}

	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return ExtractedBundle{}, fmt.Errorf("create bundle cache parent: %w", err)
	}
	if err := secureDirectoryChain(resolvedCache, parent); err != nil {
		return ExtractedBundle{}, err
	}
	if err := os.Rename(staging, target); err != nil {
		// Another loader may have won the same content-addressed rename.
		if info, statErr := os.Lstat(target); statErr == nil && info.IsDir() {
			if validateErr := validateCachedBundle(staging, target, inventory); validateErr == nil {
				return extractedBundleResult(target, runtimeEntry, manifest.UIRuntime, manifest.Bundle.DigestSHA256, inventory), nil
			}
		}
		return ExtractedBundle{}, fmt.Errorf("publish extracted bundle: %w", err)
	}
	keepStaging = true
	if err := syncDir(parent); err != nil {
		return ExtractedBundle{}, fmt.Errorf("sync bundle cache parent: %w", err)
	}
	return extractedBundleResult(target, runtimeEntry, manifest.UIRuntime, manifest.Bundle.DigestSHA256, inventory), nil
}

func normalizedBundleLimits(in BundleLimits) BundleLimits {
	defaults := DefaultBundleLimits()
	if in.MaxCompressedBytes <= 0 {
		in.MaxCompressedBytes = defaults.MaxCompressedBytes
	}
	if in.MaxExpandedBytes <= 0 {
		in.MaxExpandedBytes = defaults.MaxExpandedBytes
	}
	if in.MaxFileBytes <= 0 {
		in.MaxFileBytes = defaults.MaxFileBytes
	}
	if in.MaxFiles <= 0 {
		in.MaxFiles = defaults.MaxFiles
	}
	if in.MaxPathBytes <= 0 {
		in.MaxPathBytes = defaults.MaxPathBytes
	}
	if in.MaxDepth <= 0 {
		in.MaxDepth = defaults.MaxDepth
	}
	return in
}

func prepareBundleCache(cacheDir string) (string, error) {
	abs, err := filepath.Abs(cacheDir)
	if err != nil {
		return "", fmt.Errorf("resolve bundle cache: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", fmt.Errorf("create bundle cache: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve bundle cache symlinks: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect bundle cache: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("bundle cache must resolve to a directory")
	}
	if err := os.Chmod(resolved, 0o700); err != nil {
		return "", fmt.Errorf("secure bundle cache: %w", err)
	}
	return resolved, nil
}

func extractBundleArchive(root string, artifact []byte, runtimeEntry string, limits BundleLimits) (map[string]BundleFile, error) {
	zr, err := gzip.NewReader(bytes.NewReader(artifact))
	if err != nil {
		return nil, fmt.Errorf("open bundle gzip: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	inventory := map[string]BundleFile{}
	seen := map[string]bool{}
	entries := 0
	var expanded int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read bundle tar: %w", err)
		}
		isDir := hdr.Typeflag == tar.TypeDir
		if !isDir && hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("bundle entry type %d is not allowed for %q", hdr.Typeflag, hdr.Name)
		}
		entries++
		if entries > limits.MaxFiles {
			return nil, fmt.Errorf("bundle file count exceeds limit %d", limits.MaxFiles)
		}
		rel, err := normalizeArchivePath(hdr.Name, isDir, limits)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[rel]; duplicate {
			return nil, fmt.Errorf("bundle contains duplicate path %q", rel)
		}
		if err := validateArchiveHierarchy(seen, rel, isDir); err != nil {
			return nil, err
		}
		seen[rel] = isDir
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if isDir {
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return nil, fmt.Errorf("create bundle directory %q: %w", rel, err)
			}
			if err := os.Chmod(dst, 0o700); err != nil {
				return nil, fmt.Errorf("secure bundle directory %q: %w", rel, err)
			}
			continue
		}
		if hdr.Size < 0 || hdr.Size > limits.MaxFileBytes {
			return nil, fmt.Errorf("bundle file size %d exceeds limit %d for %q", hdr.Size, limits.MaxFileBytes, rel)
		}
		if hdr.Size > limits.MaxExpandedBytes-expanded {
			return nil, fmt.Errorf("bundle expanded size exceeds limit %d", limits.MaxExpandedBytes)
		}
		expanded += hdr.Size
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, fmt.Errorf("create bundle parent for %q: %w", rel, err)
		}
		mode := os.FileMode(0o600)
		if rel == runtimeEntry {
			mode = 0o700
		}
		file, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return nil, fmt.Errorf("create bundle file %q: %w", rel, err)
		}
		hash := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(file, hash), tr, hdr.Size)
		if copyErr == nil {
			copyErr = file.Sync()
		}
		closeErr := file.Close()
		if copyErr != nil {
			return nil, fmt.Errorf("write bundle file %q: %w", rel, copyErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close bundle file %q: %w", rel, closeErr)
		}
		if err := os.Chmod(dst, mode); err != nil {
			return nil, fmt.Errorf("normalize bundle file mode %q: %w", rel, err)
		}
		inventory[rel] = BundleFile{Size: hdr.Size, SHA256: hex.EncodeToString(hash.Sum(nil)), Mode: uint32(mode.Perm())}
	}
	return inventory, nil
}

func normalizeArchivePath(name string, isDir bool, limits BundleLimits) (string, error) {
	if name == "" || hasControl(name) || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("bundle invalid path %q", name)
	}
	value := name
	if isDir {
		value = strings.TrimSuffix(value, "/")
	}
	if value == "" || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return "", fmt.Errorf("bundle invalid path %q", name)
	}
	if len(value) > limits.MaxPathBytes {
		return "", fmt.Errorf("bundle path length exceeds limit %d for %q", limits.MaxPathBytes, name)
	}
	if depth := len(strings.Split(value, "/")); depth > limits.MaxDepth {
		return "", fmt.Errorf("bundle path depth %d exceeds limit %d for %q", depth, limits.MaxDepth, name)
	}
	return value, nil
}

func validateArchiveHierarchy(seen map[string]bool, rel string, isDir bool) error {
	for parent := path.Dir(rel); parent != "."; parent = path.Dir(parent) {
		if parentIsDir, ok := seen[parent]; ok && !parentIsDir {
			return fmt.Errorf("bundle path %q has file parent %q", rel, parent)
		}
	}
	if !isDir {
		prefix := rel + "/"
		for existing := range seen {
			if strings.HasPrefix(existing, prefix) {
				return fmt.Errorf("bundle file path %q is parent of %q", rel, existing)
			}
		}
	}
	return nil
}

func validateCachedBundle(staging, target string, inventory map[string]BundleFile) error {
	stagingDirs, err := treeDirectories(staging)
	if err != nil {
		return err
	}
	seenFiles := map[string]bool{}
	err = filepath.WalkDir(target, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == target {
			return nil
		}
		relOS, err := filepath.Rel(target, current)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(relOS)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("cached path %q is a symlink", rel)
		}
		if entry.IsDir() {
			if !stagingDirs[rel] || info.Mode().Perm() != 0o700 {
				return fmt.Errorf("cached directory %q is unexpected or has wrong mode", rel)
			}
			return nil
		}
		want, ok := inventory[rel]
		if !ok || !info.Mode().IsRegular() {
			return fmt.Errorf("cached file %q is unexpected or not regular", rel)
		}
		if info.Size() != want.Size || uint32(info.Mode().Perm()) != want.Mode {
			return fmt.Errorf("cached file %q metadata differs", rel)
		}
		digest, err := digestFile(current)
		if err != nil {
			return err
		}
		if digest != want.SHA256 {
			return fmt.Errorf("cached file %q digest differs", rel)
		}
		seenFiles[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seenFiles) != len(inventory) {
		return fmt.Errorf("cached bundle file count %d differs from expected %d", len(seenFiles), len(inventory))
	}
	return nil
}

func treeDirectories(root string) (map[string]bool, error) {
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if current == root || !entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = true
		return nil
	})
	return out, err
}

func digestFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func syncTree(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			dirs = append(dirs, current)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := syncDir(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

func syncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func secureDirectoryChain(root, leaf string) error {
	rel, err := filepath.Rel(root, leaf)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("bundle cache target escapes cache root")
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect bundle cache directory: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bundle cache path %q is not a regular directory", current)
		}
		if err := os.Chmod(current, 0o700); err != nil {
			return fmt.Errorf("secure bundle cache directory: %w", err)
		}
	}
	return nil
}

func extractedBundleResult(root, runtimeEntry string, ui *UIRuntimeSpec, digest string, inventory map[string]BundleFile) ExtractedBundle {
	result := ExtractedBundle{
		Root:        root,
		RuntimePath: filepath.Join(root, filepath.FromSlash(runtimeEntry)),
		Digest:      strings.ToLower(digest),
		Inventory:   cloneBundleInventory(inventory),
	}
	if ui != nil {
		result.UIRoot = filepath.Join(root, "ui")
		result.UIEntry = filepath.Join(root, filepath.FromSlash(ui.Entrypoint))
	}
	return result
}

func cloneBundleInventory(in map[string]BundleFile) map[string]BundleFile {
	out := make(map[string]BundleFile, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// ReadVerifiedBundleFile reads one inventory-pinned file from an extracted v2
// tree after rechecking path components, type, mode, size, and digest. Callers
// serve the returned immutable bytes rather than reopening a mutable path.
func ReadVerifiedBundleFile(loaded Loaded, rel string) ([]byte, BundleFile, error) {
	if loaded.Manifest.Schema != ManifestSchemaV2 || loaded.ExtractedRoot == "" || !safeBundlePath(rel) {
		return nil, BundleFile{}, errors.New("invalid extracted bundle file request")
	}
	want, ok := loaded.Inventory[rel]
	if !ok {
		return nil, BundleFile{}, errors.New("bundle file is not in verified inventory")
	}
	filePath := filepath.Join(loaded.ExtractedRoot, filepath.FromSlash(rel))
	if err := validateRuntimePath(loaded.ExtractedRoot, filePath, os.FileMode(want.Mode)); err != nil {
		return nil, BundleFile{}, err
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, BundleFile{}, err
	}
	if int64(len(data)) != want.Size || DigestSHA256(data) != want.SHA256 {
		return nil, BundleFile{}, errors.New("bundle file differs from verified inventory")
	}
	return data, want, nil
}
