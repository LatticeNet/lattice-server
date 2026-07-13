package plugin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Bundle layout on disk: each plugin lives in its own directory under the
// loader's root and contains exactly two files:
//
//	<bundle>/manifest.json   the signed manifest
//	<bundle>/artifact        the artifact bytes the manifest's digest pins
//
// The manifest Entrypoint is metadata describing the artifact; the artifact file
// name is fixed so an untrusted manifest cannot point the loader at an arbitrary
// path before verification.
const (
	manifestFileName = "manifest.json"
	artifactFileName = "artifact"
)

// Loaded is a verified, registered plugin: the decoded manifest plus the
// capabilities the trust policy granted at load time. Execution (host-API binding
// and invocation) is a later milestone; loading establishes the verified registry
// and is the point at which signature/digest/capability trust is enforced.
type Loaded struct {
	Manifest       Manifest
	Capabilities   []string
	BundlePath     string
	ArtifactPath   string
	ArtifactDigest string
	ExtractedRoot  string
	RuntimeEntry   string
	RuntimePath    string
	UIRoot         string
	UIEntry        string
	Inventory      map[string]BundleFile
	BundleLimits   BundleLimits
}

// LoadOutcome records the result of attempting to load one bundle so the caller
// can audit every accept and reject.
type LoadOutcome struct {
	BundlePath string
	PluginID   string
	Loaded     bool
	Reason     string // failure reason when Loaded is false
}

// Loader discovers and verifies plugin bundles under Dir against an operator
// TrustPolicy. It never executes anything; it only decides what is trusted enough
// to register.
type Loader struct {
	Dir      string
	CacheDir string
	Platform string
	Limits   BundleLimits
	Policy   TrustPolicy
}

// Load scans the plugin directory and verifies each bundle. It returns the
// verified plugins (sorted by id) and a per-bundle outcome log. A bundle that
// fails verification is skipped and recorded as a failure — one bad bundle never
// aborts the scan or blocks startup. A missing/empty directory loads nothing.
func (l Loader) Load() ([]Loaded, []LoadOutcome, error) {
	if l.Dir == "" {
		return nil, nil, nil
	}
	entries, err := os.ReadDir(l.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read plugin dir: %w", err)
	}
	var loaded []Loaded
	var outcomes []LoadOutcome
	var verified []Loaded
	var verifiedOutcomeIndexes []int
	verifiedCounts := map[string]int{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		bundle := filepath.Join(l.Dir, entry.Name())
		got, err := l.loadBundle(bundle)
		if err != nil {
			outcomes = append(outcomes, LoadOutcome{BundlePath: bundle, Loaded: false, Reason: err.Error()})
			continue
		}
		outcomes = append(outcomes, LoadOutcome{BundlePath: bundle, PluginID: got.Manifest.ID, Loaded: true})
		verified = append(verified, got)
		verifiedOutcomeIndexes = append(verifiedOutcomeIndexes, len(outcomes)-1)
		verifiedCounts[got.Manifest.ID]++
	}
	for i, got := range verified {
		if verifiedCounts[got.Manifest.ID] > 1 {
			outcome := &outcomes[verifiedOutcomeIndexes[i]]
			outcome.Loaded = false
			outcome.Reason = fmt.Sprintf("duplicate plugin id %q", got.Manifest.ID)
			continue
		}
		loaded = append(loaded, got)
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].Manifest.ID < loaded[j].Manifest.ID })
	return loaded, outcomes, nil
}

func (l Loader) loadBundle(bundle string) (Loaded, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(bundle, manifestFileName))
	if err != nil {
		return Loaded{}, fmt.Errorf("read manifest: %w", err)
	}
	m, err := DecodeManifest(manifestBytes)
	if err != nil {
		return Loaded{}, err
	}
	artifactPath := filepath.Join(bundle, artifactFileName)
	artifact, err := l.readArtifact(artifactPath, m.Schema == ManifestSchemaV2)
	if err != nil {
		return Loaded{}, fmt.Errorf("read artifact: %w", err)
	}
	if err := VerifyManifest(m, artifact, l.Policy); err != nil {
		return Loaded{}, err
	}
	caps := append([]string(nil), m.Capabilities...)
	sort.Strings(caps)
	loaded := Loaded{
		Manifest: m, Capabilities: caps, BundlePath: bundle,
		ArtifactPath: artifactPath, ArtifactDigest: manifestArtifactDigest(m),
		BundleLimits: l.Limits,
	}
	if m.Schema != ManifestSchemaV2 {
		return loaded, nil
	}
	if l.CacheDir == "" {
		return Loaded{}, errors.New("manifest v2 requires a bundle cache directory")
	}
	platform := l.Platform
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}
	extracted, err := ExtractBundleV2(l.CacheDir, m, artifact, platform, l.Limits, l.Policy)
	if err != nil {
		return Loaded{}, err
	}
	loaded.ExtractedRoot = extracted.Root
	loaded.RuntimeEntry = m.Runtime.Entrypoints[platform]
	loaded.RuntimePath = extracted.RuntimePath
	loaded.UIRoot = extracted.UIRoot
	loaded.UIEntry = extracted.UIEntry
	loaded.Inventory = extracted.Inventory
	return loaded, nil
}

func (l Loader) readArtifact(artifactPath string, bounded bool) ([]byte, error) {
	if !bounded {
		return os.ReadFile(artifactPath)
	}
	limit := normalizedBundleLimits(l.Limits).MaxCompressedBytes
	return readBoundedRegularFile(artifactPath, limit)
}

func readBoundedRegularFile(filePath string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("file size limit must be positive")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("artifact is not a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("bundle compressed size %d exceeds limit %d", info.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("bundle compressed size exceeds limit %d", limit)
	}
	return data, nil
}
