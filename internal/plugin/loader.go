package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Manifest     Manifest
	Capabilities []string
	BundlePath   string
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
	Dir    string
	Policy TrustPolicy
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
		loaded = append(loaded, got)
		outcomes = append(outcomes, LoadOutcome{BundlePath: bundle, PluginID: got.Manifest.ID, Loaded: true})
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].Manifest.ID < loaded[j].Manifest.ID })
	return loaded, outcomes, nil
}

func (l Loader) loadBundle(bundle string) (Loaded, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(bundle, manifestFileName))
	if err != nil {
		return Loaded{}, fmt.Errorf("read manifest: %w", err)
	}
	artifact, err := os.ReadFile(filepath.Join(bundle, artifactFileName))
	if err != nil {
		return Loaded{}, fmt.Errorf("read artifact: %w", err)
	}
	m, err := VerifyInstallManifest(manifestBytes, artifact, l.Policy)
	if err != nil {
		return Loaded{}, err
	}
	caps := append([]string(nil), m.Capabilities...)
	sort.Strings(caps)
	return Loaded{Manifest: m, Capabilities: caps, BundlePath: bundle}, nil
}
