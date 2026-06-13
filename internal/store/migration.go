package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/LatticeNet/lattice-server/internal/secret"
)

type MigrationOptions struct {
	Overwrite bool
}

func LoadJSONState(path string, cph secret.Cipher) (State, error) {
	if path == "" {
		return State{}, errors.New("json state path is required")
	}
	if cph == nil {
		cph = secret.Disabled()
	}
	st := emptyState()
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	if len(data) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, err
	}
	if err := decryptState(&st, cph); err != nil {
		return State{}, fmt.Errorf("load json state: %w", err)
	}
	st.ensureMaps()
	return st, nil
}

func WriteJSONState(path string, st State, cph secret.Cipher, opts MigrationOptions) error {
	if path == "" {
		return errors.New("json state path is required")
	}
	if cph == nil {
		cph = secret.Disabled()
	}
	if err := ensureWritableTarget(path, opts); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	persist, err := encryptedState(st, cph)
	if err != nil {
		return fmt.Errorf("encrypt json state: %w", err)
	}
	data, err := json.MarshalIndent(persist, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(path, data, 0o600, opts)
}

func MigrateJSONToBolt(jsonPath, boltPath string, cph secret.Cipher, opts MigrationOptions) error {
	if err := ensureWritableTarget(boltPath, opts); err != nil {
		return err
	}
	st, err := LoadJSONState(jsonPath, cph)
	if err != nil {
		return err
	}
	tmp, cleanup, err := migrationTempPath(boltPath)
	if err != nil {
		return err
	}
	defer cleanup()
	bs, err := OpenBoltState(tmp, cph)
	if err != nil {
		return err
	}
	if err := bs.ImportState(st); err != nil {
		bs.Close()
		return err
	}
	if err := bs.Close(); err != nil {
		return err
	}
	return replaceFile(tmp, boltPath, opts)
}

func ExportBoltToJSON(boltPath, jsonPath string, cph secret.Cipher, opts MigrationOptions) error {
	if err := ensureWritableTarget(jsonPath, opts); err != nil {
		return err
	}
	if err := requireReadableSource(boltPath, "bolt state"); err != nil {
		return err
	}
	bs, err := OpenBoltState(boltPath, cph)
	if err != nil {
		return err
	}
	st, err := bs.ExportState()
	closeErr := bs.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return WriteJSONState(jsonPath, st, cph, opts)
}

func ensureWritableTarget(path string, opts MigrationOptions) error {
	if path == "" {
		return errors.New("target path is required")
	}
	if opts.Overwrite {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("target already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func requireReadableSource(path, name string) error {
	if path == "" {
		return fmt.Errorf("%s path is required", name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s path is a directory: %s", name, path)
	}
	return nil
}

func migrationTempPath(path string) (string, func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", nil, err
	}
	tmp := f.Name()
	// Keep the reserved unique name on disk (do NOT remove it): a concurrent
	// migration cannot then grab the same path. The writer overwrites this
	// placeholder in place — os.WriteFile/writeSyncedFile truncates it, and
	// bbolt initializes an empty file as a fresh database.
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", nil, err
	}
	return tmp, func() { _ = os.Remove(tmp) }, nil
}

func replaceFile(tmp, target string, opts MigrationOptions) error {
	if !opts.Overwrite {
		return os.Rename(tmp, target)
	}
	backup, err := moveExistingTargetAside(target)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		if backup != "" {
			if restoreErr := os.Rename(backup, target); restoreErr != nil {
				return fmt.Errorf("replace %s: %w; restore existing target: %v", target, err, restoreErr)
			}
		}
		return err
	}
	if backup != "" {
		if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("replace %s: cleanup backup %s: %w", target, backup, err)
		}
	}
	return nil
}

func moveExistingTargetAside(target string) (string, error) {
	info, err := os.Stat(target)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("target path is a directory: %s", target)
	}
	f, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".backup-*")
	if err != nil {
		return "", err
	}
	backup := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(backup)
		return "", err
	}
	if err := os.Remove(backup); err != nil {
		return "", err
	}
	if err := os.Rename(target, backup); err != nil {
		return "", err
	}
	return backup, nil
}

func writeFileAtomically(path string, data []byte, perm os.FileMode, opts MigrationOptions) error {
	tmp, cleanup, err := migrationTempPath(path)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := writeSyncedFile(tmp, data, perm); err != nil {
		return err
	}
	if err := replaceFile(tmp, path, opts); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
