package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const migrationUsage = `usage:
  lattice-server migrate json-to-bolt -json <state.json> -bolt <state.db> [-master-key-file <path>] [-overwrite]
  lattice-server migrate bolt-to-json -bolt <state.db> -json <state.json> [-master-key-file <path>] [-overwrite]
`

type migrationCommandConfig struct {
	jsonPath      string
	boltPath      string
	masterKeyFile string
	overwrite     bool
}

func runMigrationCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, migrationUsage)
		return errors.New("missing migration command")
	}
	switch args[0] {
	case "json-to-bolt":
		return runJSONToBoltMigration(args[1:], stdout, stderr)
	case "bolt-to-json":
		return runBoltToJSONMigration(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, migrationUsage)
		return nil
	default:
		fmt.Fprint(stderr, migrationUsage)
		return fmt.Errorf("unknown migration command %q", args[0])
	}
}

func runJSONToBoltMigration(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseMigrationCommand("json-to-bolt", args, stderr)
	if err != nil {
		return err
	}
	key, err := resolveMigrationCipher(cfg)
	if err != nil {
		return err
	}
	if key.Generated {
		return errors.New("migration refused to generate a new master key")
	}
	if err := store.MigrateJSONToBolt(cfg.jsonPath, cfg.boltPath, key.Cipher, store.MigrationOptions{Overwrite: cfg.overwrite}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "migrated JSON state %s -> bbolt %s (key=%s, overwrite=%t)\n", cfg.jsonPath, cfg.boltPath, key.Source, cfg.overwrite)
	return nil
}

func runBoltToJSONMigration(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseMigrationCommand("bolt-to-json", args, stderr)
	if err != nil {
		return err
	}
	key, err := resolveMigrationCipher(cfg)
	if err != nil {
		return err
	}
	if key.Generated {
		return errors.New("migration refused to generate a new master key")
	}
	if err := store.ExportBoltToJSON(cfg.boltPath, cfg.jsonPath, key.Cipher, store.MigrationOptions{Overwrite: cfg.overwrite}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "exported bbolt state %s -> JSON %s (key=%s, overwrite=%t)\n", cfg.boltPath, cfg.jsonPath, key.Source, cfg.overwrite)
	return nil
}

func parseMigrationCommand(name string, args []string, stderr io.Writer) (migrationCommandConfig, error) {
	var cfg migrationCommandConfig
	var dataAlias string
	fs := flag.NewFlagSet("migrate "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.jsonPath, "json", "", "JSON state path")
	fs.StringVar(&dataAlias, "data", "", "alias for -json")
	fs.StringVar(&cfg.boltPath, "bolt", "", "bbolt state path")
	fs.StringVar(&cfg.masterKeyFile, "master-key-file", env("LATTICE_MASTER_KEY_FILE", ""), "at-rest encryption master key file")
	fs.BoolVar(&cfg.overwrite, "overwrite", false, "overwrite an existing target file")
	fs.Usage = func() { fmt.Fprint(stderr, migrationUsage) }
	if err := fs.Parse(args); err != nil {
		return migrationCommandConfig{}, err
	}
	if fs.NArg() != 0 {
		return migrationCommandConfig{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if cfg.jsonPath != "" && dataAlias != "" && cfg.jsonPath != dataAlias {
		return migrationCommandConfig{}, errors.New("-json and -data point to different paths")
	}
	if cfg.jsonPath == "" {
		cfg.jsonPath = dataAlias
	}
	if cfg.jsonPath == "" {
		return migrationCommandConfig{}, errors.New("-json is required")
	}
	if cfg.boltPath == "" {
		return migrationCommandConfig{}, errors.New("-bolt is required")
	}
	return cfg, nil
}

func resolveMigrationCipher(cfg migrationCommandConfig) (secret.ResolveResult, error) {
	dataDir := filepath.Dir(cfg.jsonPath)
	if cfg.masterKeyFile == "" && os.Getenv(secret.EnvMasterKey) == "" && os.Getenv(secret.EnvMasterKeyFile) == "" {
		keyFile := filepath.Join(dataDir, secret.DefaultKeyFile)
		if _, err := os.Stat(keyFile); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return secret.ResolveResult{}, fmt.Errorf("master key file %s does not exist; pass -master-key-file, set %s, set %s to a key, or set %s=disabled for legacy plaintext state", keyFile, secret.EnvMasterKeyFile, secret.EnvMasterKey, secret.EnvMasterKey)
			}
			return secret.ResolveResult{}, err
		}
	}
	return secret.Resolve(dataDir, cfg.masterKeyFile)
}
