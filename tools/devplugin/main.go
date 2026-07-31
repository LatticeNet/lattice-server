// Command devplugin supports local plugin development with per-developer keys.
// It is deliberately dev-only: publishers must be named dev.<handle>, generated
// files stay local, and production trust evaluation remains in internal/plugin.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/LatticeNet/lattice-server/internal/plugin"
)

type trustPolicyFile struct {
	AllowUnsignedHostRisk bool              `json:"allow_unsigned_host_risk"`
	TrustedPublishers     map[string]string `json:"trusted_publishers"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "devplugin: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  devplugin keygen -publisher dev.<handle> -seed <path> -trust <path>")
	fmt.Fprintln(w, "  devplugin sign -publisher dev.<handle> -seed <path> -manifest <manifest.json> -artifact <bundle.tar.gz> -output <manifest.dev.json>")
}

func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	publisher := fs.String("publisher", "", "dev publisher id, e.g. dev.alice")
	seedPath := fs.String("seed", "", "path for the local 32-byte ed25519 seed")
	trustPath := fs.String("trust", "", "path for the local plugin trust JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := requireDevPublisher(*publisher); err != nil {
		fmt.Fprintf(stderr, "devplugin keygen: %v\n", err)
		return 2
	}
	if *seedPath == "" || *trustPath == "" {
		fmt.Fprintln(stderr, "devplugin keygen: -seed and -trust are required")
		return 2
	}
	if samePath(*seedPath, *trustPath) {
		fmt.Fprintln(stderr, "devplugin keygen: -seed and -trust must be separate files")
		return 2
	}
	if err := requireNewLocalFile(*seedPath); err != nil {
		fmt.Fprintf(stderr, "devplugin keygen: seed destination: %v\n", err)
		return 1
	}
	if err := requireNewLocalFile(*trustPath); err != nil {
		fmt.Fprintf(stderr, "devplugin keygen: trust destination: %v\n", err)
		return 1
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(stderr, "devplugin keygen: generate key: %v\n", err)
		return 1
	}
	seed := priv.Seed()
	if err := writeNewLocalFile(*seedPath, seed, 0o600); err != nil {
		fmt.Fprintf(stderr, "devplugin keygen: write seed: %v\n", err)
		return 1
	}

	trust := trustPolicyFile{
		AllowUnsignedHostRisk: false,
		TrustedPublishers: map[string]string{
			*publisher: base64.StdEncoding.EncodeToString(pub),
		},
	}
	raw, err := json.MarshalIndent(trust, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "devplugin keygen: marshal trust policy: %v\n", err)
		return 1
	}
	raw = append(raw, '\n')
	if err := writeNewLocalFile(*trustPath, raw, 0o600); err != nil {
		_ = os.Remove(*seedPath)
		fmt.Fprintf(stderr, "devplugin keygen: write trust policy: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "publisher: %s\n", *publisher)
	fmt.Fprintf(stdout, "public key: %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Fprintf(stdout, "seed: %s\n", *seedPath)
	fmt.Fprintf(stdout, "trust: %s\n", *trustPath)
	return 0
}

func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	publisher := fs.String("publisher", "", "dev publisher id, e.g. dev.alice")
	seedPath := fs.String("seed", "", "path to the local 32-byte ed25519 seed")
	manifestPath := fs.String("manifest", "", "source manifest.json")
	artifactPath := fs.String("artifact", "", "packaged plugin artifact")
	outputPath := fs.String("output", "", "dev manifest output path, or '-' for stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := requireDevPublisher(*publisher); err != nil {
		fmt.Fprintf(stderr, "devplugin sign: %v\n", err)
		return 2
	}
	if *seedPath == "" || *manifestPath == "" || *artifactPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "devplugin sign: -seed, -manifest, -artifact, and -output are required")
		return 2
	}
	if *outputPath != "-" && samePath(*outputPath, *manifestPath) {
		fmt.Fprintln(stderr, "devplugin sign: -output must not overwrite the checked-in source manifest")
		return 2
	}
	if *outputPath != "-" {
		if err := rejectInputAlias(*outputPath, *seedPath, *manifestPath, *artifactPath); err != nil {
			fmt.Fprintf(stderr, "devplugin sign: output destination: %v\n", err)
			return 2
		}
	}

	priv, pub, err := readSeed(*seedPath)
	if err != nil {
		fmt.Fprintf(stderr, "devplugin sign: %v\n", err)
		return 1
	}
	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "devplugin sign: read manifest: %v\n", err)
		return 1
	}
	m, err := plugin.DecodeManifest(raw)
	if err != nil {
		fmt.Fprintf(stderr, "devplugin sign: %v\n", err)
		return 1
	}
	artifact, err := os.ReadFile(*artifactPath)
	if err != nil {
		fmt.Fprintf(stderr, "devplugin sign: read artifact: %v\n", err)
		return 1
	}

	m.Publisher = *publisher
	m.SignatureEd25519 = ""
	if m.Schema == plugin.ManifestSchemaV2 && m.Bundle != nil {
		m.Bundle.DigestSHA256 = plugin.DigestSHA256(artifact)
	} else {
		m.DigestSHA256 = plugin.DigestSHA256(artifact)
	}
	m.SignatureEd25519 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, plugin.SigningPayload(m)))

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "devplugin sign: marshal manifest: %v\n", err)
		return 1
	}
	out = append(out, '\n')

	policy := plugin.TrustPolicy{TrustedPublishers: map[string]ed25519.PublicKey{*publisher: pub}}
	if _, err := plugin.VerifyInstallManifest(out, artifact, policy); err != nil {
		fmt.Fprintf(stderr, "devplugin sign: server-parity verification failed: %v\n", err)
		return 1
	}

	if *outputPath == "-" {
		if _, err := stdout.Write(out); err != nil {
			fmt.Fprintf(stderr, "devplugin sign: write stdout: %v\n", err)
			return 1
		}
		return 0
	}
	if err := writeAtomicLocalFile(*outputPath, out, 0o600); err != nil {
		fmt.Fprintf(stderr, "devplugin sign: write manifest: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "publisher: %s\n", *publisher)
	fmt.Fprintf(stdout, "public key: %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Fprintf(stdout, "artifact digest_sha256: %s\n", plugin.DigestSHA256(artifact))
	fmt.Fprintf(stdout, "manifest: %s\n", *outputPath)
	fmt.Fprintln(stdout, "server-parity verification: OK")
	return 0
}

func requireDevPublisher(publisher string) error {
	if publisher == "" {
		return errors.New("-publisher is required")
	}
	if !strings.HasPrefix(publisher, "dev.") || len(publisher) == len("dev.") {
		return fmt.Errorf("publisher %q must be named dev.<handle>", publisher)
	}
	raw, err := json.Marshal(trustPolicyFile{
		TrustedPublishers: map[string]string{
			publisher: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		},
	})
	if err != nil {
		return err
	}
	if _, err := plugin.ParseTrustPolicyJSON(raw); err != nil {
		return err
	}
	return nil
}

func readSeed(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

var verifyLocalFileMode = verifyMode

func requireNewLocalFile(path string) error {
	if path == "" {
		return errors.New("empty path")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", path)
		}
		return fmt.Errorf("%s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func rejectInputAlias(output string, inputs ...string) error {
	if output == "" {
		return errors.New("empty path")
	}
	if info, err := os.Lstat(output); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", output)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, input := range inputs {
		if input == "" {
			continue
		}
		if samePath(output, input) {
			return fmt.Errorf("%s aliases input %s", output, input)
		}
		outInfo, outErr := os.Stat(output)
		inInfo, inErr := os.Stat(input)
		if outErr == nil && inErr == nil && os.SameFile(outInfo, inInfo) {
			return fmt.Errorf("%s aliases input %s", output, input)
		}
	}
	return nil
}

func writeNewLocalFile(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := requireNewLocalFile(path); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := verifyLocalFileMode(tmpPath, perm); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	if err := verifyLocalFileMode(path, perm); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func writeAtomicLocalFile(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return verifyLocalFileMode(path, perm)
}

func verifyMode(path string, perm os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if got := info.Mode().Perm(); got != perm {
		return fmt.Errorf("%s mode: got %o want %o", path, got, perm)
	}
	return nil
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return aa == bb
}
