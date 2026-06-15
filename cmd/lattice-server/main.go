package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LatticeNet/lattice-server/internal/logstore"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/secret"
	"github.com/LatticeNet/lattice-server/internal/selfdns"
	"github.com/LatticeNet/lattice-server/internal/server"
	"github.com/LatticeNet/lattice-server/internal/store"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err := runMigrationCLI(os.Args[2:], os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
			os.Exit(2)
		}
		return
	}

	var listen string
	var dataPath string
	var webRoot string
	var secureCookies bool
	var trustProxy bool
	var tlsCert string
	var tlsKey string
	var pluginDir string
	var pluginTrust string
	var masterKeyFile string
	var publicURL string
	var coreDNSVersion string
	var coreDNSURL string
	var coreDNSSHA256 string
	var printVersion bool
	flag.StringVar(&listen, "listen", env("LATTICE_LISTEN", "127.0.0.1:8088"), "listen address")
	flag.StringVar(&dataPath, "data", env("LATTICE_DATA", defaultDataPath()), "state file path")
	flag.StringVar(&webRoot, "web", env("LATTICE_WEB_ROOT", "../lattice-dashboard"), "static dashboard root")
	flag.BoolVar(&secureCookies, "secure-cookies", env("LATTICE_SECURE_COOKIES", "") == "1", "set Secure on session cookies (enables HSTS)")
	flag.BoolVar(&trustProxy, "trust-proxy", env("LATTICE_TRUST_PROXY", "") == "1", "trust CF-Connecting-IP / X-Forwarded-For for client IP (only behind a trusted proxy)")
	flag.StringVar(&tlsCert, "tls-cert", os.Getenv("LATTICE_TLS_CERT"), "TLS certificate file; enables HTTPS when set with -tls-key")
	flag.StringVar(&tlsKey, "tls-key", os.Getenv("LATTICE_TLS_KEY"), "TLS private key file")
	flag.StringVar(&pluginDir, "plugin-dir", env("LATTICE_PLUGIN_DIR", ""), "directory of installed plugin bundles (empty disables plugins)")
	flag.StringVar(&pluginTrust, "plugin-trust", env("LATTICE_PLUGIN_TRUST", ""), "path to the operator plugin trust policy JSON")
	flag.StringVar(&masterKeyFile, "master-key-file", env("LATTICE_MASTER_KEY_FILE", ""), "path to the at-rest encryption master key file (auto-generated under the data dir if unset)")
	flag.StringVar(&publicURL, "public-url", env("LATTICE_PUBLIC_URL", ""), "externally-reachable base URL (scheme+host), required for OIDC/SSO redirect")
	flag.StringVar(&coreDNSVersion, "coredns-binary-version", env("LATTICE_COREDNS_BINARY_VERSION", ""), "pinned CoreDNS binary version for self-host DNS apply (requires -coredns-binary-url and -coredns-binary-sha256)")
	flag.StringVar(&coreDNSURL, "coredns-binary-url", env("LATTICE_COREDNS_BINARY_URL", ""), "HTTPS URL to a direct CoreDNS executable binary for self-host DNS apply")
	flag.StringVar(&coreDNSSHA256, "coredns-binary-sha256", env("LATTICE_COREDNS_BINARY_SHA256", ""), "SHA-256 hex digest of the CoreDNS executable binary")
	flag.BoolVar(&printVersion, "version", false, "print lattice-server version and exit")
	flag.Parse()
	if printVersion {
		fmt.Printf("lattice-server %s (%s, %s)\n", version, commit, date)
		return
	}

	trustPolicy, err := loadPluginTrust(pluginTrust)
	if err != nil {
		log.Fatal(err)
	}
	if trustPolicy.AllowUnsignedHostRisk {
		log.Printf("WARNING: plugin trust policy sets allow_unsigned_host_risk=true; UNSIGNED host-risk plugins will load. Do not use in production.")
	}

	dataDir := ""
	if dataPath != "" {
		dataDir = filepath.Dir(dataPath)
	}
	keyRes, err := secret.Resolve(dataDir, masterKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	switch {
	case keyRes.Generated:
		log.Printf("at-rest encryption: generated a new master key at %s (0600) — back this up; losing it makes stored credentials unrecoverable", keyRes.KeyFilePath)
	case !keyRes.Cipher.Enabled():
		log.Printf("WARNING: at-rest encryption is DISABLED; stored credentials (TOTP secrets, API tokens, notify configs) are written in plaintext")
	default:
		log.Printf("at-rest encryption: enabled (key source: %s)", keyRes.Source)
	}

	st, err := store.OpenWithCipher(dataPath, keyRes.Cipher)
	if err != nil {
		log.Fatal(err)
	}
	// Open the dedicated bounded log store (logs.db) beside the state file, with
	// the same at-rest cipher. In-memory mode (no dataPath) disables ingestion.
	var logStore *logstore.Store
	if dataPath != "" {
		logsPath := filepath.Join(dataDir, "logs.db")
		logStore, err = logstore.Open(logsPath, keyRes.Cipher, logstore.EnvMaxSourceBytes(os.Getenv("LATTICE_LOG_MAX_SOURCE_BYTES")))
		if err != nil {
			log.Fatal(err)
		}
		defer logStore.Close()
		if keyRes.Cipher.Enabled() {
			log.Printf("log store: %s (encrypted at rest)", logsPath)
		} else {
			log.Printf("log store: %s (PLAINTEXT — logs may contain secrets; set a master key to encrypt)", logsPath)
		}
	}
	app, err := server.New(server.Options{
		Store:         st,
		LogStore:      logStore,
		WebFS:         os.DirFS(webRoot),
		AdminPassword: os.Getenv("LATTICE_ADMIN_PASSWORD"),
		SecureCookies: secureCookies,
		TrustProxy:    trustProxy,
		PluginDir:     pluginDir,
		PluginTrust:   trustPolicy,
		PublicURL:     publicURL,
		CoreDNSBinary: selfdns.CoreDNSBinarySource{Version: coreDNSVersion, URL: coreDNSURL, SHA256: coreDNSSHA256},
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if tlsCert != "" && tlsKey != "" {
		log.Printf("lattice-server listening on https://%s (data=%s, web=%s)", listen, dataPath, webRoot)
		log.Fatal(srv.ListenAndServeTLS(tlsCert, tlsKey))
		return
	}
	if !secureCookies {
		log.Printf("WARNING: serving plain HTTP without -secure-cookies; terminate TLS at a trusted proxy and bind to a private/WireGuard address")
	}
	log.Printf("lattice-server listening on http://%s (data=%s, web=%s)", listen, dataPath, webRoot)
	log.Fatal(srv.ListenAndServe())
}

// defaultDataPath keeps persistent state out of world-writable /tmp by default,
// preferring a per-user state directory. Falls back to the working directory.
func defaultDataPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "lattice", "state.json")
	}
	return "lattice-state.json"
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadPluginTrust reads the operator plugin trust policy. An empty path yields
// the fail-closed zero policy (host-risk plugins require a trusted signature).
func loadPluginTrust(path string) (plugin.TrustPolicy, error) {
	if path == "" {
		return plugin.TrustPolicy{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return plugin.TrustPolicy{}, fmt.Errorf("read plugin trust policy: %w", err)
	}
	return plugin.ParseTrustPolicyJSON(data)
}
