package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-server/internal/geoip"
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
	var requireTOTP bool
	var tlsCert string
	var tlsKey string
	var pluginDir string
	var pluginTrust string
	var pluginRuntimeDir string
	var pluginRuntimeEnv string
	var masterKeyFile string
	var publicURL string
	var coreDNSVersion string
	var coreDNSURL string
	var coreDNSSHA256 string
	var geoIPLookupURL string
	var agentReleaseRepo string
	var printVersion bool
	flag.StringVar(&listen, "listen", env("LATTICE_LISTEN", "127.0.0.1:8088"), "listen address")
	flag.StringVar(&dataPath, "data", env("LATTICE_DATA", defaultDataPath()), "state file path")
	flag.StringVar(&webRoot, "web", env("LATTICE_WEB_ROOT", "../lattice-dashboard"), "static dashboard root")
	flag.BoolVar(&secureCookies, "secure-cookies", env("LATTICE_SECURE_COOKIES", "") == "1", "set Secure on session cookies (enables HSTS)")
	flag.BoolVar(&trustProxy, "trust-proxy", env("LATTICE_TRUST_PROXY", "") == "1", "trust CF-Connecting-IP / X-Forwarded-For for client IP (only behind a trusted proxy)")
	flag.BoolVar(&requireTOTP, "require-totp", env("LATTICE_REQUIRE_TOTP", "") == "1", "require interactive users to enable TOTP before using non-setup APIs")
	flag.StringVar(&tlsCert, "tls-cert", os.Getenv("LATTICE_TLS_CERT"), "TLS certificate file; enables HTTPS when set with -tls-key")
	flag.StringVar(&tlsKey, "tls-key", os.Getenv("LATTICE_TLS_KEY"), "TLS private key file")
	flag.StringVar(&pluginDir, "plugin-dir", env("LATTICE_PLUGIN_DIR", ""), "directory of installed plugin bundles (empty disables plugins)")
	flag.StringVar(&pluginTrust, "plugin-trust", env("LATTICE_PLUGIN_TRUST", ""), "path to the operator plugin trust policy JSON")
	flag.StringVar(&pluginRuntimeDir, "plugin-runtime-dir", env("LATTICE_PLUGIN_RUNTIME_DIR", ""), "writable dir enabling the Tier-2 system runner (empty keeps the noop runner)")
	flag.StringVar(&pluginRuntimeEnv, "plugin-runtime-env", env("LATTICE_PLUGIN_RUNTIME_ENV", ""), "comma/space-separated environment variable allowlist forwarded to Tier-2 system plugins")
	flag.StringVar(&masterKeyFile, "master-key-file", env("LATTICE_MASTER_KEY_FILE", ""), "path to the at-rest encryption master key file (auto-generated under the data dir if unset)")
	flag.StringVar(&publicURL, "public-url", env("LATTICE_PUBLIC_URL", ""), "externally-reachable base URL (scheme+host), required for OIDC/SSO redirect")
	flag.StringVar(&coreDNSVersion, "coredns-binary-version", env("LATTICE_COREDNS_BINARY_VERSION", ""), "pinned CoreDNS binary version for self-host DNS apply (requires -coredns-binary-url and -coredns-binary-sha256)")
	flag.StringVar(&coreDNSURL, "coredns-binary-url", env("LATTICE_COREDNS_BINARY_URL", ""), "HTTPS URL to a direct CoreDNS executable binary for self-host DNS apply")
	flag.StringVar(&coreDNSSHA256, "coredns-binary-sha256", env("LATTICE_COREDNS_BINARY_SHA256", ""), "SHA-256 hex digest of the CoreDNS executable binary")
	flag.StringVar(&geoIPLookupURL, "geoip-lookup-url", env("LATTICE_GEOIP_LOOKUP_URL", geoip.DefaultLookupURL), "HTTPS GeoIP lookup URL template containing {ip}; set off/none/disabled to disable automatic node geolocation")
	flag.StringVar(&agentReleaseRepo, "agent-release-repo", env("LATTICE_AGENT_RELEASE_REPO", ""), "trusted GitHub owner/repo for official lattice-agent releases")
	flag.BoolVar(&printVersion, "version", false, "print lattice-server version and exit")
	flag.Parse()
	if printVersion {
		fmt.Printf("lattice-server %s (%s, %s)\n", version, commit, date)
		return
	}
	pluginRuntimeEnvAllowlist, err := parseEnvAllowlist(pluginRuntimeEnv)
	if err != nil {
		log.Fatal(err)
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
	geoResolver, err := geoip.NewHTTPResolver(geoIPLookupURL)
	if err != nil {
		log.Fatal(err)
	}
	if geoResolver != nil {
		log.Printf("geoip lookup: enabled")
	} else {
		log.Printf("geoip lookup: disabled")
	}
	app, err := server.New(server.Options{
		Store:         st,
		LogStore:      logStore,
		WebFS:         os.DirFS(webRoot),
		AdminUsername: os.Getenv("LATTICE_ADMIN_USERNAME"),
		AdminPassword: os.Getenv("LATTICE_ADMIN_PASSWORD"),
		Build: server.BuildInfo{
			ServerVersion:  version,
			ServerCommit:   commit,
			ServerDate:     date,
			DashboardRef:   os.Getenv("LATTICE_DASHBOARD_COMMIT"),
			DashboardBuilt: os.Getenv("LATTICE_DASHBOARD_BUILT_AT"),
		},
		SecureCookies:    secureCookies,
		TrustProxy:       trustProxy,
		RequireTOTP:      requireTOTP,
		PluginDir:        pluginDir,
		PluginRuntimeDir: pluginRuntimeDir,
		PluginRuntimeEnv: pluginRuntimeEnvAllowlist,
		PluginTrust:      trustPolicy,
		PublicURL:        publicURL,
		CoreDNSBinary:    selfdns.CoreDNSBinarySource{Version: coreDNSVersion, URL: coreDNSURL, SHA256: coreDNSSHA256},
		GeoResolver:      geoResolver,
		AgentReleaseRepo: agentReleaseRepo,
		Logger:           log.Default(),
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

func parseEnvAllowlist(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if !validEnvName(name) {
			return nil, fmt.Errorf("invalid -plugin-runtime-env variable name %q", name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

func validEnvName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '_':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return name != ""
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
