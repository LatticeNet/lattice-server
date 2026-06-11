package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/LatticeNet/lattice-server/internal/server"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func main() {
	var listen string
	var dataPath string
	var webRoot string
	var secureCookies bool
	var trustProxy bool
	var tlsCert string
	var tlsKey string
	flag.StringVar(&listen, "listen", env("LATTICE_LISTEN", "127.0.0.1:8088"), "listen address")
	flag.StringVar(&dataPath, "data", env("LATTICE_DATA", defaultDataPath()), "state file path")
	flag.StringVar(&webRoot, "web", env("LATTICE_WEB_ROOT", "../lattice-dashboard"), "static dashboard root")
	flag.BoolVar(&secureCookies, "secure-cookies", env("LATTICE_SECURE_COOKIES", "") == "1", "set Secure on session cookies (enables HSTS)")
	flag.BoolVar(&trustProxy, "trust-proxy", env("LATTICE_TRUST_PROXY", "") == "1", "trust CF-Connecting-IP / X-Forwarded-For for client IP (only behind a trusted proxy)")
	flag.StringVar(&tlsCert, "tls-cert", os.Getenv("LATTICE_TLS_CERT"), "TLS certificate file; enables HTTPS when set with -tls-key")
	flag.StringVar(&tlsKey, "tls-key", os.Getenv("LATTICE_TLS_KEY"), "TLS private key file")
	flag.Parse()

	st, err := store.Open(dataPath)
	if err != nil {
		log.Fatal(err)
	}
	app, err := server.New(server.Options{
		Store:         st,
		WebFS:         os.DirFS(webRoot),
		AdminPassword: os.Getenv("LATTICE_ADMIN_PASSWORD"),
		SecureCookies: secureCookies,
		TrustProxy:    trustProxy,
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
