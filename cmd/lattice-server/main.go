package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/LatticeNet/lattice-server/internal/server"
	"github.com/LatticeNet/lattice-server/internal/store"
)

func main() {
	var listen string
	var dataPath string
	var webRoot string
	var secureCookies bool
	flag.StringVar(&listen, "listen", env("LATTICE_LISTEN", "127.0.0.1:8088"), "listen address")
	flag.StringVar(&dataPath, "data", env("LATTICE_DATA", filepath.Join(os.TempDir(), "lattice-state.json")), "state file path")
	flag.StringVar(&webRoot, "web", env("LATTICE_WEB_ROOT", "../lattice-dashboard"), "static dashboard root")
	flag.BoolVar(&secureCookies, "secure-cookies", env("LATTICE_SECURE_COOKIES", "") == "1", "set Secure on session cookies")
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
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("lattice-server listening on http://%s (data=%s, web=%s)", listen, dataPath, webRoot)
	log.Fatal(http.ListenAndServe(listen, app.Handler()))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
