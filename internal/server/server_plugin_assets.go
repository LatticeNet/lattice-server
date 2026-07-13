package server

import (
	"bytes"
	"errors"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
)

var contentHashedAsset = regexp.MustCompile(`(?:^|[._-])[0-9a-fA-F]{8,}(?:[._-]|$)`)

func (s *Server) handlePluginAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	asset, ok := s.resolvePluginAssetRequest(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// A sandboxed opaque-origin document carries the operator's cookie on its
	// navigation request, but browsers intentionally omit that cookie from the
	// document's external script/style requests. Authenticate the HTML entrypoint
	// and keep subresources lifecycle-, digest-, and inventory-bound instead of
	// weakening the iframe with allow-same-origin.
	if asset.isEntrypoint {
		s.withAuth("", func(w http.ResponseWriter, r *http.Request, _ principal) {
			s.servePluginAsset(w, r, asset)
		})(w, r)
		return
	}
	if !s.apiLimiter.Allow(s.clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("rate limited"))
		return
	}
	s.servePluginAsset(w, r, asset)
}

type resolvedPluginAsset struct {
	loaded       plugin.Loaded
	assetPath    string
	isEntrypoint bool
}

func (s *Server) resolvePluginAssetRequest(r *http.Request) (resolvedPluginAsset, bool) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/plugins/assets/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return resolvedPluginAsset{}, false
	}
	pluginID, digest, assetPath := parts[0], strings.ToLower(parts[1]), parts[2]
	loaded, ok := s.loadedPlugin(pluginID)
	if !ok || loaded.Manifest.Schema != plugin.ManifestSchemaV2 || loaded.ArtifactDigest == "" ||
		!strings.EqualFold(loaded.ArtifactDigest, digest) || !strings.HasPrefix(assetPath, "ui/") {
		return resolvedPluginAsset{}, false
	}
	entrypoint := loaded.Manifest.UIRuntime != nil && assetPath == loaded.Manifest.UIRuntime.Entrypoint
	return resolvedPluginAsset{loaded: loaded, assetPath: assetPath, isEntrypoint: entrypoint}, true
}

func (s *Server) servePluginAsset(w http.ResponseWriter, r *http.Request, asset resolvedPluginAsset) {
	loaded, assetPath := asset.loaded, asset.assetPath
	if strings.EqualFold(filepath.Ext(assetPath), ".html") && !asset.isEntrypoint {
		http.NotFound(w, r)
		return
	}
	installation, ok := s.store.PluginInstallation(loaded.Manifest.ID)
	if !ok || installation.Status != model.PluginStatusActive {
		http.NotFound(w, r)
		return
	}
	data, _, err := plugin.ReadVerifiedBundleFile(loaded, assetPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	contentType, ok := pluginAssetContentType(filepath.Ext(assetPath))
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; object-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'")
	if strings.EqualFold(filepath.Ext(assetPath), ".html") {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Cache-Control", "private, no-cache, max-age=0, must-revalidate")
	} else if contentHashedAsset.MatchString(filepath.Base(assetPath)) {
		w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "private, no-cache, max-age=0, must-revalidate")
	}
	http.ServeContent(w, r, filepath.Base(assetPath), time.Time{}, bytes.NewReader(data))
}

func pluginAssetContentType(ext string) (string, bool) {
	switch strings.ToLower(ext) {
	case ".html":
		return "text/html; charset=utf-8", true
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8", true
	case ".css":
		return "text/css; charset=utf-8", true
	case ".json", ".map":
		return "application/json", true
	case ".txt":
		return "text/plain; charset=utf-8", true
	case ".svg":
		return "image/svg+xml", true
	case ".png":
		return "image/png", true
	case ".jpg", ".jpeg":
		return "image/jpeg", true
	case ".gif":
		return "image/gif", true
	case ".webp":
		return "image/webp", true
	case ".ico":
		return "image/x-icon", true
	case ".woff2":
		return "font/woff2", true
	default:
		return "", false
	}
}
