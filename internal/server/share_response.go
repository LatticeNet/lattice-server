package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

// A served link answers with the bytes first and does its bookkeeping after.
// The response carries its length, a strong validator and, for a client that
// accepts it, a gzip body, so a client polling a cached link gets its
// document as fast as the network allows and a client that sends
// If-None-Match gets a 304 when nothing moved.

// shareGzipMinBytes is the smallest body worth compressing. Below it the gzip
// header and the client's inflate cost more than the bytes saved.
const shareGzipMinBytes = 1024

// shareBody is one rendered document with what serving it needs, computed
// once when it is rendered rather than on every hit.
type shareBody struct {
	body     []byte
	gzipBody []byte
	hash     [sha256.Size]byte
}

// newShareBody digests a body and, when compress is set and it is worth it,
// compresses it. A body that will be cached is compressed once, as hard as
// gzip goes; one rendered for a single response is compressed only for a
// client that accepts gzip, at the default level.
func newShareBody(body []byte, compress bool, level int) shareBody {
	out := shareBody{body: body, hash: sha256.Sum256(body)}
	if compress && len(body) >= shareGzipMinBytes {
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, level)
		if err == nil {
			_, werr := zw.Write(body)
			if cerr := zw.Close(); werr == nil && cerr == nil && buf.Len() < len(body) {
				out.gzipBody = buf.Bytes()
			}
		}
	}
	return out
}

// shareETag is a strong validator for exactly what a response carries: the
// body, the quota header the client would see (a client that only updates
// its quota display on a 200 must not be told nothing changed when only the
// quota moved), and the content coding.
func shareETag(hash [sha256.Size]byte, userinfo string, gzipped bool) string {
	h := sha256.New()
	h.Write(hash[:])
	h.Write([]byte{0})
	h.Write([]byte(userinfo))
	sum := h.Sum(nil)
	tag := `"` + hex.EncodeToString(sum[:16])
	if gzipped {
		tag += "-gz"
	}
	return tag + `"`
}

// acceptsGzip reports whether the request names gzip with a non-zero weight.
func acceptsGzip(r *http.Request) bool {
	for _, field := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(field, ",") {
			name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "gzip" && name != "x-gzip" {
				continue
			}
			if q, ok := strings.CutPrefix(strings.ReplaceAll(strings.TrimSpace(params), " ", ""), "q="); ok {
				if weight, err := strconv.ParseFloat(q, 64); err == nil && weight <= 0 {
					return false
				}
			}
			return true
		}
	}
	return false
}

// ifNoneMatchHits reports whether If-None-Match names any of the tags, by
// the weak comparison RFC 9110 prescribes for this header.
func ifNoneMatchHits(r *http.Request, tags ...string) bool {
	for _, field := range r.Header.Values("If-None-Match") {
		for _, candidate := range strings.Split(field, ",") {
			candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
			if candidate == "*" {
				return true
			}
			for _, tag := range tags {
				if candidate == tag {
					return true
				}
			}
		}
	}
	return false
}

// writeShareBody writes a successful link response after the caller has set
// every other header. It returns whether the answer was a 304.
func writeShareBody(w http.ResponseWriter, r *http.Request, b shareBody, userinfo string) bool {
	header := w.Header()
	gzipped := b.gzipBody != nil && acceptsGzip(r)
	if b.gzipBody != nil {
		header.Add("Vary", "Accept-Encoding")
	}
	etag := shareETag(b.hash, userinfo, gzipped)
	header.Set("ETag", etag)
	// Either coding's tag means the client holds this document.
	if ifNoneMatchHits(r, shareETag(b.hash, userinfo, false), shareETag(b.hash, userinfo, true)) {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	body := b.body
	if gzipped {
		header.Set("Content-Encoding", "gzip")
		body = b.gzipBody
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return false
}
