package server

import (
	"context"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
)

// pluginKVStore is the part of the store the plugin KV host calls use. The
// server's store implements it; a test wraps it to count reads.
type pluginKVStore interface {
	KV(bucket string) []model.KVEntry
	KVEntry(bucket, key string) (model.KVEntry, bool)
	PutKV(entry model.KVEntry) error
	DeleteKV(bucket, key string) error
}

func (h *pluginHost) kvStore() pluginKVStore {
	if h.kv != nil {
		return h.kv
	}
	return h.server.store
}

// Delete serves kv.delete (plugin.KVDeleter). The broker has already checked
// kv:write and pinned the key to "plugin:<pluginID>/<key>"; the host re-checks
// the namespace as Get and Put do, so a hand-built composite key cannot reach a
// bucket that is not a plugin's. Deleting a key that is not there is not an
// error: the caller wanted it gone, and it is.
func (h *pluginHost) Delete(_ context.Context, key string) error {
	bucket, entryKey, err := splitPluginKVKey(key)
	if err != nil {
		return err
	}
	return h.kvStore().DeleteKV(bucket, entryKey)
}

// pluginHTTPResponseLimitFor is the response body bound for one plugin HTTP
// request: the method's signed http_response_bytes as the broker resolved it,
// else the 256 KiB every method had before budgets carried one, never above
// the 8 MiB host maximum.
func pluginHTTPResponseLimitFor(req plugin.HostHTTPRequest) int {
	if req.ResponseLimit <= 0 {
		return plugin.DefaultInvokeHTTPResponseBytes
	}
	return min(req.ResponseLimit, plugin.HostMaxInvokeHTTPResponseBytes)
}
