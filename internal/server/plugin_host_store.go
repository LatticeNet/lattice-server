package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/plugin"
	"github.com/LatticeNet/lattice-server/internal/store"
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

// pluginKVComparer is the store's compare-and-swap. It is a separate
// interface so a test wrapper of pluginKVStore that does not offer it makes
// the conditional kv.put fail closed instead of writing blind.
type pluginKVComparer interface {
	PutKVIfMatch(entry model.KVEntry, ifMatch string) error
}

// PutIfMatch serves a kv.put that carries if_match (plugin.KVComparePutter):
// the write lands only when the stored value's digest is ifMatch, or, with an
// empty ifMatch, only when the key does not exist. The namespace is
// re-checked as Get and Put check it.
func (h *pluginHost) PutIfMatch(_ context.Context, key string, value []byte, ifMatch string) error {
	bucket, entryKey, err := splitPluginKVKey(key)
	if err != nil {
		return err
	}
	comparer, ok := h.kvStore().(pluginKVComparer)
	if !ok {
		return fmt.Errorf("%w: kv compare-and-swap", plugin.ErrHostServiceUnavailable)
	}
	err = comparer.PutKVIfMatch(model.KVEntry{Bucket: bucket, Key: entryKey, Value: string(value)}, ifMatch)
	if errors.Is(err, store.ErrKVConflict) {
		return plugin.ErrKVConflict
	}
	return err
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
