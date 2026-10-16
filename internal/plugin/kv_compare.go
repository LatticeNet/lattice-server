package plugin

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
)

// The kv.put compare-and-swap (design 28 slice S2, plan sections 2.5 and
// 2.6). A kv.put whose payload carries if_match writes only when the stored
// value's sha256 equals it; an empty if_match writes only when the key does
// not exist (a create). A kv.put without the field writes unconditionally, as
// it always has, so a plugin built before the field existed is unaffected.
// kv.get answers the stored value's sha256 beside it, so a plugin passes the
// digest it read straight back.
//
// A refusal is an error whose text starts with kv_conflict, which is how it
// reaches the plugin through the host_response frame: the SDK's KVPutIfMatch
// recognises "kv.put: kv_conflict" and the sub-store plugin's own seam looks
// for the code anywhere in the message.

// ErrKVConflict is a conditional kv.put the host refused because the stored
// value is not the one the caller read.
var ErrKVConflict = errors.New(sdkplugin.KVConflictCode + ": the stored value moved since it was read")

// KVComparePutter is the optional compare-and-swap half of a KVHost. The
// broker answers ErrHostServiceUnavailable when the host does not implement
// it, so a host built before the compare-and-swap existed fails closed
// instead of writing blind.
type KVComparePutter interface {
	// PutIfMatch writes value under key only when the stored value's digest
	// is ifMatch, or, with an empty ifMatch, only when key does not exist.
	// The comparison and the write are one atomic step. A refusal is
	// ErrKVConflict.
	PutIfMatch(ctx context.Context, key string, value []byte, ifMatch string) error
}

// KVValueDigest is the digest kv.get reports beside a stored value and a
// conditional kv.put compares: the lowercase hex SHA-256 of the value.
func KVValueDigest(value []byte) string {
	return sdkplugin.KVValueDigest(value)
}

// validKVDigest reports a lowercase hex SHA-256.
func validKVDigest(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	for _, r := range digest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// KVPutIfMatch writes a KV value conditionally and requires kv:write. The
// bucket is pinned exactly as KVPut pins it. ifMatch must be empty or a
// lowercase hex SHA-256; anything else is refused before the store is read.
func (b *Broker) KVPutIfMatch(ctx context.Context, key string, value []byte, ifMatch string) error {
	if err := b.require(ctx, "kv.put", capKVWrite); err != nil {
		return err
	}
	if ifMatch != "" && !validKVDigest(ifMatch) {
		return errors.New("kv.put if_match must be empty or a lowercase hex sha256")
	}
	comparer, ok := b.services.KV.(KVComparePutter)
	if !ok {
		return fmt.Errorf("%w: kv compare-and-swap", ErrHostServiceUnavailable)
	}
	scoped, err := b.scopedKVKey(key)
	if err != nil {
		return err
	}
	if err := comparer.PutIfMatch(ctx, scoped, append([]byte(nil), value...), ifMatch); err != nil {
		if errors.Is(err, ErrKVConflict) {
			return ErrKVConflict
		}
		return err
	}
	return nil
}
