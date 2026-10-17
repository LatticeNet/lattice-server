package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// ErrKVConflict is a conditional KV write the store refused: the stored
// value's digest is not the one the caller named, or the caller asked for a
// create and the key exists.
var ErrKVConflict = errors.New("kv_conflict: the stored value moved since it was read")

// KVValueDigest is the digest a conditional KV write compares: the lowercase
// hex SHA-256 of the stored value's bytes.
func KVValueDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// PutKVIfMatch writes entry only when the value stored under its bucket and
// key has the digest ifMatch, or, with an empty ifMatch, only when nothing is
// stored there. The comparison and the write happen under the store lock, so
// two writers that read the same value cannot both win. A refusal is
// ErrKVConflict and writes nothing. It persists exactly as PutKV does.
func (s *Store) PutKVIfMatch(entry model.KVEntry, ifMatch string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.state.KV[entry.Bucket+"/"+entry.Key]
	switch {
	case ifMatch == "" && exists:
		return ErrKVConflict
	case ifMatch != "" && (!exists || KVValueDigest(current.Value) != ifMatch):
		return ErrKVConflict
	}
	entry.UpdatedAt = time.Now().UTC()
	if s.runtimeBoltHot != nil {
		if err := s.runtimeBoltHot.PutKV(entry); err != nil {
			return err
		}
		s.state.KV[entry.Bucket+"/"+entry.Key] = entry
		return nil
	}
	staged := s.state
	staged.KV = cloneKVEntries(s.state.KV)
	staged.KV[entry.Bucket+"/"+entry.Key] = entry
	committed, err := s.persistState(s.jsonPersistStateFrom(staged))
	if committed {
		s.state = staged
	}
	return err
}
