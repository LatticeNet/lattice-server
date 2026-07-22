package server

import (
	"sync"
	"time"
)

// lines_cache.go — a cheap read-model cache for the unified Lines view
// (design-15 follow-up). buildLineGroups walks every store collection and the
// whole fleet inventory on every call, and lines.get used to redo that fleet
// build just to linear-scan one line. The cache holds the last built groups
// plus a line_hash_id index, and is invalidated EXPLICITLY on every state
// change that feeds the read model: proxy inbound/user/profile writes, node
// writes, sing-box inventory ingest, and vpn-core identity mutations. A 60s
// TTL is the documented safety net for a missed edge path — operator-driven
// mutations all invalidate explicitly, so the UI never reads stale after its
// own actions.

const lineReadModelTTL = 60 * time.Second

type lineReadModelCache struct {
	mu         sync.RWMutex
	groups     []LineGroup
	byHash     map[string]Line
	builtAt    time.Time
	valid      bool
	generation uint64
	// beforePublish is a deterministic concurrency seam used only by tests.
	// Production servers leave it nil.
	beforePublish func()
}

// lineReadModel returns the cached Lines view, rebuilding it after an
// invalidation or when the TTL safety net expired. Callers must not mutate the
// returned slices.
func (s *Server) lineReadModel() ([]LineGroup, map[string]Line) {
	for {
		now := s.now()
		s.lineCache.mu.RLock()
		if s.lineCache.valid && now.Sub(s.lineCache.builtAt) < lineReadModelTTL {
			defer s.lineCache.mu.RUnlock()
			return s.lineCache.groups, s.lineCache.byHash
		}
		generation := s.lineCache.generation
		beforePublish := s.lineCache.beforePublish
		s.lineCache.mu.RUnlock()

		groups := s.buildLineGroups()
		index := make(map[string]Line, 64)
		for _, g := range groups {
			for _, ln := range g.Lines {
				if ln.LineHashID != "" {
					index[ln.LineHashID] = ln
				}
			}
		}
		if beforePublish != nil {
			beforePublish()
		}
		s.lineCache.mu.Lock()
		if s.lineCache.generation != generation {
			s.lineCache.mu.Unlock()
			continue
		}
		s.lineCache.groups = groups
		s.lineCache.byHash = index
		s.lineCache.builtAt = now
		s.lineCache.valid = true
		s.lineCache.mu.Unlock()
		return groups, index
	}
}

// invalidateLineReadModel marks the Lines view stale. It is called on every
// state change the view derives from (see file header).
func (s *Server) invalidateLineReadModel() {
	s.lineCache.mu.Lock()
	s.lineCache.generation++
	s.lineCache.valid = false
	s.lineCache.groups = nil
	s.lineCache.byHash = nil
	s.lineCache.mu.Unlock()
}

// lineFromReadModel resolves one line by hash without a fleet rebuild.
func (s *Server) lineFromReadModel(lineHashID string) (Line, bool) {
	_, index := s.lineReadModel()
	ln, ok := index[lineHashID]
	return ln, ok
}
