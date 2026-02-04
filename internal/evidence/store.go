package evidence

import (
	"sync/atomic"
)

// Store holds the evidence bundle and is thread-safe via atomic pointer
type Store struct {
	active atomic.Pointer[Bundle]
}

// NewStore creates a new evidence store
func NewStore() *Store {
	return &Store{}
}

// Set stores a new evidence bundle
func (s *Store) Set(b *Bundle) {
	s.active.Store(b)
}

// Get returns the current evidence bundle
func (s *Store) Get() (*Bundle, bool) {
	b := s.active.Load()
	return b, b != nil
}

// HasEvidence returns whether evidence is loaded with at least one file
func (s *Store) HasEvidence() bool {
	b := s.active.Load()
	return b != nil && len(b.Files) > 0
}

// File looks up a fetched evidence file by inventory path
func (s *Store) File(path string) (*EvidenceFile, bool) {
	b := s.active.Load()
	if b == nil {
		return nil, false
	}
	return b.File(path)
}

// FileRef looks up a file reference by path (metadata only)
func (s *Store) FileRef(path string) (*EvidenceFileRef, bool) {
	b := s.active.Load()
	if b == nil {
		return nil, false
	}
	return b.FileRef(path)
}
