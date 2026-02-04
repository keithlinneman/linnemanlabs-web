package evidence

import "sync/atomic"

// Store holds the evidence bundle for the running binary, safe for concurrent access
type Store struct {
	active atomic.Pointer[Bundle]
}

// NewStore creates a new evidence store
func NewStore() *Store {
	return &Store{}
}

// Set stores a new evidence bundle
func (s *Store) Set(b *Bundle) {
	if b != nil {
		b.buildIndex()
	}
	s.active.Store(b)
}

// Get returns the current evidence bundle
// Returns (nil, false) if no evidence has been loaded
func (s *Store) Get() (*Bundle, bool) {
	b := s.active.Load()
	return b, b != nil
}

// Artifact returns a specific artifact by name from the current bundle
func (s *Store) Artifact(name string) (*Artifact, bool) {
	b := s.active.Load()
	if b == nil {
		return nil, false
	}
	a := b.Artifact(name)
	return a, a != nil
}

// HasEvidence returns whether any evidence artifacts are loaded
func (s *Store) HasEvidence() bool {
	b := s.active.Load()
	return b != nil && len(b.Artifacts) > 0
}
