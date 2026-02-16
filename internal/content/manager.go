package content

import (
	"sync/atomic"
	"time"
)

type Manager struct {
	active atomic.Pointer[Snapshot]
}

func NewManager() *Manager { return &Manager{} }

// Set sets the active snapshot safely
func (m *Manager) Set(s Snapshot) {
	// create a copy to avoid external mutation
	cp := new(Snapshot)
	*cp = s
	// Set LoadedAt if not already set
	if cp.LoadedAt.IsZero() {
		cp.LoadedAt = time.Now().UTC()
	}
	m.active.Store(cp)
}

// Get retrieves the active snapshot value
func (m *Manager) Get() (*Snapshot, bool) {
	s := m.active.Load()
	return s, s != nil && s.FS != nil
}

// ContentVersion returns the current content version for headers
// Implements httpmw.ContentInfo interface
func (m *Manager) ContentVersion() string {
	s := m.active.Load()
	if s == nil {
		return ""
	}
	// Prefer provenance version if available
	if s.Provenance != nil && s.Provenance.Version != "" {
		return s.Provenance.Version
	}
	return s.Meta.Version
}

// ContentHash returns the current content hash for headers
// Implements httpmw.ContentInfo interface
func (m *Manager) ContentHash() string {
	s := m.active.Load()
	if s == nil {
		return ""
	}
	// Prefer provenance hash if available
	if s.Provenance != nil && s.Provenance.ContentHash != "" {
		return s.Provenance.ContentHash
	}
	return s.Meta.SHA256
}

// Provenance returns the current provenance data, if available
func (m *Manager) Provenance() *Provenance {
	s := m.active.Load()
	if s == nil {
		return nil
	}
	return s.Provenance
}

// Source returns the source of the current content, or SourceUnknown if not available
func (m *Manager) Source() Source {
	s := m.active.Load()
	if s == nil {
		return SourceUnknown
	}
	return s.Meta.Source
}

// LoadedAt returns the time when the current content snapshot was loaded, or zero if not available
func (m *Manager) LoadedAt() time.Time {
	s := m.active.Load()
	if s == nil {
		return time.Time{}
	}
	return s.LoadedAt
}
