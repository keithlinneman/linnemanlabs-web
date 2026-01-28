package content

import "sync/atomic"

type Manager struct {
	active atomic.Pointer[Snapshot]
}

func NewManager() *Manager { return &Manager{} }

// Set sets the active snapshot safely
func (m *Manager) Set(s Snapshot) {
	// create a copy to avoid external mutation
	cp := new(Snapshot)
	*cp = s
	m.active.Store(cp)
}

// Get retrieves the active snapshot value
func (m *Manager) Get() (*Snapshot, bool) {
	s := m.active.Load()
	return s, s != nil && s.FS != nil
}
