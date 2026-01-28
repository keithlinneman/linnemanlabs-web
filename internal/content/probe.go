package content

import "errors"

// ReadyErr returns an error if there is no active snapshot
func (m *Manager) ReadyErr() error {
	if _, ok := m.Get(); !ok {
		return errors.New("content: no active snapshot")
	}
	return nil
}
