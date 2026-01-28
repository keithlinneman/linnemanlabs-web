package httpmw

import (
	"net/http"
)

// Chain applies middlewares so that the first middleware in the
// list is the outermost, and the last is innermost, wrapping h.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	wrapped := h

	// Apply in reverse: last mw in the slice wraps the handler first.
	for i := len(mws) - 1; i >= 0; i-- {
		if mws[i] == nil {
			continue
		}
		wrapped = mws[i](wrapped)
	}

	return wrapped
}
