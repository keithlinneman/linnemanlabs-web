package xerrors

import (
	"errors"
	"fmt"
	"runtime"
)

type withStack struct {
	err error
	pcs []uintptr
}

func (w *withStack) Error() string       { return w.err.Error() }
func (w *withStack) Unwrap() error       { return w.err }
func (w *withStack) StackPCs() []uintptr { return w.pcs }
func (w *withStack) IsXerrorsWrapper()   {}

func captureStack(skip int) []uintptr {
	const maxDepth = 64
	pcs := make([]uintptr, maxDepth)
	// value of 2 means skip runtime.Callers + captureStack
	n := runtime.Callers(2+skip, pcs)
	return pcs[:n]
}

func withStackSkip(err error, skip int) error {
	if err == nil {
		return nil
	}
	return &withStack{err: err, pcs: captureStack(skip)}
}

func WithStack(err error) error { return withStackSkip(err, 2) }
func EnsureTrace(err error) error {
	if err == nil {
		return nil
	}
	// only add if not already stacked
	type hasStack interface{ StackPCs() []uintptr }
	var hs hasStack
	if errors.As(err, &hs) && hs != nil && len(hs.StackPCs()) > 0 {
		return err
	}
	return withStackSkip(err, 2)
}

type wrap struct {
	err error
	msg string
	pc  uintptr
}

func (w *wrap) Error() string     { return w.msg + ": " + w.err.Error() }
func (w *wrap) Unwrap() error     { return w.err }
func (w *wrap) PC() uintptr       { return w.pc }
func (w *wrap) IsXerrorsWrapper() {}

func callerPC(skip int) uintptr {
	var pcs [1]uintptr
	// value of 2 means skip runtime.Callers + callerPC
	if n := runtime.Callers(2+skip, pcs[:]); n == 0 {
		return 0
	}
	return pcs[0]
}

func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return &wrap{err: err, msg: msg, pc: callerPC(1)}
}
func Wrapf(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return &wrap{err: err, msg: fmt.Sprintf(format, args...), pc: callerPC(1)}
}

func New(msg string) error             { return withStackSkip(errors.New(msg), 2) }
func Newf(f string, args ...any) error { return withStackSkip(fmt.Errorf(f, args...), 2) }
