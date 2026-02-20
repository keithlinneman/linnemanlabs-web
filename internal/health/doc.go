// Package health provides composable health check probes and HTTP handlers
// for liveness and readiness endpoints.
//
// Probes can be combined with [All] (AND), [Any] (OR), and [Fixed] (static).
// [CheckFunc] adapts a plain function into a [Probe].
//
// [ShutdownGate] coordinates graceful shutdown: once closed, readiness probes
// fail immediately (via atomic.Bool) so load balancers stop sending traffic
// before in-flight requests are drained.
package health
