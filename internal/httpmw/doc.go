// Package httpmw provides HTTP middleware for the public-facing server.
//
// Middleware is composed in a specific order in httpserver.NewHandler:
// security headers, request ID, client IP extraction, rate limiting,
// OTEL tracing, content version headers, metrics, structured logging,
// and chi router.
//
// Each middleware is an independent function that can be tested, reordered,
// or removed individually. User-supplied data (query params, user-agent,
// headers) is intentionally excluded from logs to prevent PII leaks and
// log injection.
package httpmw
