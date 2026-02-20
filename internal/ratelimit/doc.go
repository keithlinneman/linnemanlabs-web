// Package ratelimit provides per-IP rate limiting with background eviction
// of stale entries.
//
// This is a single-instance, in-memory rate limiter intended for basic abuse
// prevention on a single server. It does not protect against distributed
// attacks, bandwidth-bill attacks, or application-layer DoS that stays under
// the rate limit. For those, use an upstream WAF or CDN-level rate limiting.
package ratelimit
