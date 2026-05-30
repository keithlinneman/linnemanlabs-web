# linnemanlabs-web

A security-focused web application platform written in Go that treats **supply chain transparency as a first-class feature**. Every artifact the system serves — the binary itself and the site content it delivers — carries cryptographically verified provenance that is exposed to visitors through machine-readable APIs and human-readable UI.

The entire stack is public. Code, infrastructure-as-code, configurations, build attestations — all open, following Kerckhoffs' principle: security comes from the design, not from hiding the implementation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  GitHub Actions CI                                          │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────┐   │
│  │ Compile │→ │ Scan/SBOM│→ │ Dual-Sign  │→ │ Publish   │   │
│  │(ldflags)│  │ (trivy,  │  │ (KMS +     │  │ (ECR, S3, │   │
│  │         │  │  grype,  │  │  GitHub    │  │  SSM)     │   │
│  │         │  │  govuln) │  │  OIDC)     │  │           │   │
│  └─────────┘  └──────────┘  └────────────┘  └───────────┘   │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Runtime (EC2 / Auto Scaling)                               │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  cmd/server                                          │   │
│  │                                                      │   │
│  │  ┌─────────┐ ┌──────────────┐ ┌───────────────────┐  │   │
│  │  │ Content │ │ Evidence     │ │ Provenance API    │  │   │
│  │  │ Loader  │ │ Loader       │ │ /api/provenance/* │  │   │
│  │  │ (S3→mem)│ │ (S3→verify)  │ │                   │  │   │
│  │  └────┬────┘ └──────┬───────┘ └───────────────────┘  │   │
│  │       ▼             ▼                                │   │
│  │  ┌─────────┐ ┌──────────────┐                        │   │
│  │  │ Content │ │ Evidence     │  ← atomic.Pointer      │   │
│  │  │ Manager │ │ Store        │     (lock-free reads)  │   │
│  │  └────┬────┘ └──────────────┘                        │   │
│  │       ▼                                              │   │
│  │ ┌──────────────────────────────────────────────────┐ │   │
│  │ │  HTTP Stack                                      │ │   │
│  │ │  chi router → middleware chain → site handler    │ │   │
│  │ └──────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────┐                                       │
│  │ Ops Listener     │  :9000 (internal only)                │
│  │ /metrics /healthz│  SG + middleware reject public IPs    │
│  │ /debug/pprof/*   │                                       │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

The server is a single Go binary with two HTTP listeners. The **site listener** (`:8080`) serves content through a security-hardened middleware chain and exposes provenance APIs. The **ops listener** (`:9000`) serves Prometheus metrics, health probes, and pprof endpoints, restricted to non-public networks at both the security group and middleware layers.

### Package layout

```
cmd/server/          → entry point, wires all components
internal/
  cfg/               → flag + env config with validation
  content/           → bundle loading, extraction, watching, in-memory FS
  cryptoutil/        → KMS verification, sigstore bundle parsing, DSSE/blob verify
  evidence/          → build evidence fetching, release manifests, policy parsing
  health/            → liveness/readiness probes, shutdown gating
  httpmw/            → middleware: logging, security headers, client IP, tracing
  httpserver/        → chi router setup, server lifecycle
  log/               → structured slog wrapper
  metrics/           → Prometheus instrumentation
  opshttp/           → admin/ops listener
  otelx/             → OpenTelemetry tracing init
  pathutil/          → path traversal protection
  prof/              → Pyroscope continuous profiling
  provenancehttp/    → provenance REST API handlers
  ratelimit/         → per-IP token bucket rate limiter
  sitehandler/       → content serving with fallback/maintenance modes
  version/           → compile-time identity via ldflags
  webassets/         → embedded fallback assets
  xerrors/           → error wrapping utilities
```

### Key design decisions

**In-memory content serving.** Content bundles are downloaded from S3, verified, and extracted into an in-memory filesystem (`fstest.MapFS`-compatible). There is no disk I/O in the serving path, which eliminates an entire class of disk-tampering threats and simplifies the deployment model. The `content.Manager` uses `atomic.Pointer` for lock-free reads during hot-swaps.

**Compile-time identity.** The binary knows who it is. `version.go` variables are injected via `-ldflags` at build time, embedding the git commit, build actor, release ID, evidence bucket location, and cosign key reference directly into the binary. At runtime, `HasProvenance()` gates whether the server fetches and serves build evidence — local dev builds skip it entirely.

**Fail-closed production builds.** When provenance data is compiled in, both KMS signing keys (content + evidence) are mandatory. If evidence fails to load at startup, the process exits. systemd restarts it; the ASG replaces it. There is no graceful degradation pat
h for a release build that can't prove its own integrity.

**Hot-swappable content.** The `content.Watcher` polls SSM for bundle hash changes every 30 seconds. When a new hash is detected, it downloads, verifies, extracts, validates, and atomically swaps the new bundle into the manager. One prior snapshot is preserved for rollback, old snapshots are garbage-collected when the pointer is replaced. Exponential backoff and staleness detection handle transient failures.

---

## Security model

The security model is built on explicit trust chains with cryptographic verification at every boundary. The philosophy is **cost imposition and detection**, not impenetrable defense — the goal is to make tampering expensive, detectable, and attributable.

### Dual-signing architecture

Every release artifact is signed twice, independently:

1. **AWS KMS** — an ECDSA key in KMS signs the artifact digest via cosign. The key never leaves AWS.
2. **GitHub OIDC** — `actions/attest-build-provenance@v2` produces a sigstore attestation tied to the GitHub Actions workflow identity.

These signatures are **parallel, not chained**. Each signer operates on the same artifact digest independently. Verification policy requires both signatures to be present and valid. Compromising one signing path doesn't help an attacker — they need both.

### Content bundle trust chain

```
SSM parameter (hash pointer)
  → S3 fetch (compressed tar.gz)
    → SHA-384 checksum verification
      → KMS signature verification (sigstore bundle)
        → In-memory extraction with strict limits
          → Provenance manifest validation
            → Atomic swap into serving path
```

Content bundles are addressed by their SHA-384 digest stored in SSM. The loader fetches the bundle from S3, verifies the checksum, then verifies the KMS signature over the raw bundle bytes using the sigstore bundle format. Only after cryptographic verification passes does extraction begin, with enforced limits on compressed size, per-file size, total extracted size, and multi-layer path traversal checks.

### Evidence verification

Build evidence (release manifests, SBOMs, vulnerability scans, license reports) follows the same pattern. The `evidence.Loader` fetches `release.json` from S3, verifies its sigstore bundle signature, then follows the inventory to fetch all referenced evidence files. Evidence signing keys are separate from content bundle signing keys.

### HTTP hardening

The middleware chain applies a comprehensive set of security headers on every response: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, COEP, COOP, CORP, and Permissions-Policy. Request body size is capped at 1KB (it's a static site — nobody should be sending bodies). The ops listener rejects connections from public IP ranges at the middleware layer as defense-in-depth behind the security group.

### Rate limiting

Per-IP token bucket rate limiting with bounded memory. The limiter tracks unique IPs with a configurable maximum capacity to prevent OOM from distributed attacks. When capacity is reached, new visitors are rejected until stale entries are evicted. First-denial logging prevents log spam while maintaining visibility. This is a single-instance defense-in-depth layer, not a replacement for upstream WAF/CDN filtering.

---

## Observability

### Prometheus metrics (`:9000/metrics`)

The server exposes a comprehensive metric set with safe label cardinality (method, route, status code — never raw paths):

- `http_requests_total`, `http_request_duration_seconds`, `http_response_size_bytes` — standard RED metrics with trace ID exemplars on sampled requests
- `http_inflight_requests` — real-time concurrency gauge
- `http_panic_total`, `http_errors_total` — error SLIs by method and route
- `http_requests_rate_limited_total`, `http_requests_rate_limited_capacity_total` — rate limiter visibility
- `content_watcher_*` — poll count, swap count, errors by type, bundle load duration, last success timestamp, staleness indicator
- `content_source_info`, `content_bundle_info`, `content_loaded_timestamp_seconds` — active content identity
- `build_info` — version, commit, build date, go version as labels (value always 1)
- `profiling_active` — whether continuous profiling is running

### Tracing

OpenTelemetry integration via OTLP/gRPC to a local collector. Parent-based sampling with configurable ratio. Trace and span IDs are propagated through `X-Trace-Id` / `X-Span-Id` response headers on sampled requests. Health checks, favicon, and static assets are excluded from tracing to reduce noise.

### Structured logging

slog-based structured logging with JSON output. Access logs include status code, duration, response size, and route pattern. Static asset requests are excluded from access logs (planned: ship to ClickHouse or S3 separately). User-supplied data (query params, user-agent, headers) is intentionally excluded to prevent PII leaks and log injection.

### Continuous profiling

Pyroscope agent integration for CPU, heap, goroutine, mutex, and block profiling in production. pprof endpoints are available on the ops listener for ad-hoc profiling.

### Health probes

Dual-probe health model: `/healthz` (liveness) and `/readyz` (readiness). Readiness requires both the shutdown gate to be open and content to be loaded. During graceful shutdown, the gate closes first to fail health checks and drain load balancer traffic before the server stops accepting connections.

---

## Provenance API

The server exposes its own supply chain evidence through a REST API:

| Endpoint | Description |
|---|---|
| `GET /api/provenance/app` | Full build provenance: version info, release manifest, policy, attestations, evidence index |
| `GET /api/provenance/app/summary` | Lightweight summary for frontend consumption |
| `GET /api/provenance/content` | Content bundle provenance: hash, source commit, file manifest |
| `GET /api/provenance/content/summary` | Content bundle summary |
| `GET /api/provenance/evidence` | Evidence file manifest |
| `GET /api/provenance/evidence/release.json` | Raw release manifest |
| `GET /api/provenance/evidence/inventory.json` | Evidence inventory |
| `GET /api/provenance/evidence/files/*` | Individual evidence files |

The summary endpoint includes policy compliance evaluation — whether signing, SBOM, scanning, license, and provenance requirements are satisfied — computed at request time from the loaded evidence bundle.

---

## Quick start

**Prerequisites:** Go 1.22+, AWS credentials (for S3/SSM/KMS in production mode)

```bash
# Build
make build

# Run locally (dev mode — no provenance, embedded fallback content)
./bin/linnemanlabs-web

# Run tests
make test

# Release (CI only — requires build-system container)
make release
```

Local builds automatically detect the absence of ldflags-injected provenance and skip evidence fetching. The server serves embedded fallback content until a content bundle is loaded.

Configuration is via flags or environment variables (`LMLABS_` prefix, e.g. `LMLABS_HTTP_PORT=8080`). Flag values take precedence over environment variables.

---

## Build pipeline

Tag-triggered GitHub Actions workflow on `v*` tags. Runs inside a pinned [https://github.com/keithlinneman/build-system](build-system with source available on GitHub) container image (referenced by digest). The pipeline compiles for `linux/amd64` and `linux/arm64`, generates SBOMs (SPDX + CycloneDX), runs vulnerability scanners (Trivy, Grype, govulncheck), performs license compliance checks against a deny/allow list, signs all artifacts with both KMS and GitHub OIDC, generates in-toto attestations, pushes to ECR, and uploads evidence to S3. The release manifest records the complete policy and all evidence file references.

---

## License

See [LICENSE](LICENSE).