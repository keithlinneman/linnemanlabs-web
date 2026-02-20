// Package content manages the lifecycle of site content bundles.
//
// It provides loading, extraction, validation, watching, and atomic
// in-memory management of tar.gz content bundles fetched from S3.
//
// The core components are:
//   - [Loader]: downloads and verifies content bundles from S3/SSM
//   - [Manager]: stores the active content snapshot using atomic.Pointer for lock-free reads
//   - [Watcher]: polls SSM for hash changes and hot-swaps bundles into the Manager
//   - [Snapshot]: an immutable in-memory filesystem with metadata and provenance
//
// Bundle extraction enforces strict security limits: maximum compressed size,
// per-file size, total extracted size, and multi-layer path traversal checks.
package content
