// Package cryptoutil provides cryptographic verification primitives
// for content integrity and build provenance.
//
// It supports:
//   - KMS-backed signature verification (ECDSA P-256/P-384, RSA-PSS with optional PKCS1v15 fallback)
//   - Sigstore bundle parsing and verification (DSSE envelopes and blob signatures)
//   - In-toto statement subject digest verification
//   - Constant-time hash comparison to prevent timing side-channels
//   - SHA-256 and SHA-384 hashing utilities
package cryptoutil
