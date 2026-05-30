package cryptoutil

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// SignaturesInfo is the dual-signature summary for an artifact. Either field
// may be nil if its bundle was absent or unparseable - the API surfaces what
// is present. The two halves are independent and verified separately by their
// respective verifiers; this struct just aggregates the post-verification
// display data.
type SignaturesInfo struct {
	Keyless *KeylessSignature `json:"keyless,omitempty"`
	KMS     *KMSSignature     `json:"kms,omitempty"`
}

// KeylessSignature carries every piece of evidence from a verified keyless
// (Fulcio) sigstore bundle: the signing certificate identity, the issuance
// chain, the Rekor transparency-log inclusion, the CT log entry, and the
// RFC3161 signing timestamp. Sub-blocks populate independently.
type KeylessSignature struct {
	Certificate *CertInfo      `json:"certificate,omitempty"`
	Chain       *ChainInfo     `json:"chain,omitempty"`
	Rekor       *RekorInfo     `json:"rekor,omitempty"`
	CTLog       *CTLogInfo     `json:"ct_log,omitempty"`
	Timestamp   *TimestampInfo `json:"timestamp,omitempty"`
}

// KMSSignature carries the evidence from a verified KMS sigstore bundle. KMS
// bundles have no leaf certificate, so there is no Certificate / Chain / CTLog
// block - just the public-key reference, the Rekor entry, and the timestamp.
// KeyRef is the bundle's verificationMaterial.publicKey.hint (base64 SHA-256
// of the KMS public key SPKI).
type KMSSignature struct {
	KeyRef    string         `json:"key_ref,omitempty"`
	Rekor     *RekorInfo     `json:"rekor,omitempty"`
	Timestamp *TimestampInfo `json:"timestamp,omitempty"`
}

// RekorInfo identifies the Rekor entry that records the signature. The proof
// hashes + signed checkpoint envelope are passed through so an auditor can
// re-verify inclusion off-server. The shape is identical for keyless and KMS
// bundles (the tlogEntries[] schema does not depend on signing material).
type RekorInfo struct {
	LogID                string   `json:"log_id"` // base64 SHA-256(SPKI) - matches tlogEntries[].logId.keyId
	LogIndex             int64    `json:"log_index"`
	TreeSize             int64    `json:"tree_size"`
	RootHash             string   `json:"root_hash"`                        // base64 from the inclusion proof
	Origin               string   `json:"origin"`                           // e.g. "rekor.trust.linnemanlabs.com"
	EntryKind            string   `json:"entry_kind"`                       // e.g. "hashedrekord"
	EntryVersion         string   `json:"entry_version"`                    // e.g. "0.0.2"
	PubKeyURL            string   `json:"pubkey_url,omitempty"`             // operator-published checkpoint pubkey
	InclusionProofHashes []string `json:"inclusion_proof_hashes,omitempty"` // base64 sibling hashes (RFC 6962 path)
	CheckpointEnvelope   string   `json:"checkpoint_envelope,omitempty"`    // raw signed-note envelope
}

// CTLogInfo describes the CT log that issued the leaf certificate's SCT.
// Only present for keyless signatures (KMS bundles have no leaf cert / SCT).
type CTLogInfo struct {
	LogID         string    `json:"log_id"`                   // base64 SHA-256(SPKI)
	Timestamp     time.Time `json:"timestamp"`                // SCT timestamp (RFC 6962)
	HashAlgorithm string    `json:"hash_algorithm,omitempty"` // e.g. "sha256"
	PubKeyURL     string    `json:"pubkey_url,omitempty"`     // operator-published log pubkey
}

// MessageImprint is the (hashAlgorithm, hashedMessage) pair that the TSA
// actually signed - here it is SHA-256 of the artifact signature bytes.
type MessageImprint struct {
	Algorithm string `json:"algorithm"` // "sha256" / "sha384" / "sha512"
	Hash      string `json:"hash"`      // base64
}

// TimestampInfo describes the RFC3161 signed timestamp that proves the
// signing time used for chain validation. RawTSR is the full base64 CMS
// TimeStampToken so an auditor can re-verify the timestamp offline.
type TimestampInfo struct {
	GenTime              time.Time       `json:"gen_time"`
	TSASubject           string          `json:"tsa_subject"`                      // TSA cert subject DN
	TSAFingerprintSHA256 string          `json:"tsa_fingerprint_sha256,omitempty"` // SHA-256 of TSA cert DER (hex)
	TSACertURL           string          `json:"tsa_cert_url,omitempty"`           // operator-published TSA cert
	MessageImprint       *MessageImprint `json:"message_imprint,omitempty"`        // what the TSA actually signed
	SerialNumber         string          `json:"serial_number,omitempty"`          // TSA-assigned timestamp serial
	PolicyOID            string          `json:"policy_oid,omitempty"`             // TSA policy OID
	RawTSR               string          `json:"raw_tsr,omitempty"`                // base64 of the full CMS token
}

// ChainInfo summarizes the trusted issuance chain for the leaf certificate.
// Only present for keyless signatures.
type ChainInfo struct {
	LeafFingerprintSHA256   string `json:"leaf_fingerprint_sha256"`
	IssuerSubject           string `json:"issuer_subject"`                      // Fulcio CA subject DN
	IssuerFingerprintSHA256 string `json:"issuer_fingerprint_sha256,omitempty"` // SHA-256 of Fulcio CA DER (hex)
	IssuerCertURL           string `json:"issuer_cert_url,omitempty"`           // operator-published Fulcio CA
	RootSubject             string `json:"root_subject"`                        // Root CA subject DN
	RootFingerprintSHA256   string `json:"root_fingerprint_sha256,omitempty"`   // SHA-256 of Root CA DER (hex)
}

// TrustedRootURL returns the operator-published URL for the aggregate
// sigstore trusted_root.json. Surfaced at the top of the provenance API so
// frontends can link to the canonical trust anchors without rederiving the
// host. Stable for a given binary build.
func TrustedRootURL() string { return trustURLTrustedRoot }

// KeylessSignatureFromBundle parses a (presumed-already-verified) keyless
// sigstore bundle and returns the signing certificate identity + transparency
// evidence. Best-effort: sub-blocks populate independently; missing data does
// not fail the whole extraction. Returns an error only when the bundle itself
// fails to parse - callers should only invoke this on bundles a KeylessVerifier
// already accepted.
func KeylessSignatureFromBundle(bundleJSON []byte) (*KeylessSignature, error) {
	bundle, err := ParseBundle(bundleJSON)
	if err != nil {
		return nil, xerrors.Wrap(err, "keyless signature: parse bundle")
	}
	out := &KeylessSignature{
		Rekor:     extractRekorInfo(bundle),
		Timestamp: extractTimestampInfo(bundle),
	}
	if cert, certErr := parseLeafCert(bundle); certErr == nil {
		out.Certificate = certInfo(cert)
		out.CTLog = extractCTLogInfo(cert)
		out.Chain = &ChainInfo{
			LeafFingerprintSHA256:   SHA256Hex(cert.Raw),
			IssuerSubject:           trustRoots.FulcioCA.Subject.String(),
			IssuerFingerprintSHA256: SHA256Hex(trustRoots.FulcioCA.Raw),
			IssuerCertURL:           trustURLFulcioCA,
			RootSubject:             trustRoots.RootCA.Subject.String(),
			RootFingerprintSHA256:   SHA256Hex(trustRoots.RootCA.Raw),
		}
	}
	return out, nil
}

// KMSSignatureFromBundle parses a (presumed-already-verified) KMS sigstore
// bundle and returns the key reference + Rekor / Timestamp evidence. KMS
// bundles carry no leaf certificate, so the result has no Certificate / Chain
// / CTLog block - just the publicKey.hint (base64 SHA-256 of the KMS pubkey
// SPKI), plus the same tlogEntries / timestamp evidence as a keyless bundle.
func KMSSignatureFromBundle(bundleJSON []byte) (*KMSSignature, error) {
	bundle, err := ParseBundle(bundleJSON)
	if err != nil {
		return nil, xerrors.Wrap(err, "kms signature: parse bundle")
	}
	return &KMSSignature{
		KeyRef:    bundle.VerificationMaterial.PublicKey.Hint,
		Rekor:     extractRekorInfo(bundle),
		Timestamp: extractTimestampInfo(bundle),
	}, nil
}

func extractRekorInfo(b *SigstoreBundle) *RekorInfo {
	if b == nil || len(b.VerificationMaterial.TlogEntries) == 0 {
		return nil
	}
	entry := b.VerificationMaterial.TlogEntries[0]
	out := &RekorInfo{
		LogID:        entry.LogID.KeyID,
		EntryKind:    entry.KindVersion.Kind,
		EntryVersion: entry.KindVersion.Version,
	}
	if ip := entry.InclusionProof; ip != nil {
		if n, err := strconv.ParseInt(ip.LogIndex, 10, 64); err == nil {
			out.LogIndex = n
		}
		if n, err := strconv.ParseInt(ip.TreeSize, 10, 64); err == nil {
			out.TreeSize = n
		}
		out.RootHash = ip.RootHash
		if origin := checkpointOrigin(ip.Checkpoint.Envelope); origin != "" {
			out.Origin = origin
		}
		// pass-through the sibling hashes + signed-note envelope so an
		// auditor can re-verify the inclusion proof offline.
		if len(ip.Hashes) > 0 {
			out.InclusionProofHashes = append([]string(nil), ip.Hashes...)
		}
		out.CheckpointEnvelope = ip.Checkpoint.Envelope
	}
	out.PubKeyURL = trustURLRekorPubKey
	return out
}

// checkpointOrigin returns the first non-empty line of the signed-note
// envelope - the log origin / name (e.g. "rekor.trust.linnemanlabs.com").
func checkpointOrigin(envelope string) string {
	for _, line := range strings.Split(envelope, "\n") {
		if line != "" {
			return line
		}
	}
	return ""
}

// extractCTLogInfo finds the first SCT in the leaf whose log_id matches a
// trusted CT log and returns its identifier + timestamp.
func extractCTLogInfo(cert *x509.Certificate) *CTLogInfo {
	extBytes, err := findSCTExtension(cert)
	if err != nil {
		return nil
	}
	scts, err := parseSCTList(extBytes)
	if err != nil {
		return nil
	}
	for _, s := range scts {
		if _, ok := trustRoots.CTLogs[s.LogID]; !ok {
			continue
		}
		return &CTLogInfo{
			LogID:         base64.StdEncoding.EncodeToString(s.LogID[:]),
			Timestamp:     time.UnixMilli(int64(s.Timestamp)).UTC(), //nolint:gosec // timestamp is uint64 ms since epoch; range is fine until year 2262
			HashAlgorithm: tlsHashName(s.HashAlgo),
			PubKeyURL:     trustURLCTLogPubKey,
		}
	}
	return nil
}

// tlsHashName maps a RFC 5246 HashAlgorithm enum value to a readable string.
func tlsHashName(algo uint8) string {
	switch algo {
	case 4:
		return "sha256"
	case 5:
		return "sha384"
	case 6:
		return "sha512"
	}
	return fmt.Sprintf("unknown-%d", algo)
}

func extractTimestampInfo(b *SigstoreBundle) *TimestampInfo {
	if b == nil || b.VerificationMaterial.TimestampVerificationData == nil {
		return nil
	}
	tss := b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps
	if len(tss) == 0 {
		return nil
	}
	tokenB64 := tss[0].SignedTimestamp
	tokenRaw, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return nil
	}
	parsed, err := parseTSTInfo(tokenRaw)
	if err != nil {
		return nil
	}
	return &TimestampInfo{
		GenTime:              parsed.GenTime,
		TSASubject:           trustRoots.TSACert.Subject.String(),
		TSAFingerprintSHA256: SHA256Hex(trustRoots.TSACert.Raw),
		TSACertURL:           trustURLTSACert,
		MessageImprint:       parsed.MessageImprint,
		SerialNumber:         parsed.SerialNumber,
		PolicyOID:            parsed.PolicyOID,
		RawTSR:               tokenB64,
	}
}

// parsedTSTInfo is the subset of RFC3161 TSTInfo we surface through the
// transparency API.
type parsedTSTInfo struct {
	GenTime        time.Time
	MessageImprint *MessageImprint
	SerialNumber   string
	PolicyOID      string
}

// parseTSTInfo parses an RFC3161 TimeStampToken just far enough to extract
// the display-friendly fields, without verifying the TSA chain or signature
// (the keyless verifier already did that). Best-effort: errors on malformed
// input.
func parseTSTInfo(token []byte) (*parsedTSTInfo, error) {
	tokenDER, err := extractTimeStampToken(token)
	if err != nil {
		return nil, err
	}
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(tokenDER, &ci); err != nil {
		return nil, err
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	var tstInfoOctets []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.Content.Bytes, &tstInfoOctets); err != nil {
		return nil, err
	}
	var ti tstInfo
	if _, err := asn1.Unmarshal(tstInfoOctets, &ti); err != nil {
		return nil, err
	}
	out := &parsedTSTInfo{
		GenTime:   ti.GenTime.UTC(),
		PolicyOID: ti.Policy.String(),
	}
	if ti.SerialNumber != nil {
		out.SerialNumber = ti.SerialNumber.String()
	}
	out.MessageImprint = &MessageImprint{
		Algorithm: hashAlgoName(ti.MessageImprint.HashAlgorithm.Algorithm),
		Hash:      base64.StdEncoding.EncodeToString(ti.MessageImprint.HashedMessage),
	}
	return out, nil
}

// hashAlgoName maps the standard SHA-2 OIDs to readable names. Falls back to
// the dotted OID string for anything else (so the API never lies about the
// algorithm by claiming sha256 when it's something else).
func hashAlgoName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidSHA256):
		return "sha256"
	case oid.Equal(oidSHA384):
		return "sha384"
	case oid.Equal(oidSHA512):
		return "sha512"
	}
	return oid.String()
}
