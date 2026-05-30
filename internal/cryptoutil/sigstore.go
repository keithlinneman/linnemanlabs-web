package cryptoutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// Sigstore bundle format (cosign output)
type SigstoreBundle struct {
	MediaType            string               `json:"mediaType"`
	VerificationMaterial VerificationMaterial `json:"verificationMaterial"`
	DSSEEnvelope         *DSSEEnvelope        `json:"dsseEnvelope,omitempty"`
	MessageSignature     *MessageSignature    `json:"messageSignature,omitempty"`
}

// TimestampVerificationData carries RFC3161 signed timestamps that bind the
// signing time to the artifact's signature.
type TimestampVerificationData struct {
	RFC3161Timestamps []RFC3161Timestamp `json:"rfc3161Timestamps"`
}

// RFC3161Timestamp is a base64-encoded DER CMS SignedData TimeStampToken
// (RFC 3161 §2.4.2).
type RFC3161Timestamp struct {
	SignedTimestamp string `json:"signedTimestamp"`
}

type VerificationMaterial struct {
	// PublicKey is set for keyed bundles (e.g. cosign sign-blob with a KMS key).
	PublicKey PublicKeyRef `json:"publicKey"`

	// Certificate / X509CertificateChain are set for keyless (Fulcio) bundles.
	// A bundle carries one or the other - newer cosign emits a single
	// certificate, older output a chain. Both hold base64 DER.
	Certificate          *CertificateRef       `json:"certificate,omitempty"`
	X509CertificateChain *X509CertificateChain `json:"x509CertificateChain,omitempty"`

	// TlogEntries are the Rekor transparency-log inclusion proofs.
	TlogEntries []RekorTlogEntry `json:"tlogEntries,omitempty"`

	// TimestampVerificationData carries the RFC3161 signed timestamps that bind
	// the artifact signature to a trusted signing time.
	TimestampVerificationData *TimestampVerificationData `json:"timestampVerificationData,omitempty"`
}

// RekorTlogEntry is one entry from a Rekor transparency log. Int fields are
// protobuf-JSON strings.
type RekorTlogEntry struct {
	LogIndex          string               `json:"logIndex"`
	LogID             RekorLogID           `json:"logId"`
	KindVersion       RekorKindVersion     `json:"kindVersion"`
	InclusionProof    *RekorInclusionProof `json:"inclusionProof,omitempty"`
	CanonicalizedBody string               `json:"canonicalizedBody"` // base64 of the canonical JSON body
}

// RekorLogID identifies a Rekor log via SHA-256 of its public key SPKI (base64).
type RekorLogID struct {
	KeyID string `json:"keyId"`
}

// RekorKindVersion identifies the kind/version of the entry body
// (e.g. hashedrekord 0.0.2).
type RekorKindVersion struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

// RekorInclusionProof carries the Merkle inclusion proof + signed checkpoint
// that proves a Rekor entry is in the log.
type RekorInclusionProof struct {
	LogIndex   string          `json:"logIndex"`
	RootHash   string          `json:"rootHash"` // base64
	TreeSize   string          `json:"treeSize"`
	Hashes     []string        `json:"hashes"` // base64 each
	Checkpoint RekorCheckpoint `json:"checkpoint"`
}

// RekorCheckpoint is the signed-note envelope (Trillian/sumdb format) used by
// Rekor to commit to a tree state.
type RekorCheckpoint struct {
	Envelope string `json:"envelope"`
}

type PublicKeyRef struct {
	Hint string `json:"hint"`
}

// CertificateRef holds a base64-encoded DER certificate (sigstore "certificate").
type CertificateRef struct {
	RawBytes string `json:"rawBytes"`
}

// X509CertificateChain holds an ordered cert chain (leaf first), base64 DER each.
type X509CertificateChain struct {
	Certificates []CertificateRef `json:"certificates"`
}

type DSSEEnvelope struct {
	Payload     string          `json:"payload"`     // base64-encoded in-toto statement
	PayloadType string          `json:"payloadType"` // "application/vnd.in-toto+json"
	Signatures  []DSSESignature `json:"signatures"`
}

type DSSESignature struct {
	Sig string `json:"sig"` // base64-encoded signature over PAE
}

// In-toto statement (decoded from DSSE payload)
type InTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []InTotoSubject `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// DSSEVerifyResult holds the outcome of a successful verification.
type DSSEVerifyResult struct {
	KeyHint       string // from bundle verification material
	SubjectName   string // from in-toto statement
	SubjectDigest string // sha256 from subject
	PredicateType string // "phxi.net/attestations/release/v1"
}

// Blob signature bundle format (from cosign sign-blob)
type MessageSignature struct {
	MessageDigest MessageDigest `json:"messageDigest"`
	Signature     string        `json:"signature"` // base64
}

type MessageDigest struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"` // base64 of the raw hash bytes
}

type BlobVerifyResult struct {
	Verified bool
	KeyHint  string
}

// PAE computes the DSSE Pre-Authentication Encoding.
// This is the exact byte sequence that cosign signed.
// Format: "DSSEv1" SP len(type) SP type SP len(body) SP body
func PAE(payloadType string, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("DSSEv1 ")
	buf.WriteString(strconv.Itoa(len(payloadType)))
	buf.WriteByte(' ')
	buf.WriteString(payloadType)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(len(payload)))
	buf.WriteByte(' ')
	buf.Write(payload)
	return buf.Bytes()
}

// ParseBundle parses a sigstore bundle JSON and extracts
// the components needed for verification.
func ParseBundle(bundleJSON []byte) (*SigstoreBundle, error) {
	var b SigstoreBundle
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		return nil, xerrors.Wrap(err, "parse sigstore bundle")
	}

	switch {
	case b.MessageSignature != nil:
		if b.MessageSignature.Signature == "" {
			return nil, xerrors.New("sigstore bundle has empty message signature")
		}
	case b.DSSEEnvelope != nil:
		if len(b.DSSEEnvelope.Signatures) == 0 {
			return nil, xerrors.New("sigstore bundle has no signatures")
		}
		if b.DSSEEnvelope.Payload == "" {
			return nil, xerrors.New("sigstore bundle has empty payload")
		}
	default:
		return nil, xerrors.New("sigstore bundle has neither DSSE envelope nor message signature")
	}

	return &b, nil
}

// DecodeDSSEPayload base64-decodes the envelope payload.
func DecodeDSSEPayload(envelope *DSSEEnvelope) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, xerrors.Wrap(err, "base64 decode DSSE payload")
	}
	return raw, nil
}

// DecodeSignature base64-decodes the first signature from the envelope.
func DecodeSignature(envelope *DSSEEnvelope) ([]byte, error) {
	if len(envelope.Signatures) == 0 {
		return nil, xerrors.New("no signatures in DSSE envelope")
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return nil, xerrors.Wrap(err, "base64 decode signature")
	}
	return sig, nil
}

// VerifySubjectDigest checks that the in-toto statement's subject
// contains a sha256 digest matching the provided artifact bytes.
func VerifySubjectDigest(statement *InTotoStatement, artifact []byte) error {
	artifactHash := SHA256Hex(artifact)

	for _, subj := range statement.Subject {
		if HashEqual(subj.Digest["sha256"], artifactHash) {
			return nil
		}
	}
	return xerrors.Newf(
		"artifact sha256 %s not found in in-toto statement subjects",
		artifactHash,
	)
}

// VerifyReleaseDSSE verifies a cosign-produced sigstore bundle
// against the original artifact bytes using a KMSVerifier.
func VerifyReleaseDSSE(ctx context.Context, v *KMSVerifier, bundleJSON, artifact []byte) (*DSSEVerifyResult, error) {
	// parse the bundle
	bundle, err := ParseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}

	if bundle.DSSEEnvelope == nil {
		return nil, xerrors.New("bundle is not a DSSE attestation (no dsseEnvelope)")
	}

	// decode the raw payload bytes (still base64 in the envelope)
	payloadBytes, err := DecodeDSSEPayload(bundle.DSSEEnvelope)
	if err != nil {
		return nil, err
	}

	// decode the signature
	sig, err := DecodeSignature(bundle.DSSEEnvelope)
	if err != nil {
		return nil, err
	}

	// compute PAE and verify signature
	pae := PAE(bundle.DSSEEnvelope.PayloadType, payloadBytes)
	if err := v.VerifySignature(ctx, pae, sig); err != nil {
		return nil, xerrors.Wrap(err, "DSSE signature verification failed")
	}

	// parse in-toto statement and check subject digest
	var statement InTotoStatement
	if err := json.Unmarshal(payloadBytes, &statement); err != nil {
		return nil, xerrors.Wrap(err, "parse in-toto statement")
	}

	if err := VerifySubjectDigest(&statement, artifact); err != nil {
		return nil, err
	}

	// build result
	result := &DSSEVerifyResult{
		KeyHint:       bundle.VerificationMaterial.PublicKey.Hint,
		PredicateType: statement.PredicateType,
	}
	if len(statement.Subject) > 0 {
		result.SubjectName = statement.Subject[0].Name
		result.SubjectDigest = statement.Subject[0].Digest["sha256"]
	}

	return result, nil
}

// VerifyBlobSignature verifies a cosign sign-blob bundle against
// the original artifact bytes using a KMSVerifier.
func VerifyBlobSignature(ctx context.Context, v *KMSVerifier, bundleJSON, artifact []byte) (*BlobVerifyResult, error) {
	bundle, err := ParseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	return verifyBlobBundle(bundle, artifact, func(message, sig []byte) error {
		return v.VerifySignature(ctx, message, sig)
	})
}

// verifyBlobBundle verifies a parsed blob (messageSignature) bundle against the
// artifact bytes. The signature step is delegated to verifySig so the same
// logic serves both the KMS path (key fetched from KMS) and the keyless path
// (key from a Fulcio leaf certificate). It also cross-checks the bundle's
// embedded digest against the artifact.
func verifyBlobBundle(bundle *SigstoreBundle, artifact []byte, verifySig func(message, sig []byte) error) (*BlobVerifyResult, error) {
	if bundle.MessageSignature == nil {
		return nil, xerrors.New("bundle is not a blob signature (no messageSignature)")
	}

	// decode signature
	sig, err := base64.StdEncoding.DecodeString(bundle.MessageSignature.Signature)
	if err != nil {
		return nil, xerrors.Wrap(err, "base64 decode signature")
	}

	// verify signature over raw artifact bytes
	if err := verifySig(artifact, sig); err != nil {
		return nil, xerrors.Wrap(err, "blob signature verification failed")
	}

	// cross-check: bundle's embedded digest must match artifact
	// cosign always includes the digest when signing;
	// empty means the bundle is malformed or tampered
	if bundle.MessageSignature.MessageDigest.Digest == "" {
		return nil, xerrors.New("bundle messageDigest.digest is empty, expected non-empty digest from cosign")
	}

	bundleDigest, err := base64.StdEncoding.DecodeString(
		bundle.MessageSignature.MessageDigest.Digest,
	)
	if err != nil {
		return nil, xerrors.Wrap(err, "decode bundle digest")
	}

	artifactDigest, err := computeDigestForAlgorithm(
		bundle.MessageSignature.MessageDigest.Algorithm, artifact,
	)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(bundleDigest, artifactDigest) != 1 {
		return nil, xerrors.New("bundle digest does not match artifact")
	}

	return &BlobVerifyResult{
		Verified: true,
		KeyHint:  bundle.VerificationMaterial.PublicKey.Hint,
	}, nil
}

// computeDigestForAlgorithm computes the hash of data using the algorithm
// specified in the sigstore bundle's messageDigest field.
// Supports SHA2_256 and SHA2_384 (the algorithms cosign uses with KMS keys).
func computeDigestForAlgorithm(algorithm string, data []byte) ([]byte, error) {
	switch algorithm {
	case "SHA2_256", "SHA_256", "sha256":
		d := sha256.Sum256(data)
		return d[:], nil
	case "SHA2_384", "SHA_384", "sha384":
		d := sha512.Sum384(data)
		return d[:], nil
	default:
		return nil, xerrors.Newf("unsupported digest algorithm in bundle: %s", algorithm)
	}
}
