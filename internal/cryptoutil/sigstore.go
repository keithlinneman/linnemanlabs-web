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

type VerificationMaterial struct {
	PublicKey PublicKeyRef `json:"publicKey"`
}

type PublicKeyRef struct {
	Hint string `json:"hint"`
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
	// parse bundle
	bundle, err := ParseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}

	if bundle.MessageSignature == nil {
		return nil, xerrors.New("bundle is not a blob signature (no messageSignature)")
	}

	// decode signature
	sig, err := base64.StdEncoding.DecodeString(bundle.MessageSignature.Signature)
	if err != nil {
		return nil, xerrors.Wrap(err, "base64 decode signature")
	}

	// verify signature over raw artifact bytes
	if err := v.VerifySignature(ctx, artifact, sig); err != nil {
		return nil, xerrors.Wrap(err, "blob signature verification failed")
	}

	// cross-check: bundle's embedded digest must match artifact
	// cosign always includes the digest when signing with KMS keys;
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
