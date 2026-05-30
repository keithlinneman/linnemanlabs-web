package cryptoutil

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// KeylessVerifier verifies a sigstore keyless (Fulcio) blob bundle: a
// cosign sign-blob messageSignature whose verification material carries an
// x509 leaf certificate instead of a public-key hint. It verifies the blob
// signature against the certificate's public key and (when configured) checks
// the certificate identity against a policy.
//
// It satisfies the BlobVerifier interface used by the content and evidence
// loaders, so it can be passed alongside the KMS verifier.
type KeylessVerifier struct {
	// AllowPKCS1v15 mirrors KMSVerifier for RSA fallback. Fulcio leaf certs are
	// ECDSA P-256 in practice, so this is effectively unused, kept for symmetry.
	AllowPKCS1v15 bool

	// Identity is the certificate-identity policy (allowed SANs, OIDC issuer,
	// Fulcio OID extensions). It is the extension point for the verification
	// filters supplied by the operator. When nil, identity is NOT enforced -
	// the cryptographic signature is still verified, but any valid Fulcio cert
	// is accepted.
	Identity CertIdentityPolicy

	// SkipTrustRootChecks disables chain-to-Fulcio-CA + RFC3161 TSA timestamp +
	// Rekor inclusion + SCT verification. Default false (production-safe);
	// tests that craft synthetic bundles without those artifacts set it true to
	// exercise just the signature + identity paths.
	SkipTrustRootChecks bool

	// MaxSigningAge bounds how old the TSA-attested signing time is allowed to
	// be. Zero (default) disables the check; production sets it to e.g. 1 year
	// so a long-stale-but-valid bundle cannot be replayed indefinitely.
	MaxSigningAge time.Duration
}

// CertIdentityPolicy decides whether a verified leaf certificate's identity is
// acceptable. This is where SAN / OIDC-issuer / Fulcio-OID-extension matching
// will be wired in once the filters are defined.
type CertIdentityPolicy interface {
	Check(cert *x509.Certificate, info *CertInfo) error
}

// NewKeylessVerifier returns a KeylessVerifier with default settings. The
// identity policy is left unset (skeleton); set Identity to enforce it.
func NewKeylessVerifier() *KeylessVerifier {
	return &KeylessVerifier{}
}

// VerifyBlob verifies a keyless blob bundle against the artifact bytes.
func (v *KeylessVerifier) VerifyBlob(ctx context.Context, bundleJSON, artifact []byte) error {
	_ = ctx // no network calls in the keyless path; ctx kept to satisfy BlobVerifier

	bundle, err := ParseBundle(bundleJSON)
	if err != nil {
		return err
	}

	cert, err := parseLeafCert(bundle)
	if err != nil {
		return err
	}

	// Verify the blob signature against the leaf certificate's public key.
	if _, err := verifyBlobBundle(bundle, artifact, func(message, sig []byte) error {
		return verifyWithPublicKey(cert.PublicKey, message, sig, v.AllowPKCS1v15)
	}); err != nil {
		return err
	}

	// Trust-root verification: chain to LinnemanLabs Fulcio CA at a trusted
	// signing time, the cert was issued via the CT log (SCT), and the entry
	// was publicly logged in Rekor with the same cert + signature + digest.
	if !v.SkipTrustRootChecks {
		if err := v.verifyTrustRoot(bundle, cert); err != nil {
			return xerrors.Wrap(err, "keyless trust root")
		}
	}

	// Certificate-identity policy (which SAN / OIDC issuer / OID values to
	// trust). When nil, identity is not enforced - cryptographic + trust-root
	// checks still apply.
	if v.Identity != nil {
		if err := v.Identity.Check(cert, certInfo(cert)); err != nil {
			return xerrors.Wrap(err, "keyless certificate identity rejected")
		}
	}

	return nil
}

// verifyTrustRoot runs the four trust-anchor verifications in order: the
// RFC3161 TSA timestamp pins a trusted signing time; the leaf certificate
// chains to the Fulcio CA at that time; the embedded SCT proves the cert was
// logged with the CT log; and the Rekor inclusion proof + signed checkpoint
// prove the cert+signature combination was publicly logged in Rekor.
func (v *KeylessVerifier) verifyTrustRoot(bundle *SigstoreBundle, cert *x509.Certificate) error {
	if bundle.MessageSignature == nil {
		return xerrors.New("bundle has no messageSignature for TSA imprint")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(bundle.MessageSignature.Signature)
	if err != nil {
		return xerrors.Wrap(err, "decode messageSignature")
	}
	imprint := sha256.Sum256(sigBytes)

	tvd := bundle.VerificationMaterial.TimestampVerificationData
	if tvd == nil || len(tvd.RFC3161Timestamps) == 0 {
		return xerrors.New("bundle has no rfc3161Timestamps")
	}
	tsRaw, err := base64.StdEncoding.DecodeString(tvd.RFC3161Timestamps[0].SignedTimestamp)
	if err != nil {
		return xerrors.Wrap(err, "decode signedTimestamp")
	}
	signingTime, err := VerifyRFC3161(tsRaw, imprint[:])
	if err != nil {
		return err
	}
	if v.MaxSigningAge > 0 {
		if age := time.Since(signingTime); age > v.MaxSigningAge {
			return xerrors.Newf("signed too long ago: age=%s > max=%s", age.Truncate(time.Second), v.MaxSigningAge)
		}
	}

	if err := VerifyLeafChain(cert, signingTime); err != nil {
		return err
	}
	if err := VerifySCT(cert); err != nil {
		return err
	}
	if err := VerifyRekorInclusion(bundle); err != nil {
		return err
	}
	return nil
}

// parseLeafCert extracts and parses the leaf certificate from a keyless bundle,
// supporting both the single-certificate and certificate-chain forms.
func parseLeafCert(b *SigstoreBundle) (*x509.Certificate, error) {
	var der []byte
	switch {
	case b.VerificationMaterial.Certificate != nil && b.VerificationMaterial.Certificate.RawBytes != "":
		raw, err := base64.StdEncoding.DecodeString(b.VerificationMaterial.Certificate.RawBytes)
		if err != nil {
			return nil, xerrors.Wrap(err, "decode certificate rawBytes")
		}
		der = raw
	case b.VerificationMaterial.X509CertificateChain != nil && len(b.VerificationMaterial.X509CertificateChain.Certificates) > 0:
		raw, err := base64.StdEncoding.DecodeString(b.VerificationMaterial.X509CertificateChain.Certificates[0].RawBytes)
		if err != nil {
			return nil, xerrors.Wrap(err, "decode certificate chain leaf rawBytes")
		}
		der = raw
	default:
		return nil, xerrors.New("keyless bundle has no certificate in verification material")
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, xerrors.Wrap(err, "parse leaf certificate")
	}
	return cert, nil
}

// CertInfo is the human/machine-readable identity of a keyless signing
// certificate, surfaced through the provenance API alongside the KMS key
// reference. The OID-extension fields are a representative subset of the
// sigstore Fulcio extensions (1.3.6.1.4.1.57264.1.x) and can be expanded.
type CertInfo struct {
	Subject           string    `json:"subject,omitempty"`
	SANs              []string  `json:"sans,omitempty"`
	Issuer            string    `json:"issuer,omitempty"`
	OIDCIssuer        string    `json:"oidc_issuer,omitempty"`
	SerialNumber      string    `json:"serial_number,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`
	NotBefore         time.Time `json:"not_before,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`

	// sigstore Fulcio OID extensions (1.3.6.1.4.1.57264.1.x), v2 form.
	SourceRepository string `json:"source_repository,omitempty"`
	SourceRevision   string `json:"source_revision,omitempty"`
	BuildSignerURI   string `json:"build_signer_uri,omitempty"`
	BuildTrigger     string `json:"build_trigger,omitempty"`
	RunInvocationURI string `json:"run_invocation_uri,omitempty"`

	// Deprecated GitHub-workflow OID extensions (1.3.6.1.4.1.57264.1.2-.6),
	// raw UTF-8 strings. These are what cosign's --certificate-github-workflow-*
	// flags match against, so the identity policy reads them from here.
	GitHubWorkflowTrigger    string `json:"github_workflow_trigger,omitempty"`
	GitHubWorkflowSHA        string `json:"github_workflow_sha,omitempty"`
	GitHubWorkflowName       string `json:"github_workflow_name,omitempty"`
	GitHubWorkflowRepository string `json:"github_workflow_repository,omitempty"`
	GitHubWorkflowRef        string `json:"github_workflow_ref,omitempty"`
}

// CertInfoFromBundle parses a keyless bundle and extracts the leaf
// certificate's identity. It does NOT verify the signature - callers that need
// verification use a KeylessVerifier; this is for surfacing already-verified
// bundle metadata to the provenance API.
func CertInfoFromBundle(bundleJSON []byte) (*CertInfo, error) {
	bundle, err := ParseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	cert, err := parseLeafCert(bundle)
	if err != nil {
		return nil, err
	}
	return certInfo(cert), nil
}

// sigstore Fulcio certificate extension OIDs. v1 (.1) stores a raw UTF-8
// string; v2 (.8+) DER-encode the value as an ASN.1 UTF8String.
var (
	// Deprecated v1 GitHub-workflow extensions (raw UTF-8 strings). These are
	// what cosign's --certificate-github-workflow-* / --certificate-oidc-issuer
	// (fallback) flags match.
	oidIssuerV1          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidGHWorkflowTrigger = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}
	oidGHWorkflowSHA     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}
	oidGHWorkflowName    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}
	oidGHWorkflowRepo    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}
	oidGHWorkflowRef     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}

	// v2 extensions (DER-encoded ASN.1 UTF8String).
	oidIssuerV2         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidBuildSignerURI   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	oidSourceRepoURI    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidSourceRepoDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}
	oidBuildTrigger     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 20}
	oidRunInvocationURI = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}
)

func certInfo(cert *x509.Certificate) *CertInfo {
	info := &CertInfo{
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		SerialNumber:      cert.SerialNumber.String(),
		FingerprintSHA256: SHA256Hex(cert.Raw),
		NotBefore:         cert.NotBefore.UTC(),
		NotAfter:          cert.NotAfter.UTC(),
	}

	info.SANs = append(info.SANs, cert.EmailAddresses...)
	info.SANs = append(info.SANs, cert.DNSNames...)
	for _, u := range cert.URIs {
		info.SANs = append(info.SANs, u.String())
	}

	info.OIDCIssuer = oidExtString(cert, oidIssuerV2)
	if info.OIDCIssuer == "" {
		info.OIDCIssuer = oidExtRaw(cert, oidIssuerV1)
	}
	info.BuildSignerURI = oidExtString(cert, oidBuildSignerURI)
	info.SourceRepository = oidExtString(cert, oidSourceRepoURI)
	info.SourceRevision = oidExtString(cert, oidSourceRepoDigest)
	info.BuildTrigger = oidExtString(cert, oidBuildTrigger)
	info.RunInvocationURI = oidExtString(cert, oidRunInvocationURI)

	// deprecated v1 GitHub-workflow extensions (raw strings)
	info.GitHubWorkflowTrigger = oidExtRaw(cert, oidGHWorkflowTrigger)
	info.GitHubWorkflowSHA = oidExtRaw(cert, oidGHWorkflowSHA)
	info.GitHubWorkflowName = oidExtRaw(cert, oidGHWorkflowName)
	info.GitHubWorkflowRepository = oidExtRaw(cert, oidGHWorkflowRepo)
	info.GitHubWorkflowRef = oidExtRaw(cert, oidGHWorkflowRef)

	return info
}

// oidExtRaw returns the raw string value of a certificate extension.
func oidExtRaw(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return string(ext.Value)
		}
	}
	return ""
}

// oidExtString returns the value of a DER-encoded ASN.1 UTF8String extension,
// falling back to the raw bytes if the value is not DER-wrapped.
func oidExtString(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		var s string
		if rest, err := asn1.Unmarshal(ext.Value, &s); err == nil && len(rest) == 0 {
			return s
		}
		return string(ext.Value)
	}
	return ""
}
