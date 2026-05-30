package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// fulcioCertOptions describes the identity baked into a test Fulcio-style leaf.
type fulcioCertOptions struct {
	sanURI           string
	oidcIssuer       string // v2 OID .8 (UTF8String)
	sourceRepository string // .12
	sourceRevision   string // .13
	buildSignerURI   string // .9
	buildTrigger     string // .20
	runInvocationURI string // .21

	// deprecated v1 GitHub-workflow extensions (raw strings)
	ghTrigger    string // .2
	ghSHA        string // .3
	ghName       string // .4
	ghRepository string // .5
	ghRef        string // .6
}

// newTestLeafCert builds a self-signed ECDSA leaf certificate whose public key
// is key.Public(), carrying a URI SAN and the sigstore Fulcio OID extensions.
func newTestLeafCert(t *testing.T, key *ecdsa.PrivateKey, opts *fulcioCertOptions) *x509.Certificate {
	t.Helper()

	utf8Ext := func(oid asn1.ObjectIdentifier, val string) pkix.Extension {
		der, err := asn1.MarshalWithParams(val, "utf8")
		if err != nil {
			t.Fatalf("marshal OID %v ext: %v", oid, err)
		}
		return pkix.Extension{Id: oid, Value: der}
	}

	var extra []pkix.Extension
	if opts.oidcIssuer != "" {
		extra = append(extra, utf8Ext(oidIssuerV2, opts.oidcIssuer))
	}
	if opts.buildSignerURI != "" {
		extra = append(extra, utf8Ext(oidBuildSignerURI, opts.buildSignerURI))
	}
	if opts.sourceRepository != "" {
		extra = append(extra, utf8Ext(oidSourceRepoURI, opts.sourceRepository))
	}
	if opts.sourceRevision != "" {
		extra = append(extra, utf8Ext(oidSourceRepoDigest, opts.sourceRevision))
	}
	if opts.buildTrigger != "" {
		extra = append(extra, utf8Ext(oidBuildTrigger, opts.buildTrigger))
	}
	if opts.runInvocationURI != "" {
		extra = append(extra, utf8Ext(oidRunInvocationURI, opts.runInvocationURI))
	}

	// deprecated v1 extensions store the raw UTF-8 string directly (no DER)
	rawExt := func(oid asn1.ObjectIdentifier, val string) pkix.Extension {
		return pkix.Extension{Id: oid, Value: []byte(val)}
	}
	if opts.ghTrigger != "" {
		extra = append(extra, rawExt(oidGHWorkflowTrigger, opts.ghTrigger))
	}
	if opts.ghSHA != "" {
		extra = append(extra, rawExt(oidGHWorkflowSHA, opts.ghSHA))
	}
	if opts.ghName != "" {
		extra = append(extra, rawExt(oidGHWorkflowName, opts.ghName))
	}
	if opts.ghRepository != "" {
		extra = append(extra, rawExt(oidGHWorkflowRepo, opts.ghRepository))
	}
	if opts.ghRef != "" {
		extra = append(extra, rawExt(oidGHWorkflowRef, opts.ghRef))
	}

	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		Issuer:          pkix.Name{CommonName: "sigstore-test-ca"},
		ExtraExtensions: extra,
	}
	if opts.sanURI != "" {
		u, err := url.Parse(opts.sanURI)
		if err != nil {
			t.Fatalf("parse SAN URI: %v", err)
		}
		tmpl.URIs = []*url.URL{u}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// signBlobECDSA signs the artifact the way cosign sign-blob does with an
// ECDSA P-256 key: ASN.1 signature over the SHA-256 digest of the raw bytes.
func signBlobECDSA(t *testing.T, key *ecdsa.PrivateKey, artifact []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(artifact)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign blob: %v", err)
	}
	return sig
}

// buildKeylessBundle builds a keyless blob bundle (messageSignature + leaf cert)
// matching cosign sign-blob keyless output. chain=true uses x509CertificateChain.
func buildKeylessBundle(t *testing.T, key *ecdsa.PrivateKey, cert *x509.Certificate, artifact []byte, chain bool) []byte {
	t.Helper()
	sig := signBlobECDSA(t, key, artifact)
	digest := sha256.Sum256(artifact)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	vm := VerificationMaterial{}
	if chain {
		vm.X509CertificateChain = &X509CertificateChain{
			Certificates: []CertificateRef{{RawBytes: certB64}},
		}
	} else {
		vm.Certificate = &CertificateRef{RawBytes: certB64}
	}

	bundle := SigstoreBundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: vm,
		MessageSignature: &MessageSignature{
			MessageDigest: MessageDigest{
				Algorithm: "SHA2_256",
				Digest:    base64.StdEncoding.EncodeToString(digest[:]),
			},
			Signature: base64.StdEncoding.EncodeToString(sig),
		},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return raw
}

func TestKeylessVerifier_Valid(t *testing.T) {
	key := generateTestECKey(t, elliptic.P256())
	cert := newTestLeafCert(t, key, &fulcioCertOptions{sanURI: "https://github.com/keithlinneman/linnemanlabs-web/.github/workflows/build.yml@refs/tags/v1.0.0"})
	artifact := []byte(`{"release_id":"v1.0.0","component":"server"}`)
	bundleJSON := buildKeylessBundle(t, key, cert, artifact, false)

	v := NewKeylessVerifier()
	v.SkipTrustRootChecks = true // synthetic bundles - no TSA/Rekor/SCT
	if err := v.VerifyBlob(t.Context(), bundleJSON, artifact); err != nil {
		t.Fatalf("VerifyBlob: %v", err)
	}
}

func TestKeylessVerifier_ValidChainForm(t *testing.T) {
	key := generateTestECKey(t, elliptic.P256())
	cert := newTestLeafCert(t, key, &fulcioCertOptions{sanURI: "https://example.com/workflow"})
	artifact := []byte("content-bundle-bytes")
	bundleJSON := buildKeylessBundle(t, key, cert, artifact, true)

	v := NewKeylessVerifier()
	v.SkipTrustRootChecks = true // synthetic bundles - no TSA/Rekor/SCT
	if err := v.VerifyBlob(t.Context(), bundleJSON, artifact); err != nil {
		t.Fatalf("VerifyBlob (chain form): %v", err)
	}
}

func TestKeylessVerifier_TamperedArtifact(t *testing.T) {
	key := generateTestECKey(t, elliptic.P256())
	cert := newTestLeafCert(t, key, &fulcioCertOptions{sanURI: "https://example.com/workflow"})
	original := []byte(`{"release_id":"v1.0.0"}`)
	bundleJSON := buildKeylessBundle(t, key, cert, original, false)

	v := NewKeylessVerifier()
	v.SkipTrustRootChecks = true // synthetic bundles - no TSA/Rekor/SCT
	tampered := []byte(`{"release_id":"v1.0.0","injected":"evil"}`)
	if err := v.VerifyBlob(t.Context(), bundleJSON, tampered); err == nil {
		t.Fatal("expected verification failure for tampered artifact")
	}
}

func TestKeylessVerifier_WrongKey(t *testing.T) {
	signingKey := generateTestECKey(t, elliptic.P256())
	wrongKey := generateTestECKey(t, elliptic.P256())
	// Certificate carries the wrong key's public key, but the blob is signed
	// by signingKey - signature must fail against the cert's public key.
	cert := newTestLeafCert(t, wrongKey, &fulcioCertOptions{sanURI: "https://example.com/workflow"})
	artifact := []byte(`{"release_id":"v1.0.0"}`)
	bundleJSON := buildKeylessBundle(t, signingKey, cert, artifact, false)

	v := NewKeylessVerifier()
	v.SkipTrustRootChecks = true // synthetic bundles - no TSA/Rekor/SCT
	if err := v.VerifyBlob(t.Context(), bundleJSON, artifact); err == nil {
		t.Fatal("expected verification failure when signature does not match cert key")
	}
}

func TestKeylessVerifier_MissingCertificate(t *testing.T) {
	// A keyed (publicKey-only) bundle has no certificate; keyless verify rejects it.
	bundle := SigstoreBundle{
		VerificationMaterial: VerificationMaterial{PublicKey: PublicKeyRef{Hint: "kms-key"}},
		MessageSignature: &MessageSignature{
			MessageDigest: MessageDigest{Algorithm: "SHA2_256", Digest: base64.StdEncoding.EncodeToString(sha256Sum([]byte("x")))},
			Signature:     base64.StdEncoding.EncodeToString([]byte("sig")),
		},
	}
	raw, _ := json.Marshal(bundle)

	v := NewKeylessVerifier()
	v.SkipTrustRootChecks = true // synthetic bundles - no TSA/Rekor/SCT
	if err := v.VerifyBlob(t.Context(), raw, []byte("x")); err == nil {
		t.Fatal("expected error for bundle without certificate")
	}
}

func TestKeylessVerifier_InvalidBundleJSON(t *testing.T) {
	v := NewKeylessVerifier()
	v.SkipTrustRootChecks = true // synthetic bundles - no TSA/Rekor/SCT
	if err := v.VerifyBlob(t.Context(), []byte(`{bad json`), []byte("artifact")); err == nil {
		t.Fatal("expected error for invalid bundle JSON")
	}
}

func TestCertInfoFromBundle_ExtractsIdentity(t *testing.T) {
	key := generateTestECKey(t, elliptic.P256())
	opts := fulcioCertOptions{
		sanURI:           "https://github.com/keithlinneman/linnemanlabs-web/.github/workflows/build.yml@refs/tags/v1.0.0",
		oidcIssuer:       "https://token.actions.githubusercontent.com",
		sourceRepository: "https://github.com/keithlinneman/linnemanlabs-web",
		sourceRevision:   "abc123def456",
		buildSignerURI:   "https://github.com/keithlinneman/linnemanlabs-web/.github/workflows/build.yml@refs/tags/v1.0.0",
		buildTrigger:     "push",
		runInvocationURI: "https://github.com/keithlinneman/linnemanlabs-web/actions/runs/42",
		ghTrigger:        "push",
		ghName:           "Build App",
		ghRepository:     "keithlinneman/linnemanlabs-web",
		ghRef:            "refs/tags/v1.0.0",
	}
	cert := newTestLeafCert(t, key, &opts)
	artifact := []byte("artifact-bytes")
	bundleJSON := buildKeylessBundle(t, key, cert, artifact, false)

	info, err := CertInfoFromBundle(bundleJSON)
	if err != nil {
		t.Fatalf("CertInfoFromBundle: %v", err)
	}

	if len(info.SANs) != 1 || info.SANs[0] != opts.sanURI {
		t.Fatalf("SANs = %v, want [%s]", info.SANs, opts.sanURI)
	}
	if info.OIDCIssuer != opts.oidcIssuer {
		t.Fatalf("OIDCIssuer = %q, want %q", info.OIDCIssuer, opts.oidcIssuer)
	}
	if info.SourceRepository != opts.sourceRepository {
		t.Fatalf("SourceRepository = %q, want %q", info.SourceRepository, opts.sourceRepository)
	}
	if info.SourceRevision != opts.sourceRevision {
		t.Fatalf("SourceRevision = %q, want %q", info.SourceRevision, opts.sourceRevision)
	}
	if info.BuildSignerURI != opts.buildSignerURI {
		t.Fatalf("BuildSignerURI = %q, want %q", info.BuildSignerURI, opts.buildSignerURI)
	}
	if info.BuildTrigger != opts.buildTrigger {
		t.Fatalf("BuildTrigger = %q, want %q", info.BuildTrigger, opts.buildTrigger)
	}
	if info.RunInvocationURI != opts.runInvocationURI {
		t.Fatalf("RunInvocationURI = %q, want %q", info.RunInvocationURI, opts.runInvocationURI)
	}
	if info.GitHubWorkflowTrigger != opts.ghTrigger {
		t.Fatalf("GitHubWorkflowTrigger = %q, want %q", info.GitHubWorkflowTrigger, opts.ghTrigger)
	}
	if info.GitHubWorkflowName != opts.ghName {
		t.Fatalf("GitHubWorkflowName = %q, want %q", info.GitHubWorkflowName, opts.ghName)
	}
	if info.GitHubWorkflowRepository != opts.ghRepository {
		t.Fatalf("GitHubWorkflowRepository = %q, want %q", info.GitHubWorkflowRepository, opts.ghRepository)
	}
	if info.GitHubWorkflowRef != opts.ghRef {
		t.Fatalf("GitHubWorkflowRef = %q, want %q", info.GitHubWorkflowRef, opts.ghRef)
	}
	if info.FingerprintSHA256 != SHA256Hex(cert.Raw) {
		t.Fatalf("FingerprintSHA256 = %q, want %q", info.FingerprintSHA256, SHA256Hex(cert.Raw))
	}
	if info.SerialNumber == "" {
		t.Fatal("SerialNumber should not be empty")
	}
}

func TestCertInfoFromBundle_NoCertificate(t *testing.T) {
	bundle := SigstoreBundle{
		VerificationMaterial: VerificationMaterial{PublicKey: PublicKeyRef{Hint: "kms"}},
		MessageSignature:     &MessageSignature{Signature: base64.StdEncoding.EncodeToString([]byte("sig"))},
	}
	raw, _ := json.Marshal(bundle)
	if _, err := CertInfoFromBundle(raw); err == nil {
		t.Fatal("expected error extracting cert info from a keyed bundle")
	}
}
