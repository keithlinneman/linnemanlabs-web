package provenancehttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/evidence"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

const testSAN = "https://github.com/keithlinneman/linnemanlabs-web/.github/workflows/build.yml@refs/tags/v1.0.0"

// buildKeylessBundleJSON builds a minimal but parseable keyless (Fulcio) blob
// bundle carrying a self-signed leaf certificate with a testSAN URI SAN.
// CertInfoFromBundle only parses (does not verify) so the signature is a stub.
func buildKeylessBundleJSON(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	u, err := url.Parse(testSAN)
	if err != nil {
		t.Fatalf("parse SAN: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		Issuer:       pkix.Name{CommonName: "test-fulcio"},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	bundle := cryptoutil.SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: cryptoutil.VerificationMaterial{
			Certificate: &cryptoutil.CertificateRef{RawBytes: base64.StdEncoding.EncodeToString(der)},
		},
		MessageSignature: &cryptoutil.MessageSignature{
			MessageDigest: cryptoutil.MessageDigest{
				Algorithm: "SHA2_256",
				Digest:    base64.StdEncoding.EncodeToString([]byte("digest")),
			},
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return raw
}

// evidenceStoreWithKeyless returns a store whose bundle carries a keyless
// bundle and a populated Signatures.Keyless block (the production loader
// builds Signatures from the bundle bytes; tests pre-populate it).
func evidenceStoreWithKeyless(t *testing.T) *evidence.Store {
	t.Helper()
	b := testBundle()
	b.ReleaseKeylessBundle = buildKeylessBundleJSON(t)
	b.Signatures = &cryptoutil.SignaturesInfo{
		Keyless: &cryptoutil.KeylessSignature{
			Certificate: &cryptoutil.CertInfo{
				SANs:       []string{testSAN},
				OIDCIssuer: "https://token.actions.githubusercontent.com",
			},
		},
	}
	s := evidence.NewStore()
	s.Set(b)
	return s
}

// contentProviderWithCert returns content whose Meta carries a keyless
// signature block with cert identity (used to assert API surfacing of
// signatures.keyless.certificate).
func contentProviderWithCert() *stubSnapshotProvider {
	cp := contentProvider()
	cp.snap.Meta.Signatures = &cryptoutil.SignaturesInfo{
		Keyless: &cryptoutil.KeylessSignature{
			Certificate: &cryptoutil.CertInfo{
				SANs:       []string{testSAN},
				OIDCIssuer: "https://token.actions.githubusercontent.com",
			},
		},
	}
	return cp
}

// nestedMap navigates a decoded JSON object by keys, failing the test if a key
// is missing or not an object.
func nestedMap(t *testing.T, m map[string]any, keys ...string) map[string]any {
	t.Helper()
	cur := m
	for _, k := range keys {
		v, ok := cur[k]
		if !ok {
			t.Fatalf("missing key %q in %v", k, cur)
		}
		next, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("key %q is not an object: %T", k, v)
		}
		cur = next
	}
	return cur
}

// sansContain reports whether the decoded JSON string array contains testSAN.
func sansContain(list any) bool {
	arr, ok := list.([]any)
	if !ok {
		return false
	}
	for _, v := range arr {
		if s, ok := v.(string); ok && s == testSAN {
			return true
		}
	}
	return false
}

func TestHandleAppSummary_IncludesKeyless(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStoreWithKeyless(t), log.Nop())
	rec := httptest.NewRecorder()
	api.HandleAppSummary(rec, httptest.NewRequest(http.MethodGet, "/api/provenance/app/summary", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	m := parseJSON(t, rec)
	// keyless bundle presence proves release.json was signed - reconciled
	// onto the build-system's signing summary.
	signing := nestedMap(t, m, "signing")
	if signed, _ := signing["release_signed"].(bool); !signed {
		t.Fatalf("signing.release_signed should be true when keyless bundle present, got %v", signing)
	}
	// cert identity lives under signatures.keyless.certificate now.
	cert := nestedMap(t, m, "signatures", "keyless", "certificate")
	if !sansContain(cert["sans"]) {
		t.Fatalf("signatures.keyless.certificate.sans should contain %q, got %v", testSAN, cert["sans"])
	}
}

func TestHandleAppProvenance_IncludesKeyless(t *testing.T) {
	api := NewAPI(noContentProvider(), evidenceStoreWithKeyless(t), log.Nop())
	rec := httptest.NewRecorder()
	api.HandleAppProvenance(rec, httptest.NewRequest(http.MethodGet, "/api/provenance/app", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	m := parseJSON(t, rec)
	cert := nestedMap(t, m, "signatures", "keyless", "certificate")
	if !sansContain(cert["sans"]) {
		t.Fatalf("signatures.keyless.certificate.sans should contain %q, got %v", testSAN, cert["sans"])
	}
}

func TestHandleContentSummary_IncludesCertificate(t *testing.T) {
	api := NewAPI(contentProviderWithCert(), nil, log.Nop())
	rec := httptest.NewRecorder()
	api.HandleContentSummary(rec, httptest.NewRequest(http.MethodGet, "/api/provenance/content/summary", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	m := parseJSON(t, rec)
	cert := nestedMap(t, m, "signatures", "keyless", "certificate")
	if !sansContain(cert["sans"]) {
		t.Fatalf("signatures.keyless.certificate.sans should contain %q, got %v", testSAN, cert["sans"])
	}
	if cert["oidc_issuer"] != "https://token.actions.githubusercontent.com" {
		t.Fatalf("signatures.keyless.certificate.oidc_issuer = %v", cert["oidc_issuer"])
	}
}

func TestHandleContentProvenance_IncludesCertificate(t *testing.T) {
	api := NewAPI(contentProviderWithCert(), nil, log.Nop())
	rec := httptest.NewRecorder()
	api.HandleContentProvenance(rec, httptest.NewRequest(http.MethodGet, "/api/provenance/content", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	m := parseJSON(t, rec)
	cert := nestedMap(t, m, "signatures", "keyless", "certificate")
	if !sansContain(cert["sans"]) {
		t.Fatalf("signatures.keyless.certificate.sans should contain %q, got %v", testSAN, cert["sans"])
	}
}

func TestHandleContentSummary_IncludesSignatures(t *testing.T) {
	cp := contentProvider()
	cp.snap.Meta.Signatures = &cryptoutil.SignaturesInfo{
		Keyless: &cryptoutil.KeylessSignature{
			Rekor: &cryptoutil.RekorInfo{
				LogID:        "H39lwR+dFuaSD2BcIpuI+3q51dfEB6atTZ+SvZcpq+o=",
				LogIndex:     463,
				TreeSize:     464,
				RootHash:     "NSyycnBz5IjAE3c7aAa3kHkio4zF5YfWb4J/kyee8Nk=",
				Origin:       "rekor.trust.linnemanlabs.com",
				EntryKind:    "hashedrekord",
				EntryVersion: "0.0.2",
			},
			Chain: &cryptoutil.ChainInfo{
				IssuerSubject: "CN=LinnemanLabs Fulcio CA,O=linnemanlabs.com",
				RootSubject:   "CN=LinnemanLabs Root CA,O=linnemanlabs.com",
			},
		},
		KMS: &cryptoutil.KMSSignature{
			KeyRef: "f6rLtaXmwykdVRA2rAGY/IzObQmMa8jEZcCEZAljqak=",
			Rekor: &cryptoutil.RekorInfo{
				LogIndex: 469,
				TreeSize: 470,
				Origin:   "rekor.trust.linnemanlabs.com",
			},
		},
	}
	api := NewAPI(cp, nil, log.Nop())
	rec := httptest.NewRecorder()
	api.HandleContentSummary(rec, httptest.NewRequest(http.MethodGet, "/api/provenance/content/summary", http.NoBody))

	m := parseJSON(t, rec)
	// top-level trusted_root_url
	if got, _ := m["trusted_root_url"].(string); got != "https://trust.linnemanlabs.com/.well-known/trusted_root.json" {
		t.Fatalf("trusted_root_url = %v", m["trusted_root_url"])
	}
	// signatures.keyless.rekor
	keylessRekor := nestedMap(t, m, "signatures", "keyless", "rekor")
	if keylessRekor["log_index"] != float64(463) {
		t.Fatalf("signatures.keyless.rekor.log_index = %v", keylessRekor["log_index"])
	}
	if keylessRekor["origin"] != "rekor.trust.linnemanlabs.com" {
		t.Fatalf("signatures.keyless.rekor.origin = %v", keylessRekor["origin"])
	}
	// signatures.keyless.chain.issuer_subject
	chain := nestedMap(t, m, "signatures", "keyless", "chain")
	if chain["issuer_subject"] == nil {
		t.Fatalf("signatures.keyless.chain.issuer_subject missing")
	}
	// signatures.kms
	kms := nestedMap(t, m, "signatures", "kms")
	if kms["key_ref"] != "f6rLtaXmwykdVRA2rAGY/IzObQmMa8jEZcCEZAljqak=" {
		t.Fatalf("signatures.kms.key_ref = %v", kms["key_ref"])
	}
	kmsRekor := nestedMap(t, m, "signatures", "kms", "rekor")
	if kmsRekor["log_index"] != float64(469) {
		t.Fatalf("signatures.kms.rekor.log_index = %v", kmsRekor["log_index"])
	}
}

// content with no signatures omits the signatures block entirely.
func TestHandleContentSummary_NoSignaturesWhenAbsent(t *testing.T) {
	api := NewAPI(contentProvider(), nil, log.Nop())
	rec := httptest.NewRecorder()
	api.HandleContentSummary(rec, httptest.NewRequest(http.MethodGet, "/api/provenance/content/summary", http.NoBody))

	m := parseJSON(t, rec)
	if _, ok := m["signatures"]; ok {
		t.Fatal("signatures should be omitted when no signatures present")
	}
	// trusted_root_url still surfaces (it's a constant, not from the bundle)
	if got, _ := m["trusted_root_url"].(string); got == "" {
		t.Fatal("trusted_root_url should always be present")
	}
}
