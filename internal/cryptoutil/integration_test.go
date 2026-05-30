package cryptoutil

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// loadRealBundle loads the operator-provided keyless bundle stored in testdata
// (a real cosign sign-blob output produced against the LinnemanLabs sigstore
// deployment). It exercises every offline-verifiable layer end-to-end.
func loadRealBundle(t *testing.T) *SigstoreBundle {
	t.Helper()
	raw, err := os.ReadFile("testdata/keyless-bundle.sigstore.json")
	if err != nil {
		t.Fatalf("read testdata bundle: %v", err)
	}
	var b SigstoreBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse testdata bundle: %v", err)
	}
	return &b
}

// realSignatureBytes decodes the artifact signature from the real bundle. The
// TSA's messageImprint commits to SHA-256 over these bytes.
func realSignatureBytes(t *testing.T, b *SigstoreBundle) []byte {
	t.Helper()
	if b.MessageSignature == nil {
		t.Fatal("bundle has no messageSignature")
	}
	sig, err := base64.StdEncoding.DecodeString(b.MessageSignature.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	return sig
}

func TestVerifyRFC3161_RealBundle(t *testing.T) {
	b := loadRealBundle(t)
	if b.VerificationMaterial.TimestampVerificationData == nil || len(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps) == 0 {
		t.Fatal("bundle has no rfc3161Timestamps")
	}
	tsRaw, err := base64.StdEncoding.DecodeString(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp)
	if err != nil {
		t.Fatalf("decode signedTimestamp: %v", err)
	}

	sigBytes := realSignatureBytes(t, b)
	imprint := sha256.Sum256(sigBytes)

	genTime, err := VerifyRFC3161(tsRaw, imprint[:])
	if err != nil {
		t.Fatalf("VerifyRFC3161: %v", err)
	}

	want := time.Date(2026, 5, 28, 1, 1, 49, 0, time.UTC)
	if !genTime.Equal(want) {
		t.Fatalf("genTime = %s, want %s", genTime, want)
	}
}

func TestVerifyLeafChain_RealBundle(t *testing.T) {
	b := loadRealBundle(t)
	tsRaw, _ := base64.StdEncoding.DecodeString(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp)
	sigBytes := realSignatureBytes(t, b)
	imprint := sha256.Sum256(sigBytes)
	signingTime, err := VerifyRFC3161(tsRaw, imprint[:])
	if err != nil {
		t.Fatalf("VerifyRFC3161: %v", err)
	}

	leaf, err := parseLeafCert(parseRealBundle(t, b))
	if err != nil {
		t.Fatalf("parseLeafCert: %v", err)
	}
	if err := VerifyLeafChain(leaf, signingTime); err != nil {
		t.Fatalf("VerifyLeafChain: %v", err)
	}
}

func TestVerifyLeafChain_WrongTimeFails(t *testing.T) {
	b := loadRealBundle(t)
	leaf, err := parseLeafCert(parseRealBundle(t, b))
	if err != nil {
		t.Fatalf("parseLeafCert: %v", err)
	}
	// far past the leaf's NotAfter -> chain validation must fail
	if err := VerifyLeafChain(leaf, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected chain verification to fail in the far future")
	}
}

// parseRealBundle calls ParseBundle on the testdata bundle and fails the test
// on error.
func parseRealBundle(t *testing.T, b *SigstoreBundle) *SigstoreBundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	return parsed
}

func TestKeylessVerifier_MaxSigningAge_RejectsStale(t *testing.T) {
	b := loadRealBundle(t)
	leaf, err := parseLeafCert(b)
	if err != nil {
		t.Fatalf("parseLeafCert: %v", err)
	}
	v := NewKeylessVerifier()
	// any non-zero value smaller than the elapsed time since the test bundle
	// was signed will trip the freshness check.
	v.MaxSigningAge = 1
	err = v.verifyTrustRoot(b, leaf)
	if err == nil {
		t.Fatal("expected freshness rejection")
	}
	if !strings.Contains(err.Error(), "signed too long ago") {
		t.Fatalf("err = %v, want 'signed too long ago'", err)
	}
}

func TestCTLogs_MultiLogReadiness(t *testing.T) {
	// Adding a second CT log key should make trustRoots.CTLogs handle two
	// entries (today there is one - tesseract). Smoke-check the map shape +
	// SCT verification path still resolves the live entry correctly.
	if len(trustRoots.CTLogs) == 0 {
		t.Fatal("trustRoots.CTLogs is empty; multi-log map not populated at init")
	}
	// inject a second synthetic log key and ensure it's resolvable.
	fakeID := [32]byte{0xAA, 0xBB}
	trustRoots.CTLogs[fakeID] = trustRoots.CTLogs[firstCTLogID(t)] // arbitrary key value
	defer delete(trustRoots.CTLogs, fakeID)
	if trustRoots.CTLogs[fakeID] == nil {
		t.Fatal("inserted key not retrievable")
	}

	// And the real bundle's SCT still verifies (no regression from the map switch).
	b := loadRealBundle(t)
	leaf, err := parseLeafCert(b)
	if err != nil {
		t.Fatalf("parseLeafCert: %v", err)
	}
	if err := VerifySCT(leaf); err != nil {
		t.Fatalf("VerifySCT after multi-log change: %v", err)
	}
}

// firstCTLogID returns any key from the trusted CTLogs map (deterministic order
// not required - we just need a known-trusted key to clone into the test fake).
func firstCTLogID(t *testing.T) [32]byte {
	t.Helper()
	for id := range trustRoots.CTLogs {
		return id
	}
	t.Fatal("no CT log keys")
	return [32]byte{}
}

func TestKeylessSignatureFromBundle_RealBundle(t *testing.T) {
	raw, err := os.ReadFile("testdata/keyless-bundle.sigstore.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	info, err := KeylessSignatureFromBundle(raw)
	if err != nil {
		t.Fatalf("KeylessSignatureFromBundle: %v", err)
	}
	if info.Rekor == nil {
		t.Fatal("Rekor block missing")
	}
	if info.Rekor.LogIndex != 463 {
		t.Fatalf("Rekor.LogIndex = %d, want 463", info.Rekor.LogIndex)
	}
	if info.Rekor.TreeSize != 464 {
		t.Fatalf("Rekor.TreeSize = %d, want 464", info.Rekor.TreeSize)
	}
	if info.Rekor.Origin != "rekor.trust.linnemanlabs.com" {
		t.Fatalf("Rekor.Origin = %q", info.Rekor.Origin)
	}
	if info.Rekor.EntryKind != "hashedrekord" {
		t.Fatalf("Rekor.EntryKind = %q", info.Rekor.EntryKind)
	}
	if info.CTLog == nil {
		t.Fatal("CTLog block missing")
	}
	if info.Timestamp == nil {
		t.Fatal("Timestamp block missing")
	}
	want := time.Date(2026, 5, 28, 1, 1, 49, 0, time.UTC)
	if !info.Timestamp.GenTime.Equal(want) {
		t.Fatalf("Timestamp.GenTime = %s, want %s", info.Timestamp.GenTime, want)
	}
	if info.Chain == nil {
		t.Fatal("Chain block missing")
	}
	if info.Certificate == nil {
		t.Fatal("Certificate block missing")
	}
	if info.Certificate.FingerprintSHA256 == "" {
		t.Fatal("Certificate.FingerprintSHA256 empty")
	}
	if info.Chain.LeafFingerprintSHA256 == "" {
		t.Fatal("Chain.LeafFingerprintSHA256 empty")
	}
	if info.Chain.LeafFingerprintSHA256 != info.Certificate.FingerprintSHA256 {
		t.Fatalf("Chain.LeafFingerprintSHA256 (%q) != Certificate.FingerprintSHA256 (%q)",
			info.Chain.LeafFingerprintSHA256, info.Certificate.FingerprintSHA256)
	}
	if !strings.Contains(info.Chain.IssuerSubject, "LinnemanLabs Fulcio CA") {
		t.Fatalf("Chain.IssuerSubject = %q", info.Chain.IssuerSubject)
	}
	if !strings.Contains(info.Chain.RootSubject, "LinnemanLabs Root CA") {
		t.Fatalf("Chain.RootSubject = %q", info.Chain.RootSubject)
	}

	// trust-asset URLs
	if info.Rekor.PubKeyURL != "https://trust.linnemanlabs.com/keys/rekor-checkpoint.pub" {
		t.Fatalf("Rekor.PubKeyURL = %q", info.Rekor.PubKeyURL)
	}
	if info.CTLog.PubKeyURL != "https://trust.linnemanlabs.com/keys/tesseract-checkpoint.pub" {
		t.Fatalf("CTLog.PubKeyURL = %q", info.CTLog.PubKeyURL)
	}
	if info.Timestamp.TSACertURL != "https://trust.linnemanlabs.com/certs/tsa.crt" {
		t.Fatalf("Timestamp.TSACertURL = %q", info.Timestamp.TSACertURL)
	}
	if info.Chain.IssuerCertURL != "https://trust.linnemanlabs.com/certs/fulcio-ca.crt" {
		t.Fatalf("Chain.IssuerCertURL = %q", info.Chain.IssuerCertURL)
	}

	// Rekor pass-throughs (proof hashes + checkpoint envelope)
	if got := len(info.Rekor.InclusionProofHashes); got != 7 {
		t.Fatalf("Rekor.InclusionProofHashes len = %d, want 7", got)
	}
	if !strings.Contains(info.Rekor.CheckpointEnvelope, "rekor.trust.linnemanlabs.com") {
		t.Fatalf("Rekor.CheckpointEnvelope does not contain origin: %q", info.Rekor.CheckpointEnvelope)
	}

	// CT log hash algo
	if info.CTLog.HashAlgorithm != "sha256" {
		t.Fatalf("CTLog.HashAlgorithm = %q, want sha256", info.CTLog.HashAlgorithm)
	}

	// Timestamp evidence
	if info.Timestamp.RawTSR == "" {
		t.Fatal("Timestamp.RawTSR empty")
	}
	// raw_tsr round-trips back to a parseable token
	if _, err := base64.StdEncoding.DecodeString(info.Timestamp.RawTSR); err != nil {
		t.Fatalf("Timestamp.RawTSR not valid base64: %v", err)
	}
	if info.Timestamp.MessageImprint == nil {
		t.Fatal("Timestamp.MessageImprint missing")
	}
	if info.Timestamp.MessageImprint.Algorithm != "sha256" {
		t.Fatalf("Timestamp.MessageImprint.Algorithm = %q", info.Timestamp.MessageImprint.Algorithm)
	}
	// the imprint must equal SHA-256 of the artifact signature bytes.
	wantImprint := wantMessageImprintFromBundle(t, "testdata/keyless-bundle.sigstore.json")
	if info.Timestamp.MessageImprint.Hash != wantImprint {
		t.Fatalf("Timestamp.MessageImprint.Hash = %q, want %q", info.Timestamp.MessageImprint.Hash, wantImprint)
	}
	if info.Timestamp.TSAFingerprintSHA256 == "" {
		t.Fatal("Timestamp.TSAFingerprintSHA256 empty")
	}
	if info.Timestamp.SerialNumber == "" {
		t.Fatal("Timestamp.SerialNumber empty")
	}
	if info.Timestamp.PolicyOID == "" {
		t.Fatal("Timestamp.PolicyOID empty")
	}

	// chain fingerprints
	if info.Chain.IssuerFingerprintSHA256 == "" {
		t.Fatal("Chain.IssuerFingerprintSHA256 empty")
	}
	if info.Chain.RootFingerprintSHA256 == "" {
		t.Fatal("Chain.RootFingerprintSHA256 empty")
	}
}

func TestKMSSignatureFromBundle_RealBundle(t *testing.T) {
	raw, err := os.ReadFile("testdata/kms-bundle.sigstore.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	info, err := KMSSignatureFromBundle(raw)
	if err != nil {
		t.Fatalf("KMSSignatureFromBundle: %v", err)
	}
	// KMS bundle: key_ref is the bundle's publicKey.hint (base64 SHA-256 of
	// the KMS pubkey SPKI). The operator-confirmed value for this bundle:
	wantKeyRef := "f6rLtaXmwykdVRA2rAGY/IzObQmMa8jEZcCEZAljqak="
	if info.KeyRef != wantKeyRef {
		t.Fatalf("KeyRef = %q, want %q", info.KeyRef, wantKeyRef)
	}

	// Rekor: same shape as keyless (the tlogEntries schema does not depend
	// on signing material). This bundle's entry is at logIndex=469, treeSize=470.
	if info.Rekor == nil {
		t.Fatal("Rekor block missing")
	}
	if info.Rekor.LogIndex != 469 {
		t.Fatalf("Rekor.LogIndex = %d, want 469", info.Rekor.LogIndex)
	}
	if info.Rekor.TreeSize != 470 {
		t.Fatalf("Rekor.TreeSize = %d, want 470", info.Rekor.TreeSize)
	}
	if info.Rekor.Origin != "rekor.trust.linnemanlabs.com" {
		t.Fatalf("Rekor.Origin = %q", info.Rekor.Origin)
	}
	if info.Rekor.EntryKind != "hashedrekord" {
		t.Fatalf("Rekor.EntryKind = %q", info.Rekor.EntryKind)
	}
	if info.Rekor.PubKeyURL != "https://trust.linnemanlabs.com/keys/rekor-checkpoint.pub" {
		t.Fatalf("Rekor.PubKeyURL = %q", info.Rekor.PubKeyURL)
	}

	// Timestamp: same extractor as keyless. TSA imprint is SHA-256 of the
	// artifact signature bytes (independent of bundle hash algorithm).
	if info.Timestamp == nil {
		t.Fatal("Timestamp block missing")
	}
	if info.Timestamp.GenTime.IsZero() {
		t.Fatal("Timestamp.GenTime is zero")
	}
	if info.Timestamp.RawTSR == "" {
		t.Fatal("Timestamp.RawTSR empty")
	}
	if info.Timestamp.MessageImprint == nil {
		t.Fatal("Timestamp.MessageImprint missing")
	}
	if info.Timestamp.MessageImprint.Algorithm != "sha256" {
		t.Fatalf("Timestamp.MessageImprint.Algorithm = %q", info.Timestamp.MessageImprint.Algorithm)
	}
	wantImprint := wantMessageImprintFromBundle(t, "testdata/kms-bundle.sigstore.json")
	if info.Timestamp.MessageImprint.Hash != wantImprint {
		t.Fatalf("Timestamp.MessageImprint.Hash = %q, want %q", info.Timestamp.MessageImprint.Hash, wantImprint)
	}
}

func TestTrustedRootURL(t *testing.T) {
	const want = "https://trust.linnemanlabs.com/.well-known/trusted_root.json"
	if got := TrustedRootURL(); got != want {
		t.Fatalf("TrustedRootURL = %q, want %q", got, want)
	}
}

// wantMessageImprintFromBundle re-derives the messageImprint hash that the TSA
// is expected to have signed: base64(SHA-256(bundle.messageSignature.signature)).
func wantMessageImprintFromBundle(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var b SigstoreBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	sig, err := base64.StdEncoding.DecodeString(b.MessageSignature.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	h := sha256.Sum256(sig)
	return base64.StdEncoding.EncodeToString(h[:])
}

// TestKeylessVerifier_FullTrustRoot_RealBundle drives every offline verification
// layer end-to-end against the operator-provided keyless bundle: TSA timestamp
// → leaf chain at signing time → CT log SCT → Rekor inclusion proof + body
// cross-check. (The artifact itself is not in the test data, so we exercise
// verifyTrustRoot directly rather than the full VerifyBlob.)
func TestKeylessVerifier_FullTrustRoot_RealBundle(t *testing.T) {
	b := loadRealBundle(t)
	leaf, err := parseLeafCert(b)
	if err != nil {
		t.Fatalf("parseLeafCert: %v", err)
	}
	v := NewKeylessVerifier()
	if err := v.verifyTrustRoot(b, leaf); err != nil {
		t.Fatalf("verifyTrustRoot: %v", err)
	}
}

func TestVerifySCT_RealBundle(t *testing.T) {
	b := loadRealBundle(t)
	leaf, err := parseLeafCert(parseRealBundle(t, b))
	if err != nil {
		t.Fatalf("parseLeafCert: %v", err)
	}
	if err := VerifySCT(leaf); err != nil {
		t.Fatalf("VerifySCT: %v", err)
	}
}

func TestVerifyRekorInclusion_RealBundle(t *testing.T) {
	b := loadRealBundle(t)
	if err := VerifyRekorInclusion(b); err != nil {
		t.Fatalf("VerifyRekorInclusion: %v", err)
	}
}

func TestVerifyRekorInclusion_TamperedProofFails(t *testing.T) {
	b := loadRealBundle(t)
	// flip a byte in the first proof hash; the Merkle walk should fail.
	orig := b.VerificationMaterial.TlogEntries[0].InclusionProof.Hashes[0]
	tampered := []byte(orig)
	tampered[len(tampered)-1] ^= 'X' // mutate the base64 → no longer valid proof
	b.VerificationMaterial.TlogEntries[0].InclusionProof.Hashes[0] = string(tampered)
	if err := VerifyRekorInclusion(b); err == nil {
		t.Fatal("expected error after tampering a proof hash")
	}
}

func TestVerifyRFC3161_WrongImprintFails(t *testing.T) {
	b := loadRealBundle(t)
	tsRaw, _ := base64.StdEncoding.DecodeString(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp)
	wrong := sha256.Sum256([]byte("not the signature"))
	if _, err := VerifyRFC3161(tsRaw, wrong[:]); err == nil {
		t.Fatal("expected error for mismatched messageImprint")
	}
}
