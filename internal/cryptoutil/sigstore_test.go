package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// PAE

func TestPAE_EmptyType(t *testing.T) {
	got := PAE("", []byte("data"))
	want := "DSSEv1 0  4 data"
	if string(got) != want {
		t.Fatalf("PAE = %q, want %q", string(got), want)
	}
}

func TestPAE_KnownVector(t *testing.T) {
	// From DSSE spec: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
	// PAE("application/vnd.in-toto+json", "{}") should produce:
	// "DSSEv1 28 application/vnd.in-toto+json 2 {}"
	payloadType := "application/vnd.in-toto+json"
	payload := []byte("{}")

	got := PAE(payloadType, payload)
	want := []byte("DSSEv1 28 application/vnd.in-toto+json 2 {}")

	if !bytes.Equal(got, want) {
		t.Fatalf("PAE mismatch\n  got:  %q\n  want: %q", string(got), string(want))
	}
}

func TestPAE_EmptyPayload(t *testing.T) {
	got := PAE("type", []byte{})
	want := []byte("DSSEv1 4 type 0 ")

	if !bytes.Equal(got, want) {
		t.Fatalf("PAE empty payload\n  got:  %q\n  want: %q", string(got), string(want))
	}
}

func TestPAE_EmptyPayloadType(t *testing.T) {
	got := PAE("", []byte("body"))
	want := []byte("DSSEv1 0  4 body")

	if !bytes.Equal(got, want) {
		t.Fatalf("PAE empty type\n  got:  %q\n  want: %q", string(got), string(want))
	}
}

func TestPAE_LengthIsDecimalNotHex(t *testing.T) {
	// 100-byte payload type should encode as "100", not "64"
	longType := strings.Repeat("a", 100)
	got := PAE(longType, []byte("x"))
	prefix := "DSSEv1 100 "
	if !bytes.HasPrefix(got, []byte(prefix)) {
		t.Fatalf("PAE should use decimal length, got prefix: %q", string(got[:min(len(got), 20)]))
	}
}

// ParseBundle - blob signature format

func TestParseBundle_BlobSignature(t *testing.T) {
	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "test-hint"},
		},
		MessageSignature: &MessageSignature{
			MessageDigest: MessageDigest{
				Algorithm: "SHA2_256",
				Digest:    base64.StdEncoding.EncodeToString([]byte("fakedigest")),
			},
			Signature: base64.StdEncoding.EncodeToString([]byte("fakesig")),
		},
	}
	raw, _ := json.Marshal(bundle)

	got, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if got.MessageSignature == nil {
		t.Fatal("expected MessageSignature to be set")
	}
	if got.VerificationMaterial.PublicKey.Hint != "test-hint" {
		t.Fatalf("Hint = %q", got.VerificationMaterial.PublicKey.Hint)
	}
}

// ParseBundle - DSSE format

func TestParseBundle_DSSE(t *testing.T) {
	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "dsse-hint"},
		},
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString([]byte(`{"_type":"test"}`)),
			PayloadType: "application/vnd.in-toto+json",
			Signatures: []DSSESignature{
				{Sig: base64.StdEncoding.EncodeToString([]byte("sig"))},
			},
		},
	}
	raw, _ := json.Marshal(bundle)

	got, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if got.DSSEEnvelope == nil {
		t.Fatal("expected DSSEEnvelope to be set")
	}
}

// ParseBundle - error cases

func TestParseBundle_InvalidJSON(t *testing.T) {
	_, err := ParseBundle([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseBundle_NoDSSESignatures(t *testing.T) {
	bundle := SigstoreBundle{
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString([]byte("payload")),
			PayloadType: "test",
			Signatures:  []DSSESignature{}, // empty
		},
	}
	raw, _ := json.Marshal(bundle)

	_, err := ParseBundle(raw)
	if err == nil {
		t.Fatal("expected error for empty signatures")
	}
}

func TestParseBundle_EmptyDSSEPayload(t *testing.T) {
	bundle := SigstoreBundle{
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     "",
			PayloadType: "test",
			Signatures:  []DSSESignature{{Sig: "c2ln"}},
		},
	}
	raw, _ := json.Marshal(bundle)

	_, err := ParseBundle(raw)
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

// ParseBundle - blob signature bundles pass validation (no DSSE checks)

func TestParseBundle_BlobSignature_NoDSSEValidation(t *testing.T) {
	bundle := SigstoreBundle{
		MessageSignature: &MessageSignature{
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		},
	}
	raw, _ := json.Marshal(bundle)

	// Should not fail - DSSE validation only applies when DSSEEnvelope is present
	_, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("unexpected error for blob signature bundle: %v", err)
	}
}

// DecodeDSSEPayload

func TestDecodeDSSEPayload_Valid(t *testing.T) {
	original := []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`)
	env := &DSSEEnvelope{
		Payload: base64.StdEncoding.EncodeToString(original),
	}

	got, err := DecodeDSSEPayload(env)
	if err != nil {
		t.Fatalf("DecodeDSSEPayload: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("payload = %q, want %q", got, original)
	}
}

func TestDecodeDSSEPayload_InvalidBase64(t *testing.T) {
	env := &DSSEEnvelope{Payload: "!!!not-base64!!!"}

	_, err := DecodeDSSEPayload(env)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

// DecodeSignature

func TestDecodeSignature_Valid(t *testing.T) {
	original := []byte("raw-signature-bytes")
	env := &DSSEEnvelope{
		Signatures: []DSSESignature{
			{Sig: base64.StdEncoding.EncodeToString(original)},
		},
	}

	got, err := DecodeSignature(env)
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("sig = %q, want %q", got, original)
	}
}

func TestDecodeSignature_NoSignatures(t *testing.T) {
	env := &DSSEEnvelope{Signatures: nil}

	_, err := DecodeSignature(env)
	if err == nil {
		t.Fatal("expected error for no signatures")
	}
}

func TestDecodeSignature_InvalidBase64(t *testing.T) {
	env := &DSSEEnvelope{
		Signatures: []DSSESignature{{Sig: "!!!"}},
	}

	_, err := DecodeSignature(env)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecodeSignature_UsesFirstSignature(t *testing.T) {
	first := []byte("first-sig")
	second := []byte("second-sig")
	env := &DSSEEnvelope{
		Signatures: []DSSESignature{
			{Sig: base64.StdEncoding.EncodeToString(first)},
			{Sig: base64.StdEncoding.EncodeToString(second)},
		},
	}

	got, err := DecodeSignature(env)
	if err != nil {
		t.Fatalf("DecodeSignature: %v", err)
	}
	if string(got) != string(first) {
		t.Fatal("should use first signature")
	}
}

// VerifySubjectDigest

func TestVerifySubjectDigest_Match(t *testing.T) {
	artifact := []byte("hello world")
	hash := sha256.Sum256(artifact)
	hexHash := hex.EncodeToString(hash[:])

	stmt := &InTotoStatement{
		Subject: []InTotoSubject{
			{
				Name:   "my-artifact",
				Digest: map[string]string{"sha256": hexHash},
			},
		},
	}

	if err := VerifySubjectDigest(stmt, artifact); err != nil {
		t.Fatalf("expected match: %v", err)
	}
}

func TestVerifySubjectDigest_Mismatch(t *testing.T) {
	stmt := &InTotoStatement{
		Subject: []InTotoSubject{
			{
				Name:   "my-artifact",
				Digest: map[string]string{"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
			},
		},
	}

	if err := VerifySubjectDigest(stmt, []byte("different content")); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestVerifySubjectDigest_MultipleSubjects_OneMatches(t *testing.T) {
	artifact := []byte("target")
	hash := sha256.Sum256(artifact)
	hexHash := hex.EncodeToString(hash[:])

	stmt := &InTotoStatement{
		Subject: []InTotoSubject{
			{Name: "other", Digest: map[string]string{"sha256": "aaaa"}},
			{Name: "target", Digest: map[string]string{"sha256": hexHash}},
		},
	}

	if err := VerifySubjectDigest(stmt, artifact); err != nil {
		t.Fatalf("expected match on second subject: %v", err)
	}
}

func TestVerifySubjectDigest_NoSubjects(t *testing.T) {
	stmt := &InTotoStatement{Subject: nil}

	if err := VerifySubjectDigest(stmt, []byte("anything")); err == nil {
		t.Fatal("expected error for no subjects")
	}
}

func TestVerifySubjectDigest_NoSHA256Key(t *testing.T) {
	stmt := &InTotoStatement{
		Subject: []InTotoSubject{
			{Name: "x", Digest: map[string]string{"sha512": "abcdef"}},
		},
	}

	if err := VerifySubjectDigest(stmt, []byte("anything")); err == nil {
		t.Fatal("expected error when no sha256 digest present")
	}
}

// helper: sign artifact bytes the way cosign sign-blob does (RSA-PSS over SHA256 of raw bytes)
func signBlob(t *testing.T, key *rsa.PrivateKey, artifact []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(artifact)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign blob: %v", err)
	}
	return sig
}

// helper: build a blob signature bundle JSON matching cosign sign-blob output
func buildBlobBundle(t *testing.T, key *rsa.PrivateKey, artifact []byte) []byte {
	t.Helper()
	sig := signBlob(t, key, artifact)
	digest := sha256.Sum256(artifact)

	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "test-key-hint"},
		},
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

// VerifyBlobSignature - valid

func TestVerifyBlobSignature_Valid(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	artifact := []byte(`{"release_id":"v1.0.0","component":"server"}`)
	bundleJSON := buildBlobBundle(t, key, artifact)

	result, err := VerifyBlobSignature(t.Context(), v, bundleJSON, artifact)
	if err != nil {
		t.Fatalf("VerifyBlobSignature: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected Verified = true")
	}
	if result.KeyHint != "test-key-hint" {
		t.Fatalf("KeyHint = %q, want %q", result.KeyHint, "test-key-hint")
	}
}

// VerifyBlobSignature - tampered artifact

func TestVerifyBlobSignature_TamperedArtifact(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	original := []byte(`{"release_id":"v1.0.0"}`)
	bundleJSON := buildBlobBundle(t, key, original)

	tampered := []byte(`{"release_id":"v1.0.0","injected":"malicious"}`)
	_, err := VerifyBlobSignature(t.Context(), v, bundleJSON, tampered)
	if err == nil {
		t.Fatal("expected verification failure for tampered artifact")
	}
}

// VerifyBlobSignature - wrong signing key

func TestVerifyBlobSignature_WrongKey(t *testing.T) {
	signingKey := generateTestKey(t)
	wrongKey := generateTestKey(t)
	v := newTestVerifier(t, &wrongKey.PublicKey)

	artifact := []byte(`{"release_id":"v1.0.0"}`)
	bundleJSON := buildBlobBundle(t, signingKey, artifact)

	_, err := VerifyBlobSignature(t.Context(), v, bundleJSON, artifact)
	if err == nil {
		t.Fatal("expected verification failure for wrong key")
	}
}

// VerifyBlobSignature - corrupted bundle JSON

func TestVerifyBlobSignature_InvalidBundleJSON(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	_, err := VerifyBlobSignature(t.Context(), v, []byte(`{bad json`), []byte("artifact"))
	if err == nil {
		t.Fatal("expected error for invalid bundle JSON")
	}
}

// VerifyBlobSignature - bundle has DSSE instead of messageSignature

func TestVerifyBlobSignature_NotBlobBundle(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	// Build a DSSE-style bundle instead of blob signature
	bundle := SigstoreBundle{
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString([]byte("payload")),
			PayloadType: "application/vnd.in-toto+json",
			Signatures:  []DSSESignature{{Sig: base64.StdEncoding.EncodeToString([]byte("sig"))}},
		},
	}
	raw, _ := json.Marshal(bundle)

	_, err := VerifyBlobSignature(t.Context(), v, raw, []byte("artifact"))
	if err == nil {
		t.Fatal("expected error for non-blob bundle")
	}
}

// VerifyBlobSignature - corrupted signature in bundle

func TestVerifyBlobSignature_CorruptedSignature(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	artifact := []byte(`{"release_id":"v1.0.0"}`)

	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "test"},
		},
		MessageSignature: &MessageSignature{
			MessageDigest: MessageDigest{
				Algorithm: "SHA2_256",
				Digest:    base64.StdEncoding.EncodeToString(sha256Sum(artifact)),
			},
			Signature: base64.StdEncoding.EncodeToString([]byte("definitely-not-a-valid-signature-but-long-enough-for-rsa")),
		},
	}
	raw, _ := json.Marshal(bundle)

	_, err := VerifyBlobSignature(t.Context(), v, raw, artifact)
	if err == nil {
		t.Fatal("expected verification failure for corrupted signature")
	}
}

// VerifyBlobSignature - invalid base64 signature

func TestVerifyBlobSignature_InvalidBase64Signature(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	bundle := SigstoreBundle{
		MessageSignature: &MessageSignature{
			Signature: "!!!not-base64!!!",
		},
	}
	raw, _ := json.Marshal(bundle)

	_, err := VerifyBlobSignature(t.Context(), v, raw, []byte("artifact"))
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

// VerifyBlobSignature - digest mismatch in bundle metadata

func TestVerifyBlobSignature_DigestMismatchInBundle(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	artifact := []byte(`{"release_id":"v1.0.0"}`)
	sig := signBlob(t, key, artifact)

	// Bundle has a valid signature but the embedded digest field is wrong
	wrongDigest := sha256.Sum256([]byte("different content"))
	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "test"},
		},
		MessageSignature: &MessageSignature{
			MessageDigest: MessageDigest{
				Algorithm: "SHA2_256",
				Digest:    base64.StdEncoding.EncodeToString(wrongDigest[:]),
			},
			Signature: base64.StdEncoding.EncodeToString(sig),
		},
	}
	raw, _ := json.Marshal(bundle)

	_, err := VerifyBlobSignature(t.Context(), v, raw, artifact)
	if err == nil {
		t.Fatal("expected error for digest mismatch in bundle metadata")
	}
}

// VerifyBlobSignature - missing digest is not an error (belt-and-suspenders check is optional)

func TestVerifyBlobSignature_EmptyDigestOK(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	artifact := []byte(`{"release_id":"v1.0.0"}`)
	sig := signBlob(t, key, artifact)

	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "test"},
		},
		MessageSignature: &MessageSignature{
			MessageDigest: MessageDigest{}, // no digest field
			Signature:     base64.StdEncoding.EncodeToString(sig),
		},
	}
	raw, _ := json.Marshal(bundle)

	result, err := VerifyBlobSignature(t.Context(), v, raw, artifact)
	if err != nil {
		t.Fatalf("expected success when digest field is empty: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected Verified = true")
	}
}

// helper
func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// VerifyReleaseDSSE - end to end with real RSA signing

func TestVerifyReleaseDSSE_Valid(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	// Build an in-toto statement with a subject matching our artifact
	artifact := []byte(`{"release_id":"v1.0.0"}`)
	artifactDigest := sha256.Sum256(artifact)

	statement := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://example.com/predicate/v1",
		Subject: []InTotoSubject{
			{
				Name:   "my-app",
				Digest: map[string]string{"sha256": SHA256Hex(artifact)},
			},
		},
		Predicate: json.RawMessage(`{"custom":"data"}`),
	}
	_ = artifactDigest // used indirectly via SHA256Hex

	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	// Compute PAE and sign it
	pae := PAE("application/vnd.in-toto+json", payload)
	paeDigest := sha256.Sum256(pae)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, paeDigest[:])
	if err != nil {
		t.Fatalf("sign PAE: %v", err)
	}

	// Build DSSE bundle
	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "dsse-test-hint"},
		},
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString(payload),
			PayloadType: "application/vnd.in-toto+json",
			Signatures: []DSSESignature{
				{Sig: base64.StdEncoding.EncodeToString(sig)},
			},
		},
	}
	bundleJSON, _ := json.Marshal(bundle)

	result, err := VerifyReleaseDSSE(t.Context(), v, bundleJSON, artifact)
	if err != nil {
		t.Fatalf("VerifyReleaseDSSE: %v", err)
	}
	if result.KeyHint != "dsse-test-hint" {
		t.Fatalf("KeyHint = %q", result.KeyHint)
	}
	if result.SubjectName != "my-app" {
		t.Fatalf("SubjectName = %q", result.SubjectName)
	}
	if result.PredicateType != "https://example.com/predicate/v1" {
		t.Fatalf("PredicateType = %q", result.PredicateType)
	}
}

// VerifyReleaseDSSE - tampered artifact

func TestVerifyReleaseDSSE_TamperedArtifact(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	original := []byte(`{"release_id":"v1.0.0"}`)

	statement := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://example.com/predicate/v1",
		Subject: []InTotoSubject{
			{
				Name:   "my-app",
				Digest: map[string]string{"sha256": SHA256Hex(original)},
			},
		},
	}

	payload, _ := json.Marshal(statement)
	pae := PAE("application/vnd.in-toto+json", payload)
	paeDigest := sha256.Sum256(pae)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, paeDigest[:])

	bundle := SigstoreBundle{
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "test"},
		},
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString(payload),
			PayloadType: "application/vnd.in-toto+json",
			Signatures:  []DSSESignature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
		},
	}
	bundleJSON, _ := json.Marshal(bundle)

	// Signature is valid, but artifact doesn't match subject digest
	tampered := []byte(`{"release_id":"v1.0.0","injected":true}`)
	_, err = VerifyReleaseDSSE(t.Context(), v, bundleJSON, tampered)
	if err == nil {
		t.Fatal("expected error for tampered artifact")
	}
}

// VerifyReleaseDSSE - tampered payload (signature fails)

func TestVerifyReleaseDSSE_TamperedPayload(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	artifact := []byte(`{"release_id":"v1.0.0"}`)

	// Sign one statement
	statement := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://example.com/predicate/v1",
		Subject: []InTotoSubject{
			{Name: "my-app", Digest: map[string]string{"sha256": SHA256Hex(artifact)}},
		},
	}
	payload, _ := json.Marshal(statement)
	pae := PAE("application/vnd.in-toto+json", payload)
	paeDigest := sha256.Sum256(pae)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, paeDigest[:])

	// But put a different payload in the envelope
	tamperedStatement := statement
	tamperedStatement.PredicateType = "https://evil.com/predicate/v1"
	tamperedPayload, _ := json.Marshal(tamperedStatement)

	bundle := SigstoreBundle{
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "test"},
		},
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString(tamperedPayload),
			PayloadType: "application/vnd.in-toto+json",
			Signatures:  []DSSESignature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
		},
	}
	bundleJSON, _ := json.Marshal(bundle)

	_, err = VerifyReleaseDSSE(t.Context(), v, bundleJSON, artifact)
	if err == nil {
		t.Fatal("expected signature verification failure for tampered payload")
	}
}

// VerifyReleaseDSSE - wrong signing key

func TestVerifyReleaseDSSE_WrongKey(t *testing.T) {
	signingKey := generateTestKey(t)
	wrongKey := generateTestKey(t)
	v := newTestVerifier(t, &wrongKey.PublicKey)

	artifact := []byte(`{"release_id":"v1.0.0"}`)
	bundleJSON := buildDSSEBundle(t, signingKey, artifact)

	_, err := VerifyReleaseDSSE(t.Context(), v, bundleJSON, artifact)
	if err == nil {
		t.Fatal("expected verification failure for wrong key")
	}
}

// VerifyReleaseDSSE - bundle is a blob signature, not DSSE

func TestVerifyReleaseDSSE_NotDSSEBundle(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	artifact := []byte(`{"release_id":"v1.0.0"}`)
	// buildBlobBundle produces a MessageSignature bundle, not DSSE
	bundleJSON := buildBlobBundle(t, key, artifact)

	_, err := VerifyReleaseDSSE(t.Context(), v, bundleJSON, artifact)
	if err == nil {
		t.Fatal("expected error when DSSE verification receives a blob bundle")
	}
}

func buildDSSEBundle(t *testing.T, key *rsa.PrivateKey, artifact []byte) []byte {
	t.Helper()

	statement := InTotoStatement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: "https://example.com/predicate/v1",
		Subject: []InTotoSubject{
			{Name: "my-app", Digest: map[string]string{"sha256": SHA256Hex(artifact)}},
		},
		Predicate: json.RawMessage(`{"custom":"data"}`),
	}

	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	pae := PAE("application/vnd.in-toto+json", payload)
	paeDigest := sha256.Sum256(pae)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, paeDigest[:])
	if err != nil {
		t.Fatalf("sign PAE: %v", err)
	}

	bundle := SigstoreBundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: VerificationMaterial{
			PublicKey: PublicKeyRef{Hint: "dsse-test-hint"},
		},
		DSSEEnvelope: &DSSEEnvelope{
			Payload:     base64.StdEncoding.EncodeToString(payload),
			PayloadType: "application/vnd.in-toto+json",
			Signatures:  []DSSESignature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
		},
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return raw
}
