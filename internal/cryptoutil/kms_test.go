package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

// generateTestRSAKey creates an RSA-2048 key pair for tests.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// generateTestKey creates an RSA-2048 key pair for backward compat with existing tests.
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	return generateTestRSAKey(t)
}

// generateTestECKey creates an ECDSA key pair for the given curve.
func generateTestECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	return key
}

// newTestVerifier creates a KMSVerifier with a pre-cached public key.
func newTestVerifier(t *testing.T, pub crypto.PublicKey) *KMSVerifier {
	t.Helper()
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test-key-id",
	}
	v.pubKey = pub
	return v
}

// --- ECDSA P-384 tests ---

func TestVerifySignature_ECDSA_P384_Valid(t *testing.T) {
	key := generateTestECKey(t, elliptic.P384())
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha512.Sum384(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), message, sig); err != nil {
		t.Fatalf("VerifySignature ECDSA P-384: %v", err)
	}
}

func TestVerifySignature_ECDSA_P384_WrongMessage(t *testing.T) {
	key := generateTestECKey(t, elliptic.P384())
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha512.Sum384(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), []byte("wrong message"), sig); err == nil {
		t.Fatal("expected verification failure for wrong message")
	}
}

func TestVerifySignature_ECDSA_P384_WrongKey(t *testing.T) {
	signingKey := generateTestECKey(t, elliptic.P384())
	wrongKey := generateTestECKey(t, elliptic.P384())
	v := newTestVerifier(t, &wrongKey.PublicKey)

	message := []byte("hello world")
	digest := sha512.Sum384(message)
	sig, err := ecdsa.SignASN1(rand.Reader, signingKey, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), message, sig); err == nil {
		t.Fatal("expected verification failure for wrong key")
	}
}

func TestVerifySignature_ECDSA_P384_CorruptedSig(t *testing.T) {
	key := generateTestECKey(t, elliptic.P384())
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha512.Sum384(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sig[0] ^= 0xff

	if err := v.VerifySignature(t.Context(), message, sig); err == nil {
		t.Fatal("expected verification failure for corrupted signature")
	}
}

// --- ECDSA P-256 tests ---

func TestVerifySignature_ECDSA_P256_Valid(t *testing.T) {
	key := generateTestECKey(t, elliptic.P256())
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), message, sig); err != nil {
		t.Fatalf("VerifySignature ECDSA P-256: %v", err)
	}
}

func TestVerifySignature_ECDSA_P256_WrongMessage(t *testing.T) {
	key := generateTestECKey(t, elliptic.P256())
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), []byte("wrong message"), sig); err == nil {
		t.Fatal("expected verification failure for wrong message")
	}
}

// --- RSA PSS tests ---

func TestVerifySignature_RSA_PSS_Valid(t *testing.T) {
	key := generateTestRSAKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("sign PSS: %v", err)
	}

	if err := v.VerifySignature(t.Context(), message, sig); err != nil {
		t.Fatalf("VerifySignature RSA-PSS: %v", err)
	}
}

func TestVerifySignature_RSA_PSS_WrongMessage(t *testing.T) {
	key := generateTestRSAKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("sign PSS: %v", err)
	}

	if err := v.VerifySignature(t.Context(), []byte("wrong message"), sig); err == nil {
		t.Fatal("expected verification failure for wrong message with PSS")
	}
}

// --- RSA PKCS1v15 backward compat tests ---

func TestVerifySignature_RSA_PKCS1v15_Valid(t *testing.T) {
	key := generateTestRSAKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), message, sig); err != nil {
		t.Fatalf("VerifySignature RSA PKCS1v15: %v", err)
	}
}

func TestVerifySignature_RSA_PKCS1v15_WrongMessage(t *testing.T) {
	key := generateTestRSAKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), []byte("wrong message"), sig); err == nil {
		t.Fatal("expected verification failure for wrong message")
	}
}

func TestVerifySignature_RSA_WrongKey(t *testing.T) {
	signingKey := generateTestRSAKey(t)
	wrongKey := generateTestRSAKey(t)
	v := newTestVerifier(t, &wrongKey.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), message, sig); err == nil {
		t.Fatal("expected verification failure for wrong key")
	}
}

func TestVerifySignature_CorruptedSignature(t *testing.T) {
	key := generateTestRSAKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sig[0] ^= 0xff

	if err := v.VerifySignature(t.Context(), message, sig); err == nil {
		t.Fatal("expected verification failure for corrupted signature")
	}
}

// --- Empty / nil inputs ---

func TestVerifySignature_EmptyMessage(t *testing.T) {
	key := generateTestRSAKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte{}
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), message, sig); err != nil {
		t.Fatalf("VerifySignature on empty message: %v", err)
	}
}

func TestVerifySignature_EmptySignature(t *testing.T) {
	key := generateTestRSAKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	if err := v.VerifySignature(t.Context(), []byte("hello"), []byte{}); err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestVerifySignature_NilSignature(t *testing.T) {
	key := generateTestRSAKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	if err := v.VerifySignature(t.Context(), []byte("hello"), nil); err == nil {
		t.Fatal("expected error for nil signature")
	}
}

// --- Unsupported key type ---

func TestVerifySignature_UnsupportedKeyType(t *testing.T) {
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test",
	}
	v.pubKey = "not-a-key"

	if err := v.VerifySignature(t.Context(), []byte("msg"), []byte("sig")); err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// --- PublicKey caching ---

func TestPublicKey_CachesResult(t *testing.T) {
	key := generateTestRSAKey(t)
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test",
	}
	v.pubKey = &key.PublicKey

	got, err := v.PublicKey(t.Context())
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	rsaPub, ok := got.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", got)
	}
	if rsaPub.N.Cmp(key.PublicKey.N) != 0 {
		t.Fatal("cached key does not match")
	}
}

func TestPublicKey_CachesECDSA(t *testing.T) {
	key := generateTestECKey(t, elliptic.P384())
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test",
	}
	v.pubKey = &key.PublicKey

	got, err := v.PublicKey(t.Context())
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	ecPub, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", got)
	}
	if ecPub.X.Cmp(key.PublicKey.X) != 0 || ecPub.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("cached key does not match")
	}
}

func TestPublicKey_NilClient_FailsOnCacheMiss(t *testing.T) {
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test",
	}

	_, err := v.PublicKey(t.Context())
	if err == nil {
		t.Fatal("expected error when client is nil and cache is empty")
	}
}
