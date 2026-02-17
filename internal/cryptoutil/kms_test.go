package cryptoutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// generateTestKey creates an RSA-2048 key pair for tests.
// 2048 is sufficient for testing; 4096 would slow tests down for no benefit.
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

// newTestVerifier creates a KMSVerifier with a pre-cached public key.
// Bypasses KMS API entirely - tests verify the crypto logic, not AWS calls.
func newTestVerifier(t *testing.T, pub crypto.PublicKey) *KMSVerifier {
	t.Helper()
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test-key-id",
	}
	v.pubKey = pub
	return v
}

// VerifySignature - valid RSA-PSS signature

func TestVerifySignature_Valid(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := v.VerifySignature(t.Context(), message, sig); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

// VerifySignature - wrong message

func TestVerifySignature_WrongMessage(t *testing.T) {
	key := generateTestKey(t)
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

// VerifySignature - wrong key

func TestVerifySignature_WrongKey(t *testing.T) {
	signingKey := generateTestKey(t)
	wrongKey := generateTestKey(t)
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

// VerifySignature - corrupted signature

func TestVerifySignature_CorruptedSignature(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	message := []byte("hello world")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// flip a byte
	sig[0] ^= 0xff

	if err := v.VerifySignature(t.Context(), message, sig); err == nil {
		t.Fatal("expected verification failure for corrupted signature")
	}
}

// VerifySignature - empty inputs

func TestVerifySignature_EmptyMessage(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	// sign empty message - should be valid
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
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	if err := v.VerifySignature(t.Context(), []byte("hello"), []byte{}); err == nil {
		t.Fatal("expected error for empty signature")
	}
}

func TestVerifySignature_NilSignature(t *testing.T) {
	key := generateTestKey(t)
	v := newTestVerifier(t, &key.PublicKey)

	if err := v.VerifySignature(t.Context(), []byte("hello"), nil); err == nil {
		t.Fatal("expected error for nil signature")
	}
}

// VerifySignature - non-RSA key type

func TestVerifySignature_NonRSAKey(t *testing.T) {
	// Passing a non-RSA key should return a clear error
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test",
	}
	// string is not a crypto.PublicKey type we handle
	v.pubKey = "not-a-key"

	if err := v.VerifySignature(t.Context(), []byte("msg"), []byte("sig")); err == nil {
		t.Fatal("expected error for non-RSA key type")
	}
}

// PublicKey caching - verify cached key is returned on second call

func TestPublicKey_CachesResult(t *testing.T) {
	key := generateTestKey(t)
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test",
	}
	// simulate a prior fetch by pre-setting the cache
	v.pubKey = &key.PublicKey

	// should return cached key without needing a KMS client
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

func TestPublicKey_NilClient_FailsOnCacheMiss(t *testing.T) {
	v := &KMSVerifier{
		keyARN: "arn:aws:kms:us-east-2:000000000000:key/test",
		// client is nil - would panic/error if cache miss tries KMS call
	}

	_, err := v.PublicKey(t.Context())
	if err == nil {
		t.Fatal("expected error when client is nil and cache is empty")
	}
}
