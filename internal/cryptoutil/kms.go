package cryptoutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

type KMSVerifier struct {
	client *kms.Client
	keyARN string

	// cached public key for local verification
	mu     sync.RWMutex
	pubKey crypto.PublicKey
}

func (v *KMSVerifier) VerifyBlob(ctx context.Context, bundleJSON, artifact []byte) error {
	// we dont need the result with the predicate type or key hint here, just a pass/fail, err is either nil or an error
	_, err := VerifyBlobSignature(ctx, v, bundleJSON, artifact)
	return err
}

func NewKMSVerifier(client *kms.Client, keyARN string) *KMSVerifier {
	return &KMSVerifier{client: client, keyARN: keyARN}
}

// PublicKey fetches and caches the KMS public key for local verification.
// First call hits KMS API, subsequent calls return cached key.
func (v *KMSVerifier) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	v.mu.RLock()
	if v.pubKey != nil {
		defer v.mu.RUnlock()
		return v.pubKey, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	// double-check after acquiring write lock
	if v.pubKey != nil {
		return v.pubKey, nil
	}

	if v.client == nil {
		return nil, xerrors.New("kms client is not configured")
	}

	out, err := v.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(v.keyARN),
	})
	if err != nil {
		return nil, xerrors.Wrap(err, "kms get public key")
	}

	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, xerrors.Wrap(err, "parse kms public key DER")
	}

	v.pubKey = pub
	return v.pubKey, nil
}

// VerifySignature fetches the public key (cached) and verifies the signature
// locally. Supports ECDSA (P-256/P-384) and RSA (PSS with fallback to PKCS1v15).
//
// Key type determines the hash algorithm:
//   - ECDSA P-384: SHA-384
//   - ECDSA P-256: SHA-256
//   - RSA: SHA-256 (PSS first, then PKCS1v15 fallback)
func (v *KMSVerifier) VerifySignature(ctx context.Context, message, signature []byte) error {
	pub, err := v.PublicKey(ctx)
	if err != nil {
		return err
	}

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(key, message, signature)
	case *rsa.PublicKey:
		return verifyRSA(key, message, signature)
	default:
		return xerrors.Newf("unsupported public key type: %T", pub)
	}
}

// verifyECDSA verifies an ECDSA signature, selecting the hash algorithm based on the curve
func verifyECDSA(key *ecdsa.PublicKey, message, signature []byte) error {
	hashFunc, digest, err := ecdsaDigest(key, message)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(key, digest, signature) {
		return xerrors.Newf("ECDSA signature verification failed. hash: %s, curve: %s", hashFunc.String(), key.Curve.Params().Name)
	}
	return nil
}

// ecdsaDigest selects the hash function based on EC curve and computes the
// digest over message. Returns the crypto.Hash, the digest bytes, and any error.
func ecdsaDigest(key *ecdsa.PublicKey, message []byte) (crypto.Hash, []byte, error) {
	switch key.Curve {
	case elliptic.P256():
		d := sha256.Sum256(message)
		return crypto.SHA256, d[:], nil
	case elliptic.P384():
		d := sha512.Sum384(message)
		return crypto.SHA384, d[:], nil
	default:
		return 0, nil, xerrors.Newf("unsupported ECDSA curve: %v", key.Curve.Params().Name)
	}
}

// verifyRSA verifies an RSA signature. Tries PSS first (preferred for new
// keys), then falls back to PKCS1v15 for backward compatibility with
// existing signatures.
func verifyRSA(key *rsa.PublicKey, message, signature []byte) error {
	digest := sha256.Sum256(message)

	// try PSS first - this is the preferred scheme for new RSA keys
	if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, nil); err == nil {
		return nil
	}

	// fall back to PKCS1v15 for backward compatibility
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}
