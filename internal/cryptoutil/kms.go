package cryptoutil

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
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

// VerifySignature fetches the public key (cached) and verifies an
// RSA-PSS SHA256 signature locally. This is for cosign signed with an AWS KMS RSA key.
func (v *KMSVerifier) VerifySignature(ctx context.Context, message, signature []byte) error {
	pub, err := v.PublicKey(ctx)
	if err != nil {
		return err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return xerrors.Newf("expected RSA public key, got %T", pub)
	}

	digest := sha256.Sum256(message)

	return rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}
