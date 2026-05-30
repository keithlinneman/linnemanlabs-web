package cryptoutil

import (
	"crypto/x509"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// VerifyLeafChain confirms the leaf cert chains to the embedded Root CA via
// the Fulcio CA intermediate, with EKU=CodeSigning, evaluated at the trusted
// signing time. Fulcio-issued leaf certs are short-lived (~10 min), so the
// signingTime - supplied by the RFC3161 timestamp - is what makes the chain
// validate.
func VerifyLeafChain(leaf *x509.Certificate, signingTime time.Time) error {
	if leaf == nil {
		return xerrors.New("chain: leaf cert is nil")
	}
	if signingTime.IsZero() {
		return xerrors.New("chain: signingTime is zero")
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         trustRoots.RootCAs,
		Intermediates: trustRoots.FulcioIntermediates,
		CurrentTime:   signingTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return xerrors.Wrap(err, "chain: leaf -> Fulcio CA -> Root CA")
	}
	return nil
}
