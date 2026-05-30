package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
)

// URLs for the embedded trust material. The transparency API exposes these
// so frontends can link out to the canonical artifact for each anchor.
// A downloader/auditor can fetch the same bytes we've embedded.
const (
	trustBaseURL = "https://trust.linnemanlabs.com"

	trustURLTSACert     = trustBaseURL + "/certs/tsa.crt"
	trustURLFulcioCA    = trustBaseURL + "/certs/fulcio-ca.crt"
	trustURLRekorPubKey = trustBaseURL + "/keys/rekor-checkpoint.pub"
	trustURLCTLogPubKey = trustBaseURL + "/keys/tesseract-checkpoint.pub"
	trustURLTrustedRoot = trustBaseURL + "/.well-known/trusted_root.json"
)

// Embedded LinnemanLabs trust roots for keyless (Fulcio) signature verification.
// These are the trust anchors compiled into the binary:
//
//   - fulcio-ca-chain.pem: LinnemanLabs Fulcio CA + Root CA (full chain)
//   - root-ca.crt:         LinnemanLabs Root CA (the single trust anchor)
//   - tsa-chain.pem:       LinnemanLabs TSA + Root CA (full chain)
//   - rekor-checkpoint.pub: ECDSA pubkey for rekor.trust.linnemanlabs.com checkpoints
//   - tesseract-checkpoint.pub: ECDSA pubkey for the CT log SCT signatures
//
// Source of truth is internal/cryptoutil/trustdata/; verification will fail
// closed at process start if any artifact is missing or unparseable.
//
// Will move to TUF distribution soon, baking in for now.
//
//go:embed trustdata/fulcio-ca-chain.pem
//go:embed trustdata/root-ca.crt
//go:embed trustdata/tsa-chain.pem
//go:embed trustdata/rekor-checkpoint.pub
//go:embed trustdata/tesseract-checkpoint.pub
var trustdataFS embed.FS

// TrustRoots holds the parsed trust anchors used by the keyless verifier.
// All fields are populated at package init; init panics on parse failure so a
// missing/corrupt embedded root prevents the binary from starting.
type TrustRoots struct {
	// RootCAs contains the LinnemanLabs Root CA. Used as the trust anchor for
	// both the Fulcio leaf chain and the TSA chain.
	RootCAs *x509.CertPool

	// RootCA is the LinnemanLabs Root CA cert, held separately so the
	// transparency-info extractor can surface its subject DN.
	RootCA *x509.Certificate

	// FulcioIntermediates contains the LinnemanLabs Fulcio CA, an intermediate
	// between leaf code-signing certs and the Root CA.
	FulcioIntermediates *x509.CertPool

	// FulcioCA is the LinnemanLabs Fulcio CA cert. Held separately so SCT
	// verification can compute issuer_key_hash = SHA-256(SPKI of FulcioCA).
	FulcioCA *x509.Certificate

	// TSAIntermediates contains the LinnemanLabs TSA cert, which signs the
	// RFC3161 TimeStampTokens. Treated as an intermediate so x509.Verify can
	// build leaf → TSA → Root for the timestamping chain.
	TSAIntermediates *x509.CertPool

	// TSACert is the LinnemanLabs TSA signing cert, also held separately so the
	// timestamp verifier can use it directly without searching the pool.
	TSACert *x509.Certificate

	// RekorPubKey verifies signatures on Rekor checkpoint envelopes.
	RekorPubKey *ecdsa.PublicKey

	// RekorLogID is SHA-256 over the Rekor public key's SPKI DER. It matches
	// the bundle's tlogEntries[].logId.keyId.
	RekorLogID [32]byte

	// CTLogs maps a CT log's RFC 6962 log_id (SHA-256 of the SPKI DER) to its
	// verification public key. Today there's a single entry ("tesseract");
	// adding another CT log is just dropping another go:embed + loader line.
	CTLogs map[[32]byte]*ecdsa.PublicKey
}

// trustRoots is the parsed, runtime-ready bundle of trust anchors.
// Populated at init from the embedded trustdata files.
var trustRoots = mustLoadTrustRoots()

func mustLoadTrustRoots() *TrustRoots {
	tr, err := loadTrustRoots()
	if err != nil {
		// binary built without valid trust roots can never safely verify a keyless signature.
		panic(fmt.Sprintf("cryptoutil: failed to load embedded trust roots: %v", err))
	}
	return tr
}

func loadTrustRoots() (*TrustRoots, error) {
	rootCert, err := loadPEMCert("trustdata/root-ca.crt")
	if err != nil {
		return nil, fmt.Errorf("root ca: %w", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	fulcioCAs, err := loadPEMChain("trustdata/fulcio-ca-chain.pem")
	if err != nil {
		return nil, fmt.Errorf("fulcio ca chain: %w", err)
	}
	fulcioIntermediates := x509.NewCertPool()
	var fulcioCA *x509.Certificate
	for _, c := range fulcioCAs {
		// only the intermediates get added, Root CA is already in rootPool.
		if !certIsEqual(c, rootCert) {
			fulcioIntermediates.AddCert(c)
			if fulcioCA == nil {
				fulcioCA = c
			}
		}
	}
	if fulcioCA == nil {
		return nil, fmt.Errorf("fulcio ca chain has no intermediate CA cert")
	}

	tsaChain, err := loadPEMChain("trustdata/tsa-chain.pem")
	if err != nil {
		return nil, fmt.Errorf("tsa chain: %w", err)
	}
	tsaIntermediates := x509.NewCertPool()
	var tsaLeaf *x509.Certificate
	for _, c := range tsaChain {
		if certIsEqual(c, rootCert) {
			continue
		}
		tsaIntermediates.AddCert(c)
		// the TSA leaf is the cert with EKU=TimeStamping
		if tsaLeaf == nil && hasEKU(c, x509.ExtKeyUsageTimeStamping) {
			tsaLeaf = c
		}
	}
	if tsaLeaf == nil {
		return nil, fmt.Errorf("tsa chain has no certificate with EKU=TimeStamping")
	}

	rekorPub, err := loadPEMECDSAPubKey("trustdata/rekor-checkpoint.pub")
	if err != nil {
		return nil, fmt.Errorf("rekor pubkey: %w", err)
	}
	rekorSPKI, err := x509.MarshalPKIXPublicKey(rekorPub)
	if err != nil {
		return nil, fmt.Errorf("rekor pubkey SPKI: %w", err)
	}

	ctLogs := map[[32]byte]*ecdsa.PublicKey{}
	if err := registerCTLog(ctLogs, "trustdata/tesseract-checkpoint.pub"); err != nil {
		return nil, err
	}
	if len(ctLogs) == 0 {
		return nil, fmt.Errorf("no CT log keys loaded")
	}

	return &TrustRoots{
		RootCAs:             rootPool,
		RootCA:              rootCert,
		FulcioIntermediates: fulcioIntermediates,
		FulcioCA:            fulcioCA,
		TSAIntermediates:    tsaIntermediates,
		TSACert:             tsaLeaf,
		RekorPubKey:         rekorPub,
		RekorLogID:          sha256.Sum256(rekorSPKI),
		CTLogs:              ctLogs,
	}, nil
}

// registerCTLog loads a CT log pubkey from the embedded PEM at name and adds
// it to the keyed-by-log_id map. Returning an error makes startup fail-closed
// if the embedded artifact is unparseable.
func registerCTLog(into map[[32]byte]*ecdsa.PublicKey, name string) error {
	pub, err := loadPEMECDSAPubKey(name)
	if err != nil {
		return fmt.Errorf("ct log pubkey %s: %w", name, err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("ct log pubkey SPKI %s: %w", name, err)
	}
	into[sha256.Sum256(spki)] = pub
	return nil
}

func loadPEMCert(name string) (*x509.Certificate, error) {
	raw, err := trustdataFS.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: not a PEM CERTIFICATE", name)
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadPEMChain(name string) ([]*x509.Certificate, error) {
	raw, err := trustdataFS.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no CERTIFICATE blocks", name)
	}
	return out, nil
}

func loadPEMECDSAPubKey(name string) (*ecdsa.PublicKey, error) {
	raw, err := trustdataFS.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s: not a PEM PUBLIC KEY", name)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA public key (%T)", name, pub)
	}
	return ec, nil
}

func certIsEqual(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

func hasEKU(c *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range c.ExtKeyUsage {
		if eku == want {
			return true
		}
	}
	return false
}
