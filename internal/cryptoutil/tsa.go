package cryptoutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// RFC 3161 / CMS / PKCS#9 / digest-algorithm OIDs we care about.
var (
	oidIDSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidIDCTTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// CMS / RFC3161 ASN.1 structures (hand-rolled; only the fields we need).
type cmsContentInfo struct {
	Raw         asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type cmsSignedData struct {
	Raw              asn1.RawContent
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo cmsEncapContentInfo
	Certificates     []asn1.RawValue   `asn1:"optional,implicit,tag:0,set"`
	CRLs             []asn1.RawValue   `asn1:"optional,implicit,tag:1,set"`
	SignerInfos      []cmsSignerInfoRV `asn1:"set"`
}

type cmsEncapContentInfo struct {
	Raw         asn1.RawContent
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// SignedAttrs is captured as a RawValue so we can re-encode it byte-for-byte
// with the SET OF tag (0x31) for signature verification, per RFC 5652 §5.4.
type cmsSignerInfoRV struct {
	Raw                asn1.RawContent
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type cmsIssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type cmsAttribute struct {
	Raw    asn1.RawContent
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type tstInfo struct {
	Raw            asn1.RawContent
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tstMessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Rest           asn1.RawValue `asn1:"optional"` // accuracy/ordering/nonce/tsa/extensions
}

type tstMessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// VerifyRFC3161 verifies an RFC 3161 TimeStampToken (or TimeStampResp wrapper),
// chains the TSA to the embedded Root CA at the timestamp's genTime, confirms
// the messageImprint covers expectedImprint, and returns the trusted signing
// time. expectedImprint should be SHA-256(messageSignature.signature_bytes) —
// the artifact-bound hash that the timestamp commits to.
func VerifyRFC3161(token, expectedImprint []byte) (time.Time, error) {
	tokenDER, err := extractTimeStampToken(token)
	if err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: extract token")
	}

	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(tokenDER, &ci); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: parse ContentInfo")
	}
	if !ci.ContentType.Equal(oidIDSignedData) {
		return time.Time{}, xerrors.Newf("rfc3161: contentType=%v, want id-signedData", ci.ContentType)
	}

	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: parse SignedData")
	}
	if !sd.EncapContentInfo.ContentType.Equal(oidIDCTTSTInfo) {
		return time.Time{}, xerrors.Newf("rfc3161: eContentType=%v, want id-ct-TSTInfo", sd.EncapContentInfo.ContentType)
	}

	// eContent is an OCTET STRING wrapping the TSTInfo DER.
	var tstInfoOctets []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.Content.Bytes, &tstInfoOctets); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: unwrap TSTInfo octet string")
	}
	var ti tstInfo
	if _, err := asn1.Unmarshal(tstInfoOctets, &ti); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: parse TSTInfo")
	}

	// messageImprint must cover the artifact signature hash.
	if len(expectedImprint) > 0 && !bytes.Equal(ti.MessageImprint.HashedMessage, expectedImprint) {
		return time.Time{}, xerrors.New("rfc3161: messageImprint does not match expected artifact hash")
	}

	if len(sd.SignerInfos) == 0 {
		return time.Time{}, xerrors.New("rfc3161: SignedData has no signerInfos")
	}
	si := sd.SignerInfos[0]

	// SignerIdentifier must match our embedded TSA cert (issuer + serial).
	if err := assertSignerIsTSA(si.SID, trustRoots.TSACert); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: signer mismatch")
	}

	// SignedAttrs must exist and must commit to eContent via the messageDigest
	// attribute. The eContent hash uses the SignerInfo's DigestAlgorithm.
	if len(si.SignedAttrs.FullBytes) == 0 {
		return time.Time{}, xerrors.New("rfc3161: signerInfo has no signedAttrs")
	}
	attrs, err := parseAttributesContent(si.SignedAttrs.Bytes)
	if err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: parse signedAttrs")
	}
	// per RFC 5652 §11.1, signedAttrs MUST include contentType binding the
	// signature to the eContent type (here, id-ct-TSTInfo).
	ctRV, err := requireAttrValue(attrs, oidAttrContentType)
	if err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: contentType attr")
	}
	var ctOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ctRV.FullBytes, &ctOID); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: parse contentType OID")
	}
	if !ctOID.Equal(oidIDCTTSTInfo) {
		return time.Time{}, xerrors.Newf("rfc3161: signed contentType=%v, want id-ct-TSTInfo", ctOID)
	}

	mdRV, err := requireAttrValue(attrs, oidAttrMessageDigest)
	if err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: messageDigest attr")
	}
	var mdValue []byte
	if _, err := asn1.Unmarshal(mdRV.FullBytes, &mdValue); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: parse messageDigest value")
	}
	hashFn, ok := hashFnForOID(si.DigestAlgorithm.Algorithm)
	if !ok {
		return time.Time{}, xerrors.Newf("rfc3161: unsupported digestAlgorithm %v", si.DigestAlgorithm.Algorithm)
	}
	wantDigest := hashFn(tstInfoOctets)
	if !bytes.Equal(mdValue, wantDigest) {
		return time.Time{}, xerrors.New("rfc3161: messageDigest attribute does not match eContent hash")
	}

	// The signed bytes are the signedAttrs encoded with the SET OF tag (0x31)
	// replacing the [0] IMPLICIT context tag (0xA0). Per RFC 5652 §5.4 the rest
	// of the encoding is identical so a single-byte tag rewrite suffices.
	signedBytes := append([]byte(nil), si.SignedAttrs.FullBytes...)
	if signedBytes[0] != 0xA0 {
		return time.Time{}, xerrors.Newf("rfc3161: signedAttrs first byte=%#x, want 0xA0", signedBytes[0])
	}
	signedBytes[0] = 0x31

	if err := verifyECDSAOverDigest(trustRoots.TSACert, si.DigestAlgorithm.Algorithm, signedBytes, si.Signature); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: signerInfo signature verification failed")
	}

	// Chain the TSA cert at genTime with EKU=TimeStamping.
	if _, err := trustRoots.TSACert.Verify(x509.VerifyOptions{
		Roots:         trustRoots.RootCAs,
		Intermediates: trustRoots.TSAIntermediates,
		CurrentTime:   ti.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return time.Time{}, xerrors.Wrap(err, "rfc3161: TSA chain verification")
	}

	return ti.GenTime.UTC(), nil
}

// extractTimeStampToken unwraps an optional RFC 3161 TimeStampResp envelope
// to return the inner TimeStampToken (CMS ContentInfo) DER bytes. Tolerates
// both wrapped (TimeStampResp) and bare (TimeStampToken) inputs.
func extractTimeStampToken(raw []byte) ([]byte, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &outer); err != nil {
		return nil, xerrors.Wrap(err, "parse outer")
	}
	if outer.Tag != asn1.TagSequence {
		return nil, xerrors.Newf("not a SEQUENCE (tag=%d)", outer.Tag)
	}
	var first asn1.RawValue
	rest, err := asn1.Unmarshal(outer.Bytes, &first)
	if err != nil {
		return nil, xerrors.Wrap(err, "parse inner first")
	}
	switch first.Tag {
	case asn1.TagOID:
		// bare ContentInfo - outer SEQUENCE IS the token
		return outer.FullBytes, nil
	case asn1.TagSequence:
		// wrapped TimeStampResp: { PKIStatusInfo, TimeStampToken? }; token is the next element
		if len(rest) == 0 {
			return nil, xerrors.New("TimeStampResp has no TimeStampToken")
		}
		var tok asn1.RawValue
		if _, err := asn1.Unmarshal(rest, &tok); err != nil {
			return nil, xerrors.Wrap(err, "parse token")
		}
		return tok.FullBytes, nil
	default:
		return nil, xerrors.Newf("unexpected first inner tag %d", first.Tag)
	}
}

// assertSignerIsTSA confirms the SignerInfo SID is IssuerAndSerialNumber and
// matches the embedded TSA cert. Subject-Key-Identifier form is rejected (our
// TSA exclusively uses IssuerAndSerialNumber).
func assertSignerIsTSA(sid asn1.RawValue, tsa *x509.Certificate) error {
	if sid.Tag != asn1.TagSequence {
		return xerrors.Newf("SID tag=%d, want SEQUENCE (IssuerAndSerialNumber)", sid.Tag)
	}
	var ias cmsIssuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
		return xerrors.Wrap(err, "parse IssuerAndSerialNumber")
	}
	if !bytes.Equal(ias.Issuer.FullBytes, tsa.RawIssuer) {
		return xerrors.New("signerInfo issuer does not match embedded TSA cert issuer")
	}
	if ias.SerialNumber.Cmp(tsa.SerialNumber) != 0 {
		return xerrors.Newf("signerInfo serial %s does not match TSA cert serial %s",
			ias.SerialNumber, tsa.SerialNumber)
	}
	return nil
}

// parseAttributesContent walks the contents of a SET OF Attribute (without the
// outer SET-OF tag/length) and returns the parsed attributes.
func parseAttributesContent(content []byte) ([]cmsAttribute, error) {
	var out []cmsAttribute
	remaining := content
	for len(remaining) > 0 {
		var a cmsAttribute
		rest, err := asn1.Unmarshal(remaining, &a)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
		remaining = rest
	}
	return out, nil
}

// requireAttrValue finds the attribute by OID and returns the first value in
// its SET as a RawValue. The caller decodes per the expected type (e.g. OID
// for contentType, OCTET STRING for messageDigest).
func requireAttrValue(attrs []cmsAttribute, oid asn1.ObjectIdentifier) (asn1.RawValue, error) {
	for _, a := range attrs {
		if !a.Type.Equal(oid) {
			continue
		}
		var v asn1.RawValue
		if _, err := asn1.Unmarshal(a.Values.Bytes, &v); err != nil {
			return asn1.RawValue{}, xerrors.Wrap(err, "parse attribute value")
		}
		return v, nil
	}
	return asn1.RawValue{}, xerrors.Newf("attribute %v not found", oid)
}

// verifyECDSAOverDigest hashes `signed` with the digest algorithm identified by
// digestOID, then ECDSA-verifies `sig` (ASN.1 DER (r,s)) against the
// certificate's ECDSA public key. RSA signers are unsupported - our TSA uses
// ECDSA only.
func verifyECDSAOverDigest(cert *x509.Certificate, digestOID asn1.ObjectIdentifier, signed, sig []byte) error {
	hashFn, ok := hashFnForOID(digestOID)
	if !ok {
		return xerrors.Newf("unsupported digestAlgorithm %v", digestOID)
	}
	digest := hashFn(signed)

	ec, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return xerrors.Newf("unsupported TSA public key type %T (want ECDSA)", cert.PublicKey)
	}
	if !ecdsa.VerifyASN1(ec, digest, sig) {
		return xerrors.New("ECDSA verification failed")
	}
	return nil
}

// hashFnForOID returns a one-shot hash function for known digest OIDs.
func hashFnForOID(oid asn1.ObjectIdentifier) (func([]byte) []byte, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }, true
	case oid.Equal(oidSHA384):
		return func(b []byte) []byte { h := sha512.Sum384(b); return h[:] }, true
	case oid.Equal(oidSHA512):
		return func(b []byte) []byte { h := sha512.Sum512(b); return h[:] }, true
	}
	return nil, false
}
