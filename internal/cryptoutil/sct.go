package cryptoutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"math/big"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// oidSCTList is RFC 6962 §3.3: the SCT-list certificate extension.
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// VerifySCT validates the embedded Signed Certificate Timestamp(s) on a Fulcio
// leaf certificate against the trusted CT log public key. At least one SCT
// matching the trusted log must verify; SCTs from other logs are ignored
// (could be added later if multi-log).
//
// Per RFC 6962 §3.2, the signed payload for a precert SCT is the TLS-encoded
// concatenation:
//
//	sct_version(1) || signature_type(1)=certificate_timestamp(0) ||
//	timestamp(8) || entry_type(2)=precert_entry(1) ||
//	issuer_key_hash(32) || tbs_certificate(uint24-len + bytes) ||
//	extensions(uint16-len + bytes)
//
// tbs_certificate is the leaf TBSCertificate DER with the SCT-list extension
// removed.
func VerifySCT(leaf *x509.Certificate) error {
	if leaf == nil {
		return xerrors.New("sct: leaf is nil")
	}
	sctExtBytes, err := findSCTExtension(leaf)
	if err != nil {
		return xerrors.Wrap(err, "sct: find extension")
	}
	scts, err := parseSCTList(sctExtBytes)
	if err != nil {
		return xerrors.Wrap(err, "sct: parse list")
	}
	if len(scts) == 0 {
		return xerrors.New("sct: extension contains zero SCTs")
	}

	// Rebuild TBSCertificate without the SCT extension.
	tbsNoSCT, err := tbsWithoutSCT(leaf)
	if err != nil {
		return xerrors.Wrap(err, "sct: rebuild TBS without SCT")
	}

	issuerKeyHash := sha256.Sum256(trustRoots.FulcioCA.RawSubjectPublicKeyInfo)

	var lastErr error
	for i, sct := range scts {
		pubKey, ok := trustRoots.CTLogs[sct.LogID]
		if !ok {
			lastErr = xerrors.Newf("sct[%d] from unknown log %x", i, sct.LogID[:8])
			continue
		}
		payload, err := buildPreCertSCTSignedPayload(sct.Version, sct.Timestamp, issuerKeyHash[:], tbsNoSCT, sct.Extensions)
		if err != nil {
			lastErr = xerrors.Wrapf(err, "sct[%d] build payload", i)
			continue
		}
		if err := verifySCTSignature(&sct, payload, pubKey); err != nil {
			lastErr = xerrors.Wrapf(err, "sct[%d] signature", i)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = xerrors.New("no SCT matched any trusted CT log")
	}
	return lastErr
}

// findSCTExtension extracts the TLS-encoded SCT list from the cert's SCT-list
// extension. The extension value is an OCTET STRING whose contents are an
// OCTET STRING (the TLS-encoded list).
func findSCTExtension(leaf *x509.Certificate) ([]byte, error) {
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidSCTList) {
			continue
		}
		// ext.Value is the inner of the extension's OCTET STRING (Go's x509
		// already unwraps the outer extnValue OCTET STRING). The contents are
		// themselves an OCTET STRING wrapping the TLS bytes - unwrap once more.
		var inner []byte
		if _, err := asn1.Unmarshal(ext.Value, &inner); err != nil {
			return nil, xerrors.Wrap(err, "unwrap inner OCTET STRING")
		}
		return inner, nil
	}
	return nil, xerrors.New("certificate has no SCT-list extension")
}

// sct is one parsed SCT in RFC 6962 v1 form.
type sct struct {
	Version    uint8 // 0 == v1
	LogID      [32]byte
	Timestamp  uint64 // ms since epoch
	Extensions []byte
	HashAlgo   uint8 // RFC 5246: 4=SHA256, 5=SHA384, 6=SHA512
	SigAlgo    uint8 // RFC 5246: 1=RSA, 3=ECDSA
	Signature  []byte
}

// parseSCTList decodes a TLS-encoded SignedCertificateTimestampList.
//
//	struct { opaque sct_list<1..2^16-1>; } SignedCertificateTimestampList;
//	struct { opaque sct<1..2^16-1>; }     SerializedSCT;
func parseSCTList(buf []byte) ([]sct, error) {
	r := newTLSReader(buf)
	listLen, err := r.uint16()
	if err != nil {
		return nil, xerrors.Wrap(err, "read sct_list length")
	}
	listBytes, err := r.bytes(int(listLen))
	if err != nil {
		return nil, xerrors.Wrap(err, "read sct_list")
	}
	if r.remaining() != 0 {
		return nil, xerrors.Newf("trailing %d bytes after sct_list", r.remaining())
	}

	out := []sct{}
	for inner := newTLSReader(listBytes); inner.remaining() > 0; {
		serializedLen, err := inner.uint16()
		if err != nil {
			return nil, xerrors.Wrap(err, "read serialized sct length")
		}
		serialized, err := inner.bytes(int(serializedLen))
		if err != nil {
			return nil, xerrors.Wrap(err, "read serialized sct")
		}
		s, err := parseSerializedSCT(serialized)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// parseSerializedSCT decodes one SCT per RFC 6962 §3.2.
func parseSerializedSCT(buf []byte) (sct, error) {
	r := newTLSReader(buf)
	var s sct
	v, err := r.uint8()
	if err != nil {
		return s, xerrors.Wrap(err, "read version")
	}
	s.Version = v
	if v != 0 {
		return s, xerrors.Newf("unsupported sct_version %d", v)
	}
	logID, err := r.bytes(32)
	if err != nil {
		return s, xerrors.Wrap(err, "read log_id")
	}
	copy(s.LogID[:], logID)

	ts, err := r.uint64()
	if err != nil {
		return s, xerrors.Wrap(err, "read timestamp")
	}
	s.Timestamp = ts

	extLen, err := r.uint16()
	if err != nil {
		return s, xerrors.Wrap(err, "read ct_extensions length")
	}
	ext, err := r.bytes(int(extLen))
	if err != nil {
		return s, xerrors.Wrap(err, "read ct_extensions")
	}
	s.Extensions = ext

	s.HashAlgo, err = r.uint8()
	if err != nil {
		return s, xerrors.Wrap(err, "read hash_algo")
	}
	s.SigAlgo, err = r.uint8()
	if err != nil {
		return s, xerrors.Wrap(err, "read sig_algo")
	}
	sigLen, err := r.uint16()
	if err != nil {
		return s, xerrors.Wrap(err, "read signature length")
	}
	sig, err := r.bytes(int(sigLen))
	if err != nil {
		return s, xerrors.Wrap(err, "read signature")
	}
	s.Signature = sig
	if r.remaining() != 0 {
		return s, xerrors.Newf("trailing %d bytes after sct", r.remaining())
	}
	return s, nil
}

// SCT signed-payload TLS constants (RFC 6962 §3.2 / RFC 5246 enum values).
const (
	tlsSigTypeCertificateTimestamp = 0
	tlsLogEntryTypePreCertEntry    = 1
)

// buildPreCertSCTSignedPayload constructs the TLS-encoded byte string that the
// CT log signs for a precert SCT, per RFC 6962 §3.2.
func buildPreCertSCTSignedPayload(version uint8, timestamp uint64, issuerKeyHash, tbs, extensions []byte) ([]byte, error) {
	if len(extensions) > 0xFFFF {
		return nil, xerrors.Newf("ct_extensions too long: %d", len(extensions))
	}
	if len(tbs) > 0xFFFFFF {
		return nil, xerrors.Newf("tbs_certificate too long: %d", len(tbs))
	}
	var buf bytes.Buffer
	buf.WriteByte(version)
	buf.WriteByte(tlsSigTypeCertificateTimestamp)
	_ = binary.Write(&buf, binary.BigEndian, timestamp)
	_ = binary.Write(&buf, binary.BigEndian, uint16(tlsLogEntryTypePreCertEntry))
	buf.Write(issuerKeyHash)
	writeUint24Length(&buf, len(tbs))
	buf.Write(tbs)
	extLen := uint16(len(extensions)) //nolint:gosec // bounded above (len <= 0xFFFF)
	_ = binary.Write(&buf, binary.BigEndian, extLen)
	buf.Write(extensions)
	return buf.Bytes(), nil
}

func writeUint24Length(buf *bytes.Buffer, n int) {
	buf.WriteByte(byte((n >> 16) & 0xff))
	buf.WriteByte(byte((n >> 8) & 0xff))
	buf.WriteByte(byte(n & 0xff))
}

// verifySCTSignature ECDSA-verifies the SCT signature over the TLS-encoded
// payload using the trusted CT log public key. Only ECDSA + SHA256 is
// supported; that matches the LinnemanLabs CT log (and is the common case).
func verifySCTSignature(s *sct, payload []byte, pubKey *ecdsa.PublicKey) error {
	if s.SigAlgo != 3 { // 3 = ECDSA per RFC 5246
		return xerrors.Newf("unsupported sct signature algo %d (want ECDSA)", s.SigAlgo)
	}
	if s.HashAlgo != 4 { // 4 = SHA256
		return xerrors.Newf("unsupported sct hash algo %d (want SHA256)", s.HashAlgo)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pubKey, digest[:], s.Signature) {
		return xerrors.New("ECDSA verify failed")
	}
	return nil
}

// tlsReader is a minimal sequential reader for TLS-encoded primitives.
type tlsReader struct {
	buf []byte
	off int
}

func newTLSReader(b []byte) *tlsReader { return &tlsReader{buf: b} }

func (r *tlsReader) remaining() int { return len(r.buf) - r.off }

func (r *tlsReader) bytes(n int) ([]byte, error) {
	if r.off+n > len(r.buf) {
		return nil, xerrors.Newf("short read: want %d, have %d", n, len(r.buf)-r.off)
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *tlsReader) uint8() (uint8, error) {
	b, err := r.bytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *tlsReader) uint16() (uint16, error) {
	b, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *tlsReader) uint64() (uint64, error) {
	b, err := r.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// --- TBSCertificate re-encoding without the SCT-list extension ----

// rawExtension is a minimal Extension shape using RawValue for the SCT-list
// detection and pkix-equivalent encoding for round-trip.
type rawExtension struct {
	Raw      asn1.RawContent
	OID      asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// rawTBSCertificate captures the TBSCertificate fields as RawValue except for
// Extensions, which we filter and re-marshal.
type rawTBSCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	UniqueID           asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString `asn1:"optional,tag:2"`
	Extensions         []rawExtension `asn1:"optional,explicit,tag:3"`
}

// tbsWithoutSCT decodes the leaf's RawTBSCertificate, filters out the
// SCT-list extension, and re-marshals the result. The signed precert payload
// (per RFC 6962) is exactly this — the TBS as the CA would have signed before
// embedding the SCT.
func tbsWithoutSCT(leaf *x509.Certificate) ([]byte, error) {
	var tbs rawTBSCertificate
	if _, err := asn1.Unmarshal(leaf.RawTBSCertificate, &tbs); err != nil {
		return nil, xerrors.Wrap(err, "unmarshal TBS")
	}
	filtered := tbs.Extensions[:0]
	for _, ext := range tbs.Extensions {
		if ext.OID.Equal(oidSCTList) {
			continue
		}
		filtered = append(filtered, ext)
	}
	if len(filtered) == len(tbs.Extensions) {
		return nil, xerrors.New("TBS has no SCT-list extension to remove")
	}
	tbs.Extensions = filtered
	// Drop the Raw blob so asn1.Marshal re-emits from fields.
	tbs.Raw = nil
	out, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, xerrors.Wrap(err, "remarshal TBS")
	}
	return out, nil
}
