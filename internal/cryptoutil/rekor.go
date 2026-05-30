package cryptoutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// VerifyRekorInclusion verifies that a Rekor transparency-log entry is
// genuinely included in our trusted Rekor log AND that the entry's body
// commits to the same cert + signature + artifact digest as the surrounding
// bundle. Layered checks:
//
//  1. entry.LogID matches the embedded Rekor log ID.
//  2. The signed checkpoint envelope is signed by the trusted Rekor key.
//  3. The checkpoint's treeSize + rootHash match the InclusionProof.
//  4. The RFC 6962 Merkle path from the leaf hash reaches the root.
//  5. The leaf body (hashedrekord 0.0.2) reports the same cert/sig/digest as
//     the bundle's verificationMaterial + messageSignature.
//
// Returns nil on full success.
func VerifyRekorInclusion(b *SigstoreBundle) error {
	if b == nil || len(b.VerificationMaterial.TlogEntries) == 0 {
		return xerrors.New("rekor: bundle has no tlogEntries")
	}
	entry := b.VerificationMaterial.TlogEntries[0]

	expectedLogID := base64.StdEncoding.EncodeToString(trustRoots.RekorLogID[:])
	if entry.LogID.KeyID != expectedLogID {
		return xerrors.Newf("rekor: logId %q does not match trusted log %q", entry.LogID.KeyID, expectedLogID)
	}
	if entry.KindVersion.Kind != "hashedrekord" {
		return xerrors.Newf("rekor: unsupported entry kind %q (want hashedrekord)", entry.KindVersion.Kind)
	}

	if entry.InclusionProof == nil {
		return xerrors.New("rekor: entry has no inclusionProof")
	}
	ip := entry.InclusionProof

	bodyBytes, err := base64.StdEncoding.DecodeString(entry.CanonicalizedBody)
	if err != nil {
		return xerrors.Wrap(err, "rekor: decode canonicalizedBody")
	}
	rootHash, err := base64.StdEncoding.DecodeString(ip.RootHash)
	if err != nil {
		return xerrors.Wrap(err, "rekor: decode rootHash")
	}
	proofHashes := make([][]byte, 0, len(ip.Hashes))
	for i, h := range ip.Hashes {
		d, err := base64.StdEncoding.DecodeString(h)
		if err != nil {
			return xerrors.Wrapf(err, "rekor: decode proof hash[%d]", i)
		}
		proofHashes = append(proofHashes, d)
	}
	leafIdx, err := strconv.ParseInt(ip.LogIndex, 10, 64)
	if err != nil {
		return xerrors.Wrap(err, "rekor: parse logIndex")
	}
	treeSize, err := strconv.ParseInt(ip.TreeSize, 10, 64)
	if err != nil {
		return xerrors.Wrap(err, "rekor: parse treeSize")
	}

	// Merkle inclusion proof: leafHash → rootHash via the supplied path.
	leafHash := rfc6962LeafHash(bodyBytes)
	if err := verifyMerkleInclusion(leafIdx, treeSize, leafHash, proofHashes, rootHash); err != nil {
		return xerrors.Wrap(err, "rekor: Merkle inclusion")
	}

	// Checkpoint envelope: trusted signature + commits to same root/size.
	cpSize, cpRoot, err := verifyRekorCheckpoint(ip.Checkpoint.Envelope)
	if err != nil {
		return xerrors.Wrap(err, "rekor: checkpoint")
	}
	if cpSize != treeSize {
		return xerrors.Newf("rekor: checkpoint treeSize %d != proof treeSize %d", cpSize, treeSize)
	}
	if !bytes.Equal(cpRoot, rootHash) {
		return xerrors.New("rekor: checkpoint rootHash != proof rootHash")
	}

	// Body cross-check: the Rekor entry must reference the same cert + sig +
	// artifact digest as the bundle, otherwise an attacker could replay a
	// real inclusion proof for someone else's entry.
	if err := assertRekorBodyMatchesBundle(bodyBytes, b); err != nil {
		return xerrors.Wrap(err, "rekor: body cross-check")
	}

	return nil
}

// RFC 6962 §2.1: leaf hash = SHA-256(0x00 || leaf_data).
func rfc6962LeafHash(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(leaf)
	return h.Sum(nil)
}

// RFC 6962 §2.1: interior node = SHA-256(0x01 || left || right).
func rfc6962NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// verifyMerkleInclusion walks the inclusion proof per RFC 9162 §2.1.4 and
// errors if the computed root does not equal expectedRoot.
func verifyMerkleInclusion(leafIdx, treeSize int64, leafHash []byte, path [][]byte, expectedRoot []byte) error {
	if leafIdx < 0 || treeSize <= 0 || leafIdx >= treeSize {
		return xerrors.Newf("invalid indices leafIdx=%d treeSize=%d", leafIdx, treeSize)
	}
	fn := leafIdx
	sn := treeSize - 1
	r := leafHash

	for i, h := range path {
		if sn == 0 {
			return xerrors.Newf("inclusion proof too long at step %d", i)
		}
		if (fn&1) == 1 || fn == sn {
			r = rfc6962NodeHash(h, r)
			if (fn & 1) == 0 {
				for (fn & 1) == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = rfc6962NodeHash(r, h)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return xerrors.New("inclusion proof too short")
	}
	if !bytes.Equal(r, expectedRoot) {
		return xerrors.New("computed root does not match expected root")
	}
	return nil
}

// verifyRekorCheckpoint parses a Trillian/sumdb signed-note envelope, verifies
// the signature against the trusted Rekor public key, and returns the
// checkpoint's claimed (treeSize, rootHash).
//
// Envelope layout:
//
//	<origin>\n<treeSize>\n<base64 rootHash>\n[<optional extras>\n]\n— <name> <b64(hint||sig)>\n[...]
//
// Body is everything up to (and including the trailing \n of) the line before
// the blank separator line. Signature line format per
// golang.org/x/mod/sumdb/note: `— ` U+2014 space, then NAME, space, base64 of
// (4-byte SHA-256-of-SPKI prefix || ASN.1 DER ECDSA signature).
func verifyRekorCheckpoint(envelope string) (treeSize int64, rootHash []byte, err error) {
	const sep = "\n\n"
	cut := strings.Index(envelope, sep)
	if cut < 0 {
		return 0, nil, xerrors.New("checkpoint missing body/signature separator")
	}
	body := envelope[:cut+1] // include trailing \n of last body line
	sigBlock := envelope[cut+2:]

	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) < 3 {
		return 0, nil, xerrors.Newf("checkpoint body has %d lines, want >=3", len(lines))
	}
	// lines[0] is origin (e.g. rekor.trust.linnemanlabs.com)
	treeSize, err = strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return 0, nil, xerrors.Wrap(err, "checkpoint parse treeSize")
	}
	rootHash, err = base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return 0, nil, xerrors.Wrap(err, "checkpoint parse rootHash")
	}

	// Find a signature line for our trusted Rekor log.
	if !verifyAnyNoteSignature(sigBlock, []byte(body), trustRoots.RekorPubKey, trustRoots.RekorLogID[:4]) {
		return 0, nil, xerrors.New("checkpoint signature did not verify with the trusted Rekor key")
	}
	return treeSize, rootHash, nil
}

// verifyAnyNoteSignature returns true if any signature line in sigBlock
// verifies against pubKey over signedBody. sigBlock has lines formatted as
// "— NAME b64(hint||sig)". hint is the first 4 bytes of SHA-256(SPKI(pubKey));
// only signatures whose hint matches expectedHint are considered.
func verifyAnyNoteSignature(sigBlock string, signedBody []byte, pubKey *ecdsa.PublicKey, expectedHint []byte) bool {
	digest := sha256.Sum256(signedBody)
	for _, line := range strings.Split(strings.TrimRight(sigBlock, "\n"), "\n") {
		// signature line prefix: "— NAME " (note: U+2014 EM DASH, 3 bytes UTF-8)
		const sigPrefix = "— "
		if !strings.HasPrefix(line, sigPrefix) {
			continue
		}
		rest := strings.TrimPrefix(line, sigPrefix)
		// split into NAME + b64sig at the last space
		sp := strings.LastIndexByte(rest, ' ')
		if sp < 0 {
			continue
		}
		b64sig := rest[sp+1:]
		raw, err := base64.StdEncoding.DecodeString(b64sig)
		if err != nil || len(raw) < 4 {
			continue
		}
		if !bytes.Equal(raw[:4], expectedHint) {
			continue
		}
		if ecdsa.VerifyASN1(pubKey, digest[:], raw[4:]) {
			return true
		}
	}
	return false
}

// rekorHashedRekordBody mirrors enough of the hashedrekord 0.0.2 spec to
// cross-check the entry against the bundle. Other variants are not consumed.
type rekorHashedRekordBody struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		HashedRekordV002 struct {
			Data struct {
				Algorithm string `json:"algorithm"`
				Digest    string `json:"digest"`
			} `json:"data"`
			Signature struct {
				Content  string `json:"content"`
				Verifier struct {
					KeyDetails      string `json:"keyDetails"`
					X509Certificate struct {
						RawBytes string `json:"rawBytes"`
					} `json:"x509Certificate"`
				} `json:"verifier"`
			} `json:"signature"`
		} `json:"hashedRekordV002"`
	} `json:"spec"`
}

// assertRekorBodyMatchesBundle decodes the canonicalized Rekor entry body and
// confirms it commits to exactly the cert, signature, and artifact digest that
// the surrounding bundle carries.
func assertRekorBodyMatchesBundle(bodyBytes []byte, b *SigstoreBundle) error {
	var body rekorHashedRekordBody
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return xerrors.Wrap(err, "parse hashedrekord body")
	}
	spec := body.Spec.HashedRekordV002

	if b.MessageSignature == nil {
		return xerrors.New("bundle has no messageSignature to cross-check")
	}
	if spec.Data.Algorithm != b.MessageSignature.MessageDigest.Algorithm {
		return xerrors.Newf("digest algorithm mismatch: body=%q bundle=%q",
			spec.Data.Algorithm, b.MessageSignature.MessageDigest.Algorithm)
	}
	if spec.Data.Digest != b.MessageSignature.MessageDigest.Digest {
		return xerrors.New("messageDigest mismatch between Rekor body and bundle")
	}
	if spec.Signature.Content != b.MessageSignature.Signature {
		return xerrors.New("signature content mismatch between Rekor body and bundle")
	}
	if b.VerificationMaterial.Certificate == nil {
		return xerrors.New("bundle has no certificate to cross-check")
	}
	if spec.Signature.Verifier.X509Certificate.RawBytes != b.VerificationMaterial.Certificate.RawBytes {
		return xerrors.New("certificate mismatch between Rekor body and bundle")
	}
	return nil
}
