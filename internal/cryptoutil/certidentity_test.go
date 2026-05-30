package cryptoutil

import (
	"crypto/elliptic"
	"testing"
)

// contentMatchingOpts is a leaf identity that satisfies ContentCertIdentity.
func contentMatchingOpts() fulcioCertOptions {
	return fulcioCertOptions{
		sanURI:       "https://github.com/keithlinneman/linnemanlabs-site/.github/workflows/build.yml@refs/tags/v1.2.3",
		oidcIssuer:   "https://token.actions.githubusercontent.com",
		ghTrigger:    "push",
		ghName:       "Build Site",
		ghRepository: "keithlinneman/linnemanlabs-site",
	}
}

// checkContentIdentity builds a leaf cert from opts and runs it through the
// hardcoded content identity policy.
func checkContentIdentity(t *testing.T, opts *fulcioCertOptions) error {
	t.Helper()
	key := generateTestECKey(t, elliptic.P256())
	cert := newTestLeafCert(t, key, opts)
	return ContentCertIdentity().Check(cert, certInfo(cert))
}

func TestContentCertIdentity_Matches(t *testing.T) {
	opts := contentMatchingOpts()
	if err := checkContentIdentity(t, &opts); err != nil {
		t.Fatalf("matching identity should pass: %v", err)
	}
}

func TestContentCertIdentity_Rejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fulcioCertOptions)
	}{
		{"wrong issuer", func(o *fulcioCertOptions) { o.oidcIssuer = "https://accounts.google.com" }},
		{"wrong repo in SAN", func(o *fulcioCertOptions) {
			o.sanURI = "https://github.com/keithlinneman/linnemanlabs-web/.github/workflows/build.yml@refs/tags/v1.2.3"
		}},
		{"non-semver tag in SAN", func(o *fulcioCertOptions) {
			o.sanURI = "https://github.com/keithlinneman/linnemanlabs-site/.github/workflows/build.yml@refs/heads/main"
		}},
		{"wrong workflow trigger", func(o *fulcioCertOptions) { o.ghTrigger = "pull_request" }},
		{"wrong workflow repository", func(o *fulcioCertOptions) { o.ghRepository = "attacker/evil" }},
		{"wrong workflow name", func(o *fulcioCertOptions) { o.ghName = "Evil Workflow" }},
		{"missing workflow name", func(o *fulcioCertOptions) { o.ghName = "" }},
		{"missing issuer", func(o *fulcioCertOptions) { o.oidcIssuer = "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := contentMatchingOpts()
			tc.mutate(&opts)
			if err := checkContentIdentity(t, &opts); err == nil {
				t.Fatalf("identity %q should be rejected", tc.name)
			}
		})
	}
}

func TestCertIdentity_OnlyConfiguredCriteriaChecked(t *testing.T) {
	// An empty policy accepts any certificate identity.
	key := generateTestECKey(t, elliptic.P256())
	cert := newTestLeafCert(t, key, &fulcioCertOptions{sanURI: "https://example.com/whatever"})

	var empty CertIdentity
	if err := empty.Check(cert, certInfo(cert)); err != nil {
		t.Fatalf("empty policy should accept any identity: %v", err)
	}
}

// End-to-end: a KeylessVerifier with an Identity policy rejects a
// cryptographically-valid signature whose certificate identity does not match.
func TestKeylessVerifier_IdentityEnforced(t *testing.T) {
	artifact := []byte("content-bundle-bytes")

	matchOpts := contentMatchingOpts()
	matchKey := generateTestECKey(t, elliptic.P256())
	matchCert := newTestLeafCert(t, matchKey, &matchOpts)
	matchBundle := buildKeylessBundle(t, matchKey, matchCert, artifact, false)

	v := NewKeylessVerifier()
	v.SkipTrustRootChecks = true // synthetic bundles - no TSA/Rekor/SCT
	v.Identity = ContentCertIdentity()

	if err := v.VerifyBlob(t.Context(), matchBundle, artifact); err != nil {
		t.Fatalf("matching identity should verify: %v", err)
	}

	// valid signature, wrong identity (linnemanlabs-web rather than -site)
	wrongOpts := contentMatchingOpts()
	wrongOpts.sanURI = "https://github.com/keithlinneman/linnemanlabs-web/.github/workflows/build.yml@refs/tags/v1.2.3"
	wrongOpts.ghRepository = "keithlinneman/linnemanlabs-web"
	wrongKey := generateTestECKey(t, elliptic.P256())
	wrongCert := newTestLeafCert(t, wrongKey, &wrongOpts)
	wrongBundle := buildKeylessBundle(t, wrongKey, wrongCert, artifact, false)

	if err := v.VerifyBlob(t.Context(), wrongBundle, artifact); err == nil {
		t.Fatal("valid signature with wrong identity should be rejected")
	}
}

// appMatchingOpts is a leaf identity that satisfies EvidenceCertIdentity
// (the linnemanlabs-web release build).
func appMatchingOpts() fulcioCertOptions {
	return fulcioCertOptions{
		sanURI:       "https://github.com/keithlinneman/linnemanlabs-web/.github/workflows/build.yml@refs/tags/v1.2.3",
		oidcIssuer:   "https://token.actions.githubusercontent.com",
		ghTrigger:    "push",
		ghName:       "Build App",
		ghRepository: "keithlinneman/linnemanlabs-web",
	}
}

func TestEvidenceCertIdentity_Matches(t *testing.T) {
	opts := appMatchingOpts()
	key := generateTestECKey(t, elliptic.P256())
	cert := newTestLeafCert(t, key, &opts)
	if err := EvidenceCertIdentity().Check(cert, certInfo(cert)); err != nil {
		t.Fatalf("app identity should pass EvidenceCertIdentity: %v", err)
	}
}

// The content and evidence policies must be mutually exclusive: a cert minted
// for one repo's build must never satisfy the other's policy.
func TestCertIdentity_ContentAndEvidenceAreDistinct(t *testing.T) {
	key := generateTestECKey(t, elliptic.P256())

	contentOpts := contentMatchingOpts()
	contentCert := newTestLeafCert(t, key, &contentOpts)
	appOpts := appMatchingOpts()
	appCert := newTestLeafCert(t, key, &appOpts)

	if err := EvidenceCertIdentity().Check(contentCert, certInfo(contentCert)); err == nil {
		t.Fatal("EvidenceCertIdentity should reject the content (linnemanlabs-site) identity")
	}
	if err := ContentCertIdentity().Check(appCert, certInfo(appCert)); err == nil {
		t.Fatal("ContentCertIdentity should reject the app (linnemanlabs-web) identity")
	}
}
