package cryptoutil

import (
	"crypto/x509"
	"regexp"

	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

// CertIdentity is a CertIdentityPolicy that asserts a keyless signing
// certificate matches an expected identity, mirroring cosign verify-blob's
// --certificate-* flags. Every non-empty criterion must match; an empty field
// is not checked. A configured criterion whose certificate value is missing is
// a rejection.
type CertIdentity struct {
	// Issuer is the exact expected OIDC issuer (--certificate-oidc-issuer).
	Issuer string

	// IdentityRegexp must match at least one certificate SAN
	// (--certificate-identity-regexp).
	IdentityRegexp *regexp.Regexp

	// Deprecated GitHub-workflow extension matchers
	// (--certificate-github-workflow-*), exact match.
	GitHubWorkflowTrigger    string
	GitHubWorkflowRepository string
	GitHubWorkflowName       string
}

// Check reports whether the certificate identity satisfies the policy. The
// cert is accepted via the parsed CertInfo; the raw certificate is available
// for future trust-root / chain checks.
func (c *CertIdentity) Check(_ *x509.Certificate, info *CertInfo) error {
	if c.Issuer != "" && info.OIDCIssuer != c.Issuer {
		return xerrors.Newf("certificate OIDC issuer %q does not match expected %q", info.OIDCIssuer, c.Issuer)
	}

	if c.IdentityRegexp != nil && !c.matchesAnySAN(info.SANs) {
		return xerrors.Newf("no certificate SAN %v matches identity %q", info.SANs, c.IdentityRegexp.String())
	}

	if c.GitHubWorkflowTrigger != "" && info.GitHubWorkflowTrigger != c.GitHubWorkflowTrigger {
		return xerrors.Newf("certificate github workflow trigger %q does not match expected %q",
			info.GitHubWorkflowTrigger, c.GitHubWorkflowTrigger)
	}
	if c.GitHubWorkflowRepository != "" && info.GitHubWorkflowRepository != c.GitHubWorkflowRepository {
		return xerrors.Newf("certificate github workflow repository %q does not match expected %q",
			info.GitHubWorkflowRepository, c.GitHubWorkflowRepository)
	}
	if c.GitHubWorkflowName != "" && info.GitHubWorkflowName != c.GitHubWorkflowName {
		return xerrors.Newf("certificate github workflow name %q does not match expected %q",
			info.GitHubWorkflowName, c.GitHubWorkflowName)
	}

	return nil
}

func (c *CertIdentity) matchesAnySAN(sans []string) bool {
	for _, san := range sans {
		if c.IdentityRegexp.MatchString(san) {
			return true
		}
	}
	return false
}

// githubReleaseIdentity builds the trusted-signer policy for a GitHub Actions
// release: a keyless signature produced by {repo}'s {workflowFile} workflow
// (named {workflowName}) on a `push` to a strict-semver tag, via the GitHub
// OIDC issuer. The SAN regexp is assembled from compile-time literals
// (QuoteMeta on the repo/file so dots etc. are literal), so MustCompile is safe
// — a malformed pattern fails immediately under test. These policies are
// hardcoded (not env-configurable) so the trust policy cannot be weakened at
// runtime.
func githubReleaseIdentity(repo, workflowFile, workflowName string) *CertIdentity {
	re := regexp.MustCompile(`^https://github\.com/` + regexp.QuoteMeta(repo) +
		`/\.github/workflows/` + regexp.QuoteMeta(workflowFile) +
		`@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`)
	return &CertIdentity{
		Issuer:                   "https://token.actions.githubusercontent.com",
		IdentityRegexp:           re,
		GitHubWorkflowTrigger:    "push",
		GitHubWorkflowRepository: repo,
		GitHubWorkflowName:       workflowName,
	}
}

// ContentCertIdentity is the trusted signer for content bundles: the
// linnemanlabs-site build workflow.
func ContentCertIdentity() *CertIdentity {
	return githubReleaseIdentity("keithlinneman/linnemanlabs-site", "build.yml", "Build Site")
}

// EvidenceCertIdentity is the trusted signer for this app's release evidence
// (release.json): the linnemanlabs-web build workflow.
func EvidenceCertIdentity() *CertIdentity {
	return githubReleaseIdentity("keithlinneman/linnemanlabs-web", "build.yml", "Build App")
}
