package evidence

import (
	"encoding/json"
	"sort"
	"strings"
)

// LicenseReport is the parsed form of a phxi.license_report.v1 evidence file.
// These are produced by the build system from CycloneDX SBOMs and contain
// per-package license information plus aggregate summaries.
type LicenseReport struct {
	Schema        string               `json:"schema"`
	PredicateType string               `json:"predicate_type"`
	GeneratedAt   string               `json:"generated_at"`
	Scope         string               `json:"scope"` // "source" or "artifacts"
	Component     string               `json:"component"`
	Input         LicenseReportInput   `json:"input"`
	Summary       LicenseReportSummary `json:"summary"`
	Items         []LicenseReportItem  `json:"items"`
}

// LicenseReportInput describes which SBOM was used as input
type LicenseReportInput struct {
	SBOM *LicenseReportSBOMRef `json:"sbom,omitempty"`
}

// LicenseReportSBOMRef is the SBOM reference in the license report input
type LicenseReportSBOMRef struct {
	Path     string            `json:"path"`
	Hashes   map[string]string `json:"hashes"`
	Size     int64             `json:"size"`
	Format   string            `json:"format"`
	Producer string            `json:"producer"`
}

// LicenseReportSummary is the aggregate license info from the report
type LicenseReportSummary struct {
	ItemsTotal      int                 `json:"items_total"`
	WithLicenses    int                 `json:"with_licenses"`
	WithoutLicenses int                 `json:"without_licenses"`
	UniqueLicenses  int                 `json:"unique_licenses"`
	ByLicense       []LicenseCountEntry `json:"by_license"`
}

// LicenseCountEntry is a license -> count pair from the report summary
type LicenseCountEntry struct {
	License string `json:"license"`
	Count   int    `json:"count"`
}

// LicenseReportItem is a single package entry from the license report
type LicenseReportItem struct {
	BomRef   string   `json:"bom_ref"`
	Type     string   `json:"type"` // "application" or "library"
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Purl     string   `json:"purl"`
	Licenses []string `json:"licenses"`
}

// ParseLicenseReport parses a phxi.license_report.v1 JSON file.
// Returns nil if the data is empty or unparseable.
func ParseLicenseReport(data []byte) (*LicenseReport, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var r LicenseReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// LicenseStatus is the evaluated compliance status for a single license
type LicenseStatus string

const (
	LicenseAllowed LicenseStatus = "allowed"
	LicenseDenied  LicenseStatus = "denied"
	LicenseUnknown LicenseStatus = "unknown"
)

// PackageInfo is the API-facing per-package license entry
type PackageInfo struct {
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	License       string        `json:"license"`
	LicenseStatus LicenseStatus `json:"license_status"`
	Ecosystem     string        `json:"ecosystem"`
}

// LicenseEvaluator computes license_status for packages against the build policy.
// Holds pre-processed denied patterns and allowed set for efficient evaluation.
type LicenseEvaluator struct {
	denied       []string // SPDX patterns from policy (e.g. "GPL-*", "AGPL-*")
	allowed      map[string]bool
	hasAllowList bool
	allowUnknown bool
}

// NewLicenseEvaluator creates an evaluator from parsed policy.
// If policy is nil or has no license rules, all known licenses are allowed.
func NewLicenseEvaluator(policy *ReleasePolicy) *LicenseEvaluator {
	e := &LicenseEvaluator{}

	if policy == nil {
		return e
	}

	e.denied = policy.License.Denied
	e.allowUnknown = policy.License.AllowUnknown

	if len(policy.License.Allowed) > 0 {
		e.hasAllowList = true
		e.allowed = make(map[string]bool, len(policy.License.Allowed))
		for _, a := range policy.License.Allowed {
			e.allowed[a] = true
		}
	}

	return e
}

// Evaluate returns the license_status for a single license string.
//   - empty license → "unknown"
//   - matches denied pattern → "denied"
//   - allowed list exists and license not in it → "denied"
//   - otherwise → "allowed"
func (e *LicenseEvaluator) Evaluate(license string) LicenseStatus {
	if license == "" {
		return LicenseUnknown
	}

	// check denied patterns
	for _, pattern := range e.denied {
		if matchLicensePattern(pattern, license) {
			return LicenseDenied
		}
	}

	// if there's an explicit allow-list, license must be in it
	if e.hasAllowList && !e.allowed[license] {
		return LicenseDenied
	}

	return LicenseAllowed
}

// matchLicensePattern does simple glob matching for SPDX license patterns.
// Supports trailing wildcard only (e.g. "GPL-*" matches "GPL-3.0-only").
func matchLicensePattern(pattern, license string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(license, prefix)
	}
	return pattern == license
}

// BuildPackageList parses a license report and evaluates each package against policy.
// Returns the sorted package list and license_counts map.
// The package list is sorted alphabetically by name.
func BuildPackageList(report *LicenseReport, eval *LicenseEvaluator) ([]PackageInfo, map[string]int) {
	if report == nil {
		return nil, nil
	}

	packages := make([]PackageInfo, 0, len(report.Items))
	for _, item := range report.Items {
		// determine the single license string for the API
		// most Go packages have exactly one; if multiple, join with " AND "
		license := ""
		if len(item.Licenses) == 1 {
			license = item.Licenses[0]
		} else if len(item.Licenses) > 1 {
			license = strings.Join(item.Licenses, " AND ")
		}

		// evaluate status — if multiple licenses, evaluate each and take worst
		status := eval.Evaluate(license)
		if len(item.Licenses) > 1 {
			for _, lic := range item.Licenses {
				s := eval.Evaluate(lic)
				if s == LicenseDenied {
					status = LicenseDenied
					break
				}
				if s == LicenseUnknown && status == LicenseAllowed {
					status = LicenseUnknown
				}
			}
		}

		// detect ecosystem from purl scheme
		ecosystem := detectEcosystem(item.Purl)

		packages = append(packages, PackageInfo{
			Name:          item.Name,
			Version:       item.Version,
			License:       license,
			LicenseStatus: status,
			Ecosystem:     ecosystem,
		})
	}

	// sort alphabetically by name
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name < packages[j].Name
	})

	// build license_counts from the report summary (already aggregated by build system)
	var licenseCounts map[string]int
	if len(report.Summary.ByLicense) > 0 {
		licenseCounts = make(map[string]int, len(report.Summary.ByLicense))
		for _, entry := range report.Summary.ByLicense {
			licenseCounts[entry.License] = entry.Count
		}
	}

	return packages, licenseCounts
}

// detectEcosystem infers the package ecosystem from a purl string.
// e.g. "pkg:golang/..." → "go", "pkg:npm/..." → "npm"
func detectEcosystem(purl string) string {
	if purl == "" {
		return ""
	}
	// purl format: pkg:<type>/...
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	rest := purl[len(prefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return ""
	}
	typ := rest[:slash]

	// normalize common purl types to friendly names
	switch typ {
	case "golang":
		return "go"
	case "npm":
		return "npm"
	case "pypi":
		return "python"
	case "maven":
		return "java"
	case "nuget":
		return "dotnet"
	case "cargo":
		return "rust"
	case "gem":
		return "ruby"
	default:
		return typ
	}
}
