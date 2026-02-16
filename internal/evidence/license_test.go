package evidence

import (
	"testing"
)

// ParseLicenseReport

func TestParseLicenseReport_Empty(t *testing.T) {
	r, err := ParseLicenseReport(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Fatal("expected nil report for nil input")
	}

	r, err = ParseLicenseReport([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Fatal("expected nil report for empty input")
	}
}

func TestParseLicenseReport_InvalidJSON(t *testing.T) {
	_, err := ParseLicenseReport([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseLicenseReport_Valid(t *testing.T) {
	raw := []byte(`{
		"schema": "phxi.license_report.v1",
		"predicate_type": "https://phxi.io/license-report/v1",
		"generated_at": "2026-02-01T12:00:00Z",
		"scope": "source",
		"component": "linnemanlabs-web",
		"summary": {
			"items_total": 3,
			"with_licenses": 2,
			"without_licenses": 1,
			"unique_licenses": 2,
			"by_license": [
				{"license": "MIT", "count": 1},
				{"license": "Apache-2.0", "count": 1}
			]
		},
		"items": [
			{"bom_ref": "ref1", "type": "library", "name": "pkg-a", "version": "1.0.0", "purl": "pkg:golang/example.com/pkg-a@v1.0.0", "licenses": ["MIT"]},
			{"bom_ref": "ref2", "type": "library", "name": "pkg-b", "version": "2.0.0", "purl": "pkg:golang/example.com/pkg-b@v2.0.0", "licenses": ["Apache-2.0"]},
			{"bom_ref": "ref3", "type": "library", "name": "pkg-c", "version": "0.1.0", "purl": "pkg:golang/example.com/pkg-c@v0.1.0", "licenses": []}
		]
	}`)

	r, err := ParseLicenseReport(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil report")
	}
	if r.Schema != "phxi.license_report.v1" {
		t.Fatalf("Schema = %q", r.Schema)
	}
	if r.Scope != "source" {
		t.Fatalf("Scope = %q", r.Scope)
	}
	if r.Summary.ItemsTotal != 3 {
		t.Fatalf("Summary.ItemsTotal = %d", r.Summary.ItemsTotal)
	}
	if r.Summary.WithLicenses != 2 {
		t.Fatalf("Summary.WithLicenses = %d", r.Summary.WithLicenses)
	}
	if r.Summary.WithoutLicenses != 1 {
		t.Fatalf("Summary.WithoutLicenses = %d", r.Summary.WithoutLicenses)
	}
	if len(r.Summary.ByLicense) != 2 {
		t.Fatalf("Summary.ByLicense length = %d", len(r.Summary.ByLicense))
	}
	if len(r.Items) != 3 {
		t.Fatalf("Items length = %d", len(r.Items))
	}
	if r.Items[0].Name != "pkg-a" || r.Items[0].Purl != "pkg:golang/example.com/pkg-a@v1.0.0" {
		t.Fatalf("Items[0] = %+v", r.Items[0])
	}
}

// matchLicensePattern

func TestMatchLicensePattern(t *testing.T) {
	tests := []struct {
		pattern string
		license string
		want    bool
	}{
		// exact match
		{"MIT", "MIT", true},
		{"MIT", "Apache-2.0", false},
		{"Apache-2.0", "Apache-2.0", true},

		// wildcard
		{"GPL-*", "GPL-3.0-only", true},
		{"GPL-*", "GPL-2.0-or-later", true},
		{"GPL-*", "MIT", false},
		{"AGPL-*", "AGPL-3.0-only", true},
		{"AGPL-*", "GPL-3.0-only", false},

		// wildcard with empty prefix
		{"*", "anything", true},
		{"*", "", true},

		// exact match with no wildcard
		{"GPL-3.0-only", "GPL-3.0-only", true},
		{"GPL-3.0-only", "GPL-3.0-or-later", false},

		// empty
		{"", "", true},
		{"", "MIT", false},
	}

	for _, tt := range tests {
		got := matchLicensePattern(tt.pattern, tt.license)
		if got != tt.want {
			t.Fatalf("matchLicensePattern(%q, %q) = %v, want %v", tt.pattern, tt.license, got, tt.want)
		}
	}
}

// LicenseEvaluator
func TestLicenseEvaluator_NilPolicy(t *testing.T) {
	eval := NewLicenseEvaluator(nil)

	if s := eval.Evaluate("MIT"); s != LicenseAllowed {
		t.Fatalf("Evaluate('MIT') = %q, want allowed", s)
	}
	if s := eval.Evaluate(""); s != LicenseUnknown {
		t.Fatalf("Evaluate('') = %q, want unknown", s)
	}
}

func TestLicenseEvaluator_EmptyPolicy(t *testing.T) {
	eval := NewLicenseEvaluator(&ReleasePolicy{})

	if s := eval.Evaluate("MIT"); s != LicenseAllowed {
		t.Fatalf("Evaluate('MIT') = %q, want allowed with empty policy", s)
	}
}

func TestLicenseEvaluator_DenyList(t *testing.T) {
	policy := &ReleasePolicy{
		License: PolicyLicense{
			Denied: []string{"GPL-*", "AGPL-*", "SSPL-1.0"},
		},
	}
	eval := NewLicenseEvaluator(policy)

	tests := []struct {
		license string
		want    LicenseStatus
	}{
		{"MIT", LicenseAllowed},
		{"Apache-2.0", LicenseAllowed},
		{"GPL-3.0-only", LicenseDenied},
		{"GPL-2.0-or-later", LicenseDenied},
		{"AGPL-3.0-only", LicenseDenied},
		{"SSPL-1.0", LicenseDenied},
		{"ISC", LicenseAllowed},
		{"", LicenseUnknown},
	}

	for _, tt := range tests {
		got := eval.Evaluate(tt.license)
		if got != tt.want {
			t.Fatalf("Evaluate(%q) = %q, want %q", tt.license, got, tt.want)
		}
	}
}

func TestLicenseEvaluator_AllowList(t *testing.T) {
	policy := &ReleasePolicy{
		License: PolicyLicense{
			Allowed: []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"},
		},
	}
	eval := NewLicenseEvaluator(policy)

	tests := []struct {
		license string
		want    LicenseStatus
	}{
		{"MIT", LicenseAllowed},
		{"Apache-2.0", LicenseAllowed},
		{"BSD-3-Clause", LicenseAllowed},
		{"ISC", LicenseAllowed},
		{"GPL-3.0-only", LicenseDenied}, // not in allow list
		{"MPL-2.0", LicenseDenied},      // not in allow list
		{"", LicenseUnknown},
	}

	for _, tt := range tests {
		got := eval.Evaluate(tt.license)
		if got != tt.want {
			t.Fatalf("Evaluate(%q) = %q, want %q", tt.license, got, tt.want)
		}
	}
}

func TestLicenseEvaluator_DenyTakesPrecedenceOverAllow(t *testing.T) {
	// License is in both deny and allow — deny should win
	policy := &ReleasePolicy{
		License: PolicyLicense{
			Denied:  []string{"MIT"},
			Allowed: []string{"MIT", "Apache-2.0"},
		},
	}
	eval := NewLicenseEvaluator(policy)

	if s := eval.Evaluate("MIT"); s != LicenseDenied {
		t.Fatalf("Evaluate('MIT') = %q, want denied (deny takes precedence)", s)
	}
	if s := eval.Evaluate("Apache-2.0"); s != LicenseAllowed {
		t.Fatalf("Evaluate('Apache-2.0') = %q, want allowed", s)
	}
}

func TestLicenseEvaluator_AllowUnknown(t *testing.T) {
	// allowUnknown doesn't affect the evaluator directly — it's a policy flag
	// the evaluator returns "unknown" for empty licenses regardless
	policy := &ReleasePolicy{
		License: PolicyLicense{
			AllowUnknown: true,
		},
	}
	eval := NewLicenseEvaluator(policy)

	if s := eval.Evaluate(""); s != LicenseUnknown {
		t.Fatalf("Evaluate('') = %q, want unknown", s)
	}
	if s := eval.Evaluate("MIT"); s != LicenseAllowed {
		t.Fatalf("Evaluate('MIT') = %q, want allowed", s)
	}
}

// detectEcosystem

func TestDetectEcosystem(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"pkg:golang/example.com/pkg@v1.0.0", "go"},
		{"pkg:npm/%40scope/pkg@1.0.0", "npm"},
		{"pkg:pypi/requests@2.28.0", "python"},
		{"pkg:maven/org.apache/commons@1.0", "java"},
		{"pkg:nuget/Newtonsoft.Json@13.0.0", "dotnet"},
		{"pkg:cargo/serde@1.0.0", "rust"},
		{"pkg:gem/rails@7.0.0", "ruby"},

		// unknown type passes through
		{"pkg:conan/boost@1.80.0", "conan"},
		{"pkg:deb/ubuntu/openssl@3.0.0", "deb"},

		// edge cases
		{"", ""},
		{"not-a-purl", ""},
		{"pkg:", ""},       // no type/slash
		{"pkg:golang", ""}, // no slash after type
	}

	for _, tt := range tests {
		got := detectEcosystem(tt.purl)
		if got != tt.want {
			t.Fatalf("detectEcosystem(%q) = %q, want %q", tt.purl, got, tt.want)
		}
	}
}

// BuildPackageList

func TestBuildPackageList_NilReport(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	pkgs, counts := BuildPackageList(nil, eval)
	if pkgs != nil {
		t.Fatal("expected nil packages for nil report")
	}
	if counts != nil {
		t.Fatal("expected nil counts for nil report")
	}
}

func TestBuildPackageList_EmptyReport(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{}
	pkgs, counts := BuildPackageList(report, eval)
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(pkgs))
	}
	if counts != nil {
		t.Fatalf("expected nil counts for empty summary, got %v", counts)
	}
}

func TestBuildPackageList_SingleLicense(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{
		Items: []LicenseReportItem{
			{Name: "pkg-a", Version: "1.0.0", Purl: "pkg:golang/example.com/pkg-a@v1.0.0", Licenses: []string{"MIT"}},
		},
	}
	pkgs, _ := BuildPackageList(report, eval)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].License != "MIT" {
		t.Fatalf("License = %q, want MIT", pkgs[0].License)
	}
	if pkgs[0].LicenseStatus != LicenseAllowed {
		t.Fatalf("LicenseStatus = %q, want allowed", pkgs[0].LicenseStatus)
	}
	if pkgs[0].Ecosystem != "go" {
		t.Fatalf("Ecosystem = %q, want go", pkgs[0].Ecosystem)
	}
}

func TestBuildPackageList_MultipleLicenses_JoinedWithAND(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{
		Items: []LicenseReportItem{
			{Name: "dual", Version: "1.0.0", Licenses: []string{"MIT", "Apache-2.0"}},
		},
	}
	pkgs, _ := BuildPackageList(report, eval)
	if pkgs[0].License != "MIT AND Apache-2.0" {
		t.Fatalf("License = %q, want 'MIT AND Apache-2.0'", pkgs[0].License)
	}
}

func TestBuildPackageList_MultipleLicenses_DeniedWins(t *testing.T) {
	policy := &ReleasePolicy{
		License: PolicyLicense{
			Denied: []string{"GPL-*"},
		},
	}
	eval := NewLicenseEvaluator(policy)
	report := &LicenseReport{
		Items: []LicenseReportItem{
			{Name: "mixed", Version: "1.0.0", Licenses: []string{"MIT", "GPL-3.0-only"}},
		},
	}
	pkgs, _ := BuildPackageList(report, eval)
	if pkgs[0].LicenseStatus != LicenseDenied {
		t.Fatalf("LicenseStatus = %q, want denied (one of the licenses is denied)", pkgs[0].LicenseStatus)
	}
}

func TestBuildPackageList_MultipleLicenses_UnknownEscalates(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{
		Items: []LicenseReportItem{
			// One real license, one empty — the empty evaluates as unknown
			// but the multi-license path checks individual licenses
			{Name: "partial", Version: "1.0.0", Licenses: []string{"MIT", ""}},
		},
	}
	pkgs, _ := BuildPackageList(report, eval)
	if pkgs[0].LicenseStatus != LicenseUnknown {
		t.Fatalf("LicenseStatus = %q, want unknown (empty license in multi-license)", pkgs[0].LicenseStatus)
	}
}

func TestBuildPackageList_NoLicenses(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{
		Items: []LicenseReportItem{
			{Name: "unlicensed", Version: "0.1.0", Licenses: []string{}},
		},
	}
	pkgs, _ := BuildPackageList(report, eval)
	if pkgs[0].License != "" {
		t.Fatalf("License = %q, want empty", pkgs[0].License)
	}
	if pkgs[0].LicenseStatus != LicenseUnknown {
		t.Fatalf("LicenseStatus = %q, want unknown", pkgs[0].LicenseStatus)
	}
}

func TestBuildPackageList_SortedAlphabetically(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{
		Items: []LicenseReportItem{
			{Name: "zeta", Version: "1.0.0", Licenses: []string{"MIT"}},
			{Name: "alpha", Version: "1.0.0", Licenses: []string{"MIT"}},
			{Name: "mu", Version: "1.0.0", Licenses: []string{"MIT"}},
		},
	}
	pkgs, _ := BuildPackageList(report, eval)
	if pkgs[0].Name != "alpha" || pkgs[1].Name != "mu" || pkgs[2].Name != "zeta" {
		t.Fatalf("packages not sorted: %q, %q, %q", pkgs[0].Name, pkgs[1].Name, pkgs[2].Name)
	}
}

func TestBuildPackageList_LicenseCounts(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{
		Summary: LicenseReportSummary{
			ByLicense: []LicenseCountEntry{
				{License: "MIT", Count: 45},
				{License: "Apache-2.0", Count: 12},
				{License: "BSD-3-Clause", Count: 5},
			},
		},
		Items: []LicenseReportItem{
			{Name: "pkg-a", Version: "1.0.0", Licenses: []string{"MIT"}},
		},
	}
	_, counts := BuildPackageList(report, eval)
	if counts == nil {
		t.Fatal("expected non-nil counts")
	}
	if counts["MIT"] != 45 {
		t.Fatalf("counts[MIT] = %d, want 45", counts["MIT"])
	}
	if counts["Apache-2.0"] != 12 {
		t.Fatalf("counts[Apache-2.0] = %d, want 12", counts["Apache-2.0"])
	}
	if counts["BSD-3-Clause"] != 5 {
		t.Fatalf("counts[BSD-3-Clause] = %d, want 5", counts["BSD-3-Clause"])
	}
}

func TestBuildPackageList_NoByLicense_NilCounts(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{
		Summary: LicenseReportSummary{
			ByLicense: nil,
		},
		Items: []LicenseReportItem{
			{Name: "pkg-a", Version: "1.0.0", Licenses: []string{"MIT"}},
		},
	}
	_, counts := BuildPackageList(report, eval)
	if counts != nil {
		t.Fatalf("expected nil counts when ByLicense is nil, got %v", counts)
	}
}

func TestBuildPackageList_EcosystemDetection(t *testing.T) {
	eval := NewLicenseEvaluator(nil)
	report := &LicenseReport{
		Items: []LicenseReportItem{
			{Name: "go-pkg", Version: "1.0.0", Purl: "pkg:golang/example.com/go-pkg@v1.0.0", Licenses: []string{"MIT"}},
			{Name: "npm-pkg", Version: "2.0.0", Purl: "pkg:npm/npm-pkg@2.0.0", Licenses: []string{"MIT"}},
			{Name: "no-purl", Version: "3.0.0", Purl: "", Licenses: []string{"MIT"}},
		},
	}
	pkgs, _ := BuildPackageList(report, eval)

	// sorted: go-pkg, no-purl, npm-pkg
	if pkgs[0].Ecosystem != "go" {
		t.Fatalf("go-pkg ecosystem = %q, want go", pkgs[0].Ecosystem)
	}
	if pkgs[1].Ecosystem != "" {
		t.Fatalf("no-purl ecosystem = %q, want empty", pkgs[1].Ecosystem)
	}
	if pkgs[2].Ecosystem != "npm" {
		t.Fatalf("npm-pkg ecosystem = %q, want npm", pkgs[2].Ecosystem)
	}
}

func TestBuildPackageList_WithDenyPolicy(t *testing.T) {
	policy := &ReleasePolicy{
		License: PolicyLicense{
			Denied: []string{"GPL-*", "AGPL-*"},
		},
	}
	eval := NewLicenseEvaluator(policy)
	report := &LicenseReport{
		Items: []LicenseReportItem{
			{Name: "allowed-pkg", Version: "1.0.0", Licenses: []string{"MIT"}},
			{Name: "denied-pkg", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}},
			{Name: "unknown-pkg", Version: "1.0.0", Licenses: []string{}},
		},
	}
	pkgs, _ := BuildPackageList(report, eval)

	// sorted: allowed-pkg, denied-pkg, unknown-pkg
	if pkgs[0].LicenseStatus != LicenseAllowed {
		t.Fatalf("allowed-pkg status = %q", pkgs[0].LicenseStatus)
	}
	if pkgs[1].LicenseStatus != LicenseDenied {
		t.Fatalf("denied-pkg status = %q", pkgs[1].LicenseStatus)
	}
	if pkgs[2].LicenseStatus != LicenseUnknown {
		t.Fatalf("unknown-pkg status = %q", pkgs[2].LicenseStatus)
	}
}

// ParseLicenseReport round-trip with BuildPackageList

func TestParseLicenseReport_IntoPackageList(t *testing.T) {
	raw := []byte(`{
		"schema": "phxi.license_report.v1",
		"scope": "source",
		"summary": {
			"items_total": 2,
			"with_licenses": 2,
			"without_licenses": 0,
			"unique_licenses": 2,
			"by_license": [
				{"license": "MIT", "count": 1},
				{"license": "BSD-3-Clause", "count": 1}
			]
		},
		"items": [
			{"name": "zlib", "version": "1.2.13", "purl": "pkg:golang/example.com/zlib@v1.2.13", "licenses": ["MIT"]},
			{"name": "acme", "version": "0.5.0", "purl": "pkg:golang/example.com/acme@v0.5.0", "licenses": ["BSD-3-Clause"]}
		]
	}`)

	report, err := ParseLicenseReport(raw)
	if err != nil {
		t.Fatalf("ParseLicenseReport: %v", err)
	}

	policy := &ReleasePolicy{
		License: PolicyLicense{
			Allowed: []string{"MIT", "BSD-3-Clause", "Apache-2.0"},
		},
	}
	eval := NewLicenseEvaluator(policy)
	pkgs, counts := BuildPackageList(report, eval)

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	// sorted: acme, zlib
	if pkgs[0].Name != "acme" || pkgs[1].Name != "zlib" {
		t.Fatalf("unexpected order: %q, %q", pkgs[0].Name, pkgs[1].Name)
	}
	if pkgs[0].LicenseStatus != LicenseAllowed || pkgs[1].LicenseStatus != LicenseAllowed {
		t.Fatal("expected all allowed")
	}
	if counts["MIT"] != 1 || counts["BSD-3-Clause"] != 1 {
		t.Fatalf("unexpected counts: %v", counts)
	}
}
