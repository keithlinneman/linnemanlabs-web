package provenancehttp

type AppSummaryPolicyCompliance struct {
	Enforcement string `json:"enforcement"`

	SigningRequired  bool `json:"signing_required"`
	SigningSatisfied bool `json:"signing_satisfied"`

	SBOMRequired  bool `json:"sbom_required"`
	SBOMSatisfied bool `json:"sbom_satisfied"`

	ScanRequired  bool `json:"scan_required"`
	ScanSatisfied bool `json:"scan_satisfied"`

	LicenseRequired  bool `json:"license_required"`
	LicenseSatisfied bool `json:"license_satisfied"`

	ProvenanceRequired  bool `json:"provenance_required"`
	ProvenanceSatisfied bool `json:"provenance_satisfied"`

	VulnGating     []string `json:"vuln_gating,omitempty"`
	VulnGateResult string   `json:"vuln_gate_result,omitempty"`

	LicenseGating    bool `json:"license_gating"`
	LicenseCompliant bool `json:"license_compliant"`
}
