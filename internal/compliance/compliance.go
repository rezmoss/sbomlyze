// Package compliance evaluates SBOM completeness against recognized standards:
// NTIA Minimum Elements, CISA FSCT-3, and BSI TR-03183-2.
package compliance

import (
	"fmt"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// Standard identifies a compliance framework.
type Standard string

const (
	StandardNTIA Standard = "NTIA"
	StandardCISA Standard = "CISA"
	StandardBSI  Standard = "BSI-TR-03183"
)

// CheckResult holds the result of a single compliance check.
type CheckResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	Details     string `json:"details,omitempty"`
}

// FrameworkResult holds all check results for one standard.
type FrameworkResult struct {
	Standard Standard      `json:"standard"`
	Score    int           `json:"score"`     // 0-100 percentage
	MaxScore int           `json:"max_score"` // always 100
	Passed   int           `json:"passed"`
	Total    int           `json:"total"`
	Checks   []CheckResult `json:"checks"`
}

// Report holds compliance results across all standards.
type Report struct {
	NTIA    *FrameworkResult `json:"ntia,omitempty"`
	CISA    *FrameworkResult `json:"cisa,omitempty"`
	BSI     *FrameworkResult `json:"bsi_tr03183,omitempty"`
	Overall int              `json:"overall_score"` // average across evaluated standards
}

// Evaluate checks SBOM completeness against all three standards and returns a Report.
func Evaluate(comps []sbom.Component, info sbom.SBOMInfo) Report {
	report := Report{
		NTIA: evaluateNTIA(comps, info),
		CISA: evaluateCISA(comps, info),
		BSI:  evaluateBSI(comps, info),
	}

	var sum int
	var count int
	if report.NTIA != nil {
		sum += report.NTIA.Score
		count++
	}
	if report.CISA != nil {
		sum += report.CISA.Score
		count++
	}
	if report.BSI != nil {
		sum += report.BSI.Score
		count++
	}
	if count > 0 {
		report.Overall = sum / count
	}

	return report
}

// --- NTIA Minimum Elements (2021) ---
// 7 required fields: Supplier, Component Name, Version, Other Unique Identifiers,
// Dependency Relationship, Author of SBOM Data, Timestamp.

func evaluateNTIA(comps []sbom.Component, info sbom.SBOMInfo) *FrameworkResult {
	if len(comps) == 0 {
		return nil
	}

	total := len(comps)

	// Component-level checks (percentage of components passing)
	withName := countWith(comps, func(c sbom.Component) bool { return c.Name != "" })
	withVersion := countWith(comps, func(c sbom.Component) bool { return c.Version != "" })
	withSupplier := countWith(comps, func(c sbom.Component) bool { return c.Supplier != "" })
	withUniqueID := countWith(comps, func(c sbom.Component) bool {
		return c.PURL != "" || len(c.CPEs) > 0 || c.BOMRef != "" || c.SPDXID != ""
	})
	// SBOM-level checks (boolean)
	hasAuthor := info.SBOMAuthor != "" || info.ToolName != ""
	hasTimestamp := info.SBOMTimestamp != ""

	checks := []CheckResult{
		componentCheck("ntia-name", "Component Name",
			"NTIA requires a component name for each entry (NTIA Minimum Elements §2.2)",
			withName, total),
		componentCheck("ntia-version", "Component Version",
			"NTIA requires a version identifier for each component (NTIA Minimum Elements §2.3)",
			withVersion, total),
		componentCheck("ntia-supplier", "Supplier Name",
			"NTIA requires the supplier/author name for each component (NTIA Minimum Elements §2.1)",
			withSupplier, total),
		componentCheck("ntia-unique-id", "Other Unique Identifiers",
			"NTIA requires additional identifiers (PURL, CPE, etc.) for lookups (NTIA Minimum Elements §2.4)",
			withUniqueID, total),
		sbomCheck("ntia-dep-relation", "Dependency Relationship",
			"NTIA requires dependency relationships to be described (NTIA Minimum Elements §2.5)",
			hasAnyDependency(comps), sbomDepSummary(comps)),
		sbomCheck("ntia-author", "SBOM Author",
			"NTIA requires identifying the entity that created the SBOM (NTIA Minimum Elements §2.6)",
			hasAuthor, authorValue(info)),
		sbomCheck("ntia-timestamp", "SBOM Timestamp",
			"NTIA requires a timestamp for when the SBOM was assembled (NTIA Minimum Elements §2.7)",
			hasTimestamp, info.SBOMTimestamp),
	}

	return buildFrameworkResult(StandardNTIA, checks)
}

// --- CISA FSCT-3 / 2025 Minimum Elements ---
// Builds on NTIA with tighter requirements: richer identity (PURL preferred),
// license information, hashes for integrity, and SBOM-level metadata.

func evaluateCISA(comps []sbom.Component, info sbom.SBOMInfo) *FrameworkResult {
	if len(comps) == 0 {
		return nil
	}

	total := len(comps)

	withName := countWith(comps, func(c sbom.Component) bool { return c.Name != "" })
	withVersion := countWith(comps, func(c sbom.Component) bool { return c.Version != "" })
	withSupplier := countWith(comps, func(c sbom.Component) bool { return c.Supplier != "" })
	withUniqueID := countWith(comps, func(c sbom.Component) bool {
		return c.PURL != "" || len(c.CPEs) > 0 || c.BOMRef != "" || c.SPDXID != ""
	})
	withPURL := countWith(comps, func(c sbom.Component) bool { return c.PURL != "" })
	withLicense := countWith(comps, func(c sbom.Component) bool { return len(c.Licenses) > 0 })
	withHash := countWith(comps, func(c sbom.Component) bool { return len(c.Hashes) > 0 })
	withCPE := countWith(comps, func(c sbom.Component) bool { return len(c.CPEs) > 0 })

	hasAuthor := info.SBOMAuthor != "" || info.ToolName != ""
	hasTimestamp := info.SBOMTimestamp != ""

	checks := []CheckResult{
		componentCheck("cisa-name", "Component Name",
			"CISA requires a component name for each entry",
			withName, total),
		componentCheck("cisa-version", "Component Version",
			"CISA requires a version identifier for each component",
			withVersion, total),
		componentCheck("cisa-supplier", "Supplier Name",
			"CISA requires supplier identification for each component",
			withSupplier, total),
		componentCheck("cisa-unique-id", "Unique Identifiers",
			"CISA requires additional identifiers for vulnerability lookups",
			withUniqueID, total),
		sbomCheck("cisa-dep-relation", "Dependency Relationship",
			"CISA requires dependency relationships to be described",
			hasAnyDependency(comps), sbomDepSummary(comps)),
		componentCheck("cisa-purl", "Package URL (PURL)",
			"CISA strongly recommends PURLs for precise component identification (CISA 2025 §3.1)",
			withPURL, total),
		componentCheck("cisa-license", "License Information",
			"CISA recommends license data for compliance and risk assessment (CISA 2025 §3.2)",
			withLicense, total),
		componentCheck("cisa-hash", "Integrity Hashes",
			"CISA recommends cryptographic hashes for tamper detection (CISA 2025 §3.3)",
			withHash, total),
		componentCheck("cisa-cpe", "CPE Identifiers",
			"CISA recommends CPEs for vulnerability database correlation (CISA 2025 §3.4)",
			withCPE, total),
		sbomCheck("cisa-author", "SBOM Author",
			"CISA requires identifying the entity that created the SBOM",
			hasAuthor, authorValue(info)),
		sbomCheck("cisa-timestamp", "SBOM Timestamp",
			"CISA requires a timestamp for SBOM assembly",
			hasTimestamp, info.SBOMTimestamp),
	}

	return buildFrameworkResult(StandardCISA, checks)
}

// --- BSI TR-03183-2 ---
// Strictest standard: requires SHA-512 hashes, SPDX license identifiers,
// component creator contact, filename, dependency completeness flag,
// and binary properties (executable, archive, structured).

func evaluateBSI(comps []sbom.Component, info sbom.SBOMInfo) *FrameworkResult {
	if len(comps) == 0 {
		return nil
	}

	total := len(comps)

	withName := countWith(comps, func(c sbom.Component) bool { return c.Name != "" })
	withVersion := countWith(comps, func(c sbom.Component) bool { return c.Version != "" })
	withSupplier := countWith(comps, func(c sbom.Component) bool { return c.Supplier != "" })
	withUniqueID := countWith(comps, func(c sbom.Component) bool {
		return c.PURL != "" || len(c.CPEs) > 0 || c.BOMRef != "" || c.SPDXID != ""
	})
	withPURL := countWith(comps, func(c sbom.Component) bool { return c.PURL != "" })
	withLicense := countWith(comps, func(c sbom.Component) bool { return len(c.Licenses) > 0 })
	withHash := countWith(comps, func(c sbom.Component) bool { return len(c.Hashes) > 0 })
	withSHA512 := countWith(comps, func(c sbom.Component) bool {
		for algo := range c.Hashes {
			if algo == "SHA-512" || algo == "SHA512" {
				return true
			}
		}
		return false
	})
	hasAuthor := info.SBOMAuthor != "" || info.ToolName != ""
	hasTimestamp := info.SBOMTimestamp != ""

	checks := []CheckResult{
		componentCheck("bsi-name", "Component Name",
			"BSI TR-03183-2 §5.2.2 requires a component name",
			withName, total),
		componentCheck("bsi-version", "Component Version",
			"BSI TR-03183-2 §5.2.2 requires a version identifier",
			withVersion, total),
		componentCheck("bsi-creator", "Component Creator",
			"BSI TR-03183-2 §5.2.2 requires the component creator (supplier) contact",
			withSupplier, total),
		componentCheck("bsi-unique-id", "Unique Identifiers",
			"BSI TR-03183-2 §5.2.2 requires additional identifiers (CPE, PURL, SWID, etc.)",
			withUniqueID, total),
		componentCheck("bsi-purl", "Package URL (PURL)",
			"BSI TR-03183-2 recommends PURLs for unambiguous package identification",
			withPURL, total),
		componentCheck("bsi-license", "Distribution Licenses",
			"BSI TR-03183-2 §5.2.2 requires SPDX license identifiers for each component",
			withLicense, total),
		componentCheck("bsi-hash", "Integrity Hash",
			"BSI TR-03183-2 §5.2.2 recommends cryptographic hashes for integrity",
			withHash, total),
		componentCheck("bsi-sha512", "SHA-512 Hash",
			"BSI TR-03183-2 §5.2.2 specifically requires SHA-512 checksums",
			withSHA512, total),
		sbomCheck("bsi-dep-relation", "Dependency Relationship",
			"BSI TR-03183-2 §5.2.2 requires dependency enumeration with completeness indication",
			hasAnyDependency(comps), sbomDepSummary(comps)),
		sbomCheck("bsi-author", "SBOM Author/Creator",
			"BSI TR-03183-2 §5.2.1 requires the email/URL of the SBOM creator",
			hasAuthor, authorValue(info)),
		sbomCheck("bsi-timestamp", "SBOM Timestamp",
			"BSI TR-03183-2 §5.2.1 requires the date/time of SBOM compilation",
			hasTimestamp, info.SBOMTimestamp),
	}

	return buildFrameworkResult(StandardBSI, checks)
}

// --- Helpers ---


// authorValue returns the best author identifier for display.
func authorValue(info sbom.SBOMInfo) string {
	if info.SBOMAuthor != "" {
		return info.SBOMAuthor
	}
	return info.ToolName
}


// hasAnyDependency reports whether the SBOM carries any dependency information
// at all (a single component with a dependency list, or any component depending
// on another). This is an SBOM-level check — leaf components without deps do
// not fail it.
func hasAnyDependency(comps []sbom.Component) bool {
	for _, c := range comps {
		if len(c.Dependencies) > 0 {
			return true
		}
	}
	return false
}

// sbomDepSummary renders a short human-readable summary of dependency coverage
// for the compliance report.
func sbomDepSummary(comps []sbom.Component) string {
	withDeps := 0
	for _, c := range comps {
		if len(c.Dependencies) > 0 {
			withDeps++
		}
	}
	if withDeps == 0 {
		return "no dependency relationships declared"
	}
	return fmt.Sprintf("%d/%d components declare dependencies", withDeps, len(comps))
}

func countWith(comps []sbom.Component, pred func(sbom.Component) bool) int {
	n := 0
	for _, c := range comps {
		if pred(c) {
			n++
		}
	}
	return n
}

func componentCheck(id, name, desc string, passedCount, total int) CheckResult {
	passed := passedCount == total
	details := fmt.Sprintf("%d/%d components", passedCount, total)
	if passed {
		details = fmt.Sprintf("All %d components", total)
	}
	return CheckResult{
		ID:          id,
		Name:        name,
		Description: desc,
		Passed:      passed,
		Details:     details,
	}
}

func sbomCheck(id, name, desc string, passed bool, value string) CheckResult {
	details := "present"
	if !passed {
		details = "missing"
	}
	if value != "" && passed {
		details = value
	}
	return CheckResult{
		ID:          id,
		Name:        name,
		Description: desc,
		Passed:      passed,
		Details:     details,
	}
}

func buildFrameworkResult(standard Standard, checks []CheckResult) *FrameworkResult {
	passed := 0
	for _, c := range checks {
		if c.Passed {
			passed++
		}
	}
	total := len(checks)
	score := 0
	if total > 0 {
		score = passed * 100 / total
	}
	return &FrameworkResult{
		Standard: standard,
		Score:    score,
		MaxScore: 100,
		Passed:   passed,
		Total:    total,
		Checks:   checks,
	}
}

// PrintReport prints a text compliance report.
func PrintReport(report Report) {
	printFrameworkReport(report.NTIA)
	printFrameworkReport(report.CISA)
	printFrameworkReport(report.BSI)

	fmt.Printf("\n📊 Overall Compliance Score: %d/100\n", report.Overall)
}

func printFrameworkReport(fr *FrameworkResult) {
	if fr == nil {
		return
	}

	fmt.Printf("\n%c %s Compliance\n", frameworkIcon(fr.Score), fr.Standard)
	fmt.Printf("%s\n", repeat("=", 40))
	fmt.Printf("Score: %d/%d (%d/%d checks passed)\n\n", fr.Score, fr.MaxScore, fr.Passed, fr.Total)

	for _, c := range fr.Checks {
		icon := "✅"
		if !c.Passed {
			icon = "❌"
		}
		fmt.Printf("  %s %-30s %s\n", icon, c.Name, c.Details)
		if !c.Passed {
			fmt.Printf("     %s\n", c.Description)
		}
	}
}

func frameworkIcon(score int) rune {
	switch {
	case score >= 90:
		return '🟢'
	case score >= 70:
		return '🟡'
	case score >= 50:
		return '🟠'
	default:
		return '🔴'
	}
}

func repeat(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
