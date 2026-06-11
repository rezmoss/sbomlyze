// Package compliance scores SBOM completeness vs NTIA Minimum Elements (2021),
// CISA 2025 Minimum Elements (draft), and BSI TR-03183-2 (v2.1.0).
package compliance

import (
	"fmt"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
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
// 7 data fields: supplier name, component name, version, other unique IDs,
// dependency relationship, SBOM author, timestamp. Report has no § numbers.

func evaluateNTIA(comps []sbom.Component, info sbom.SBOMInfo) *FrameworkResult {
	if len(comps) == 0 {
		return nil
	}

	total := len(comps)

	withName := countWith(comps, func(c sbom.Component) bool { return c.Name != "" })
	withVersion := countWith(comps, func(c sbom.Component) bool { return c.Version != "" })
	withSupplier := countWith(comps, func(c sbom.Component) bool { return c.Supplier != "" })
	withUniqueID := countWith(comps, hasLookupIdentifier)
	depCoverage := depGraphCoverage(comps)
	// NTIA allows the author to be a tool, so ToolName qualifies
	hasAuthor := info.SBOMAuthor != "" || info.ToolName != ""
	hasTimestamp := info.SBOMTimestamp != ""

	checks := []CheckResult{
		componentCheck("ntia-name", "Component Name",
			"NTIA Minimum Elements (2021) requires the name assigned to each component by its supplier",
			withName, total),
		componentCheck("ntia-version", "Component Version",
			"NTIA Minimum Elements (2021) requires a version identifier for each component",
			withVersion, total),
		componentCheck("ntia-supplier", "Supplier Name",
			"NTIA Minimum Elements (2021) requires the name of the entity that creates and identifies each component",
			withSupplier, total),
		componentCheck("ntia-unique-id", "Other Unique Identifiers",
			"NTIA Minimum Elements (2021) lists lookup identifiers (PURL, CPE, SWID) to include where they exist",
			withUniqueID, total),
		componentCheck("ntia-dep-relation", "Dependency Relationship",
			"NTIA Minimum Elements (2021) requires dependency relationships covering at least all top-level dependencies",
			depCoverage, total),
		sbomCheck("ntia-author", "SBOM Author",
			"NTIA Minimum Elements (2021) requires the entity (or tool) that created the SBOM data",
			hasAuthor, authorValue(info)),
		sbomCheck("ntia-timestamp", "SBOM Timestamp",
			"NTIA Minimum Elements (2021) requires the date and time of SBOM data assembly",
			hasTimestamp, info.SBOMTimestamp),
	}

	return buildFrameworkResult(StandardNTIA, checks)
}

// --- CISA 2025 Minimum Elements (Aug 2025 draft) ---
// NTIA + component hash, license, tool name, generation context. Needs >=1
// software ID per component (PURL/CPE preferred, neither mandated). 10 of 11
// elements checked; generation context (lifecycle phase) not parsed.

func evaluateCISA(comps []sbom.Component, info sbom.SBOMInfo) *FrameworkResult {
	if len(comps) == 0 {
		return nil
	}

	total := len(comps)

	withName := countWith(comps, func(c sbom.Component) bool { return c.Name != "" })
	withVersion := countWith(comps, func(c sbom.Component) bool { return c.Version != "" })
	withSupplier := countWith(comps, func(c sbom.Component) bool { return c.Supplier != "" })
	withUniqueID := countWith(comps, hasLookupIdentifier)
	withLicense := countWith(comps, func(c sbom.Component) bool { return len(c.Licenses) > 0 })
	withHash := countWith(comps, func(c sbom.Component) bool { return len(c.Hashes) > 0 })
	depCoverage := depGraphCoverage(comps)

	// CISA 2025: author and tool are separate; author is not the tool
	hasAuthor := info.SBOMAuthor != ""
	hasTool := info.ToolName != ""
	hasTimestamp := info.SBOMTimestamp != ""

	checks := []CheckResult{
		componentCheck("cisa-name", "Component Name",
			"CISA 2025 Minimum Elements requires a component name for each entry",
			withName, total),
		componentCheck("cisa-version", "Component Version",
			"CISA 2025 Minimum Elements requires a version identifier for each component",
			withVersion, total),
		componentCheck("cisa-supplier", "Software Producer",
			"CISA 2025 Minimum Elements requires identifying the producer of each component",
			withSupplier, total),
		componentCheck("cisa-unique-id", "Software Identifiers",
			"CISA 2025 Minimum Elements requires at least one software identifier per component (PURL and CPE preferred)",
			withUniqueID, total),
		componentCheck("cisa-dep-relation", "Dependency Relationship",
			"CISA 2025 Minimum Elements requires a dependency graph covering components and their dependencies",
			depCoverage, total),
		componentCheck("cisa-license", "License Information",
			"CISA 2025 Minimum Elements adds license data per component (an explicit 'unknown' is permitted)",
			withLicense, total),
		componentCheck("cisa-hash", "Component Hash",
			"CISA 2025 Minimum Elements adds a cryptographic hash per component where the artifact is available",
			withHash, total),
		sbomCheck("cisa-tool", "Tool Name",
			"CISA 2025 Minimum Elements adds the name of the tool(s) used to generate the SBOM",
			hasTool, info.ToolName),
		sbomCheck("cisa-author", "SBOM Author",
			"CISA 2025 Minimum Elements requires the person or organization that created the SBOM (distinct from the tool)",
			hasAuthor, info.SBOMAuthor),
		sbomCheck("cisa-timestamp", "SBOM Timestamp",
			"CISA 2025 Minimum Elements requires an ISO 8601 timestamp of SBOM creation",
			hasTimestamp, info.SBOMTimestamp),
	}

	return buildFrameworkResult(StandardCISA, checks)
}

// --- BSI TR-03183-2 (v2.1.0, 2025) ---
// §5.2.1: SBOM creator (email/URL), timestamp. §5.2.2: component creator,
// name, version, deps w/ completeness, SPDX licences (§6.1), SHA-512 hash.
// §5.2.4: CPE/PURL if they exist.
// Not parsed, so unchecked: filename, exec/archive/structured props, dep
// completeness flags, source/deployable URIs.

func evaluateBSI(comps []sbom.Component, info sbom.SBOMInfo) *FrameworkResult {
	if len(comps) == 0 {
		return nil
	}

	total := len(comps)

	withName := countWith(comps, func(c sbom.Component) bool { return c.Name != "" })
	withVersion := countWith(comps, func(c sbom.Component) bool { return c.Version != "" })
	withSupplier := countWith(comps, func(c sbom.Component) bool { return c.Supplier != "" })
	withUniqueID := countWith(comps, hasLookupIdentifier)
	withLicense := countWith(comps, hasValidSPDXLicenses)
	withSHA512 := countWith(comps, func(c sbom.Component) bool {
		for algo := range c.Hashes {
			if algo == "SHA-512" || algo == "SHA512" {
				return true
			}
		}
		return false
	})
	depCoverage := depGraphCoverage(comps)
	// §5.2.1 needs creator email (or URL); a bare name/tool fails
	hasCreatorContact := strings.Contains(info.SBOMAuthor, "@") ||
		strings.HasPrefix(info.SBOMAuthor, "http://") ||
		strings.HasPrefix(info.SBOMAuthor, "https://")
	hasTimestamp := info.SBOMTimestamp != ""

	checks := []CheckResult{
		componentCheck("bsi-name", "Component Name",
			"BSI TR-03183-2 §5.2.2 requires a component name (or the actual filename if unnamed)",
			withName, total),
		componentCheck("bsi-version", "Component Version",
			"BSI TR-03183-2 §5.2.2 requires a version identifier",
			withVersion, total),
		componentCheck("bsi-creator", "Component Creator",
			"BSI TR-03183-2 §5.2.2 requires the creator of each component (email or URL contact)",
			withSupplier, total),
		componentCheck("bsi-unique-id", "Unique Identifiers",
			"BSI TR-03183-2 §5.2.4 requires identifiers such as CPE or PURL where they exist",
			withUniqueID, total),
		componentCheck("bsi-license", "Distribution Licences",
			"BSI TR-03183-2 §5.2.2 requires distribution licences, expressed as SPDX identifiers per §6.1",
			withLicense, total),
		componentCheck("bsi-sha512", "SHA-512 Hash",
			"BSI TR-03183-2 §5.2.2 requires a SHA-512 checksum of each deployable component",
			withSHA512, total),
		componentCheck("bsi-dep-relation", "Dependency Relationship",
			"BSI TR-03183-2 §5.2.2 requires per-component dependency enumeration with completeness indication",
			depCoverage, total),
		sbomCheck("bsi-author", "SBOM Creator Contact",
			"BSI TR-03183-2 §5.2.1 requires the email address (or URL) of the SBOM creator — a tool name does not qualify",
			hasCreatorContact, info.SBOMAuthor),
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

// hasLookupIdentifier: external lookup key (PURL/CPE). bom-ref/SPDXID excluded
// on purpose — every doc has them, so they'd make the check always pass.
func hasLookupIdentifier(c sbom.Component) bool {
	return c.PURL != "" || len(c.CPEs) > 0
}

// hasValidSPDXLicenses: all licences are valid SPDX exprs (§6.1).
// NONE/NOASSERTION/free-text fail.
func hasValidSPDXLicenses(c sbom.Component) bool {
	if len(c.Licenses) == 0 {
		return false
	}
	valid, _ := spdxexp.ValidateLicenses(c.Licenses)
	return valid
}

// depGraphCoverage counts components in the dep graph (declare deps or are
// a dep of another). One stray edge isn't enough — all must be covered.
func depGraphCoverage(comps []sbom.Component) int {
	children := make(map[string]bool)
	for _, c := range comps {
		for _, d := range c.Dependencies {
			children[d] = true
		}
	}
	n := 0
	for _, c := range comps {
		if c.DepsDeclared || len(c.Dependencies) > 0 || children[c.ID] {
			n++
		}
	}
	return n
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
	fmt.Printf("%s\n", strings.Repeat("=", 40))
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
