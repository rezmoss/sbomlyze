package main

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// OutputFormat represents supported output formats
type OutputFormat string

const (
	FormatText     OutputFormat = "text"
	FormatJSON     OutputFormat = "json"
	FormatSARIF    OutputFormat = "sarif"
	FormatJUnit    OutputFormat = "junit"
	FormatMarkdown OutputFormat = "markdown"
	FormatPatch    OutputFormat = "patch"
)

// =============================================================================
// SARIF Output (GitHub Code Scanning)
// =============================================================================

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SARIFMessage     `json:"shortDescription"`
	FullDescription  SARIFMessage     `json:"fullDescription,omitempty"`
	DefaultConfig    SARIFRuleConfig  `json:"defaultConfiguration,omitempty"`
	Help             *SARIFMessage    `json:"help,omitempty"`
	Properties       *SARIFProperties `json:"properties,omitempty"`
}

type SARIFRuleConfig struct {
	Level string `json:"level"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

func generateSARIF(result DiffResult, violations []PolicyViolation, sbomFile string) SARIFReport {
	rules := []SARIFRule{
		{
			ID:               "integrity-drift",
			Name:             "Integrity Drift Detected",
			ShortDescription: SARIFMessage{Text: "Component hash changed without version change"},
			DefaultConfig:    SARIFRuleConfig{Level: "error"},
			Properties:       &SARIFProperties{Tags: []string{"security", "supply-chain"}},
		},
		{
			ID:               "new-component",
			Name:             "New Component Added",
			ShortDescription: SARIFMessage{Text: "A new component was added to the SBOM"},
			DefaultConfig:    SARIFRuleConfig{Level: "note"},
		},
		{
			ID:               "removed-component",
			Name:             "Component Removed",
			ShortDescription: SARIFMessage{Text: "A component was removed from the SBOM"},
			DefaultConfig:    SARIFRuleConfig{Level: "note"},
		},
		{
			ID:               "version-change",
			Name:             "Version Changed",
			ShortDescription: SARIFMessage{Text: "Component version was updated"},
			DefaultConfig:    SARIFRuleConfig{Level: "note"},
		},
		{
			ID:               "deep-dependency",
			Name:             "Deep Transitive Dependency",
			ShortDescription: SARIFMessage{Text: "New dependency introduced at depth 3 or greater"},
			DefaultConfig:    SARIFRuleConfig{Level: "warning"},
			Properties:       &SARIFProperties{Tags: []string{"security", "supply-chain"}},
		},
		{
			ID:               "policy-violation",
			Name:             "Policy Violation",
			ShortDescription: SARIFMessage{Text: "SBOM policy rule was violated"},
			DefaultConfig:    SARIFRuleConfig{Level: "error"},
		},
	}

	var results []SARIFResult

	// Add integrity drift results
	for _, changed := range result.Changed {
		if changed.Drift != nil && changed.Drift.Type == DriftTypeIntegrity {
			results = append(results, SARIFResult{
				RuleID:  "integrity-drift",
				Level:   "error",
				Message: SARIFMessage{Text: fmt.Sprintf("Component %s has hash change without version change (potential supply chain attack)", changed.Name)},
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
					},
				}},
			})
		}
	}

	// Add deep dependency results
	if result.Dependencies != nil {
		for _, td := range result.Dependencies.TransitiveNew {
			if td.Depth >= 3 {
				results = append(results, SARIFResult{
					RuleID:  "deep-dependency",
					Level:   "warning",
					Message: SARIFMessage{Text: fmt.Sprintf("New transitive dependency %s at depth %d", td.Target, td.Depth)},
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
						},
					}},
				})
			}
		}
	}

	// Add policy violations
	for _, v := range violations {
		level := "error"
		if v.Severity == SeverityWarning {
			level = "warning"
		}
		results = append(results, SARIFResult{
			RuleID:  "policy-violation",
			Level:   level,
			Message: SARIFMessage{Text: fmt.Sprintf("[%s] %s", v.Rule, v.Message)},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: sbomFile},
				},
			}},
		})
	}

	return SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "sbomlyze",
					Version:        version,
					InformationURI: "https://github.com/rezmoss/sbomlyze",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

// =============================================================================
// JUnit Output (CI Test UI)
// =============================================================================

type JUnitTestSuites struct {
	XMLName   xml.Name         `xml:"testsuites"`
	Name      string           `xml:"name,attr"`
	Tests     int              `xml:"tests,attr"`
	Failures  int              `xml:"failures,attr"`
	Errors    int              `xml:"errors,attr"`
	Time      float64          `xml:"time,attr"`
	TestSuite []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      float64         `xml:"time,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Skipped   *JUnitSkipped `xml:"skipped,omitempty"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

type JUnitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}

func generateJUnit(result DiffResult, violations []PolicyViolation) JUnitTestSuites {
	var testCases []JUnitTestCase
	failures := 0
	errors := 0

	// Test: No integrity drift
	integrityDrift := 0
	if result.DriftSummary != nil {
		integrityDrift = result.DriftSummary.IntegrityDrift
	}
	tc := JUnitTestCase{
		Name:      "No Integrity Drift",
		ClassName: "sbomlyze.security",
		Time:      0.001,
	}
	if integrityDrift > 0 {
		tc.Failure = &JUnitFailure{
			Message: fmt.Sprintf("%d components have hash changes without version changes", integrityDrift),
			Type:    "IntegrityDrift",
		}
		failures++
	}
	testCases = append(testCases, tc)

	// Test: No deep dependencies
	deepDeps := 0
	if result.Dependencies != nil && result.Dependencies.DepthSummary != nil {
		deepDeps = result.Dependencies.DepthSummary.Depth3Plus
	}
	tc = JUnitTestCase{
		Name:      "No Deep Transitive Dependencies",
		ClassName: "sbomlyze.dependencies",
		Time:      0.001,
	}
	if deepDeps > 0 {
		tc.Failure = &JUnitFailure{
			Message: fmt.Sprintf("%d new dependencies at depth 3+", deepDeps),
			Type:    "DeepDependency",
		}
		failures++
	}
	testCases = append(testCases, tc)

	// Test: Policy compliance
	for _, v := range violations {
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("Policy: %s", v.Rule),
			ClassName: "sbomlyze.policy",
			Time:      0.001,
		}
		if v.Severity == SeverityError {
			tc.Failure = &JUnitFailure{
				Message: v.Message,
				Type:    "PolicyViolation",
			}
			failures++
		}
		testCases = append(testCases, tc)
	}

	// Test: Component changes summary
	tc = JUnitTestCase{
		Name:      "SBOM Diff Summary",
		ClassName: "sbomlyze.diff",
		Time:      0.001,
	}
	// This is informational, not a failure
	testCases = append(testCases, tc)

	return JUnitTestSuites{
		Name:     "sbomlyze",
		Tests:    len(testCases),
		Failures: failures,
		Errors:   errors,
		Time:     0.01,
		TestSuite: []JUnitTestSuite{{
			Name:      "SBOM Analysis",
			Tests:     len(testCases),
			Failures:  failures,
			Errors:    errors,
			Time:      0.01,
			TestCases: testCases,
		}},
	}
}

// =============================================================================
// Markdown Output (PR Comments)
// =============================================================================

func generateMarkdown(result DiffResult, violations []PolicyViolation) string {
	var sb strings.Builder

	sb.WriteString("## 📦 SBOM Diff Report\n\n")

	// Summary table
	sb.WriteString("### Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Added | %d |\n", len(result.Added)))
	sb.WriteString(fmt.Sprintf("| Removed | %d |\n", len(result.Removed)))
	sb.WriteString(fmt.Sprintf("| Changed | %d |\n", len(result.Changed)))

	// Drift summary
	if result.DriftSummary != nil {
		sb.WriteString("\n### Drift Summary\n\n")
		sb.WriteString("| Type | Count | Status |\n")
		sb.WriteString("|------|-------|--------|\n")

		versionStatus := "✅"
		sb.WriteString(fmt.Sprintf("| Version | %d | %s |\n", result.DriftSummary.VersionDrift, versionStatus))

		integrityStatus := "✅"
		if result.DriftSummary.IntegrityDrift > 0 {
			integrityStatus = "⚠️ **Review Required**"
		}
		sb.WriteString(fmt.Sprintf("| Integrity | %d | %s |\n", result.DriftSummary.IntegrityDrift, integrityStatus))

		metadataStatus := "✅"
		sb.WriteString(fmt.Sprintf("| Metadata | %d | %s |\n", result.DriftSummary.MetadataDrift, metadataStatus))
	}

	// Dependency depth summary
	if result.Dependencies != nil && result.Dependencies.DepthSummary != nil {
		ds := result.Dependencies.DepthSummary
		sb.WriteString("\n### New Dependencies by Depth\n\n")
		sb.WriteString("| Depth | Count | Risk |\n")
		sb.WriteString("|-------|-------|------|\n")
		sb.WriteString(fmt.Sprintf("| 1 (direct) | %d | Low |\n", ds.Depth1))
		sb.WriteString(fmt.Sprintf("| 2 | %d | Medium |\n", ds.Depth2))

		depth3Risk := "Medium"
		if ds.Depth3Plus > 0 {
			depth3Risk = "⚠️ **High**"
		}
		sb.WriteString(fmt.Sprintf("| 3+ | %d | %s |\n", ds.Depth3Plus, depth3Risk))
	}

	// Policy violations
	if len(violations) > 0 {
		var errors, warnings []PolicyViolation
		for _, v := range violations {
			if v.Severity == SeverityError {
				errors = append(errors, v)
			} else {
				warnings = append(warnings, v)
			}
		}

		if len(errors) > 0 {
			sb.WriteString("\n### ❌ Policy Errors\n\n")
			for _, v := range errors {
				sb.WriteString(fmt.Sprintf("- **%s**: %s\n", v.Rule, v.Message))
			}
		}

		if len(warnings) > 0 {
			sb.WriteString("\n### ⚠️ Policy Warnings\n\n")
			for _, v := range warnings {
				sb.WriteString(fmt.Sprintf("- **%s**: %s\n", v.Rule, v.Message))
			}
		}
	}

	// Added components (collapsible)
	if len(result.Added) > 0 {
		sb.WriteString("\n<details>\n")
		sb.WriteString(fmt.Sprintf("<summary>➕ Added Components (%d)</summary>\n\n", len(result.Added)))
		sb.WriteString("| Name | Version |\n")
		sb.WriteString("|------|--------|\n")
		for _, c := range result.Added {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", c.Name, c.Version))
		}
		sb.WriteString("\n</details>\n")
	}

	// Removed components (collapsible)
	if len(result.Removed) > 0 {
		sb.WriteString("\n<details>\n")
		sb.WriteString(fmt.Sprintf("<summary>➖ Removed Components (%d)</summary>\n\n", len(result.Removed)))
		sb.WriteString("| Name | Version |\n")
		sb.WriteString("|------|--------|\n")
		for _, c := range result.Removed {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", c.Name, c.Version))
		}
		sb.WriteString("\n</details>\n")
	}

	// Changed components (collapsible)
	if len(result.Changed) > 0 {
		sb.WriteString("\n<details>\n")
		sb.WriteString(fmt.Sprintf("<summary>🔄 Changed Components (%d)</summary>\n\n", len(result.Changed)))
		sb.WriteString("| Name | Before | After | Drift |\n")
		sb.WriteString("|------|--------|-------|-------|\n")
		for _, c := range result.Changed {
			drift := ""
			if c.Drift != nil {
				switch c.Drift.Type {
				case DriftTypeIntegrity:
					drift = "⚠️ Integrity"
				case DriftTypeVersion:
					drift = "📦 Version"
				case DriftTypeMetadata:
					drift = "📝 Metadata"
				}
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", c.Name, c.Before.Version, c.After.Version, drift))
		}
		sb.WriteString("\n</details>\n")
	}

	// Footer
	sb.WriteString("\n---\n")
	sb.WriteString(fmt.Sprintf("*Generated by [sbomlyze](https://github.com/rezmoss/sbomlyze) at %s*\n", time.Now().UTC().Format(time.RFC3339)))

	return sb.String()
}

// =============================================================================
// JSON Patch Output (RFC 6902)
// =============================================================================

type JSONPatchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
	From  string      `json:"from,omitempty"`
}

func generateJSONPatch(result DiffResult) []JSONPatchOp {
	var ops []JSONPatchOp

	// Added components
	for i, c := range result.Added {
		ops = append(ops, JSONPatchOp{
			Op:    "add",
			Path:  fmt.Sprintf("/components/%d", i),
			Value: c,
		})
	}

	// Removed components
	for _, c := range result.Removed {
		ops = append(ops, JSONPatchOp{
			Op:   "remove",
			Path: fmt.Sprintf("/components/%s", c.ID),
		})
	}

	// Changed components
	for _, c := range result.Changed {
		// Version change
		if c.Before.Version != c.After.Version {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/version", c.ID),
				Value: c.After.Version,
			})
		}

		// License changes
		if !stringSliceEqual(c.Before.Licenses, c.After.Licenses) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/licenses", c.ID),
				Value: c.After.Licenses,
			})
		}

		// Hash changes
		if !hashMapEqual(c.Before.Hashes, c.After.Hashes) {
			ops = append(ops, JSONPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/components/%s/hashes", c.ID),
				Value: c.After.Hashes,
			})
		}
	}

	return ops
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hashMapEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
