package output

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/compliance"
	"github.com/rezmoss/sbomlyze/internal/policy"
)

// GenerateMarkdownWithOverview creates a Markdown diff report.
func GenerateMarkdownWithOverview(result analysis.DiffResult, violations []policy.Violation, overview analysis.DiffOverview, findings analysis.KeyFindings) string {
	return GenerateMarkdownWithOverviewAndCompliance(result, violations, overview, findings, nil)
}

// GenerateMarkdownWithOverviewAndCompliance creates a Markdown diff report with optional compliance scoring.
func GenerateMarkdownWithOverviewAndCompliance(result analysis.DiffResult, violations []policy.Violation, overview analysis.DiffOverview, findings analysis.KeyFindings, complianceReport *compliance.Report) string {
	var sb strings.Builder

	sb.WriteString("## 📦 SBOM Diff Report\n\n")

	b := overview.Before
	a := overview.After
	sb.WriteString("### SBOM Comparison\n\n")
	sb.WriteString("| | Before | After |\n")
	sb.WriteString("|---|---|---|\n")
	fmt.Fprintf(&sb, "| **File** | %s | %s |\n", filepath.Base(b.FileName), filepath.Base(a.FileName))
	fmt.Fprintf(&sb, "| **File Size** | %s | %s |\n", formatFileSize(b.FileSize), formatFileSize(a.FileSize))
	fmt.Fprintf(&sb, "| **Format** | %s | %s |\n", orNone(b.Info.ToolName), orNone(a.Info.ToolName))
	fmt.Fprintf(&sb, "| **OS** | %s | %s |\n", orNone(b.Info.OSPrettyName), orNone(a.Info.OSPrettyName))
	fmt.Fprintf(&sb, "| **Source** | %s | %s |\n", orNone(b.Info.SourceName), orNone(a.Info.SourceName))
	fmt.Fprintf(&sb, "| **Total Components** | %d | %d |\n", b.Stats.TotalComponents, a.Stats.TotalComponents)
	fmt.Fprintf(&sb, "| **PURL Coverage** | %s | %s |\n",
		formatPct(b.Stats.WithPURL, b.Stats.TotalComponents),
		formatPct(a.Stats.WithPURL, a.Stats.TotalComponents))
	fmt.Fprintf(&sb, "| **License Coverage** | %s | %s |\n",
		formatPct(b.Stats.TotalComponents-b.Stats.WithoutLicense, b.Stats.TotalComponents),
		formatPct(a.Stats.TotalComponents-a.Stats.WithoutLicense, a.Stats.TotalComponents))
	fmt.Fprintf(&sb, "| **Hash Coverage** | %s | %s |\n",
		formatPct(b.Stats.WithHashes, b.Stats.TotalComponents),
		formatPct(a.Stats.WithHashes, a.Stats.TotalComponents))
	fmt.Fprintf(&sb, "| **CPE Coverage** | %s | %s |\n",
		formatPct(b.Stats.WithCPEs, b.Stats.TotalComponents),
		formatPct(a.Stats.WithCPEs, a.Stats.TotalComponents))
	sb.WriteString("\n")

	hasSchema := b.Info.SchemaVersion != "" || a.Info.SchemaVersion != ""
	hasScope := b.Info.SearchScope != "" || a.Info.SearchScope != ""
	if hasSchema || hasScope {
		sb.WriteString("### Scan Context\n\n")
		sb.WriteString("| | Before | After |\n")
		sb.WriteString("|---|---|---|\n")
		if hasSchema {
			fmt.Fprintf(&sb, "| **Schema** | %s | %s |\n", orNone(b.Info.SchemaVersion), orNone(a.Info.SchemaVersion))
		}
		if hasScope {
			fmt.Fprintf(&sb, "| **Scan Scope** | %s | %s |\n", orNone(b.Info.SearchScope), orNone(a.Info.SearchScope))
		}
		sb.WriteString("\n")
	}

	if len(findings.Findings) > 0 {
		sb.WriteString("### Key Findings\n\n")
		for _, f := range findings.Findings {
			fmt.Fprintf(&sb, "- %s %s\n", f.Icon, f.Message)
		}
		sb.WriteString("\n")
	}

	if complianceReport != nil {
		writeMarkdownCompliance(&sb, *complianceReport)
	}

	if len(result.AddedByType) > 0 {
		sb.WriteString("<details>\n")
		fmt.Fprintf(&sb, "<summary>➕ Added Packages by Type (%d total)</summary>\n\n", len(result.Added))
		for _, group := range result.AddedByType {
			fmt.Fprintf(&sb, "**%s** (%d)\n\n", group.Type, group.Total)
			sb.WriteString("| Name | Version | Location |\n")
			sb.WriteString("|------|---------|----------|\n")
			for _, s := range group.Samples {
				loc := ""
				if len(s.Locations) > 0 {
					loc = s.Locations[0]
				}
				fmt.Fprintf(&sb, "| %s | %s | %s |\n", s.Name, s.Version, loc)
			}
			remaining := group.Total - len(group.Samples)
			if remaining > 0 {
				fmt.Fprintf(&sb, "\n*...and %d more*\n\n", remaining)
			}
		}
		sb.WriteString("\n</details>\n\n")
	}

	if len(result.RemovedByType) > 0 {
		sb.WriteString("<details>\n")
		fmt.Fprintf(&sb, "<summary>➖ Removed Packages by Type (%d total)</summary>\n\n", len(result.Removed))
		for _, group := range result.RemovedByType {
			fmt.Fprintf(&sb, "**%s** (%d)\n\n", group.Type, group.Total)
			sb.WriteString("| Name | Version | Location |\n")
			sb.WriteString("|------|---------|----------|\n")
			for _, s := range group.Samples {
				loc := ""
				if len(s.Locations) > 0 {
					loc = s.Locations[0]
				}
				fmt.Fprintf(&sb, "| %s | %s | %s |\n", s.Name, s.Version, loc)
			}
			remaining := group.Total - len(group.Samples)
			if remaining > 0 {
				fmt.Fprintf(&sb, "\n*...and %d more*\n\n", remaining)
			}
		}
		sb.WriteString("\n</details>\n\n")
	}

	writeMarkdownDiffBody(&sb, result, violations)

	return sb.String()
}

// GenerateMarkdown creates a Markdown report.
func GenerateMarkdown(result analysis.DiffResult, violations []policy.Violation) string {
	var sb strings.Builder

	sb.WriteString("## 📦 SBOM Diff Report\n\n")
	writeMarkdownDiffBody(&sb, result, violations)

	return sb.String()
}

func writeMarkdownCompliance(sb *strings.Builder, report compliance.Report) {
	sb.WriteString("### 📊 Compliance Scoring\n\n")

	standards := []struct {
		name   string
		result *compliance.FrameworkResult
	}{
		{"NTIA Minimum Elements", report.NTIA},
		{"CISA FSCT-3", report.CISA},
		{"BSI TR-03183-2", report.BSI},
	}

	sb.WriteString("| Standard | Score | Passed | Checks |\n")
	sb.WriteString("|----------|-------|--------|--------|\n")
	for _, s := range standards {
		if s.result != nil {
			icon := "🔴"
			switch {
			case s.result.Score >= 90:
				icon = "🟢"
			case s.result.Score >= 70:
				icon = "🟡"
			case s.result.Score >= 50:
				icon = "🟠"
			}
			fmt.Fprintf(sb, "| %s %s | %d/100 | %d | %d |\n", icon, s.name, s.result.Score, s.result.Passed, s.result.Total)
		}
	}
	fmt.Fprintf(sb, "| **Overall** | **%d/100** | | |\n", report.Overall)
	sb.WriteString("\n")

	// Show failed checks for each framework
	for _, s := range standards {
		if s.result == nil {
			continue
		}
		var failed []compliance.CheckResult
		for _, c := range s.result.Checks {
			if !c.Passed {
				failed = append(failed, c)
			}
		}
		if len(failed) > 0 {
			sb.WriteString("<details>\n")
			fmt.Fprintf(sb, "<summary>%s - %d failed checks</summary>\n\n", s.name, len(failed))
			for _, c := range failed {
				fmt.Fprintf(sb, "- **%s**: %s (%s)\n", c.Name, c.Details, c.Description)
			}
			sb.WriteString("\n</details>\n\n")
		}
	}
}

func writeMarkdownDiffBody(sb *strings.Builder, result analysis.DiffResult, violations []policy.Violation) {
	sb.WriteString("### Summary\n\n")
	sb.WriteString("| Metric | Count |\n")
	sb.WriteString("|--------|-------|\n")
	fmt.Fprintf(sb, "| Added | %d |\n", len(result.Added))
	fmt.Fprintf(sb, "| Removed | %d |\n", len(result.Removed))
	fmt.Fprintf(sb, "| Changed | %d |\n", len(result.Changed))

	if result.DriftSummary != nil {
		sb.WriteString("\n### Drift Summary\n\n")
		sb.WriteString("| Type | Count | Status |\n")
		sb.WriteString("|------|-------|--------|\n")

		versionStatus := "✅"
		fmt.Fprintf(sb, "| Version | %d | %s |\n", result.DriftSummary.VersionDrift, versionStatus)

		integrityStatus := "✅"
		if result.DriftSummary.IntegrityDrift > 0 {
			integrityStatus = "⚠️ **Review Required**"
		}
		fmt.Fprintf(sb, "| Integrity | %d | %s |\n", result.DriftSummary.IntegrityDrift, integrityStatus)

		metadataStatus := "✅"
		fmt.Fprintf(sb, "| Metadata | %d | %s |\n", result.DriftSummary.MetadataDrift, metadataStatus)
	}

	if result.Dependencies != nil && result.Dependencies.DepthSummary != nil {
		ds := result.Dependencies.DepthSummary
		sb.WriteString("\n### New Dependencies by Depth\n\n")
		sb.WriteString("| Depth | Count | Risk |\n")
		sb.WriteString("|-------|-------|------|\n")
		fmt.Fprintf(sb, "| 1 (direct) | %d | Low |\n", ds.Depth1)
		fmt.Fprintf(sb, "| 2 | %d | Medium |\n", ds.Depth2)

		depth3Risk := "Medium"
		if ds.Depth3Plus > 0 {
			depth3Risk = "⚠️ **High**"
		}
		fmt.Fprintf(sb, "| 3+ | %d | %s |\n", ds.Depth3Plus, depth3Risk)
	}

	if len(violations) > 0 {
		var errors, warnings []policy.Violation
		for _, v := range violations {
			if v.Severity == policy.SeverityError {
				errors = append(errors, v)
			} else {
				warnings = append(warnings, v)
			}
		}

		if len(errors) > 0 {
			sb.WriteString("\n### ❌ Policy Errors\n\n")
			for _, v := range errors {
				fmt.Fprintf(sb, "- **%s**: %s\n", v.Rule, v.Message)
			}
		}

		if len(warnings) > 0 {
			sb.WriteString("\n### ⚠️ Policy Warnings\n\n")
			for _, v := range warnings {
				fmt.Fprintf(sb, "- **%s**: %s\n", v.Rule, v.Message)
			}
		}
	}

	if len(result.Added) > 0 {
		sb.WriteString("\n<details>\n")
		fmt.Fprintf(sb, "<summary>➕ Added Components (%d)</summary>\n\n", len(result.Added))
		sb.WriteString("| Name | Version |\n")
		sb.WriteString("|------|--------|\n")
		for _, c := range result.Added {
			fmt.Fprintf(sb, "| %s | %s |\n", c.Name, c.Version)
		}
		sb.WriteString("\n</details>\n")
	}

	if len(result.Removed) > 0 {
		sb.WriteString("\n<details>\n")
		fmt.Fprintf(sb, "<summary>➖ Removed Components (%d)</summary>\n\n", len(result.Removed))
		sb.WriteString("| Name | Version |\n")
		sb.WriteString("|------|--------|\n")
		for _, c := range result.Removed {
			fmt.Fprintf(sb, "| %s | %s |\n", c.Name, c.Version)
		}
		sb.WriteString("\n</details>\n")
	}

	if len(result.Changed) > 0 {
		sb.WriteString("\n<details>\n")
		fmt.Fprintf(sb, "<summary>🔄 Changed Components (%d)</summary>\n\n", len(result.Changed))
		sb.WriteString("| Name | Before | After | Drift |\n")
		sb.WriteString("|------|--------|-------|-------|\n")
		for _, c := range result.Changed {
			drift := ""
			if c.Drift != nil {
				switch c.Drift.Type {
				case analysis.DriftTypeIntegrity:
					drift = "⚠️ Integrity"
				case analysis.DriftTypeVersion:
					drift = "📦 Version"
				case analysis.DriftTypeMetadata:
					drift = "📝 Metadata"
				}
			}
			fmt.Fprintf(sb, "| %s | %s | %s | %s |\n", c.Name, c.Before.Version, c.After.Version, drift)
		}
		sb.WriteString("\n</details>\n")
	}

	sb.WriteString("\n---\n")
	fmt.Fprintf(sb, "*Generated by [sbomlyze](https://github.com/rezmoss/sbomlyze) at %s*\n", time.Now().UTC().Format(time.RFC3339))
}
