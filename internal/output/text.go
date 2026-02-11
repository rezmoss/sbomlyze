package output

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/policy"
)

// formatFileSize formats bytes into a human-readable string
func formatFileSize(size int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case size >= gb:
		return fmt.Sprintf("%.1f GB", float64(size)/float64(gb))
	case size >= mb:
		return fmt.Sprintf("%.0f MB", float64(size)/float64(mb))
	case size >= kb:
		return fmt.Sprintf("%.0f KB", float64(size)/float64(kb))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

// formatPct formats a percentage from a count and total
func formatPct(count, total int) string {
	if total == 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(count)/float64(total)*100)
}

// orNone returns the string or "(none)" if empty
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// PrintDiffOverview prints the side-by-side SBOM comparison header
func PrintDiffOverview(overview analysis.DiffOverview) {
	b := overview.Before
	a := overview.After

	sep := strings.Repeat("=", 70)
	fmt.Printf("\nSBOM Comparison\n%s\n", sep)
	fmt.Printf("%-24s%-24s%s\n", "", "Before", "After")
	fmt.Printf("%-24s%-24s%s\n", "File:", filepath.Base(b.FileName), filepath.Base(a.FileName))
	fmt.Printf("%-24s%-24s%s\n", "File Size:", formatFileSize(b.FileSize), formatFileSize(a.FileSize))
	fmt.Printf("%-24s%-24s%s\n", "Format:", orNone(b.Info.ToolName), orNone(a.Info.ToolName))
	fmt.Printf("%-24s%-24s%s\n", "OS:", orNone(b.Info.OSPrettyName), orNone(a.Info.OSPrettyName))
	fmt.Printf("%-24s%-24s%s\n", "Source:", orNone(b.Info.SourceName), orNone(a.Info.SourceName))
	fmt.Printf("%-24s%-24s%s\n", "Source Type:", orNone(b.Info.SourceType), orNone(a.Info.SourceType))
	fmt.Printf("%-24s%-24s%s\n", "Total Components:",
		fmt.Sprintf("%d", b.Stats.TotalComponents),
		fmt.Sprintf("%d", a.Stats.TotalComponents))

	// Merge all type keys from both sides
	allTypes := make(map[string]bool)
	for t := range b.Stats.ByType {
		allTypes[t] = true
	}
	for t := range a.Stats.ByType {
		allTypes[t] = true
	}
	if len(allTypes) > 0 {
		types := analysis.SortedByValue(b.Stats.ByType)
		// Add types only in 'after' that are missing from 'before'
		afterOnly := analysis.SortedByValue(a.Stats.ByType)
		seen := make(map[string]bool)
		for _, t := range types {
			seen[t] = true
		}
		for _, t := range afterOnly {
			if !seen[t] {
				types = append(types, t)
			}
		}
		for _, t := range types {
			bCount := b.Stats.ByType[t]
			aCount := a.Stats.ByType[t]
			diff := aCount - bCount
			diffStr := ""
			if diff > 0 {
				diffStr = fmt.Sprintf("+%d", diff)
			} else if diff < 0 {
				diffStr = fmt.Sprintf("%d", diff)
			}
			label := fmt.Sprintf("  %s:", t)
			fmt.Printf("%-24s%-24s%-16s%s\n", label,
				fmt.Sprintf("%d", bCount),
				fmt.Sprintf("%d", aCount),
				diffStr)
		}
	}

	// Data quality section
	fmt.Printf("Data Quality:\n")
	fmt.Printf("%-24s%-24s%s\n", "  PURL Coverage:",
		formatPct(b.Stats.WithPURL, b.Stats.TotalComponents),
		formatPct(a.Stats.WithPURL, a.Stats.TotalComponents))
	fmt.Printf("%-24s%-24s%s\n", "  License Coverage:",
		formatPct(b.Stats.TotalComponents-b.Stats.WithoutLicense, b.Stats.TotalComponents),
		formatPct(a.Stats.TotalComponents-a.Stats.WithoutLicense, a.Stats.TotalComponents))
	fmt.Printf("%-24s%-24s%s\n", "  Hash Coverage:",
		formatPct(b.Stats.WithHashes, b.Stats.TotalComponents),
		formatPct(a.Stats.WithHashes, a.Stats.TotalComponents))
	fmt.Printf("%-24s%-24s%s\n", "  CPE Coverage:",
		formatPct(b.Stats.WithCPEs, b.Stats.TotalComponents),
		formatPct(a.Stats.WithCPEs, a.Stats.TotalComponents))
	fmt.Printf("%s\n", sep)
}

// PrintPackageSamples prints sample packages grouped by type for added/removed
func PrintPackageSamples(added, removed []analysis.PackageSamplesByType) {
	if len(added) > 0 {
		fmt.Printf("\n+ Added by type (up to 5 samples each):\n")
		for _, group := range added {
			fmt.Printf("  %s (%d total):\n", group.Type, group.Total)
			for _, s := range group.Samples {
				fmt.Printf("    + %s %s\n", s.Name, s.Version)
				for _, loc := range s.Locations {
					fmt.Printf("      %s\n", loc)
				}
			}
			remaining := group.Total - len(group.Samples)
			if remaining > 0 {
				fmt.Printf("    ...and %d more\n", remaining)
			}
		}
	}

	if len(removed) > 0 {
		fmt.Printf("\n- Removed by type (up to 5 samples each):\n")
		for _, group := range removed {
			fmt.Printf("  %s (%d total):\n", group.Type, group.Total)
			for _, s := range group.Samples {
				fmt.Printf("    - %s %s\n", s.Name, s.Version)
				for _, loc := range s.Locations {
					fmt.Printf("      %s\n", loc)
				}
			}
			remaining := group.Total - len(group.Samples)
			if remaining > 0 {
				fmt.Printf("    ...and %d more\n", remaining)
			}
		}
	}
}

// PrintTextDiff outputs the diff result in human-readable text format
func PrintTextDiff(result analysis.DiffResult) {
	if len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Changed) == 0 && result.Duplicates == nil && result.Dependencies == nil {
		fmt.Println("No differences found")
		return
	}

	// Print drift summary first if there are changes
	if result.DriftSummary != nil {
		fmt.Println("\n📊 Drift Summary:")
		if result.DriftSummary.VersionDrift > 0 {
			fmt.Printf("  📦 Version drift:   %d components\n", result.DriftSummary.VersionDrift)
		}
		if result.DriftSummary.IntegrityDrift > 0 {
			fmt.Printf("  ⚠️  Integrity drift: %d components (hash changed without version change!)\n", result.DriftSummary.IntegrityDrift)
		}
		if result.DriftSummary.MetadataDrift > 0 {
			fmt.Printf("  📝 Metadata drift:  %d components\n", result.DriftSummary.MetadataDrift)
		}
	}

	if len(result.Added) > 0 {
		fmt.Printf("\n+ Added (%d):\n", len(result.Added))
		for _, c := range result.Added {
			fmt.Printf("  + %s %s\n", c.Name, c.Version)
		}
	}

	if len(result.Removed) > 0 {
		fmt.Printf("\n- Removed (%d):\n", len(result.Removed))
		for _, c := range result.Removed {
			fmt.Printf("  - %s %s\n", c.Name, c.Version)
		}
	}

	if len(result.Changed) > 0 {
		fmt.Printf("\n~ Changed (%d):\n", len(result.Changed))
		for _, c := range result.Changed {
			driftIndicator := ""
			if c.Drift != nil {
				switch c.Drift.Type {
				case analysis.DriftTypeIntegrity:
					driftIndicator = " ⚠️  [INTEGRITY]"
				case analysis.DriftTypeVersion:
					driftIndicator = ""
				case analysis.DriftTypeMetadata:
					driftIndicator = " [metadata]"
				}
			}
			fmt.Printf("  ~ %s%s\n", c.Name, driftIndicator)
			for _, ch := range c.Changes {
				fmt.Printf("      %s\n", ch)
			}
		}
	}

	if result.Duplicates != nil {
		if len(result.Duplicates.Before) > 0 {
			fmt.Printf("\n! Duplicates in first SBOM (%d):\n", len(result.Duplicates.Before))
			for _, d := range result.Duplicates.Before {
				fmt.Printf("  ! %s: %v\n", d.Name, d.Versions)
			}
		}
		if len(result.Duplicates.After) > 0 {
			fmt.Printf("\n! Duplicates in second SBOM (%d):\n", len(result.Duplicates.After))
			for _, d := range result.Duplicates.After {
				fmt.Printf("  ! %s: %v\n", d.Name, d.Versions)
			}
		}
		if result.Duplicates.VersionDiff != nil {
			vd := result.Duplicates.VersionDiff
			if len(vd.NewDuplicates) > 0 {
				fmt.Printf("\n++ New duplicate groups (%d):\n", len(vd.NewDuplicates))
				for _, d := range vd.NewDuplicates {
					fmt.Printf("  ++ %s: %v\n", d.Name, d.Versions)
				}
			}
			if len(vd.ResolvedDuplicates) > 0 {
				fmt.Printf("\n-- Resolved duplicate groups (%d):\n", len(vd.ResolvedDuplicates))
				for _, d := range vd.ResolvedDuplicates {
					fmt.Printf("  -- %s: %v\n", d.Name, d.Versions)
				}
			}
			if len(vd.VersionsAdded) > 0 {
				fmt.Printf("\n+v Versions added to duplicates:\n")
				for id, versions := range vd.VersionsAdded {
					fmt.Printf("  %s: +%v\n", id, versions)
				}
			}
			if len(vd.VersionsRemoved) > 0 {
				fmt.Printf("\n-v Versions removed from duplicates:\n")
				for id, versions := range vd.VersionsRemoved {
					fmt.Printf("  %s: -%v\n", id, versions)
				}
			}
		}
		if len(result.Duplicates.Collisions) > 0 {
			fmt.Printf("\n⚠️  Identity Collisions (%d):\n", len(result.Duplicates.Collisions))
			for _, c := range result.Duplicates.Collisions {
				fmt.Printf("  [%s] %s\n", c.Reason, c.ID)
				for _, comp := range c.Components {
					fmt.Printf("    - %s %s\n", comp.Name, comp.Version)
				}
			}
		}
	}

	if result.Dependencies != nil {
		if len(result.Dependencies.AddedDeps) > 0 {
			fmt.Printf("\n>> Added dependencies:\n")
			for comp, deps := range result.Dependencies.AddedDeps {
				fmt.Printf("  %s: +%v\n", comp, deps)
			}
		}
		if len(result.Dependencies.RemovedDeps) > 0 {
			fmt.Printf("\n<< Removed dependencies:\n")
			for comp, deps := range result.Dependencies.RemovedDeps {
				fmt.Printf("  %s: -%v\n", comp, deps)
			}
		}

		// Transitive dependency changes
		if len(result.Dependencies.TransitiveNew) > 0 {
			fmt.Printf("\n🔗 New transitive dependencies (%d):\n", len(result.Dependencies.TransitiveNew))
			for _, td := range result.Dependencies.TransitiveNew {
				fmt.Printf("  + %s (depth %d)\n", td.Target, td.Depth)
				if len(td.Via) > 0 {
					fmt.Printf("    via: %v\n", td.Via)
				}
			}
		}
		if len(result.Dependencies.TransitiveLost) > 0 {
			fmt.Printf("\n🔓 Removed transitive dependencies (%d):\n", len(result.Dependencies.TransitiveLost))
			for _, td := range result.Dependencies.TransitiveLost {
				fmt.Printf("  - %s (depth %d)\n", td.Target, td.Depth)
			}
		}

		// Depth summary
		if result.Dependencies.DepthSummary != nil {
			ds := result.Dependencies.DepthSummary
			if ds.Depth1 > 0 || ds.Depth2 > 0 || ds.Depth3Plus > 0 {
				fmt.Printf("\n📊 New deps by depth:\n")
				if ds.Depth1 > 0 {
					fmt.Printf("  Depth 1 (direct):     %d\n", ds.Depth1)
				}
				if ds.Depth2 > 0 {
					fmt.Printf("  Depth 2:              %d\n", ds.Depth2)
				}
				if ds.Depth3Plus > 0 {
					fmt.Printf("  Depth 3+ (risky):     %d ⚠️\n", ds.Depth3Plus)
				}
			}
		}
	}

	fmt.Println()
}

// PrintViolations outputs policy violations in human-readable format
func PrintViolations(violations []policy.Violation) {
	if len(violations) == 0 {
		return
	}

	// Separate errors and warnings
	var errors, warnings []policy.Violation
	for _, v := range violations {
		if v.Severity == policy.SeverityWarning {
			warnings = append(warnings, v)
		} else {
			errors = append(errors, v)
		}
	}

	if len(errors) > 0 {
		fmt.Printf("\n❌ Policy Errors (%d):\n", len(errors))
		for _, v := range errors {
			fmt.Printf("  [%s] %s\n", v.Rule, v.Message)
		}
	}
	if len(warnings) > 0 {
		fmt.Printf("\n⚠️  Policy Warnings (%d):\n", len(warnings))
		for _, v := range warnings {
			fmt.Printf("  [%s] %s\n", v.Rule, v.Message)
		}
	}
	fmt.Println()
}
