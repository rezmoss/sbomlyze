package output

import (
	"fmt"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/policy"
)

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
