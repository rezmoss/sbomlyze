package policy

import (
	"testing"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/compliance"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestLoadPolicy(t *testing.T) {
	t.Run("loads valid policy from JSON", func(t *testing.T) {
		jsonData := `{
			"max_added": 10,
			"max_removed": 5,
			"deny_licenses": ["GPL-3.0", "AGPL-3.0"],
			"require_licenses": true,
			"deny_integrity_drift": true,
			"max_depth": 3
		}`

		policy, err := Load([]byte(jsonData))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if policy.MaxAdded != 10 {
			t.Errorf("expected MaxAdded=10, got %d", policy.MaxAdded)
		}
		if len(policy.DenyLicenses) != 2 {
			t.Errorf("expected 2 denied licenses, got %d", len(policy.DenyLicenses))
		}
		if !policy.DenyIntegrityDrift {
			t.Error("expected DenyIntegrityDrift=true")
		}
		if policy.MaxDepth != 3 {
			t.Errorf("expected MaxDepth=3, got %d", policy.MaxDepth)
		}
	})

	t.Run("loads compliance score fields from JSON", func(t *testing.T) {
		jsonData := `{
			"min_ntia_score": 80,
			"min_cisa_score": 70,
			"min_bsi_score": 50,
			"min_overall_compliance": 75
		}`

		policy, err := Load([]byte(jsonData))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if policy.MinNTIAScore != 80 {
			t.Errorf("expected MinNTIAScore=80, got %d", policy.MinNTIAScore)
		}
		if policy.MinCISAScore != 70 {
			t.Errorf("expected MinCISAScore=70, got %d", policy.MinCISAScore)
		}
		if policy.MinBSIScore != 50 {
			t.Errorf("expected MinBSIScore=50, got %d", policy.MinBSIScore)
		}
		if policy.MinOverallCompliance != 75 {
			t.Errorf("expected MinOverallCompliance=75, got %d", policy.MinOverallCompliance)
		}
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		_, err := Load([]byte("invalid"))
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestEvaluatePolicy(t *testing.T) {
	t.Run("passes when within limits", func(t *testing.T) {
		policy := Policy{
			MaxAdded:   10,
			MaxRemoved: 10,
		}
		result := analysis.DiffResult{
			Added:   make([]sbom.Component, 5),
			Removed: make([]sbom.Component, 3),
		}

		violations := Evaluate(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d: %v", len(violations), violations)
		}
	})

	t.Run("fails when too many added", func(t *testing.T) {
		policy := Policy{MaxAdded: 2}
		result := analysis.DiffResult{
			Added: make([]sbom.Component, 5),
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Severity != SeverityError {
			t.Error("expected severity error")
		}
	})

	t.Run("fails when too many removed", func(t *testing.T) {
		policy := Policy{MaxRemoved: 2}
		result := analysis.DiffResult{
			Removed: make([]sbom.Component, 5),
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("detects denied licenses in added components", func(t *testing.T) {
		policy := Policy{
			DenyLicenses: []string{"GPL-3.0", "AGPL-3.0"},
		}
		result := analysis.DiffResult{
			Added: []sbom.Component{
				{Name: "lib1", Licenses: []string{"MIT"}},
				{Name: "lib2", Licenses: []string{"GPL-3.0"}},
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("detects missing licenses when required", func(t *testing.T) {
		policy := Policy{RequireLicenses: true}
		result := analysis.DiffResult{
			Added: []sbom.Component{
				{Name: "lib1", Licenses: []string{"MIT"}},
				{Name: "lib2", Licenses: nil},
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("fails when too many changes", func(t *testing.T) {
		policy := Policy{MaxChanged: 3}
		result := analysis.DiffResult{
			Changed: make([]analysis.ChangedComponent, 5),
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("fails when duplicates exist and not allowed", func(t *testing.T) {
		policy := Policy{DenyDuplicates: true}
		result := analysis.DiffResult{
			Duplicates: &analysis.DuplicateReport{
				After: []analysis.DuplicateGroup{{Name: "lodash"}},
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("multiple violations reported", func(t *testing.T) {
		policy := Policy{
			MaxAdded:   1,
			MaxRemoved: 1,
		}
		result := analysis.DiffResult{
			Added:   make([]sbom.Component, 5),
			Removed: make([]sbom.Component, 5),
		}

		violations := Evaluate(policy, result)

		if len(violations) != 2 {
			t.Errorf("expected 2 violations, got %d", len(violations))
		}
	})

	t.Run("zero limits are ignored", func(t *testing.T) {
		policy := Policy{
			MaxAdded:   0,
			MaxRemoved: 0,
			MaxChanged: 0,
		}
		result := analysis.DiffResult{
			Added:   make([]sbom.Component, 5),
			Removed: make([]sbom.Component, 5),
			Changed: make([]analysis.ChangedComponent, 5),
		}

		violations := Evaluate(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations (zero means unlimited), got %d", len(violations))
		}
	})
}

func TestDenyIntegrityDrift(t *testing.T) {
	t.Run("fails when integrity drift detected", func(t *testing.T) {
		policy := Policy{DenyIntegrityDrift: true}
		result := analysis.DiffResult{
			Changed: []analysis.ChangedComponent{
				{
					Name: "suspicious-pkg",
					Drift: &analysis.DriftInfo{
						Type: analysis.DriftTypeIntegrity,
					},
				},
			},
			DriftSummary: &analysis.DriftSummary{
				IntegrityDrift: 1,
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Rule != "deny_integrity_drift" {
			t.Errorf("expected rule deny_integrity_drift, got %s", violations[0].Rule)
		}
		if violations[0].Severity != SeverityError {
			t.Error("expected severity error")
		}
	})

	t.Run("passes when no integrity drift", func(t *testing.T) {
		policy := Policy{DenyIntegrityDrift: true}
		result := analysis.DiffResult{
			Changed: []analysis.ChangedComponent{
				{
					Name: "normal-pkg",
					Drift: &analysis.DriftInfo{
						Type: analysis.DriftTypeVersion,
					},
				},
			},
			DriftSummary: &analysis.DriftSummary{
				VersionDrift:   1,
				IntegrityDrift: 0,
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d", len(violations))
		}
	})
}

func TestMaxDepth(t *testing.T) {
	t.Run("fails when new deps exceed max depth", func(t *testing.T) {
		policy := Policy{MaxDepth: 3}
		result := analysis.DiffResult{
			Dependencies: &analysis.DependencyDiff{
				TransitiveNew: []analysis.TransitiveDep{
					{Target: "deep-lib", Depth: 4},
					{Target: "another-deep", Depth: 5},
				},
				DepthSummary: &analysis.DepthSummary{
					Depth3Plus: 2,
				},
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Rule != "max_depth" {
			t.Errorf("expected rule max_depth, got %s", violations[0].Rule)
		}
	})

	t.Run("passes when deps within max depth", func(t *testing.T) {
		policy := Policy{MaxDepth: 3}
		result := analysis.DiffResult{
			Dependencies: &analysis.DependencyDiff{
				TransitiveNew: []analysis.TransitiveDep{
					{Target: "lib-a", Depth: 2},
				},
				DepthSummary: &analysis.DepthSummary{
					Depth2: 1,
				},
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d", len(violations))
		}
	})
}

func TestWarnSupplierChange(t *testing.T) {
	t.Run("warns when supplier changes", func(t *testing.T) {
		policy := Policy{WarnSupplierChange: true}
		result := analysis.DiffResult{
			Changed: []analysis.ChangedComponent{
				{
					Name:   "pkg",
					Before: sbom.Component{Supplier: "Original Corp"},
					After:  sbom.Component{Supplier: "New Corp"},
				},
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Rule != "warn_supplier_change" {
			t.Errorf("expected rule warn_supplier_change, got %s", violations[0].Rule)
		}
		if violations[0].Severity != SeverityWarning {
			t.Error("expected severity warning")
		}
	})

	t.Run("no warning when supplier unchanged", func(t *testing.T) {
		policy := Policy{WarnSupplierChange: true}
		result := analysis.DiffResult{
			Changed: []analysis.ChangedComponent{
				{
					Name:   "pkg",
					Before: sbom.Component{Supplier: "Same Corp"},
					After:  sbom.Component{Supplier: "Same Corp"},
				},
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d", len(violations))
		}
	})
}

func TestWarnNewTransitive(t *testing.T) {
	t.Run("warns when new transitive deps found", func(t *testing.T) {
		policy := Policy{WarnNewTransitive: true}
		result := analysis.DiffResult{
			Dependencies: &analysis.DependencyDiff{
				TransitiveNew: []analysis.TransitiveDep{
					{Target: "new-dep", Depth: 2},
				},
			},
		}

		violations := Evaluate(policy, result)

		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Severity != SeverityWarning {
			t.Error("expected severity warning")
		}
	})
}

func TestHasErrors(t *testing.T) {
	t.Run("returns true when errors present", func(t *testing.T) {
		violations := []Violation{
			{Rule: "warning", Severity: SeverityWarning},
			{Rule: "error", Severity: SeverityError},
		}

		if !HasErrors(violations) {
			t.Error("expected HasErrors=true")
		}
	})

	t.Run("returns false when only warnings", func(t *testing.T) {
		violations := []Violation{
			{Rule: "warning1", Severity: SeverityWarning},
			{Rule: "warning2", Severity: SeverityWarning},
		}

		if HasErrors(violations) {
			t.Error("expected HasErrors=false")
		}
	})

	t.Run("returns false when no violations", func(t *testing.T) {
		if HasErrors(nil) {
			t.Error("expected HasErrors=false for empty list")
		}
	})
}

func TestEvaluateCompliance(t *testing.T) {
	t.Run("no violations when scores meet thresholds", func(t *testing.T) {
		pol := Policy{
			MinNTIAScore:         80,
			MinCISAScore:         70,
			MinOverallCompliance: 75,
		}
		report := compliance.Report{
			NTIA: &compliance.FrameworkResult{Score: 100, Passed: 7, Total: 7},
			CISA: &compliance.FrameworkResult{Score: 100, Passed: 11, Total: 11},
			BSI:  &compliance.FrameworkResult{Score: 90, Passed: 10, Total: 11},
			Overall: 96,
		}

		violations := EvaluateCompliance(pol, report)
		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d: %v", len(violations), violations)
		}
	})

	t.Run("violates when NTIA score below threshold", func(t *testing.T) {
		pol := Policy{MinNTIAScore: 80}
		report := compliance.Report{
			NTIA: &compliance.FrameworkResult{Score: 57, Passed: 4, Total: 7},
			Overall: 57,
		}

		violations := EvaluateCompliance(pol, report)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Rule != "min_ntia_score" {
			t.Errorf("expected rule min_ntia_score, got %s", violations[0].Rule)
		}
		if violations[0].Severity != SeverityError {
			t.Error("expected severity error")
		}
	})

	t.Run("violates when CISA score below threshold", func(t *testing.T) {
		pol := Policy{MinCISAScore: 90}
		report := compliance.Report{
			CISA: &compliance.FrameworkResult{Score: 72, Passed: 8, Total: 11},
			Overall: 72,
		}

		violations := EvaluateCompliance(pol, report)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Rule != "min_cisa_score" {
			t.Errorf("expected rule min_cisa_score, got %s", violations[0].Rule)
		}
	})

	t.Run("violates when BSI score below threshold", func(t *testing.T) {
		pol := Policy{MinBSIScore: 80}
		report := compliance.Report{
			BSI: &compliance.FrameworkResult{Score: 54, Passed: 6, Total: 11},
			Overall: 54,
		}

		violations := EvaluateCompliance(pol, report)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Rule != "min_bsi_score" {
			t.Errorf("expected rule min_bsi_score, got %s", violations[0].Rule)
		}
	})

	t.Run("violates when overall compliance below threshold", func(t *testing.T) {
		pol := Policy{MinOverallCompliance: 80}
		report := compliance.Report{
			NTIA: &compliance.FrameworkResult{Score: 100, Passed: 7, Total: 7},
			CISA: &compliance.FrameworkResult{Score: 50, Passed: 5, Total: 11},
			Overall: 50,
		}

		violations := EvaluateCompliance(pol, report)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Rule != "min_overall_compliance" {
			t.Errorf("expected rule min_overall_compliance, got %s", violations[0].Rule)
		}
	})

	t.Run("multiple compliance violations", func(t *testing.T) {
		pol := Policy{
			MinNTIAScore:         80,
			MinCISAScore:         80,
			MinOverallCompliance: 80,
		}
		report := compliance.Report{
			NTIA: &compliance.FrameworkResult{Score: 57, Passed: 4, Total: 7},
			CISA: &compliance.FrameworkResult{Score: 45, Passed: 5, Total: 11},
			Overall: 34,
		}

		violations := EvaluateCompliance(pol, report)
		if len(violations) != 3 {
			t.Errorf("expected 3 violations, got %d", len(violations))
		}
	})

	t.Run("skips nil framework results", func(t *testing.T) {
		pol := Policy{
			MinNTIAScore: 80,
			MinCISAScore: 80,
			MinBSIScore:  80,
		}
		report := compliance.Report{
			NTIA: nil, // empty SBOM = nil NTIA
			Overall: 0,
		}

		violations := EvaluateCompliance(pol, report)
		// Should only get min_overall_compliance (0 < 80 would trigger if set),
		// but NTIA, CISA, BSI are nil so they're skipped
		if len(violations) != 0 {
			t.Errorf("expected 0 violations (nil frameworks are skipped), got %d", len(violations))
		}
	})

	t.Run("zero thresholds are ignored", func(t *testing.T) {
		pol := Policy{} // all zeros
		report := compliance.Report{
			NTIA: &compliance.FrameworkResult{Score: 10, Passed: 1, Total: 7},
			Overall: 10,
		}

		violations := EvaluateCompliance(pol, report)
		if len(violations) != 0 {
			t.Errorf("expected no violations (zero thresholds = disabled), got %d", len(violations))
		}
	})
}
