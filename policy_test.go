package main

import "testing"

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

		policy, err := loadPolicyFromJSON([]byte(jsonData))
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

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		_, err := loadPolicyFromJSON([]byte("invalid"))
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
		result := DiffResult{
			Added:   make([]Component, 5),
			Removed: make([]Component, 3),
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d: %v", len(violations), violations)
		}
	})

	t.Run("fails when too many added", func(t *testing.T) {
		policy := Policy{MaxAdded: 2}
		result := DiffResult{
			Added: make([]Component, 5),
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Severity != SeverityError {
			t.Error("expected severity error")
		}
	})

	t.Run("fails when too many removed", func(t *testing.T) {
		policy := Policy{MaxRemoved: 2}
		result := DiffResult{
			Removed: make([]Component, 5),
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("detects denied licenses in added components", func(t *testing.T) {
		policy := Policy{
			DenyLicenses: []string{"GPL-3.0", "AGPL-3.0"},
		}
		result := DiffResult{
			Added: []Component{
				{Name: "lib1", Licenses: []string{"MIT"}},
				{Name: "lib2", Licenses: []string{"GPL-3.0"}},
			},
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("detects missing licenses when required", func(t *testing.T) {
		policy := Policy{RequireLicenses: true}
		result := DiffResult{
			Added: []Component{
				{Name: "lib1", Licenses: []string{"MIT"}},
				{Name: "lib2", Licenses: nil},
			},
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("fails when too many changes", func(t *testing.T) {
		policy := Policy{MaxChanged: 3}
		result := DiffResult{
			Changed: make([]ChangedComponent, 5),
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("fails when duplicates exist and not allowed", func(t *testing.T) {
		policy := Policy{DenyDuplicates: true}
		result := DiffResult{
			Duplicates: &DuplicateReport{
				After: []DuplicateGroup{{Name: "lodash"}},
			},
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 1 {
			t.Errorf("expected 1 violation, got %d", len(violations))
		}
	})

	t.Run("multiple violations reported", func(t *testing.T) {
		policy := Policy{
			MaxAdded:   1,
			MaxRemoved: 1,
		}
		result := DiffResult{
			Added:   make([]Component, 5),
			Removed: make([]Component, 5),
		}

		violations := evaluatePolicy(policy, result)

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
		result := DiffResult{
			Added:   make([]Component, 5),
			Removed: make([]Component, 5),
			Changed: make([]ChangedComponent, 5),
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations (zero means unlimited), got %d", len(violations))
		}
	})
}

func TestDenyIntegrityDrift(t *testing.T) {
	t.Run("fails when integrity drift detected", func(t *testing.T) {
		policy := Policy{DenyIntegrityDrift: true}
		result := DiffResult{
			Changed: []ChangedComponent{
				{
					Name: "suspicious-pkg",
					Drift: &DriftInfo{
						Type: DriftTypeIntegrity,
					},
				},
			},
			DriftSummary: &DriftSummary{
				IntegrityDrift: 1,
			},
		}

		violations := evaluatePolicy(policy, result)

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
		result := DiffResult{
			Changed: []ChangedComponent{
				{
					Name: "normal-pkg",
					Drift: &DriftInfo{
						Type: DriftTypeVersion,
					},
				},
			},
			DriftSummary: &DriftSummary{
				VersionDrift:   1,
				IntegrityDrift: 0,
			},
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d", len(violations))
		}
	})
}

func TestMaxDepth(t *testing.T) {
	t.Run("fails when new deps exceed max depth", func(t *testing.T) {
		policy := Policy{MaxDepth: 3}
		result := DiffResult{
			Dependencies: &DependencyDiff{
				TransitiveNew: []TransitiveDep{
					{Target: "deep-lib", Depth: 4},
					{Target: "another-deep", Depth: 5},
				},
				DepthSummary: &DepthSummary{
					Depth3Plus: 2,
				},
			},
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if violations[0].Rule != "max_depth" {
			t.Errorf("expected rule max_depth, got %s", violations[0].Rule)
		}
	})

	t.Run("passes when deps within max depth", func(t *testing.T) {
		policy := Policy{MaxDepth: 3}
		result := DiffResult{
			Dependencies: &DependencyDiff{
				TransitiveNew: []TransitiveDep{
					{Target: "lib-a", Depth: 2},
				},
				DepthSummary: &DepthSummary{
					Depth2: 1,
				},
			},
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d", len(violations))
		}
	})
}

func TestWarnSupplierChange(t *testing.T) {
	t.Run("warns when supplier changes", func(t *testing.T) {
		policy := Policy{WarnSupplierChange: true}
		result := DiffResult{
			Changed: []ChangedComponent{
				{
					Name:   "pkg",
					Before: Component{Supplier: "Original Corp"},
					After:  Component{Supplier: "New Corp"},
				},
			},
		}

		violations := evaluatePolicy(policy, result)

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
		result := DiffResult{
			Changed: []ChangedComponent{
				{
					Name:   "pkg",
					Before: Component{Supplier: "Same Corp"},
					After:  Component{Supplier: "Same Corp"},
				},
			},
		}

		violations := evaluatePolicy(policy, result)

		if len(violations) != 0 {
			t.Errorf("expected no violations, got %d", len(violations))
		}
	})
}

func TestWarnNewTransitive(t *testing.T) {
	t.Run("warns when new transitive deps found", func(t *testing.T) {
		policy := Policy{WarnNewTransitive: true}
		result := DiffResult{
			Dependencies: &DependencyDiff{
				TransitiveNew: []TransitiveDep{
					{Target: "new-dep", Depth: 2},
				},
			},
		}

		violations := evaluatePolicy(policy, result)

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
		violations := []PolicyViolation{
			{Rule: "warning", Severity: SeverityWarning},
			{Rule: "error", Severity: SeverityError},
		}

		if !HasErrors(violations) {
			t.Error("expected HasErrors=true")
		}
	})

	t.Run("returns false when only warnings", func(t *testing.T) {
		violations := []PolicyViolation{
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

func TestPolicyViolation(t *testing.T) {
	t.Run("violation has correct fields", func(t *testing.T) {
		v := PolicyViolation{
			Rule:     "max_added",
			Message:  "too many components added: 10 > 5",
			Severity: SeverityError,
		}

		if v.Rule != "max_added" {
			t.Errorf("expected rule=max_added, got %s", v.Rule)
		}
		if v.Severity != SeverityError {
			t.Errorf("expected severity=error, got %s", v.Severity)
		}
	})
}
