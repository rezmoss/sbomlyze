package main

import "testing"

func TestLoadPolicy(t *testing.T) {
	t.Run("loads valid policy from JSON", func(t *testing.T) {
		jsonData := `{
			"max_added": 10,
			"max_removed": 5,
			"deny_licenses": ["GPL-3.0", "AGPL-3.0"],
			"require_licenses": true,
			"max_critical_changes": 0
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

func TestPolicyViolation(t *testing.T) {
	t.Run("violation has correct fields", func(t *testing.T) {
		v := PolicyViolation{
			Rule:    "max_added",
			Message: "too many components added: 10 > 5",
		}

		if v.Rule != "max_added" {
			t.Errorf("expected rule=max_added, got %s", v.Rule)
		}
	})
}
