package main

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
)

func TestGenerateSARIF(t *testing.T) {
	t.Run("generates valid SARIF structure", func(t *testing.T) {
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
		violations := []PolicyViolation{
			{Rule: "test", Message: "test message", Severity: SeverityError},
		}

		sarif := generateSARIF(result, violations, "test.json")

		if sarif.Version != "2.1.0" {
			t.Errorf("expected SARIF version 2.1.0, got %s", sarif.Version)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
		}
		if sarif.Runs[0].Tool.Driver.Name != "sbomlyze" {
			t.Error("expected tool name sbomlyze")
		}
		if len(sarif.Runs[0].Results) == 0 {
			t.Error("expected at least one result")
		}
	})

	t.Run("includes integrity drift results", func(t *testing.T) {
		result := DiffResult{
			Changed: []ChangedComponent{
				{
					Name: "pkg1",
					Drift: &DriftInfo{
						Type: DriftTypeIntegrity,
					},
				},
			},
			DriftSummary: &DriftSummary{
				IntegrityDrift: 1,
			},
		}

		sarif := generateSARIF(result, nil, "test.json")

		found := false
		for _, r := range sarif.Runs[0].Results {
			if r.RuleID == "integrity-drift" {
				found = true
				if r.Level != "error" {
					t.Error("integrity drift should be error level")
				}
			}
		}
		if !found {
			t.Error("expected integrity-drift result")
		}
	})

	t.Run("includes deep dependency results", func(t *testing.T) {
		result := DiffResult{
			Dependencies: &DependencyDiff{
				TransitiveNew: []TransitiveDep{
					{Target: "deep-lib", Depth: 4},
				},
			},
		}

		sarif := generateSARIF(result, nil, "test.json")

		found := false
		for _, r := range sarif.Runs[0].Results {
			if r.RuleID == "deep-dependency" {
				found = true
				if r.Level != "warning" {
					t.Error("deep dependency should be warning level")
				}
			}
		}
		if !found {
			t.Error("expected deep-dependency result")
		}
	})

	t.Run("SARIF is valid JSON", func(t *testing.T) {
		sarif := generateSARIF(DiffResult{}, nil, "test.json")

		data, err := json.Marshal(sarif)
		if err != nil {
			t.Fatalf("failed to marshal SARIF: %v", err)
		}
		if len(data) == 0 {
			t.Error("SARIF JSON should not be empty")
		}
	})
}

func TestGenerateJUnit(t *testing.T) {
	t.Run("generates valid JUnit structure", func(t *testing.T) {
		result := DiffResult{}
		violations := []PolicyViolation{}

		junit := generateJUnit(result, violations)

		if junit.Name != "sbomlyze" {
			t.Errorf("expected name sbomlyze, got %s", junit.Name)
		}
		if len(junit.TestSuite) != 1 {
			t.Fatalf("expected 1 test suite, got %d", len(junit.TestSuite))
		}
	})

	t.Run("counts failures correctly", func(t *testing.T) {
		result := DiffResult{
			DriftSummary: &DriftSummary{
				IntegrityDrift: 2,
			},
		}
		violations := []PolicyViolation{
			{Rule: "test", Severity: SeverityError},
		}

		junit := generateJUnit(result, violations)

		if junit.Failures < 2 {
			t.Errorf("expected at least 2 failures, got %d", junit.Failures)
		}
	})

	t.Run("JUnit is valid XML", func(t *testing.T) {
		junit := generateJUnit(DiffResult{}, nil)

		data, err := xml.Marshal(junit)
		if err != nil {
			t.Fatalf("failed to marshal JUnit: %v", err)
		}
		if len(data) == 0 {
			t.Error("JUnit XML should not be empty")
		}
	})
}

func TestGenerateMarkdown(t *testing.T) {
	t.Run("generates markdown with summary", func(t *testing.T) {
		result := DiffResult{
			Added:   []Component{{Name: "lib1", Version: "1.0"}},
			Removed: []Component{{Name: "lib2", Version: "2.0"}},
			Changed: []ChangedComponent{
				{
					Name:   "lib3",
					Before: Component{Version: "1.0"},
					After:  Component{Version: "2.0"},
					Drift:  &DriftInfo{Type: DriftTypeVersion},
				},
			},
		}

		md := generateMarkdown(result, nil)

		if !strings.Contains(md, "## 📦 SBOM Diff Report") {
			t.Error("expected markdown header")
		}
		if !strings.Contains(md, "| Added | 1 |") {
			t.Error("expected added count in summary")
		}
		if !strings.Contains(md, "lib1") {
			t.Error("expected added component name")
		}
	})

	t.Run("includes drift summary", func(t *testing.T) {
		result := DiffResult{
			DriftSummary: &DriftSummary{
				VersionDrift:   5,
				IntegrityDrift: 1,
			},
		}

		md := generateMarkdown(result, nil)

		if !strings.Contains(md, "Drift Summary") {
			t.Error("expected drift summary section")
		}
		if !strings.Contains(md, "Integrity") {
			t.Error("expected integrity drift in summary")
		}
	})

	t.Run("includes policy violations", func(t *testing.T) {
		violations := []PolicyViolation{
			{Rule: "test-error", Message: "error message", Severity: SeverityError},
			{Rule: "test-warn", Message: "warn message", Severity: SeverityWarning},
		}

		md := generateMarkdown(DiffResult{}, violations)

		if !strings.Contains(md, "Policy Errors") {
			t.Error("expected policy errors section")
		}
		if !strings.Contains(md, "Policy Warnings") {
			t.Error("expected policy warnings section")
		}
	})

	t.Run("uses collapsible sections", func(t *testing.T) {
		result := DiffResult{
			Added: []Component{{Name: "lib1", Version: "1.0"}},
		}

		md := generateMarkdown(result, nil)

		if !strings.Contains(md, "<details>") {
			t.Error("expected collapsible sections")
		}
		if !strings.Contains(md, "</details>") {
			t.Error("expected closing details tag")
		}
	})
}

func TestGenerateJSONPatch(t *testing.T) {
	t.Run("generates add operations for added components", func(t *testing.T) {
		result := DiffResult{
			Added: []Component{
				{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
			},
		}

		ops := generateJSONPatch(result)

		if len(ops) == 0 {
			t.Fatal("expected at least one operation")
		}
		if ops[0].Op != "add" {
			t.Errorf("expected add operation, got %s", ops[0].Op)
		}
	})

	t.Run("generates remove operations for removed components", func(t *testing.T) {
		result := DiffResult{
			Removed: []Component{
				{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
			},
		}

		ops := generateJSONPatch(result)

		if len(ops) == 0 {
			t.Fatal("expected at least one operation")
		}
		if ops[0].Op != "remove" {
			t.Errorf("expected remove operation, got %s", ops[0].Op)
		}
	})

	t.Run("generates replace operations for version changes", func(t *testing.T) {
		result := DiffResult{
			Changed: []ChangedComponent{
				{
					ID:     "pkg:npm/lodash",
					Before: Component{Version: "4.17.20"},
					After:  Component{Version: "4.17.21"},
				},
			},
		}

		ops := generateJSONPatch(result)

		found := false
		for _, op := range ops {
			if op.Op == "replace" && strings.Contains(op.Path, "version") {
				found = true
			}
		}
		if !found {
			t.Error("expected replace operation for version")
		}
	})

	t.Run("JSON patch is valid JSON", func(t *testing.T) {
		result := DiffResult{
			Added: []Component{{ID: "test", Name: "test", Version: "1.0"}},
		}

		ops := generateJSONPatch(result)
		data, err := json.Marshal(ops)
		if err != nil {
			t.Fatalf("failed to marshal JSON patch: %v", err)
		}
		if len(data) == 0 {
			t.Error("JSON patch should not be empty")
		}
	})
}

func TestStringSliceEqual(t *testing.T) {
	t.Run("equal slices", func(t *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"a", "b", "c"}
		if !stringSliceEqual(a, b) {
			t.Error("expected slices to be equal")
		}
	})

	t.Run("different length", func(t *testing.T) {
		a := []string{"a", "b"}
		b := []string{"a", "b", "c"}
		if stringSliceEqual(a, b) {
			t.Error("expected slices to be unequal")
		}
	})

	t.Run("different content", func(t *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"a", "x", "c"}
		if stringSliceEqual(a, b) {
			t.Error("expected slices to be unequal")
		}
	})
}

func TestHashMapEqual(t *testing.T) {
	t.Run("equal maps", func(t *testing.T) {
		a := map[string]string{"SHA256": "abc"}
		b := map[string]string{"SHA256": "abc"}
		if !hashMapEqual(a, b) {
			t.Error("expected maps to be equal")
		}
	})

	t.Run("different values", func(t *testing.T) {
		a := map[string]string{"SHA256": "abc"}
		b := map[string]string{"SHA256": "xyz"}
		if hashMapEqual(a, b) {
			t.Error("expected maps to be unequal")
		}
	})
}
