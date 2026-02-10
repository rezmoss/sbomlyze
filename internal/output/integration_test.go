//go:build integration

package output

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/policy"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func buildRealDiffResult() analysis.DiffResult {
	before := []sbom.Component{
		{ID: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20",
			Licenses: []string{"MIT"}, Hashes: map[string]string{"SHA256": "aaa111"}},
		{ID: "pkg:npm/express@4.17.0", Name: "express", Version: "4.17.0", PURL: "pkg:npm/express@4.17.0",
			Licenses: []string{"MIT"}},
		{ID: "pkg:npm/removed-pkg@1.0.0", Name: "removed-pkg", Version: "1.0.0", PURL: "pkg:npm/removed-pkg@1.0.0"},
	}
	after := []sbom.Component{
		{ID: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21",
			Licenses: []string{"MIT"}, Hashes: map[string]string{"SHA256": "bbb222"}},
		{ID: "pkg:npm/express@4.17.0", Name: "express", Version: "4.17.0", PURL: "pkg:npm/express@4.17.0",
			Licenses: []string{"MIT", "Apache-2.0"}},
		{ID: "pkg:npm/new-pkg@2.0.0", Name: "new-pkg", Version: "2.0.0", PURL: "pkg:npm/new-pkg@2.0.0",
			Licenses: []string{"BSD-3-Clause"}},
	}
	return analysis.DiffComponents(before, after)
}

func TestSARIFOutput_ValidSchema(t *testing.T) {
	result := buildRealDiffResult()
	violations := []policy.Violation{
		{Rule: "test_rule", Message: "test violation", Severity: policy.SeverityError},
	}

	sarif := GenerateSARIF(result, violations, "test-sbom.json")

	// Check schema URL
	if sarif.Schema != "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json" {
		t.Errorf("unexpected schema: %s", sarif.Schema)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", sarif.Version)
	}

	// Verify it serializes to valid JSON
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal SARIF: %v", err)
	}

	// Verify we can parse it back
	var parsed SARIFReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}

	if len(parsed.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(parsed.Runs))
	}
	if len(parsed.Runs[0].Tool.Driver.Rules) == 0 {
		t.Error("expected non-empty rules")
	}
	if len(parsed.Runs[0].Results) == 0 {
		t.Error("expected non-empty results")
	}
}

func TestJUnitOutput_ValidXML(t *testing.T) {
	result := buildRealDiffResult()
	violations := []policy.Violation{
		{Rule: "test_rule", Message: "test violation", Severity: policy.SeverityError},
		{Rule: "test_warn", Message: "test warning", Severity: policy.SeverityWarning},
	}

	junit := GenerateJUnit(result, violations)

	// Verify it serializes to valid XML
	data, err := xml.MarshalIndent(junit, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal JUnit XML: %v", err)
	}

	// Verify we can parse it back
	var parsed JUnitTestSuites
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JUnit XML: %v", err)
	}

	if parsed.Name != "sbomlyze" {
		t.Errorf("expected name 'sbomlyze', got %s", parsed.Name)
	}
	if parsed.Tests == 0 {
		t.Error("expected >0 tests")
	}
	if len(parsed.TestSuite) == 0 {
		t.Error("expected non-empty test suites")
	}
}

func TestMarkdownOutput_ValidMarkdown(t *testing.T) {
	result := buildRealDiffResult()
	violations := []policy.Violation{
		{Rule: "test_rule", Message: "test violation", Severity: policy.SeverityError},
	}

	md := GenerateMarkdown(result, violations)

	// Check expected markdown structure
	if !strings.Contains(md, "## ") {
		t.Error("expected H2 headers in markdown")
	}
	if !strings.Contains(md, "### Summary") {
		t.Error("expected Summary section")
	}
	if !strings.Contains(md, "| Metric | Count |") {
		t.Error("expected summary table")
	}
	if !strings.Contains(md, "<details>") {
		t.Error("expected collapsible details sections")
	}
	if !strings.Contains(md, "Policy Errors") {
		t.Error("expected policy errors section")
	}
}

func TestJSONPatch_ValidRFC6902(t *testing.T) {
	result := buildRealDiffResult()
	patch := GenerateJSONPatch(result)

	if len(patch) == 0 {
		t.Fatal("expected non-empty patch for diff with changes")
	}

	// Verify all ops are valid RFC 6902 operations
	validOps := map[string]bool{"add": true, "remove": true, "replace": true, "move": true, "copy": true, "test": true}
	for _, op := range patch {
		if !validOps[op.Op] {
			t.Errorf("invalid RFC 6902 operation: %s", op.Op)
		}
		if op.Path == "" {
			t.Errorf("empty path in patch operation: %+v", op)
		}
	}

	// Verify it serializes to valid JSON
	data, err := json.MarshalIndent(patch, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal JSON Patch: %v", err)
	}

	// Verify we can parse it back
	var parsed []JSONPatchOp
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON Patch: %v", err)
	}
	if len(parsed) != len(patch) {
		t.Errorf("round-trip changed patch count: %d -> %d", len(patch), len(parsed))
	}
}

