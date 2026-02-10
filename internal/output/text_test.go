package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/policy"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old
	return string(out)
}

func TestPrintTextDiff_NoDifferences(t *testing.T) {
	out := captureOutput(func() {
		PrintTextDiff(analysis.DiffResult{})
	})
	if !strings.Contains(out, "No differences found") {
		t.Errorf("expected 'No differences found', got: %s", out)
	}
}

func TestPrintTextDiff_Added(t *testing.T) {
	result := analysis.DiffResult{
		Added: []sbom.Component{
			{Name: "new-pkg", Version: "1.0.0"},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "+ Added") {
		t.Error("expected '+ Added' section")
	}
	if !strings.Contains(out, "new-pkg") {
		t.Error("expected component name in output")
	}
}

func TestPrintTextDiff_Removed(t *testing.T) {
	result := analysis.DiffResult{
		Removed: []sbom.Component{
			{Name: "old-pkg", Version: "1.0.0"},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "- Removed") {
		t.Error("expected '- Removed' section")
	}
	if !strings.Contains(out, "old-pkg") {
		t.Error("expected component name in output")
	}
}

func TestPrintTextDiff_Changed(t *testing.T) {
	result := analysis.DiffResult{
		Changed: []analysis.ChangedComponent{
			{
				Name:    "changed-pkg",
				Changes: []string{"version: 1.0 -> 2.0"},
				Drift:   &analysis.DriftInfo{Type: analysis.DriftTypeVersion},
			},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "~ Changed") {
		t.Error("expected '~ Changed' section")
	}
	if !strings.Contains(out, "changed-pkg") {
		t.Error("expected component name in output")
	}
}

func TestPrintTextDiff_IntegrityDrift(t *testing.T) {
	result := analysis.DiffResult{
		Changed: []analysis.ChangedComponent{
			{
				Name:    "suspicious-pkg",
				Changes: []string{"hash[SHA256]: abc -> xyz"},
				Drift:   &analysis.DriftInfo{Type: analysis.DriftTypeIntegrity},
			},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "[INTEGRITY]") {
		t.Error("expected [INTEGRITY] indicator")
	}
}

func TestPrintTextDiff_MetadataDrift(t *testing.T) {
	result := analysis.DiffResult{
		Changed: []analysis.ChangedComponent{
			{
				Name:    "meta-pkg",
				Changes: []string{"licenses changed"},
				Drift:   &analysis.DriftInfo{Type: analysis.DriftTypeMetadata},
			},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "[metadata]") {
		t.Error("expected [metadata] indicator")
	}
}

func TestPrintTextDiff_Duplicates(t *testing.T) {
	result := analysis.DiffResult{
		Duplicates: &analysis.DuplicateReport{
			Before: []analysis.DuplicateGroup{
				{Name: "dup-pkg", Versions: []string{"1.0", "2.0"}},
			},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "Duplicates") {
		t.Error("expected Duplicates section")
	}
}

func TestPrintTextDiff_Dependencies(t *testing.T) {
	result := analysis.DiffResult{
		Dependencies: &analysis.DependencyDiff{
			AddedDeps: map[string][]string{
				"pkg-a": {"pkg-b", "pkg-c"},
			},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "Added dependencies") {
		t.Error("expected 'Added dependencies' section")
	}
}

func TestPrintTextDiff_TransitiveDeps(t *testing.T) {
	result := analysis.DiffResult{
		Dependencies: &analysis.DependencyDiff{
			TransitiveNew: []analysis.TransitiveDep{
				{Target: "deep-lib", Via: []string{"root", "mid", "deep-lib"}, Depth: 3},
			},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "transitive") {
		t.Error("expected transitive section")
	}
	if !strings.Contains(out, "depth") {
		t.Error("expected depth info")
	}
}

func TestPrintTextDiff_DepthSummary(t *testing.T) {
	result := analysis.DiffResult{
		Dependencies: &analysis.DependencyDiff{
			TransitiveNew: []analysis.TransitiveDep{
				{Target: "a", Depth: 2},
			},
			DepthSummary: &analysis.DepthSummary{
				Depth1: 1, Depth2: 2, Depth3Plus: 1,
			},
		},
	}
	out := captureOutput(func() {
		PrintTextDiff(result)
	})
	if !strings.Contains(out, "Depth") || !strings.Contains(out, "depth") {
		t.Error("expected depth summary section")
	}
}

func TestPrintViolations_Empty(t *testing.T) {
	out := captureOutput(func() {
		PrintViolations(nil)
	})
	if len(strings.TrimSpace(out)) > 0 {
		t.Errorf("expected no output for empty violations, got: %q", out)
	}
}

func TestPrintViolations_ErrorsAndWarnings(t *testing.T) {
	violations := []policy.Violation{
		{Rule: "deny_licenses", Message: "denied GPL", Severity: policy.SeverityError},
		{Rule: "warn_supplier", Message: "supplier changed", Severity: policy.SeverityWarning},
	}
	out := captureOutput(func() {
		PrintViolations(violations)
	})
	if !strings.Contains(out, "Policy Errors") {
		t.Error("expected Policy Errors section")
	}
	if !strings.Contains(out, "Policy Warnings") {
		t.Error("expected Policy Warnings section")
	}
}

func TestPrintViolations_ErrorsOnly(t *testing.T) {
	violations := []policy.Violation{
		{Rule: "deny_licenses", Message: "denied GPL", Severity: policy.SeverityError},
	}
	out := captureOutput(func() {
		PrintViolations(violations)
	})
	if !strings.Contains(out, "Policy Errors") {
		t.Error("expected Policy Errors section")
	}
	if strings.Contains(out, "Policy Warnings") {
		t.Error("expected NO Policy Warnings section")
	}
}

func TestPrintViolations_WarningsOnly(t *testing.T) {
	violations := []policy.Violation{
		{Rule: "warn_supplier", Message: "supplier changed", Severity: policy.SeverityWarning},
	}
	out := captureOutput(func() {
		PrintViolations(violations)
	})
	if strings.Contains(out, "Policy Errors") {
		t.Error("expected NO Policy Errors section")
	}
	if !strings.Contains(out, "Policy Warnings") {
		t.Error("expected Policy Warnings section")
	}
}
