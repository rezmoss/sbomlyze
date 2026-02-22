package output

import (
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/policy"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestGenerateHTML_ValidStructure(t *testing.T) {
	result := analysis.DiffResult{
		Added:   []sbom.Component{{Name: "new-lib", Version: "1.0.0"}},
		Removed: []sbom.Component{{Name: "old-lib", Version: "0.9.0"}},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "before.json", Stats: analysis.Stats{TotalComponents: 10}},
		After:  analysis.SBOMSide{FileName: "after.json", Stats: analysis.Stats{TotalComponents: 11}},
	}
	findings := analysis.KeyFindings{}

	html := GenerateHTML(result, nil, overview, findings)

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("expected DOCTYPE declaration")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("expected closing html tag")
	}
	if !strings.Contains(html, "SBOM Diff Report") {
		t.Error("expected report title")
	}
	if !strings.Contains(html, "sbomlyze") {
		t.Error("expected sbomlyze attribution")
	}
}

func TestGenerateHTML_ContainsComponents(t *testing.T) {
	result := analysis.DiffResult{
		Added:   []sbom.Component{{Name: "lodash", Version: "4.17.21"}},
		Removed: []sbom.Component{{Name: "underscore", Version: "1.13.6"}},
		Changed: []analysis.ChangedComponent{
			{
				Name:   "express",
				Before: sbom.Component{Version: "4.18.0"},
				After:  sbom.Component{Version: "4.19.0"},
				Drift:  &analysis.DriftInfo{Type: analysis.DriftTypeVersion},
			},
		},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(result, nil, overview, analysis.KeyFindings{})

	if !strings.Contains(html, "lodash") {
		t.Error("expected added component 'lodash'")
	}
	if !strings.Contains(html, "underscore") {
		t.Error("expected removed component 'underscore'")
	}
	if !strings.Contains(html, "express") {
		t.Error("expected changed component 'express'")
	}
	if !strings.Contains(html, "4.19.0") {
		t.Error("expected new version in changed component")
	}
}

func TestGenerateHTML_DriftSummary(t *testing.T) {
	result := analysis.DiffResult{
		DriftSummary: &analysis.DriftSummary{
			VersionDrift:   3,
			IntegrityDrift: 1,
			MetadataDrift:  2,
		},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(result, nil, overview, analysis.KeyFindings{})

	if !strings.Contains(html, "Drift Summary") {
		t.Error("expected drift summary section")
	}
	if !strings.Contains(html, "Review Required") {
		t.Error("expected 'Review Required' for integrity drift > 0")
	}
}

func TestGenerateHTML_PolicyViolations(t *testing.T) {
	violations := []policy.Violation{
		{Rule: "no-gpl", Message: "GPL license found in component foo", Severity: policy.SeverityError},
		{Rule: "max-depth", Message: "Dependency depth exceeds 3", Severity: policy.SeverityWarning},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(analysis.DiffResult{}, violations, overview, analysis.KeyFindings{})

	if !strings.Contains(html, "Policy Errors") {
		t.Error("expected policy errors section")
	}
	if !strings.Contains(html, "Policy Warnings") {
		t.Error("expected policy warnings section")
	}
	if !strings.Contains(html, "no-gpl") {
		t.Error("expected error rule name")
	}
	if !strings.Contains(html, "max-depth") {
		t.Error("expected warning rule name")
	}
}

func TestGenerateHTML_KeyFindings(t *testing.T) {
	findings := analysis.KeyFindings{
		Findings: []analysis.Finding{
			{Icon: "🔴", Message: "Critical integrity drift detected"},
			{Icon: "📦", Message: "15 new components added"},
		},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(analysis.DiffResult{}, nil, overview, findings)

	if !strings.Contains(html, "Key Findings") {
		t.Error("expected key findings section")
	}
	if !strings.Contains(html, "Critical integrity drift detected") {
		t.Error("expected finding message")
	}
}

func TestGenerateHTML_DepthSummary(t *testing.T) {
	result := analysis.DiffResult{
		Dependencies: &analysis.DependencyDiff{
			DepthSummary: &analysis.DepthSummary{
				Depth1:     5,
				Depth2:     3,
				Depth3Plus: 2,
			},
		},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(result, nil, overview, analysis.KeyFindings{})

	if !strings.Contains(html, "Dependencies by Depth") {
		t.Error("expected depth summary section")
	}
	if !strings.Contains(html, "High") {
		t.Error("expected 'High' risk for depth 3+")
	}
}

func TestGenerateHTML_EmptyDiff(t *testing.T) {
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(analysis.DiffResult{}, nil, overview, analysis.KeyFindings{})

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("expected valid HTML even for empty diff")
	}
	// Should not contain component sections
	if strings.Contains(html, "Added Components") {
		t.Error("should not have added components section for empty diff")
	}
}

func TestGenerateHTML_EscapesHTML(t *testing.T) {
	result := analysis.DiffResult{
		Added: []sbom.Component{{Name: "<script>alert('xss')</script>", Version: "1.0"}},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(result, nil, overview, analysis.KeyFindings{})

	if strings.Contains(html, "<script>alert") {
		t.Error("HTML should be escaped to prevent XSS")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected escaped script tag")
	}
}

func TestGenerateHTML_SelfContained(t *testing.T) {
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(analysis.DiffResult{}, nil, overview, analysis.KeyFindings{})

	if !strings.Contains(html, "<style>") {
		t.Error("expected embedded CSS (self-contained)")
	}
	// Should not reference external stylesheets
	if strings.Contains(html, "link rel=\"stylesheet\"") {
		t.Error("should be self-contained with no external CSS")
	}
}

func TestGenerateHTML_IntegrityDriftCard(t *testing.T) {
	result := analysis.DiffResult{
		DriftSummary: &analysis.DriftSummary{
			IntegrityDrift: 3,
		},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(result, nil, overview, analysis.KeyFindings{})

	if !strings.Contains(html, "Integrity Drift") {
		t.Error("expected integrity drift card for non-zero integrity drift")
	}
}

func TestGenerateHTMLStats_ValidStructure(t *testing.T) {
	stats := analysis.Stats{
		TotalComponents: 50,
		WithHashes:      30,
		WithoutLicense:  5,
		ByType:          map[string]int{"npm": 40, "golang": 10},
		ByLicense:       map[string]int{"MIT": 30, "Apache-2.0": 15},
		LicenseCategories: &analysis.LicenseCategory{
			Permissive: 45,
			Unknown:    5,
		},
	}
	info := sbom.SBOMInfo{ToolName: "syft", OSPrettyName: "Ubuntu 22.04"}
	findings := analysis.KeyFindings{}

	html := GenerateHTMLStats(stats, info, findings)

	if !strings.Contains(html, "SBOM Statistics Report") {
		t.Error("expected statistics report title")
	}
	if !strings.Contains(html, "syft") {
		t.Error("expected tool name")
	}
	if !strings.Contains(html, "50") {
		t.Error("expected total components count")
	}
	if !strings.Contains(html, "npm") {
		t.Error("expected package type")
	}
	if !strings.Contains(html, "MIT") {
		t.Error("expected license name")
	}
}

func TestGenerateHTMLStats_Duplicates(t *testing.T) {
	stats := analysis.Stats{
		DuplicateCount: 2,
		Duplicates: []analysis.DuplicateGroup{
			{Name: "lodash", Versions: []string{"4.17.20", "4.17.21"}},
		},
	}

	html := GenerateHTMLStats(stats, sbom.SBOMInfo{}, analysis.KeyFindings{})

	if !strings.Contains(html, "Duplicates") {
		t.Error("expected duplicates section")
	}
	if !strings.Contains(html, "lodash") {
		t.Error("expected duplicate package name")
	}
}

func TestGenerateHTML_ChangedDriftTypes(t *testing.T) {
	result := analysis.DiffResult{
		Changed: []analysis.ChangedComponent{
			{Name: "a", Before: sbom.Component{Version: "1"}, After: sbom.Component{Version: "2"}, Drift: &analysis.DriftInfo{Type: analysis.DriftTypeVersion}},
			{Name: "b", Before: sbom.Component{Version: "1"}, After: sbom.Component{Version: "1"}, Drift: &analysis.DriftInfo{Type: analysis.DriftTypeIntegrity}},
			{Name: "c", Before: sbom.Component{Version: "1"}, After: sbom.Component{Version: "1"}, Drift: &analysis.DriftInfo{Type: analysis.DriftTypeMetadata}},
		},
	}
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{FileName: "a.json"},
		After:  analysis.SBOMSide{FileName: "b.json"},
	}

	html := GenerateHTML(result, nil, overview, analysis.KeyFindings{})

	if !strings.Contains(html, "Version") {
		t.Error("expected Version drift type")
	}
	if !strings.Contains(html, "Integrity") {
		t.Error("expected Integrity drift type")
	}
	if !strings.Contains(html, "Metadata") {
		t.Error("expected Metadata drift type")
	}
}
