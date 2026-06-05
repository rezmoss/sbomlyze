package compliance

import (
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestEvaluate_NTIABasic(t *testing.T) {
	comps := []sbom.Component{
		{
			ID: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21",
			PURL: "pkg:npm/lodash@4.17.21", Supplier: "lodash-dev",
			Licenses: []string{"MIT"}, Hashes: map[string]string{"SHA-256": "abc123"},
			Dependencies: []string{"pkg:npm/some-dep"},
		},
	}
	info := sbom.SBOMInfo{ToolName: "syft", SchemaVersion: "1.0.0", SBOMAuthor: "syft", SBOMTimestamp: "2025-01-01T00:00:00Z"}

	report := Evaluate(comps, info)
	if report.NTIA == nil {
		t.Fatal("expected NTIA report")
	}
	if report.NTIA.Score != 100 {
		t.Errorf("expected NTIA score 100, got %d", report.NTIA.Score)
	}
	if report.NTIA.Passed != 7 {
		t.Errorf("expected 7 NTIA checks passed, got %d", report.NTIA.Passed)
	}
}

func TestEvaluate_NTIAEmptySBOM(t *testing.T) {
	report := Evaluate([]sbom.Component{}, sbom.SBOMInfo{})
	if report.NTIA != nil {
		t.Error("expected nil NTIA for empty SBOM")
	}
	if report.Overall != 0 {
		t.Errorf("expected overall 0 for empty SBOM, got %d", report.Overall)
	}
}

func TestEvaluate_NTIAMissingFields(t *testing.T) {
	comps := []sbom.Component{
		{Name: "a"},
	}
	info := sbom.SBOMInfo{}

	report := Evaluate(comps, info)
	if report.NTIA == nil {
		t.Fatal("expected NTIA report")
	}
	if report.NTIA.Passed >= report.NTIA.Total {
		t.Errorf("expected some NTIA checks to fail, got %d/%d passed", report.NTIA.Passed, report.NTIA.Total)
	}
}

func TestEvaluate_CISABasic(t *testing.T) {
	comps := []sbom.Component{
		{
			ID: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21",
			PURL: "pkg:npm/lodash@4.17.21", Supplier: "lodash-dev",
			Licenses: []string{"MIT"}, Hashes: map[string]string{"SHA-256": "abc123"},
			CPEs:      []string{"cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"},
			Dependencies: []string{"pkg:npm/some-dep"},
		},
	}
	info := sbom.SBOMInfo{ToolName: "syft", SchemaVersion: "1.0.0", SBOMAuthor: "syft", SBOMTimestamp: "2025-01-01T00:00:00Z"}

	report := Evaluate(comps, info)
	if report.CISA == nil {
		t.Fatal("expected CISA report")
	}
	if report.CISA.Score != 100 {
		t.Errorf("expected CISA score 100, got %d", report.CISA.Score)
	}
}

func TestEvaluate_CISAMissingPURL(t *testing.T) {
	comps := []sbom.Component{
		{
			Name: "a", Version: "1.0", Supplier: "dev",
			Licenses: []string{"MIT"}, Hashes: map[string]string{"SHA-256": "abc"},
			Dependencies: []string{"b"},
		},
	}
	info := sbom.SBOMInfo{ToolName: "syft", SchemaVersion: "1.0", SBOMAuthor: "syft", SBOMTimestamp: "2025-01-01T00:00:00Z"}

	report := Evaluate(comps, info)
	if report.CISA == nil {
		t.Fatal("expected CISA report")
	}

	var purlCheck *CheckResult
	for i := range report.CISA.Checks {
		if report.CISA.Checks[i].ID == "cisa-purl" {
			purlCheck = &report.CISA.Checks[i]
			break
		}
	}
	if purlCheck == nil {
		t.Fatal("expected CISA PURL check")
	}
	if purlCheck.Passed {
		t.Error("expected CISA PURL check to fail when no PURLs are present")
	}
}

func TestEvaluate_BSISHA512(t *testing.T) {
	comps := []sbom.Component{
		{
			Name: "a", Version: "1.0", Supplier: "dev",
			PURL: "pkg:npm/a@1.0", Licenses: []string{"MIT"},
			Hashes:      map[string]string{"SHA-512": "abc123def456"},
			Dependencies: []string{"b"},
		},
	}
	info := sbom.SBOMInfo{ToolName: "syft", SchemaVersion: "1.0", SBOMAuthor: "syft", SBOMTimestamp: "2025-01-01T00:00:00Z"}

	report := Evaluate(comps, info)
	if report.BSI == nil {
		t.Fatal("expected BSI report")
	}

	var sha512Check *CheckResult
	for i := range report.BSI.Checks {
		if report.BSI.Checks[i].ID == "bsi-sha512" {
			sha512Check = &report.BSI.Checks[i]
			break
		}
	}
	if sha512Check == nil {
		t.Fatal("expected BSI SHA-512 check")
	}
	if !sha512Check.Passed {
		t.Error("expected BSI SHA-512 check to pass when SHA-512 hash is present")
	}
}

func TestEvaluate_BSINoSHA512(t *testing.T) {
	comps := []sbom.Component{
		{
			Name: "a", Version: "1.0", Supplier: "dev",
			PURL: "pkg:npm/a@1.0", Licenses: []string{"MIT"},
			Hashes:      map[string]string{"SHA-256": "abc123"},
			Dependencies: []string{"b"},
		},
	}
	info := sbom.SBOMInfo{ToolName: "syft", SchemaVersion: "1.0", SBOMAuthor: "syft", SBOMTimestamp: "2025-01-01T00:00:00Z"}

	report := Evaluate(comps, info)

	var sha512Check *CheckResult
	for i := range report.BSI.Checks {
		if report.BSI.Checks[i].ID == "bsi-sha512" {
			sha512Check = &report.BSI.Checks[i]
			break
		}
	}
	if sha512Check == nil {
		t.Fatal("expected BSI SHA-512 check")
	}
	if sha512Check.Passed {
		t.Error("expected BSI SHA-512 check to fail when only SHA-256 is present")
	}
}

func TestEvaluate_OverallScore(t *testing.T) {
	comps := []sbom.Component{
		{
			Name: "a", Version: "1.0", Supplier: "dev",
			PURL: "pkg:npm/a@1.0", Licenses: []string{"MIT"},
			Hashes:      map[string]string{"SHA-256": "abc123"},
			Dependencies: []string{"b"},
		},
	}
	info := sbom.SBOMInfo{ToolName: "syft", SchemaVersion: "1.0", SBOMAuthor: "syft", SBOMTimestamp: "2025-01-01T00:00:00Z"}

	report := Evaluate(comps, info)

	if report.Overall == 0 {
		t.Error("expected non-zero overall score")
	}
	if report.Overall > 100 {
		t.Errorf("overall score should not exceed 100, got %d", report.Overall)
	}
}

func TestEvaluate_MultipleComponents(t *testing.T) {
	comps := []sbom.Component{
		{Name: "a", Version: "1.0", Supplier: "dev-a", PURL: "pkg:npm/a@1.0", Licenses: []string{"MIT"}},
		{Name: "b", Version: "2.0"},
	}
	info := sbom.SBOMInfo{ToolName: "syft", SchemaVersion: "1.0", SBOMAuthor: "syft", SBOMTimestamp: "2025-01-01T00:00:00Z"}

	report := Evaluate(comps, info)
	if report.NTIA == nil {
		t.Fatal("expected NTIA report")
	}
	if report.NTIA.Score == 100 {
		t.Error("expected NTIA score < 100 when some components lack fields")
	}
}

func TestEvaluate_NTIAComponentChecksCount(t *testing.T) {
	comps := []sbom.Component{
		{Name: "a", Version: "1.0"},
	}
	info := sbom.SBOMInfo{ToolName: "test", SBOMAuthor: "test", SBOMTimestamp: "2025-01-01T00:00:00Z"}
	report := Evaluate(comps, info)

	if report.NTIA.Total != 7 {
		t.Errorf("expected 7 NTIA checks, got %d", report.NTIA.Total)
	}
}

func TestEvaluate_CISAComponentChecksCount(t *testing.T) {
	comps := []sbom.Component{
		{Name: "a", Version: "1.0"},
	}
	info := sbom.SBOMInfo{ToolName: "test", SBOMAuthor: "test", SBOMTimestamp: "2025-01-01T00:00:00Z"}
	report := Evaluate(comps, info)

	if report.CISA.Total != 11 {
		t.Errorf("expected 11 CISA checks, got %d", report.CISA.Total)
	}
}

func TestEvaluate_BSIComponentChecksCount(t *testing.T) {
	comps := []sbom.Component{
		{Name: "a", Version: "1.0"},
	}
	info := sbom.SBOMInfo{ToolName: "test", SBOMAuthor: "test", SBOMTimestamp: "2025-01-01T00:00:00Z"}
	report := Evaluate(comps, info)

	if report.BSI.Total != 11 {
		t.Errorf("expected 11 BSI checks, got %d", report.BSI.Total)
	}
}

func TestEvaluate_FrameworkIcon(t *testing.T) {
	tests := []struct {
		score    int
		expected rune
	}{
		{100, '🟢'},
		{90, '🟢'},
		{89, '🟡'},
		{70, '🟡'},
		{69, '🟠'},
		{50, '🟠'},
		{49, '🔴'},
		{0, '🔴'},
	}
	for _, tt := range tests {
		result := frameworkIcon(tt.score)
		if result != tt.expected {
			t.Errorf("frameworkIcon(%d) = %q, want %q", tt.score, result, tt.expected)
		}
	}
}
