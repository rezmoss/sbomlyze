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
			CPEs:         []string{"cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"},
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

	var idCheck *CheckResult
	for i := range report.CISA.Checks {
		if report.CISA.Checks[i].ID == "cisa-unique-id" {
			idCheck = &report.CISA.Checks[i]
			break
		}
	}
	if idCheck == nil {
		t.Fatal("expected CISA software identifier check")
	}
	if idCheck.Passed {
		t.Error("expected CISA software identifier check to fail when no PURL/CPE is present")
	}
}

func TestEvaluate_BSISHA512(t *testing.T) {
	comps := []sbom.Component{
		{
			Name: "a", Version: "1.0", Supplier: "dev",
			PURL: "pkg:npm/a@1.0", Licenses: []string{"MIT"},
			Hashes:       map[string]string{"SHA-512": "abc123def456"},
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
			Hashes:       map[string]string{"SHA-256": "abc123"},
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
			Hashes:       map[string]string{"SHA-256": "abc123"},
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

	if report.CISA.Total != 10 {
		t.Errorf("expected 10 CISA checks, got %d", report.CISA.Total)
	}
}

func TestEvaluate_BSIComponentChecksCount(t *testing.T) {
	comps := []sbom.Component{
		{Name: "a", Version: "1.0"},
	}
	info := sbom.SBOMInfo{ToolName: "test", SBOMAuthor: "test", SBOMTimestamp: "2025-01-01T00:00:00Z"}
	report := Evaluate(comps, info)

	if report.BSI.Total != 9 {
		t.Errorf("expected 9 BSI checks, got %d", report.BSI.Total)
	}
}

func TestEvaluate_IdentifierChecksIgnoreInternalRefs(t *testing.T) {
	// bom-ref/SPDXID are internal refs, must not satisfy unique-id checks
	comps := []sbom.Component{
		{Name: "a", Version: "1.0", BOMRef: "ref-1", SPDXID: "SPDXRef-a"},
	}
	info := sbom.SBOMInfo{ToolName: "test", SBOMAuthor: "test", SBOMTimestamp: "2025-01-01T00:00:00Z"}
	report := Evaluate(comps, info)

	for _, fw := range []*FrameworkResult{report.NTIA, report.CISA, report.BSI} {
		for _, c := range fw.Checks {
			if (c.ID == "ntia-unique-id" || c.ID == "cisa-unique-id" || c.ID == "bsi-unique-id") && c.Passed {
				t.Errorf("%s: expected fail when only bom-ref/SPDXID are present", c.ID)
			}
		}
	}
}

func TestEvaluate_CISAAuthorDistinctFromTool(t *testing.T) {
	comps := []sbom.Component{{Name: "a", Version: "1.0"}}
	// tool only, no author: cisa-tool passes, cisa-author fails
	report := Evaluate(comps, sbom.SBOMInfo{ToolName: "syft", SBOMTimestamp: "2025-01-01T00:00:00Z"})

	got := map[string]bool{}
	for _, c := range report.CISA.Checks {
		got[c.ID] = c.Passed
	}
	if !got["cisa-tool"] {
		t.Error("expected cisa-tool to pass when ToolName is set")
	}
	if got["cisa-author"] {
		t.Error("expected cisa-author to fail when only the tool name is known")
	}
	// NTIA allows a tool as author
	for _, c := range report.NTIA.Checks {
		if c.ID == "ntia-author" && !c.Passed {
			t.Error("expected ntia-author to pass via tool name")
		}
	}
}

func TestEvaluate_BSICreatorContact(t *testing.T) {
	comps := []sbom.Component{{Name: "a", Version: "1.0"}}

	cases := []struct {
		author string
		want   bool
	}{
		{"sbom@example.com", true},
		{"https://example.com/sbom", true},
		{"Anchore, Inc", false}, // bare name: §5.2.1 needs email/URL
		{"syft", false},
		{"", false},
	}
	for _, tc := range cases {
		report := Evaluate(comps, sbom.SBOMInfo{SBOMAuthor: tc.author, SBOMTimestamp: "2025-01-01T00:00:00Z"})
		for _, c := range report.BSI.Checks {
			if c.ID == "bsi-author" && c.Passed != tc.want {
				t.Errorf("bsi-author with author %q: passed=%v, want %v", tc.author, c.Passed, tc.want)
			}
		}
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

func TestEvaluate_BSILicenseRequiresValidSPDXExpression(t *testing.T) {
	cases := []struct {
		licenses []string
		want     bool
	}{
		{[]string{"MIT"}, true},
		{[]string{"Apache-2.0 OR MIT"}, true},
		{[]string{"NOT-A-REAL-LICENSE"}, false},
		{[]string{"NOASSERTION"}, false},
	}
	for _, tc := range cases {
		comps := []sbom.Component{
			{Name: "a", Version: "1.0", Licenses: tc.licenses},
		}
		info := sbom.SBOMInfo{SBOMAuthor: "sbom@example.com", SBOMTimestamp: "2025-01-01T00:00:00Z"}
		report := Evaluate(comps, info)
		for _, c := range report.BSI.Checks {
			if c.ID == "bsi-license" && c.Passed != tc.want {
				t.Errorf("bsi-license with licenses %v: passed=%v, want %v", tc.licenses, c.Passed, tc.want)
			}
		}
	}
}

func TestEvaluate_DependencyChecksRequireGraphCoverage(t *testing.T) {
	// one isolated component (c) not covered by the dependency graph at all:
	// the dep-relation checks must not pass on a single stray edge
	comps := []sbom.Component{
		{ID: "id-a", Name: "a", Version: "1.0", Dependencies: []string{"id-b"}},
		{ID: "id-b", Name: "b", Version: "2.0"},
		{ID: "id-c", Name: "c", Version: "3.0"},
	}
	info := sbom.SBOMInfo{ToolName: "test", SBOMAuthor: "test", SBOMTimestamp: "2025-01-01T00:00:00Z"}
	report := Evaluate(comps, info)

	for _, fw := range []*FrameworkResult{report.NTIA, report.CISA, report.BSI} {
		for _, c := range fw.Checks {
			if (c.ID == "ntia-dep-relation" || c.ID == "cisa-dep-relation" || c.ID == "bsi-dep-relation") && c.Passed {
				t.Errorf("%s: expected fail when a component is absent from the dependency graph (c is isolated)", c.ID)
			}
		}
	}
}

func TestEvaluate_DependencyChecksPassWithFullCoverage(t *testing.T) {
	// a -> b -> c: every component appears in the graph (as parent or child)
	comps := []sbom.Component{
		{ID: "id-a", Name: "a", Version: "1.0", Dependencies: []string{"id-b"}},
		{ID: "id-b", Name: "b", Version: "2.0", Dependencies: []string{"id-c"}},
		{ID: "id-c", Name: "c", Version: "3.0"},
	}
	info := sbom.SBOMInfo{ToolName: "test", SBOMAuthor: "test", SBOMTimestamp: "2025-01-01T00:00:00Z"}
	report := Evaluate(comps, info)

	for _, fw := range []*FrameworkResult{report.NTIA, report.CISA, report.BSI} {
		for _, c := range fw.Checks {
			if (c.ID == "ntia-dep-relation" || c.ID == "cisa-dep-relation" || c.ID == "bsi-dep-relation") && !c.Passed {
				t.Errorf("%s: expected pass when all components are covered by the dependency graph", c.ID)
			}
		}
	}
}
