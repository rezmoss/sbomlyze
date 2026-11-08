package output

import (
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestGenerateHTML_FormatAndGeneratorRows(t *testing.T) {
	overview := analysis.DiffOverview{
		Before: analysis.SBOMSide{Info: sbom.SBOMInfo{Format: "CycloneDX", SpecVersion: "1.6", ToolName: "syft", ToolVersion: "1.55.0"}},
		After:  analysis.SBOMSide{Info: sbom.SBOMInfo{Format: "SPDX", SpecVersion: "SPDX-2.3", ToolName: "syft", ToolVersion: "1.57.0"}},
	}
	html := GenerateHTML(analysis.DiffResult{}, nil, overview, analysis.KeyFindings{})
	for _, want := range []string{
		"<tr><td><strong>Format</strong></td><td>CycloneDX 1.6</td><td>SPDX 2.3</td></tr>",
		"<tr><td><strong>Generator</strong></td><td>syft 1.55.0</td><td>syft 1.57.0</td></tr>",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestOccurrenceOutputsKeepLocations(t *testing.T) {
	change := func(loc string) analysis.ChangedComponent {
		return analysis.ChangedComponent{
			ID: "pkg:golang/x", Name: "x", Location: loc,
			Before: sbom.Component{Version: "v1.0.0"}, After: sbom.Component{Version: "v0.9.0"},
			Drift: &analysis.DriftInfo{Type: analysis.DriftTypeVersion, Direction: analysis.DirectionDowngrade},
		}
	}
	result := analysis.DiffResult{
		Changed:      []analysis.ChangedComponent{change("/a/go.mod"), change("/b/go.mod")},
		FileChanges:  []analysis.FileChange{{Path: "/go.mod"}},
		DriftSummary: &analysis.DriftSummary{VersionDrift: 2, Downgrades: 2, FileChanges: 1},
	}

	sarif := GenerateSARIF(result, nil, "after.json")
	fps := map[string]bool{}
	for _, r := range sarif.Runs[0].Results {
		if r.RuleID == "version-change" {
			fps[r.PartialFingerprints["primaryLocationLineHash"]] = true
			if !strings.Contains(r.Message.Text, "@ /") || !strings.Contains(r.Message.Text, "(downgrade)") {
				t.Errorf("SARIF message = %q", r.Message.Text)
			}
		}
	}
	if len(fps) != 2 {
		t.Errorf("one package in two locations must yield two SARIF fingerprints, got %d", len(fps))
	}

	paths := map[string]bool{}
	for _, op := range GenerateJSONPatch(result) {
		paths[op.Path] = true
	}
	if !paths["/components/pkg:golang/x@/a/go.mod/version"] || !paths["/components/pkg:golang/x@/b/go.mod/version"] {
		t.Errorf("patch paths = %v", paths)
	}

	md := GenerateMarkdown(result, nil)
	if !strings.Contains(md, "| File entries (not package drift) | 1 |") {
		t.Errorf("markdown missing file-change row:\n%s", md)
	}
}
