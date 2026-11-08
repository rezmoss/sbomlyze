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

// Codex review: patch, Markdown and HTML must show digests, file changes and moves.
func TestOutputsRenderNewChangeKinds(t *testing.T) {
	result := analysis.DiffResult{
		Changed: []analysis.ChangedComponent{{
			ID: "pkg:golang/x", Name: "x", Location: "/go.mod",
			Before: sbom.Component{Version: "v1.0.0", Digests: map[string]string{sbom.DigestGoH1: "h1:A="}},
			After:  sbom.Component{Version: "v1.0.0", Digests: map[string]string{sbom.DigestGoH1: "h1:B="}},
			Drift:  &analysis.DriftInfo{Type: analysis.DriftTypeIntegrity},
		}},
		Moved:             []analysis.MovedComponent{{ID: "pkg:golang/m", Name: "m", Version: "v1.0.0", From: "/a/go.mod", To: "/b/go.mod"}},
		FileChanges:       []analysis.FileChange{{Path: "/go.mod", HashesAfter: map[string]string{"SHA-256": "bb"}}},
		VersionSetChanges: []analysis.VersionSetChange{{Name: "e", Location: "/package-lock.json", RemovedVersions: []string{"1.10.0"}, AddedVersions: []string{"1.11.0", "1.9.2"}}},
	}

	ops := map[string]JSONPatchOp{}
	for _, op := range GenerateJSONPatch(result) {
		ops[op.Op+" "+op.Path] = op
	}
	for _, want := range []string{
		"replace /components/pkg:golang/x@/go.mod/digests",
		"move /components/pkg:golang/m@/b/go.mod",
		"replace /files//go.mod/hashes",
	} {
		if _, ok := ops[want]; !ok {
			t.Errorf("patch missing %q; got %v", want, ops)
		}
	}
	if got := GenerateJSONPatch(analysis.DiffResult{}); got == nil || len(got) != 0 {
		t.Errorf("empty diff patch = %#v, want []", got)
	}

	overview := analysis.DiffOverview{After: analysis.SBOMSide{Info: sbom.SBOMInfo{Format: "CycloneDX", SpecVersion: "1.6", ToolName: "syft"}}}
	md := GenerateMarkdownWithOverview(result, nil, overview, analysis.KeyFindings{})
	html := GenerateHTML(result, nil, overview, analysis.KeyFindings{})
	for name, doc := range map[string]string{"markdown": md, "html": html} {
		for _, want := range []string{"Moved Components (1)", "/a/go.mod", "/b/go.mod", "File Changes (1", "Version Set Changes (1", "1.11.0, 1.9.2", "x @ /go.mod"} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s missing %q", name, want)
			}
		}
	}
	if !strings.Contains(md, "| **Format** | (none) | CycloneDX 1.6 |") || !strings.Contains(md, "| **Generator** | (none) | syft |") {
		t.Errorf("markdown Format/Generator rows wrong:\n%s", md)
	}
}
