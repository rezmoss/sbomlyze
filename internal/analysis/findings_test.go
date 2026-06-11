package analysis

import (
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestDetectDominantType_IgnoresFileComponents(t *testing.T) {
	comps := []sbom.Component{
		{ID: "1", Name: "a", PURL: "pkg:npm/a@1", Type: "library"},
		{ID: "2", Name: "b", PURL: "pkg:npm/b@1", Type: "library"},
		{ID: "3", Name: "c", PURL: "pkg:npm/c@1", Type: "library"},
		{ID: "4", Name: "/f1", Type: "file"},
		{ID: "5", Name: "/f2", Type: "file"},
		{ID: "6", Name: "/f3", Type: "file"},
		{ID: "7", Name: "/f4", Type: "file"},
		{ID: "8", Name: "/f5", Type: "file"},
	}
	stats := ComputeStats(comps)
	findings := ComputeSingleFindings(stats, sbom.SBOMInfo{}, comps)
	for _, f := range findings.Findings {
		if strings.Contains(f.Message, "Dominated by file") {
			t.Errorf("dominant-type finding must ignore file components, got: %s", f.Message)
		}
	}
}
