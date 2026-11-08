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

func TestUpgradeFindingShowsRevisionLevel(t *testing.T) {
	deb := func(v string) sbom.Component {
		return sbom.Component{ID: "pkg:deb/debian/libc6", Name: "libc6", Version: v, PURL: "pkg:deb/debian/libc6@" + v}
	}
	r := DiffComponents([]sbom.Component{deb("2.36-9")}, []sbom.Component{deb("2.36-10")})
	f := ComputeKeyFindings(r, DiffOverview{})
	if m := findingWith(f, "version upgrades"); !strings.Contains(m, "1 revision") {
		t.Errorf("finding = %q", m)
	}
}

func TestAttackSurfaceIconFollowsFileDelta(t *testing.T) {
	ov := DiffOverview{
		Before: SBOMSide{Stats: Stats{TotalComponents: 10}, Info: sbom.SBOMInfo{FilesCount: 100}},
		After:  SBOMSide{Stats: Stats{TotalComponents: 10}, Info: sbom.SBOMInfo{FilesCount: 103}},
	}
	f := detectAttackSurfaceDelta(ov)
	if len(f) != 1 || f[0].Icon != "\U0001f4c8" {
		t.Errorf("files went up, want increasing icon: %+v", f)
	}
}

func TestFileChangesSplitByOwner(t *testing.T) {
	r := DiffResult{
		FileChanges: []FileChange{
			{Path: "/usr/bin/a", Owners: []string{"pkg@2"}},
			{Path: "/usr/bin/b", Owners: []string{"same@1"}},
			{Path: "/var/lib/dpkg/status"},
		},
		OwnedFileDrift: []OwnedFileDrift{{Name: "same", Version: "1"}},
	}
	f := detectFileChanges(r)
	want := "3 file entries changed content: 1 in packages that changed version, 1 in same-version packages, 1 not owned by any package: /var/lib/dpkg/status"
	if len(f) != 1 || f[0].Message != want {
		t.Errorf("got %+v", f)
	}
	// no ownership data (CycloneDX): unchanged wording
	f = detectFileChanges(DiffResult{FileChanges: []FileChange{{Path: "/go.mod"}}})
	if len(f) != 1 || f[0].Message != "1 file entries changed content (not package integrity drift): /go.mod" {
		t.Errorf("got %+v", f)
	}
}

func TestOwnedFileDriftNotesBaseOSChange(t *testing.T) {
	r := DiffResult{OwnedFileDrift: []OwnedFileDrift{{Name: "x", Version: "1-r0", Files: []OwnedFileChange{{Path: "/usr/lib/x.so", Change: FileModified}}}}}
	ov := DiffOverview{
		Before: SBOMSide{Info: sbom.SBOMInfo{OSPrettyName: "Alpine Linux v3.20"}},
		After:  SBOMSide{Info: sbom.SBOMInfo{OSPrettyName: "Alpine Linux v3.21"}},
	}
	if m := detectOwnedFileDrift(r, ov)[0].Message; !strings.Contains(m, "base OS changed (Alpine Linux v3.20 → Alpine Linux v3.21)") {
		t.Errorf("got %q", m)
	}
	if m := detectOwnedFileDrift(r, DiffOverview{})[0].Message; strings.Contains(m, "base OS changed") {
		t.Errorf("same OS must not claim a rebuild: %q", m)
	}
}

func TestSplitLicenseFinding(t *testing.T) {
	comps := []sbom.Component{
		{Name: "aom-libs", Licenses: []string{"AND", "BSD-2-Clause", "custom"}},
		{Name: "ok", Licenses: []string{"MIT AND Zlib"}},
	}
	f := detectSplitLicenses(comps)
	if len(f) != 1 || !strings.Contains(f[0].Message, "1 packages list AND/OR/WITH as a license") || !strings.Contains(f[0].Message, "aom-libs") {
		t.Errorf("got %+v", f)
	}
}
