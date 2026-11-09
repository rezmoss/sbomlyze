package analysis

import (
	"math/rand"
	"slices"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func diffWithFiles(t *testing.T, before, after string) DiffResult {
	t.Helper()
	b, bi := loadFixture(t, before)
	a, ai := loadFixture(t, after)
	return DiffSBOMs(b, a, bi.Files, ai.Files)
}

// setFileHash rewrites a file's hashes
func setFileHash(files []sbom.FileEntry, path, value string) []sbom.FileEntry {
	out := slices.Clone(files)
	for i := range out {
		if out[i].Path == path {
			out[i].Hashes = map[string]string{"sha1": value, "sha256": value + value}
		}
	}
	return out
}

func TestOwnedFileDrift_TamperedImages(t *testing.T) {
	for _, tc := range []struct{ before, after, pkg, path, config string }{
		{"files/alpine-base.syft.json", "files/alpine-tamp.syft.json", "alpine-baselayout-data", "/etc/profile", ConfigUnknown},
		{"files/alpine-base.spdx.json", "files/alpine-tamp.spdx.json", "alpine-baselayout-data", "/etc/profile", ConfigUnknown},
		{"files/debian-base.syft.json", "files/debian-tamp.syft.json", "coreutils", "/usr/bin/ls", ConfigNo},
		{"files/scanelf-3.19.syft.json", "files/scanelf-3.20.syft.json", "scanelf", "/usr/bin/scanelf", ConfigUnknown}, // real same-version rebuild
	} {
		r := diffWithFiles(t, tc.before, tc.after)
		if len(r.OwnedFileDrift) != 1 {
			t.Fatalf("%s: owned_file_drift = %+v", tc.after, r.OwnedFileDrift)
		}
		d := r.OwnedFileDrift[0]
		if d.Name != tc.pkg || len(d.Files) != 1 || d.Files[0].Path != tc.path || d.Files[0].Change != FileModified || d.Files[0].Config != tc.config {
			t.Errorf("%s: drift = %+v", tc.after, d)
		}
		if s := summary(r); s.OwnedFileDrift != 1 || s.OwnedFilesChanged != 1 || s.IntegrityDrift != 0 {
			t.Errorf("%s: summary = %+v", tc.after, s)
		}
		if !r.HasChanges() {
			t.Errorf("%s: owned file drift must count as a change", tc.after)
		}
	}
}

func TestFileChanges_UnownedBinary(t *testing.T) {
	r := diffWithFiles(t, "files/gobin-base.syft.json", "files/gobin-tamp.syft.json")
	if len(r.OwnedFileDrift) != 0 {
		t.Fatalf("no owner recorded, want no owned drift: %+v", r.OwnedFileDrift)
	}
	if len(r.FileChanges) != 1 || r.FileChanges[0].Path != "/usr/local/bin/syft" || len(r.FileChanges[0].Owners) != 0 {
		t.Errorf("file_changes = %+v", r.FileChanges)
	}
}

func TestOwnedFileDrift_SharedFileOwners(t *testing.T) {
	b, bi := loadFixture(t, "files/alpine-base.syft.json")
	a, ai := loadFixture(t, "files/alpine-base.syft.json")
	r := DiffSBOMs(b, a, bi.Files, setFileHash(ai.Files, "/bin/busybox", "ff"))
	var pkgs []string
	for _, d := range r.OwnedFileDrift {
		pkgs = append(pkgs, d.Name)
	}
	if !slices.Equal(pkgs, []string{"busybox", "busybox-binsh"}) {
		t.Fatalf("both owners must report the file, got %v", pkgs)
	}
	if s := summary(r); s.OwnedFileDrift != 2 || s.OwnedFilesChanged != 1 {
		t.Errorf("summary = %+v", s)
	}
	if len(r.FileChanges) != 1 || !slices.Equal(r.FileChanges[0].Owners, []string{"busybox-binsh@1.36.1-r31", "busybox@1.36.1-r31"}) {
		t.Errorf("file_changes = %+v", r.FileChanges)
	}
}

func TestOwnedFileDrift_ConfigFile(t *testing.T) {
	b, bi := loadFixture(t, "files/debian-base.syft.json")
	a, ai := loadFixture(t, "files/debian-base.syft.json")
	r := DiffSBOMs(b, a, bi.Files, setFileHash(ai.Files, "/etc/adduser.conf", "ee"))
	if len(r.OwnedFileDrift) != 1 || r.OwnedFileDrift[0].Files[0].Config != ConfigYes {
		t.Fatalf("drift = %+v", r.OwnedFileDrift)
	}
	if got := r.OwnedFileDrift[0].GatedFiles(false); len(got) != 0 {
		t.Errorf("config files are skipped by default, got %+v", got)
	}
	if got := r.OwnedFileDrift[0].GatedFiles(true); len(got) != 1 {
		t.Errorf("include_config must gate it, got %+v", got)
	}
}

func TestOwnedFileDrift_AddedAndRemovedFiles(t *testing.T) {
	b, bi := loadFixture(t, "files/debian-base.syft.json")
	a, ai := loadFixture(t, "files/debian-base.syft.json")
	// coreutils gains one file, loses one, same ver
	for i := range a {
		if a[i].Name == "coreutils" {
			a[i].OwnedFiles = append(slices.DeleteFunc(slices.Clone(a[i].OwnedFiles), func(p string) bool { return p == "/usr/bin/ls" }), "/usr/bin/evil")
		}
	}
	files := append(slices.Clone(ai.Files), sbom.FileEntry{Path: "/usr/bin/evil", Hashes: map[string]string{"sha256": "00"}})
	r := DiffSBOMs(b, a, bi.Files, files)
	if len(r.OwnedFileDrift) != 1 {
		t.Fatalf("drift = %+v", r.OwnedFileDrift)
	}
	changes := map[string]string{}
	for _, f := range r.OwnedFileDrift[0].Files {
		changes[f.Path] = f.Change
	}
	if changes["/usr/bin/evil"] != FileAdded || changes["/usr/bin/ls"] != FileRemoved {
		t.Errorf("changes = %v", changes)
	}
	if len(r.FilesAdded) != 1 || r.FilesAdded[0].Path != "/usr/bin/evil" {
		t.Errorf("files_added = %+v", r.FilesAdded)
	}
}

func TestFileComparison_OnlySameKind(t *testing.T) {
	if compareHashes(map[string]string{"SHA-256": "AA"}, map[string]string{"sha256": "aa"}) != "equal" {
		t.Error("SHA-256 and sha256 of the same value must be equal")
	}
	if compareHashes(map[string]string{"sha1": "aa"}, map[string]string{"sha256": "bb"}) != "" {
		t.Error("disjoint kinds must be unverified, not modified")
	}
	if compareHashes(map[string]string{"sha1": "aa"}, map[string]string{"sha1": "aa", "sha256": "bb"}) != "equal" {
		t.Error("a hash kind added on one side is not a modification")
	}

	// CDX file entries: one-sided hash unverified
	file := func(h map[string]string) sbom.Component {
		return sbom.Component{ID: "ref:f", Name: "/go.mod", Type: "file", Hashes: h}
	}
	r := DiffComponents([]sbom.Component{file(map[string]string{"SHA-1": "aa"})}, []sbom.Component{file(map[string]string{"SHA-256": "bb"})})
	if len(r.FileChanges) != 0 || r.FileCoverage.FilesUnverified != 1 {
		t.Errorf("file_changes=%+v coverage=%+v", r.FileChanges, r.FileCoverage)
	}
}

func TestFileDelta_AllMatchIsStrict(t *testing.T) {
	pkg := func(v string, files ...string) sbom.Component {
		c := goPkg("x", v, "/lib/apk/db/installed")
		c.OwnedFiles = files
		return c
	}
	inv := func(h string) []sbom.FileEntry {
		return []sbom.FileEntry{{Path: "/a", Hashes: map[string]string{"sha256": "1"}}, {Path: "/b", Hashes: map[string]string{h: "2"}}}
	}
	r := DiffSBOMs([]sbom.Component{pkg("v1.0.0", "/a", "/b")}, []sbom.Component{pkg("v1.0.1", "/a", "/b")}, inv("sha256"), inv("sha256"))
	if f := r.Changed[0].Drift.Files; f == nil || !f.AllMatch {
		t.Fatalf("identical owned files: %+v", f)
	}
	r = DiffSBOMs([]sbom.Component{pkg("v1.0.0", "/a", "/b")}, []sbom.Component{pkg("v1.0.1", "/a", "/b")}, inv("sha256"), inv("md5"))
	if f := r.Changed[0].Drift.Files; f.AllMatch || f.Unverified != 1 {
		t.Errorf("an unverifiable file must clear all_match: %+v", f)
	}
}

func TestFileInventory_DuplicatePathNotCompared(t *testing.T) {
	inv := func(h string) []sbom.FileEntry {
		return []sbom.FileEntry{
			{Path: "/etc/x", Hashes: map[string]string{"sha256": h}, Layer: "l1"},
			{Path: "/etc/x", Hashes: map[string]string{"sha256": "zz"}, Layer: "l2"},
		}
	}
	r := DiffSBOMs(nil, nil, inv("aa"), inv("bb"))
	if len(r.FileChanges) != 0 || r.FileCoverage.AmbiguousPaths != 1 {
		t.Errorf("all-layers duplicate paths must not be guessed: %+v / %+v", r.FileChanges, r.FileCoverage)
	}
}

func TestFileDiffIndependentOfOrder(t *testing.T) {
	b, bi := loadFixture(t, "files/alpine-base.syft.json")
	a, ai := loadFixture(t, "files/alpine-tamp.syft.json")
	want := DiffSBOMs(b, a, bi.Files, ai.Files)
	rnd := rand.New(rand.NewSource(3))
	for i := 0; i < 3; i++ {
		sb, sa, fb, fa := slices.Clone(b), slices.Clone(a), slices.Clone(bi.Files), slices.Clone(ai.Files)
		rnd.Shuffle(len(sa), func(i, j int) { sa[i], sa[j] = sa[j], sa[i] })
		rnd.Shuffle(len(fa), func(i, j int) { fa[i], fa[j] = fa[j], fa[i] })
		rnd.Shuffle(len(fb), func(i, j int) { fb[i], fb[j] = fb[j], fb[i] })
		got := DiffSBOMs(sb, sa, fb, fa)
		if summary(got) != summary(want) || len(got.FileChanges) != len(want.FileChanges) || len(got.OwnedFileDrift) != len(want.OwnedFileDrift) {
			t.Fatalf("order-dependent result")
		}
	}
}

func TestOwnedFileDelta_Counts(t *testing.T) {
	files := func(h string) []sbom.FileEntry {
		return []sbom.FileEntry{
			{Path: "/same", Hashes: map[string]string{"sha256": "aa"}},
			{Path: "/mod", Hashes: map[string]string{"sha256": h}},
			{Path: "/nohash"},
		}
	}
	pkg := sbom.Component{Name: "p", OwnedFiles: []string{"/same", "/mod", "/nohash"}}
	bf, af := files("bb"), files("cc")
	bi, ai := newFileIndex(bf, []sbom.Component{pkg}), newFileIndex(af, []sbom.Component{pkg})
	_, d := ownedFileDelta(pkg, pkg, bi, ai)
	if d.Unchanged != 1 || d.Modified != 1 || d.Unverified != 1 || d.AllMatch {
		t.Errorf("got %+v", d)
	}
	ai = newFileIndex(files("bb"), []sbom.Component{pkg})
	_, d = ownedFileDelta(pkg, pkg, bi, ai)
	if d.Unchanged != 2 || d.AllMatch {
		t.Errorf("unhashed file must block all_match: %+v", d)
	}
}

func TestCrossFormatFiles(t *testing.T) {
	pkg := func(v string, owned ...string) sbom.Component {
		return sbom.Component{ID: "pkg:deb/a", Name: "a", Version: v, PURL: "pkg:deb/debian/a@" + v, OwnedFiles: owned}
	}
	inv := []sbom.FileEntry{{Path: "/usr/bin/a", Hashes: map[string]string{"sha256": "11"}}, {Path: "/usr/lib/x.so"}}
	cdxFile := sbom.Component{ID: "/usr/bin/a", Name: "/usr/bin/a", Type: "file", Hashes: map[string]string{"SHA-256": "11"}}
	osComp := sbom.Component{ID: "os:debian", Name: "debian", Version: "12.10", Type: "operating-system"}
	// Syft JSON (owned, unhashed file listed) vs CycloneDX (no ownership, hashed files only, OS entry)
	r := DiffSBOMs([]sbom.Component{pkg("1", "/usr/bin/a", "/usr/lib/x.so")}, []sbom.Component{pkg("1"), cdxFile, osComp}, inv, nil)
	if r.HasChanges() || r.FileCoverage == nil || r.FileCoverage.FilesCompared != 1 {
		t.Errorf("same image across formats must be clean: %+v", r)
	}
	// CycloneDX vs CycloneDX: file entries land in files_added, not added
	r = DiffSBOMs([]sbom.Component{pkg("1")}, []sbom.Component{pkg("1"), cdxFile}, nil, nil)
	if len(r.Added) != 0 || len(r.FilesAdded) != 1 || r.FilesAdded[0].Path != "/usr/bin/a" {
		t.Errorf("added %+v files_added %+v", r.Added, r.FilesAdded)
	}
}

func TestUnhashedFileChangesNotHidden(t *testing.T) {
	x := sbom.Component{ID: "pkg:generic/x", Name: "x", Version: "1"}
	gone := sbom.Component{ID: "/removed", Name: "/removed", Type: "file"}
	// same format (CycloneDX both sides), unhashed file removed
	r := DiffSBOMs([]sbom.Component{x, gone}, []sbom.Component{x}, nil, nil)
	if len(r.FilesRemoved) != 1 || !r.HasChanges() {
		t.Errorf("unhashed removal must show: %+v", r.FilesRemoved)
	}
	// Syft JSON both sides, unhashed file removed
	r = DiffSBOMs([]sbom.Component{x}, []sbom.Component{x}, []sbom.FileEntry{{Path: "/a"}, {Path: "/b", Hashes: map[string]string{"sha256": "1"}}}, []sbom.FileEntry{{Path: "/b", Hashes: map[string]string{"sha256": "1"}}})
	if len(r.FilesRemoved) != 1 {
		t.Errorf("got %+v", r.FilesRemoved)
	}
}

func TestOwnershipLossReported(t *testing.T) {
	files := []sbom.FileEntry{{Path: "/x", Hashes: map[string]string{"sha256": "1"}}}
	b := []sbom.Component{{ID: "pkg:deb/a", Name: "a", Version: "1", OwnedFiles: []string{"/x"}}}
	a := []sbom.Component{{ID: "pkg:deb/a", Name: "a", Version: "1"}}
	r := DiffSBOMs(b, a, files, files)
	if len(r.OwnedFileDrift) != 1 || r.OwnedFileDrift[0].Files[0].Change != FileRemoved {
		t.Errorf("losing the last owned file is drift: %+v", r.OwnedFileDrift)
	}
}

func TestIdentifiedOSIsAPackage(t *testing.T) {
	os := func(v string) sbom.Component {
		return sbom.Component{ID: "pkg:generic/x", Name: "x", Version: v, Type: "operating-system", PURL: "pkg:generic/x@" + v}
	}
	r := DiffComponents([]sbom.Component{os("12")}, []sbom.Component{os("11")})
	if len(r.Changed) != 1 || r.Changed[0].Drift.Direction != DirectionDowngrade {
		t.Errorf("OS with a PURL is matched like a package: %+v", r.Changed)
	}
	syftOS := func(v string) sbom.Component {
		return sbom.Component{ID: "os:debian", Name: "debian", Version: v, Type: "operating-system"}
	}
	if r := DiffComponents([]sbom.Component{syftOS("12.10")}, []sbom.Component{syftOS("12.12")}); len(r.Changed) != 0 {
		t.Errorf("identity-less OS goes to os_change: %+v", r.Changed)
	}
	c := OSChangeOf(sbom.SBOMInfo{OSPrettyName: "Debian 12", OSVersionID: "12.10"}, sbom.SBOMInfo{OSPrettyName: "Debian 12", OSVersionID: "12.12"})
	if c == nil || c.From != "Debian 12 12.10" || !(DiffResult{OSChange: c}).HasChanges() {
		t.Errorf("got %+v", c)
	}
	if OSChangeOf(sbom.SBOMInfo{OSPrettyName: "Debian 12"}, sbom.SBOMInfo{}) != nil {
		t.Error("unknown side is no change")
	}
}

func TestDuplicateFileCopyLost(t *testing.T) {
	x := sbom.Component{ID: "pkg:generic/x", Name: "x", Version: "1"}
	f := sbom.Component{ID: "/x", Name: "/x", Type: "file", Hashes: map[string]string{"SHA-256": "1"}}
	r := DiffSBOMs([]sbom.Component{x, f, f}, []sbom.Component{x, f}, nil, nil)
	if len(r.FilesRemoved) != 1 || !r.HasChanges() {
		t.Errorf("one of two copies removed: %+v", r.FilesRemoved)
	}
}
