package analysis

import (
	"encoding/json"
	"math/rand"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func loadFixture(t *testing.T, name string) ([]sbom.Component, sbom.SBOMInfo) {
	t.Helper()
	comps, info, err := sbom.ParseFileWithInfo(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return sbom.NormalizeComponents(comps), info
}

func diffFixtures(t *testing.T, before, after string) DiffResult {
	t.Helper()
	b, _ := loadFixture(t, before)
	a, _ := loadFixture(t, after)
	return DiffComponents(b, a)
}

func goPkg(name, version, loc string) sbom.Component {
	c := sbom.Component{
		ID:      "pkg:golang/" + name,
		Name:    name,
		Version: version,
		PURL:    "pkg:golang/" + name + "@" + version,
		Type:    "library",
	}
	if loc != "" {
		c.Locations = []string{loc}
	}
	return c
}

func withH1(c sbom.Component, h1 string) sbom.Component {
	c.Digests = map[string]string{sbom.DigestGoH1: h1}
	return c
}

func summary(r DiffResult) DriftSummary {
	if r.DriftSummary == nil {
		return DriftSummary{}
	}
	return *r.DriftSummary
}

func names(comps []sbom.Component) []string {
	out := make([]string, len(comps))
	for i, c := range comps {
		out[i] = c.Name + " " + c.Version
	}
	return out
}

// FIX-SPEC repro 1: v-prefixed versions, pseudo-versions.
func TestRepro1VersionDirection(t *testing.T) {
	r := diffFixtures(t, "repro1-before.cdx.json", "repro1-after.cdx.json")
	s := summary(r)
	if s.Upgrades != 5 || s.Downgrades != 0 || s.UnknownDirection != 0 {
		t.Fatalf("want 5 upgrades, 0 downgrades; got %+v", s)
	}
	levels := map[string]int{}
	for _, c := range r.Changed {
		levels[c.Drift.Level]++
	}
	if levels[LevelMajor] != 3 || levels[LevelMinor] != 1 || levels[LevelPatch] != 1 {
		t.Errorf("want 3 major, 1 minor, 1 patch; got %v", levels)
	}
	b, bi := loadFixture(t, "repro1-before.cdx.json")
	a, ai := loadFixture(t, "repro1-after.cdx.json")
	f := ComputeKeyFindings(r, ComputeDiffOverview("", "", b, a, bi, ai))
	for _, fd := range f.Findings {
		if strings.Contains(fd.Message, "downgrade") {
			t.Errorf("unexpected downgrade finding: %s", fd.Message)
		}
	}
}

// FIX-SPEC repro 2: shared ID never dropped
func TestRepro2SharedIDNotDropped(t *testing.T) {
	r := diffFixtures(t, "repro2-before.cdx.json", "repro2-after.cdx.json")
	if got := names(r.Added); !slices.Equal(got, []string{"example.com/m v0.2.17"}) {
		t.Fatalf("added = %v", got)
	}
	if len(r.Added[0].Locations) != 1 || r.Added[0].Locations[0] != "/sub/Cargo.lock" {
		t.Errorf("added location = %v", r.Added[0].Locations)
	}
	if len(r.Changed) != 0 || len(r.Removed) != 0 {
		t.Errorf("want no changed/removed, got changed=%d removed=%d", len(r.Changed), len(r.Removed))
	}
}

// FIX-SPEC repro 3: files not integrity drift
func TestRepro3FileVsPackageIntegrity(t *testing.T) {
	r := diffFixtures(t, "repro3-before.cdx.json", "repro3-after.cdx.json")
	s := summary(r)
	if s.IntegrityDrift != 1 || s.FileChanges != 1 {
		t.Fatalf("want integrity 1, file_changes 1; got %+v", s)
	}
	if len(r.Changed) != 1 || r.Changed[0].Name != "example.com/x" || r.Changed[0].Drift.Type != DriftTypeIntegrity {
		t.Fatalf("changed = %+v", r.Changed)
	}
	if hc := r.Changed[0].Drift.HashChanges; hc == nil || hc.Changed[sbom.DigestGoH1].After != "h1:BBBB=" {
		t.Errorf("hash_changes = %+v", hc)
	}
	if len(r.FileChanges) != 1 || r.FileChanges[0].Path != "/go.mod" {
		t.Errorf("file_changes = %+v", r.FileChanges)
	}
	if r.DigestCoverage == nil || r.DigestCoverage.Comparable != 1 || r.DigestCoverage.ByKind[sbom.DigestGoH1] != 1 {
		t.Errorf("digest_coverage = %+v", r.DigestCoverage)
	}
}

func TestMatchOccurrences(t *testing.T) {
	t.Run("moved at the same version is not a version change", func(t *testing.T) {
		r := DiffComponents(
			[]sbom.Component{goPkg("example.com/a", "v1.0.0", "/a/go.mod")},
			[]sbom.Component{goPkg("example.com/a", "v1.0.0", "/b/go.mod")})
		if len(r.Moved) != 1 || r.Moved[0].From != "/a/go.mod" || r.Moved[0].To != "/b/go.mod" {
			t.Fatalf("moved = %+v", r.Moved)
		}
		if len(r.Changed)+len(r.Added)+len(r.Removed) != 0 || !r.HasChanges() {
			t.Errorf("want only a move; got %+v", r)
		}
	})

	t.Run("two versions, one bumped", func(t *testing.T) {
		r := DiffComponents(
			[]sbom.Component{goPkg("m", "v1.0.0", "/a/go.mod"), goPkg("m", "v2.0.0", "/b/go.mod")},
			[]sbom.Component{goPkg("m", "v1.0.0", "/a/go.mod"), goPkg("m", "v2.1.0", "/b/go.mod")})
		if len(r.Changed) != 1 || r.Changed[0].Location != "/b/go.mod" || r.Changed[0].Drift.VersionTo != "v2.1.0" {
			t.Fatalf("changed = %+v", r.Changed)
		}
		if len(r.Added)+len(r.Removed) != 0 {
			t.Errorf("added/removed = %v / %v", names(r.Added), names(r.Removed))
		}
	})

	t.Run("three versions to two at one location: one removed", func(t *testing.T) {
		loc := "/package-lock.json"
		r := DiffComponents(
			[]sbom.Component{goPkg("m", "v1.0.0", loc), goPkg("m", "v2.0.0", loc), goPkg("m", "v3.0.0", loc)},
			[]sbom.Component{goPkg("m", "v1.0.0", loc), goPkg("m", "v3.0.0", loc)})
		if got := names(r.Removed); !slices.Equal(got, []string{"m v2.0.0"}) || len(r.Changed) != 0 {
			t.Fatalf("removed = %v, changed = %d", got, len(r.Changed))
		}
	})

	t.Run("several leftovers at one location: version set change, no pairing", func(t *testing.T) {
		loc := "/frontend/package-lock.json"
		r := DiffComponents(
			[]sbom.Component{goPkg("e", "v1.10.0", loc)},
			[]sbom.Component{goPkg("e", "v1.11.0", loc), goPkg("e", "v1.9.2", loc)})
		if len(r.Changed) != 0 || len(r.VersionSetChanges) != 1 {
			t.Fatalf("changed=%d version_set_changes=%+v", len(r.Changed), r.VersionSetChanges)
		}
		v := r.VersionSetChanges[0]
		if !slices.Equal(v.RemovedVersions, []string{"v1.10.0"}) || !slices.Equal(v.AddedVersions, []string{"v1.11.0", "v1.9.2"}) {
			t.Errorf("version set = %+v", v)
		}
		if len(r.Added) != 2 || len(r.Removed) != 1 {
			t.Errorf("occurrences must stay in added/removed: %v / %v", names(r.Added), names(r.Removed))
		}
	})

	t.Run("never pair across lockfiles (codeql os_str_bytes)", func(t *testing.T) {
		// both lockfiles exist on both sides
		live := []sbom.Component{goPkg("serde", "v1.0.0", "/Cargo.lock"), goPkg("serde", "v1.0.0", "/cpp/extractor/bmn/Cargo.lock")}
		r := DiffComponents(
			append(slices.Clone(live), goPkg("os_str_bytes", "v7.2.0", "/Cargo.lock")),
			append(slices.Clone(live), goPkg("os_str_bytes", "v7.1.1", "/cpp/extractor/bmn/Cargo.lock")))
		if len(r.Changed) != 0 || len(r.Added) != 1 || len(r.Removed) != 1 {
			t.Fatalf("want removed+added; got changed=%d added=%v removed=%v", len(r.Changed), names(r.Added), names(r.Removed))
		}
	})

	t.Run("replaced install directory pairs the single occurrence (image upgrade)", func(t *testing.T) {
		py := func(dir, v string) sbom.Component {
			return sbom.Component{
				ID: "pkg:pypi/pip", Name: "pip", Version: v, PURL: "pkg:pypi/pip@" + v,
				Locations: []string{dir + "/site-packages/pip-" + v + ".dist-info/METADATA"},
			}
		}
		r := DiffComponents(
			[]sbom.Component{py("/usr/local/lib/python3.11", "24.0")},
			[]sbom.Component{py("/usr/local/lib/python3.12", "24.2")})
		if len(r.Changed) != 1 || r.Changed[0].Drift.Direction != DirectionUpgrade || len(r.Added)+len(r.Removed) != 0 {
			t.Fatalf("changed=%+v added=%v removed=%v", r.Changed, names(r.Added), names(r.Removed))
		}
	})

	t.Run("Syft primary evidence location is the match location", func(t *testing.T) {
		deb := func(v, doc string) sbom.Component {
			return sbom.Component{
				ID: "pkg:deb/libc6", Name: "libc6", Version: v, PURL: "pkg:deb/debian/libc6@" + v,
				Locations:        []string{"/var/lib/dpkg/status", doc},
				PrimaryLocations: []string{"/var/lib/dpkg/status"},
			}
		}
		r := DiffComponents([]sbom.Component{deb("2.36-9", "/usr/share/doc/a")}, []sbom.Component{deb("2.36-10", "/usr/share/doc/b")})
		if len(r.Changed) != 1 || r.Changed[0].Location != "/var/lib/dpkg/status" {
			t.Fatalf("changed=%+v", r.Changed)
		}
	})

	t.Run("no location on one side matches the single occurrence", func(t *testing.T) {
		r := DiffComponents(
			[]sbom.Component{goPkg("m", "v1.0.0", "")},
			[]sbom.Component{goPkg("m", "v1.1.0", "/go.mod")})
		if len(r.Changed) != 1 || len(r.Added)+len(r.Removed)+len(r.Moved) != 0 {
			t.Fatalf("changed=%d added=%d removed=%d moved=%d", len(r.Changed), len(r.Added), len(r.Removed), len(r.Moved))
		}
	})

	t.Run("version embedded in the path is still one location", func(t *testing.T) {
		py := func(v string) sbom.Component {
			return sbom.Component{
				ID: "pkg:pypi/requests", Name: "requests", Version: v, PURL: "pkg:pypi/requests@" + v,
				Locations: []string{"/usr/lib/python3/site-packages/requests-" + v + ".dist-info/METADATA"},
			}
		}
		r := DiffComponents([]sbom.Component{py("2.31.0")}, []sbom.Component{py("2.32.3")})
		if len(r.Changed) != 1 || r.Changed[0].Drift.Direction != DirectionUpgrade {
			t.Fatalf("want one upgrade; changed=%+v added=%d removed=%d", r.Changed, len(r.Added), len(r.Removed))
		}
	})

	t.Run("version masking does not merge unrelated directories", func(t *testing.T) {
		if k1, k2 := locationMatchKey("/opt/v1/lib/x", "1"), locationMatchKey("/opt/v2/lib/x", "2"); k1 == k2 {
			t.Errorf("unrelated paths merged: %s", k1)
		}
		if k := locationMatchKey("/app/lib/foo-1.2.jar", "1.2"); k != "/app/lib/foo-{version}.jar" {
			t.Errorf("jar key = %s", k)
		}
		if k := locationMatchKey("/app/lib/foo-1.2.jar", "1"); k != "/app/lib/foo-1.2.jar" {
			t.Errorf("partial version must not be masked: %s", k)
		}
	})

	t.Run("npm names match case-insensitively, Go names do not", func(t *testing.T) {
		npm := func(name, v string) sbom.Component {
			return sbom.Component{ID: "pkg:npm/" + name, Name: name, Version: v, PURL: "pkg:npm/" + name + "@" + v}
		}
		r := DiffComponents([]sbom.Component{npm("JSONStream", "1.0.0")}, []sbom.Component{npm("jsonstream", "1.1.0")})
		if len(r.Changed) != 1 {
			t.Errorf("npm case fold: changed=%d added=%d", len(r.Changed), len(r.Added))
		}
		r = DiffComponents([]sbom.Component{goPkg("github.com/Foo/bar", "v1.0.0", "")}, []sbom.Component{goPkg("github.com/foo/bar", "v1.1.0", "")})
		if len(r.Changed) != 0 || len(r.Added) != 1 {
			t.Errorf("go paths are case-sensitive: changed=%d added=%d", len(r.Changed), len(r.Added))
		}
	})
}

func TestIntegrityDriftRules(t *testing.T) {
	loc := "/go.mod"
	t.Run("file-only change: no integrity drift, one file change", func(t *testing.T) {
		file := func(h string) sbom.Component {
			return sbom.Component{ID: "ref:f", Name: "/go.mod", Type: "file", Hashes: map[string]string{"SHA-256": h}}
		}
		r := DiffComponents([]sbom.Component{file("aa")}, []sbom.Component{file("bb")})
		if s := summary(r); s.IntegrityDrift != 0 || s.FileChanges != 1 || len(r.Changed) != 0 {
			t.Fatalf("summary=%+v changed=%d", s, len(r.Changed))
		}
		if !r.HasChanges() {
			t.Error("a file change must still count as a change")
		}
	})
	t.Run("h1 change at the same version", func(t *testing.T) {
		r := DiffComponents([]sbom.Component{withH1(goPkg("x", "v1.0.0", loc), "h1:A=")},
			[]sbom.Component{withH1(goPkg("x", "v1.0.0", loc), "h1:B=")})
		if s := summary(r); s.IntegrityDrift != 1 {
			t.Fatalf("summary=%+v", s)
		}
	})
	t.Run("version change plus digest change is version drift only", func(t *testing.T) {
		r := DiffComponents([]sbom.Component{withH1(goPkg("x", "v1.0.0", loc), "h1:A=")},
			[]sbom.Component{withH1(goPkg("x", "v1.0.1", loc), "h1:B=")})
		if s := summary(r); s.IntegrityDrift != 0 || s.VersionDrift != 1 {
			t.Fatalf("summary=%+v", s)
		}
	})
	t.Run("digest only after is coverage, not a change", func(t *testing.T) {
		r := DiffComponents([]sbom.Component{goPkg("x", "v1.0.0", loc)},
			[]sbom.Component{withH1(goPkg("x", "v1.0.0", loc), "h1:B=")})
		if len(r.Changed) != 0 || r.DriftSummary != nil {
			t.Fatalf("changed=%+v summary=%+v", r.Changed, r.DriftSummary)
		}
		if r.DigestCoverage.AfterOnly != 1 || r.DigestCoverage.Comparable != 0 {
			t.Errorf("coverage=%+v", r.DigestCoverage)
		}
	})
	t.Run("Bug 9: added digest plus license change is metadata drift", func(t *testing.T) {
		b := goPkg("x", "v1.0.0", loc)
		a := withH1(goPkg("x", "v1.0.0", loc), "h1:B=")
		a.Licenses = []string{"MIT"}
		r := DiffComponents([]sbom.Component{b}, []sbom.Component{a})
		if s := summary(r); s.IntegrityDrift != 0 || s.MetadataDrift != 1 || s.LicenseChanges != 1 {
			t.Fatalf("summary=%+v", s)
		}
	})
	t.Run("different digest kinds are never compared", func(t *testing.T) {
		b := goPkg("x", "v1.0.0", loc)
		b.Hashes = map[string]string{"SHA-256": "aa"}
		a := withH1(goPkg("x", "v1.0.0", loc), "h1:B=")
		r := DiffComponents([]sbom.Component{b}, []sbom.Component{a})
		if len(r.Changed) != 0 || r.DigestCoverage.DisjointKinds != 1 {
			t.Fatalf("changed=%d coverage=%+v", len(r.Changed), r.DigestCoverage)
		}
	})
	t.Run("empty version is never integrity drift", func(t *testing.T) {
		b := goPkg("x", "", loc)
		b.Hashes = map[string]string{"SHA-256": "aa"}
		a := goPkg("x", "", loc)
		a.Hashes = map[string]string{"SHA-256": "bb"}
		if s := summary(DiffComponents([]sbom.Component{b}, []sbom.Component{a})); s.IntegrityDrift != 0 {
			t.Fatalf("summary=%+v", s)
		}
	})
	t.Run("conflicting same-version duplicates do not depend on order", func(t *testing.T) {
		before := []sbom.Component{withH1(goPkg("x", "v1.0.0", loc), "h1:A="), withH1(goPkg("x", "v1.0.0", loc), "h1:B=")}
		after := []sbom.Component{withH1(goPkg("x", "v1.0.0", loc), "h1:B="), withH1(goPkg("x", "v1.0.0", loc), "h1:C=")}
		r1 := DiffComponents(before, after)
		r2 := DiffComponents(before, []sbom.Component{after[1], after[0]})
		r3 := DiffComponents([]sbom.Component{before[1], before[0]}, after)
		if s := summary(r1); s.IntegrityDrift != 1 {
			t.Fatalf("want identical B=B cancelled and A->C drift; got %+v", s)
		}
		if summary(r2) != summary(r1) || summary(r3) != summary(r1) {
			t.Errorf("order-dependent: %+v / %+v / %+v", summary(r1), summary(r2), summary(r3))
		}
	})
	t.Run("existing CycloneDX integrity fixture still drifts", func(t *testing.T) {
		r := diffFixtures(t, "cyclonedx-before.json", "cyclonedx-integrity-drift.json")
		if s := summary(r); s.IntegrityDrift != 1 {
			t.Fatalf("summary=%+v", s)
		}
	})
	t.Run("tamper demo (sbomlyze-go-spdx-demo PR #2) still drifts", func(t *testing.T) {
		r := diffFixtures(t, "tamper-demo-base.spdx.json", "tamper-demo-head.spdx.json")
		if s := summary(r); s.IntegrityDrift != 1 {
			t.Fatalf("summary=%+v", s)
		}
	})
}

// result must not depend on input order
func TestDiffIndependentOfInputOrder(t *testing.T) {
	pairs := [][2]string{
		{"realworld/syft-before.cdx.json", "realworld/syft-after.cdx.json"},
		{"realworld/codeql-before.cdx.json", "realworld/codeql-after.cdx.json"},
		{"realworld/infisical-before.cdx.json", "realworld/infisical-after.cdx.json"},
		{"realworld/prowler-before.cdx.json", "realworld/prowler-after.cdx.json"},
		{"repro2-before.cdx.json", "repro2-after.cdx.json"},
	}
	for _, p := range pairs {
		b, bi := loadFixture(t, p[0])
		a, ai := loadFixture(t, p[1])
		want := encodeDiff(t, b, a, bi, ai)
		rnd := rand.New(rand.NewSource(1))
		for i := 0; i < 3; i++ {
			sb, sa := slices.Clone(b), slices.Clone(a)
			rnd.Shuffle(len(sb), func(i, j int) { sb[i], sb[j] = sb[j], sb[i] })
			rnd.Shuffle(len(sa), func(i, j int) { sa[i], sa[j] = sa[j], sa[i] })
			if got := encodeDiff(t, sb, sa, bi, ai); got != want {
				t.Fatalf("%s: output changed after shuffling input", p[0])
			}
		}
	}
}

func encodeDiff(t *testing.T, b, a []sbom.Component, bi, ai sbom.SBOMInfo) string {
	t.Helper()
	r := DiffComponents(b, a)
	ComputePackageSamples(&r)
	f := ComputeKeyFindings(r, ComputeDiffOverview("", "", b, a, bi, ai))
	out, err := json.Marshal(struct {
		D DiffResult
		F KeyFindings
	}{r, f})
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func findingWith(f KeyFindings, substr string) string {
	for _, fd := range f.Findings {
		if strings.Contains(fd.Message, substr) {
			return fd.Message
		}
	}
	return ""
}

// FIX-SPEC section 5 rows, trimmed real SBOMs
func TestRealWorldAcceptance(t *testing.T) {
	t.Run("anchore/syft", func(t *testing.T) {
		b, bi := loadFixture(t, "realworld/syft-before.cdx.json")
		a, ai := loadFixture(t, "realworld/syft-after.cdx.json")
		r := DiffComponents(b, a)
		s := summary(r)
		want := DriftSummary{VersionDrift: 43, Upgrades: 43, DistinctVersionChanges: 40, FileChanges: 6}
		if s != want {
			t.Errorf("summary = %+v, want %+v", s, want)
		}
		cov := r.DigestCoverage
		if cov.Comparable != 302 || cov.ByKind[sbom.DigestGoH1] != 302 || cov.PackagesTotal != 362 || cov.SameVersionPairs != 318 {
			t.Errorf("coverage = %+v", cov)
		}
		levels := map[string]map[string]bool{}
		for _, c := range r.Changed {
			if levels[c.Drift.Level] == nil {
				levels[c.Drift.Level] = map[string]bool{}
			}
			levels[c.Drift.Level][c.ID+c.Drift.VersionFrom+c.Drift.VersionTo] = true
		}
		if len(levels[LevelMajor]) != 1 || len(levels[LevelMinor]) != 17 || len(levels[LevelPatch]) != 20 || len(levels[LevelPrerelease]) != 2 {
			t.Errorf("levels: major %d minor %d patch %d prerelease %d", len(levels[LevelMajor]), len(levels[LevelMinor]), len(levels[LevelPatch]), len(levels[LevelPrerelease]))
		}
		locs := map[string][]string{}
		for _, c := range r.Changed {
			locs[c.ID] = append(locs[c.ID], c.Location)
		}
		if l := locs["pkg:golang/golang.org/x/sys"]; !slices.Equal(l, []string{"/.make/go.mod"}) {
			t.Errorf("x/sys locations = %v", l)
		}
		for _, id := range []string{"pkg:golang/github.com/bmatcuk/doublestar/v4", "pkg:golang/golang.org/x/mod", "pkg:github/anchore/go-make#.github/actions/setup"} {
			if len(locs[id]) != 2 {
				t.Errorf("%s changes in %d locations, want 2", id, len(locs[id]))
			}
		}
		if got := names(r.Added); !slices.Equal(got, []string{"github.com/varlink/go v0.4.1-0.20261015173642-c935be0c53f7"}) {
			t.Errorf("added = %v", got)
		}
		if got := names(r.Removed); !slices.Equal(got, []string{"github.com/becheran/wildmatch-go v1.0.0"}) {
			t.Errorf("removed = %v", got)
		}
		if _, ok := locs["pkg:golang/github.com/Microsoft/go-winio"]; !ok {
			t.Error("go-winio missing")
		}
		for _, c := range r.Changed {
			if c.ID == "pkg:golang/github.com/Microsoft/go-winio" && c.Name != "github.com/Microsoft/go-winio" {
				t.Errorf("name case lost: %s", c.Name)
			}
		}
		f := ComputeKeyFindings(r, ComputeDiffOverview("", "", b, a, bi, ai))
		if m := findingWith(f, "downgrade"); m != "" {
			t.Errorf("unexpected: %s", m)
		}
		if m := findingWith(f, "unchanged"); m != "" {
			t.Errorf("types with version changes reported unchanged: %s", m)
		}
		if m := findingWith(f, "golang: 342 packages before and after"); m == "" {
			t.Errorf("missing per-type count finding: %v", f.Findings)
		}
	})

	t.Run("github/codeql", func(t *testing.T) {
		r := diffFixtures(t, "realworld/codeql-before.cdx.json", "realworld/codeql-after.cdx.json")
		if s := summary(r); s.Downgrades != 0 {
			t.Errorf("downgrades = %d", s.Downgrades)
		}
		added := strings.Join(names(r.Added), ",")
		if !strings.Contains(added, "cpufeatures 0.2.17") || !strings.Contains(added, "os_str_bytes 7.1.1") {
			t.Errorf("added = %s", added)
		}
		if !slices.Contains(names(r.Removed), "os_str_bytes 7.2.0") {
			t.Errorf("removed = %v", names(r.Removed))
		}
		for _, c := range r.Changed {
			if c.Name == "cpufeatures" || c.Name == "os_str_bytes" {
				t.Errorf("%s must not be paired: %+v", c.Name, c.Drift)
			}
		}
	})

	t.Run("Infisical", func(t *testing.T) {
		r := diffFixtures(t, "realworld/infisical-before.cdx.json", "realworld/infisical-after.cdx.json")
		var downs []string
		lic := map[string][]string{}
		for _, c := range r.Changed {
			if c.Drift.Direction == DirectionDowngrade {
				downs = append(downs, c.Name+" "+c.Drift.VersionFrom+"->"+c.Drift.VersionTo+" @ "+c.Location)
			}
			lic[c.Name+" "+c.Drift.VersionFrom+"->"+c.Drift.VersionTo] = c.Drift.LicensesDiff
		}
		if !slices.Equal(downs, []string{"cluster-key-slot 1.1.2->1.1.1 @ /backend/package-lock.json"}) {
			t.Errorf("downgrades = %v", downs)
		}
		for k, want := range map[string]string{"@noble/hashes 1.4.0->1.8.0": "+MIT", "cluster-key-slot 1.1.2->1.1.1": "+Apache-2.0", "pkijs 3.2.4->3.4.2": "+BSD-3-Clause"} {
			if !slices.Contains(lic[k], want) {
				t.Errorf("%s licenses_diff = %v, want %s", k, lic[k], want)
			}
		}
		if len(r.VersionSetChanges) != 2 {
			t.Errorf("version_set_changes = %+v", r.VersionSetChanges)
		}
	})

	t.Run("cfn-lint unknown direction is listed", func(t *testing.T) {
		b, bi := loadFixture(t, "realworld/cfn-lint-before.cdx.json")
		a, ai := loadFixture(t, "realworld/cfn-lint-after.cdx.json")
		r := DiffComponents(b, a)
		if s := summary(r); s.UnknownDirection != 1 || s.IntegrityDrift != 0 || s.FileChanges != 1 {
			t.Errorf("summary = %+v", s)
		}
		f := ComputeKeyFindings(r, ComputeDiffOverview("", "", b, a, bi, ai))
		if m := findingWith(f, "unknown direction"); !strings.Contains(m, "release/v1→v1.14.3") {
			t.Errorf("unknown-direction finding = %q", m)
		}
		if m := findingWith(f, "github (19) unchanged"); m != "" {
			t.Errorf("Bug 4: %s", m)
		}
	})

	t.Run("prowler several versions per lockfile", func(t *testing.T) {
		r := diffFixtures(t, "realworld/prowler-before.cdx.json", "realworld/prowler-after.cdx.json")
		if len(r.VersionSetChanges) != 1 || r.VersionSetChanges[0].Name != "brace-expansion" {
			t.Fatalf("version_set_changes = %+v", r.VersionSetChanges)
		}
		if s := summary(r); s.Downgrades != 0 || s.IntegrityDrift != 0 {
			t.Errorf("summary = %+v", s)
		}
	})
}

// Codex: moves keep license changes
func TestMovedKeepsLicenseChange(t *testing.T) {
	b := goPkg("m", "v1.0.0", "/a/go.mod")
	b.Licenses = []string{"MIT"}
	a := goPkg("m", "v1.0.0", "/b/go.mod")
	a.Licenses = []string{"Apache-2.0"}
	r := DiffComponents([]sbom.Component{b}, []sbom.Component{a})
	if len(r.Moved) != 1 {
		t.Fatalf("moved = %+v", r.Moved)
	}
	if s := summary(r); s.MetadataDrift != 1 || s.LicenseChanges != 1 || s.IntegrityDrift != 0 {
		t.Fatalf("summary = %+v", s)
	}
	if r.Changed[0].Location != "/b/go.mod" || !slices.Equal(r.Changed[0].Drift.LicensesDiff, []string{"+Apache-2.0", "-MIT"}) {
		t.Errorf("changed = %+v", r.Changed[0])
	}
}
