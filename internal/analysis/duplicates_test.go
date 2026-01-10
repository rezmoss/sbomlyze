package analysis

import (
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestDetectDuplicates(t *testing.T) {
	t.Run("detects duplicate packages with different versions", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20"},
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
			{ID: "pkg:npm/express", Name: "express", Version: "4.18.0"},
		}

		dups := DetectDuplicates(comps)

		if len(dups) != 1 {
			t.Errorf("expected 1 duplicate group, got %d", len(dups))
		}
		if len(dups) > 0 {
			if dups[0].Name != "lodash" {
				t.Errorf("expected lodash, got %s", dups[0].Name)
			}
			if len(dups[0].Versions) != 2 {
				t.Errorf("expected 2 versions, got %d", len(dups[0].Versions))
			}
		}
	})

	t.Run("no duplicates when all unique", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
			{ID: "pkg:npm/express", Name: "express", Version: "4.18.0"},
		}

		dups := DetectDuplicates(comps)

		if len(dups) != 0 {
			t.Errorf("expected 0 duplicate groups, got %d", len(dups))
		}
	})

	t.Run("detects same version duplicates", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
		}

		dups := DetectDuplicates(comps)

		if len(dups) != 1 {
			t.Errorf("expected 1 duplicate group, got %d", len(dups))
		}
		if len(dups) > 0 && len(dups[0].Versions) != 1 {
			t.Errorf("expected 1 unique version, got %d", len(dups[0].Versions))
		}
	})

	t.Run("empty input returns no duplicates", func(t *testing.T) {
		dups := DetectDuplicates([]sbom.Component{})
		if len(dups) != 0 {
			t.Errorf("expected 0 duplicate groups, got %d", len(dups))
		}
	})

	t.Run("multiple duplicate groups", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20"},
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
			{ID: "pkg:npm/express", Name: "express", Version: "4.17.0"},
			{ID: "pkg:npm/express", Name: "express", Version: "4.18.0"},
		}

		dups := DetectDuplicates(comps)

		if len(dups) != 2 {
			t.Errorf("expected 2 duplicate groups, got %d", len(dups))
		}
	})
}

func TestDiffDuplicateVersions(t *testing.T) {
	t.Run("detects versions added to duplicate group", func(t *testing.T) {
		before := []DuplicateGroup{
			{ID: "pkg:npm/lodash", Name: "lodash", Versions: []string{"4.17.20"}},
		}
		after := []DuplicateGroup{
			{ID: "pkg:npm/lodash", Name: "lodash", Versions: []string{"4.17.20", "4.17.21"}},
		}

		diff := DiffDuplicateVersions(before, after)

		if len(diff.VersionsAdded) != 1 {
			t.Fatalf("expected 1 component with versions added, got %d", len(diff.VersionsAdded))
		}
		if diff.VersionsAdded["pkg:npm/lodash"][0] != "4.17.21" {
			t.Errorf("expected 4.17.21 added, got %v", diff.VersionsAdded["pkg:npm/lodash"])
		}
	})

	t.Run("detects versions removed from duplicate group", func(t *testing.T) {
		before := []DuplicateGroup{
			{ID: "pkg:npm/lodash", Name: "lodash", Versions: []string{"4.17.20", "4.17.21"}},
		}
		after := []DuplicateGroup{
			{ID: "pkg:npm/lodash", Name: "lodash", Versions: []string{"4.17.21"}},
		}

		diff := DiffDuplicateVersions(before, after)

		if len(diff.VersionsRemoved) != 1 {
			t.Fatalf("expected 1 component with versions removed, got %d", len(diff.VersionsRemoved))
		}
		if diff.VersionsRemoved["pkg:npm/lodash"][0] != "4.17.20" {
			t.Errorf("expected 4.17.20 removed, got %v", diff.VersionsRemoved["pkg:npm/lodash"])
		}
	})

	t.Run("detects new duplicate group", func(t *testing.T) {
		before := []DuplicateGroup{}
		after := []DuplicateGroup{
			{ID: "pkg:npm/lodash", Name: "lodash", Versions: []string{"4.17.20", "4.17.21"}},
		}

		diff := DiffDuplicateVersions(before, after)

		if len(diff.NewDuplicates) != 1 {
			t.Fatalf("expected 1 new duplicate, got %d", len(diff.NewDuplicates))
		}
	})

	t.Run("detects resolved duplicate group", func(t *testing.T) {
		before := []DuplicateGroup{
			{ID: "pkg:npm/lodash", Name: "lodash", Versions: []string{"4.17.20", "4.17.21"}},
		}
		after := []DuplicateGroup{}

		diff := DiffDuplicateVersions(before, after)

		if len(diff.ResolvedDuplicates) != 1 {
			t.Fatalf("expected 1 resolved duplicate, got %d", len(diff.ResolvedDuplicates))
		}
	})

	t.Run("no changes for identical duplicates", func(t *testing.T) {
		before := []DuplicateGroup{
			{ID: "pkg:npm/lodash", Name: "lodash", Versions: []string{"4.17.20", "4.17.21"}},
		}
		after := []DuplicateGroup{
			{ID: "pkg:npm/lodash", Name: "lodash", Versions: []string{"4.17.20", "4.17.21"}},
		}

		diff := DiffDuplicateVersions(before, after)

		if !diff.IsEmpty() {
			t.Error("expected empty diff for identical duplicates")
		}
	})
}

func TestDetectCollisions(t *testing.T) {
	t.Run("detects identity collision with different names", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20"},
			{ID: "pkg:npm/lodash", Name: "lodash-es", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		}

		collisions := DetectCollisions(comps)

		if len(collisions) != 1 {
			t.Fatalf("expected 1 collision, got %d", len(collisions))
		}
		if collisions[0].ID != "pkg:npm/lodash" {
			t.Errorf("expected pkg:npm/lodash collision, got %s", collisions[0].ID)
		}
	})

	t.Run("no collision for same name different versions", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20"},
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
		}

		collisions := DetectCollisions(comps)

		if len(collisions) != 0 {
			t.Errorf("expected no collisions for same-name duplicates, got %d", len(collisions))
		}
	})

	t.Run("detects collision with different hashes", func(t *testing.T) {
		comps := []sbom.Component{
			{ID: "pkg:npm/a", Name: "a", Version: "1.0.0", Hashes: map[string]string{"SHA256": "abc123"}},
			{ID: "pkg:npm/a", Name: "a", Version: "1.0.0", Hashes: map[string]string{"SHA256": "def456"}},
		}

		collisions := DetectCollisions(comps)

		if len(collisions) != 1 {
			t.Fatalf("expected 1 collision for different hashes, got %d", len(collisions))
		}
		if collisions[0].Reason != "hash_mismatch" {
			t.Errorf("expected hash_mismatch reason, got %s", collisions[0].Reason)
		}
	})
}
