package analysis

import (
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func TestDiffComponents_AddedComponents(t *testing.T) {
	before := []sbom.Component{}
	after := []sbom.Component{
		{ID: "pkg:npm/a", Name: "a", Version: "1.0"},
		{ID: "pkg:npm/b", Name: "b", Version: "1.0"},
	}
	result := DiffComponents(before, after)
	if len(result.Added) != 2 {
		t.Errorf("expected 2 added, got %d", len(result.Added))
	}
}

func TestDiffComponents_RemovedComponents(t *testing.T) {
	before := []sbom.Component{
		{ID: "pkg:npm/a", Name: "a", Version: "1.0"},
		{ID: "pkg:npm/b", Name: "b", Version: "1.0"},
	}
	after := []sbom.Component{}
	result := DiffComponents(before, after)
	if len(result.Removed) != 2 {
		t.Errorf("expected 2 removed, got %d", len(result.Removed))
	}
}

func TestDiffComponents_ChangedComponents(t *testing.T) {
	before := []sbom.Component{
		{ID: "pkg:npm/a", Name: "a", Version: "1.0"},
	}
	after := []sbom.Component{
		{ID: "pkg:npm/a", Name: "a", Version: "2.0"},
	}
	result := DiffComponents(before, after)
	if len(result.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(result.Changed))
	}
	if result.Changed[0].Before.Version != "1.0" || result.Changed[0].After.Version != "2.0" {
		t.Error("expected version change 1.0 -> 2.0")
	}
}

func TestDiffComponents_NoChanges(t *testing.T) {
	comps := []sbom.Component{
		{ID: "pkg:npm/a", Name: "a", Version: "1.0"},
	}
	result := DiffComponents(comps, comps)
	if len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Changed) != 0 {
		t.Errorf("expected no changes, got added=%d removed=%d changed=%d",
			len(result.Added), len(result.Removed), len(result.Changed))
	}
}

func TestDiffComponents_DriftClassified(t *testing.T) {
	before := []sbom.Component{
		{ID: "pkg:npm/a", Name: "a", Version: "1.0", Hashes: map[string]string{"SHA256": "abc"}},
	}
	after := []sbom.Component{
		{ID: "pkg:npm/a", Name: "a", Version: "1.0", Hashes: map[string]string{"SHA256": "xyz"}},
	}
	result := DiffComponents(before, after)
	if len(result.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(result.Changed))
	}
	if result.Changed[0].Drift == nil {
		t.Fatal("expected drift info")
	}
	if result.Changed[0].Drift.Type != DriftTypeIntegrity {
		t.Errorf("expected integrity drift, got %s", result.Changed[0].Drift.Type)
	}
}

func TestDiffComponents_EmptyInputs(t *testing.T) {
	result := DiffComponents(nil, nil)
	if len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Changed) != 0 {
		t.Error("expected empty diff for nil inputs")
	}
}

func TestDiffComponents_OneEmpty(t *testing.T) {
	comps := []sbom.Component{
		{ID: "a", Name: "a", Version: "1.0"},
		{ID: "b", Name: "b", Version: "1.0"},
	}
	result := DiffComponents(comps, nil)
	if len(result.Removed) != 2 {
		t.Errorf("expected 2 removed, got %d", len(result.Removed))
	}
	result = DiffComponents(nil, comps)
	if len(result.Added) != 2 {
		t.Errorf("expected 2 added, got %d", len(result.Added))
	}
}

func TestDiffComponents_DuplicatesIncluded(t *testing.T) {
	before := []sbom.Component{}
	after := []sbom.Component{
		{ID: "pkg:npm/a", Name: "a", Version: "1.0"},
		{ID: "pkg:npm/a", Name: "a", Version: "2.0"},
	}
	result := DiffComponents(before, after)
	if result.Duplicates == nil {
		t.Fatal("expected duplicates report")
	}
	if len(result.Duplicates.After) != 1 {
		t.Errorf("expected 1 duplicate group in after, got %d", len(result.Duplicates.After))
	}
}

func TestDiffComponents_DependenciesIncluded(t *testing.T) {
	before := []sbom.Component{
		{ID: "a", Name: "a", Dependencies: []string{}},
	}
	after := []sbom.Component{
		{ID: "a", Name: "a", Dependencies: []string{"b"}},
		{ID: "b", Name: "b"},
	}
	result := DiffComponents(before, after)
	if result.Dependencies == nil {
		t.Fatal("expected dependency diff")
	}
	if len(result.Dependencies.AddedDeps) == 0 {
		t.Error("expected added deps")
	}
}
