package main

import "testing"

func TestBuildDependencyGraph(t *testing.T) {
	t.Run("builds graph from dependencies", func(t *testing.T) {
		comps := []Component{
			{ID: "pkg:npm/app", Name: "app", Version: "1.0.0", Dependencies: []string{"pkg:npm/lodash", "pkg:npm/express"}},
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
			{ID: "pkg:npm/express", Name: "express", Version: "4.18.0", Dependencies: []string{"pkg:npm/lodash"}},
		}

		graph := buildDependencyGraph(comps)

		if len(graph["pkg:npm/app"]) != 2 {
			t.Errorf("expected app to have 2 dependencies, got %d", len(graph["pkg:npm/app"]))
		}
		if len(graph["pkg:npm/express"]) != 1 {
			t.Errorf("expected express to have 1 dependency, got %d", len(graph["pkg:npm/express"]))
		}
		if len(graph["pkg:npm/lodash"]) != 0 {
			t.Errorf("expected lodash to have 0 dependencies, got %d", len(graph["pkg:npm/lodash"]))
		}
	})

	t.Run("handles empty dependencies", func(t *testing.T) {
		comps := []Component{
			{ID: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21"},
		}

		graph := buildDependencyGraph(comps)

		if len(graph) != 1 {
			t.Errorf("expected 1 entry, got %d", len(graph))
		}
	})

	t.Run("handles empty input", func(t *testing.T) {
		graph := buildDependencyGraph([]Component{})

		if len(graph) != 0 {
			t.Errorf("expected empty graph, got %d entries", len(graph))
		}
	})
}

func TestDiffDependencyGraphs(t *testing.T) {
	t.Run("detects added dependencies", func(t *testing.T) {
		before := map[string][]string{
			"pkg:npm/app": {"pkg:npm/lodash"},
		}
		after := map[string][]string{
			"pkg:npm/app": {"pkg:npm/lodash", "pkg:npm/express"},
		}

		diff := diffDependencyGraphs(before, after)

		if len(diff.AddedDeps) != 1 {
			t.Errorf("expected 1 added dep, got %d", len(diff.AddedDeps))
		}
		if diff.AddedDeps["pkg:npm/app"][0] != "pkg:npm/express" {
			t.Errorf("expected pkg:npm/express to be added")
		}
	})

	t.Run("detects removed dependencies", func(t *testing.T) {
		before := map[string][]string{
			"pkg:npm/app": {"pkg:npm/lodash", "pkg:npm/express"},
		}
		after := map[string][]string{
			"pkg:npm/app": {"pkg:npm/lodash"},
		}

		diff := diffDependencyGraphs(before, after)

		if len(diff.RemovedDeps) != 1 {
			t.Errorf("expected 1 removed dep, got %d", len(diff.RemovedDeps))
		}
	})

	t.Run("no changes for identical graphs", func(t *testing.T) {
		graph := map[string][]string{
			"pkg:npm/app": {"pkg:npm/lodash"},
		}

		diff := diffDependencyGraphs(graph, graph)

		if len(diff.AddedDeps) != 0 || len(diff.RemovedDeps) != 0 {
			t.Errorf("expected no changes")
		}
	})

	t.Run("handles new component with deps", func(t *testing.T) {
		before := map[string][]string{}
		after := map[string][]string{
			"pkg:npm/app": {"pkg:npm/lodash"},
		}

		diff := diffDependencyGraphs(before, after)

		if len(diff.AddedDeps) != 1 {
			t.Errorf("expected 1 added dep entry, got %d", len(diff.AddedDeps))
		}
	})

	t.Run("handles removed component with deps", func(t *testing.T) {
		before := map[string][]string{
			"pkg:npm/app": {"pkg:npm/lodash"},
		}
		after := map[string][]string{}

		diff := diffDependencyGraphs(before, after)

		if len(diff.RemovedDeps) != 1 {
			t.Errorf("expected 1 removed dep entry, got %d", len(diff.RemovedDeps))
		}
	})
}

func TestDiffResultWithDependencies(t *testing.T) {
	t.Run("includes dependency diff in result", func(t *testing.T) {
		before := []Component{
			{ID: "pkg:npm/app", Name: "app", Version: "1.0.0", Dependencies: []string{"pkg:npm/lodash"}},
		}
		after := []Component{
			{ID: "pkg:npm/app", Name: "app", Version: "1.0.0", Dependencies: []string{"pkg:npm/lodash", "pkg:npm/express"}},
		}

		result := diffComponents(before, after)

		if result.Dependencies == nil {
			t.Fatal("expected dependencies diff, got nil")
		}
		if len(result.Dependencies.AddedDeps) != 1 {
			t.Errorf("expected 1 added dep, got %d", len(result.Dependencies.AddedDeps))
		}
	})

	t.Run("no dependency diff when unchanged", func(t *testing.T) {
		before := []Component{
			{ID: "pkg:npm/app", Name: "app", Version: "1.0.0", Dependencies: []string{"pkg:npm/lodash"}},
		}
		after := []Component{
			{ID: "pkg:npm/app", Name: "app", Version: "1.0.0", Dependencies: []string{"pkg:npm/lodash"}},
		}

		result := diffComponents(before, after)

		if result.Dependencies != nil {
			t.Errorf("expected no dependencies diff, got %+v", result.Dependencies)
		}
	})
}
