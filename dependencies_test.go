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

func TestTransitiveReachability(t *testing.T) {
	t.Run("detects new transitive dependency", func(t *testing.T) {
		before := map[string][]string{
			"app":     {"express"},
			"express": {},
		}
		after := map[string][]string{
			"app":        {"express"},
			"express":    {"lodash"},
			"lodash":     {"underscore"},
			"underscore": {},
		}

		diff := diffDependencyGraphs(before, after)

		if len(diff.TransitiveNew) == 0 {
			t.Fatal("expected new transitive dependencies")
		}

		found := make(map[string]bool)
		for _, td := range diff.TransitiveNew {
			found[td.Target] = true
		}
		if !found["underscore"] {
			t.Error("expected underscore to be detected as new transitive dep")
		}
	})

	t.Run("detects lost transitive dependency", func(t *testing.T) {
		before := map[string][]string{
			"app":     {"express"},
			"express": {"lodash"},
			"lodash":  {},
		}
		after := map[string][]string{
			"app":     {"express"},
			"express": {},
		}

		diff := diffDependencyGraphs(before, after)

		if len(diff.TransitiveLost) == 0 {
			t.Fatal("expected lost transitive dependencies")
		}

		found := false
		for _, td := range diff.TransitiveLost {
			if td.Target == "lodash" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected lodash to be detected as lost transitive dep")
		}
	})

	t.Run("reports correct depth", func(t *testing.T) {
		before := map[string][]string{
			"app": {},
		}
		after := map[string][]string{
			"app": {"a"},
			"a":   {"b"},
			"b":   {"c"},
			"c":   {},
		}

		diff := diffDependencyGraphs(before, after)

		var maxDepth int
		for _, td := range diff.TransitiveNew {
			if td.Depth > maxDepth {
				maxDepth = td.Depth
			}
		}
		if maxDepth < 3 {
			t.Errorf("expected depth >= 3, got %d", maxDepth)
		}
	})
}

func TestDepthSummary(t *testing.T) {
	t.Run("summarizes deps by depth", func(t *testing.T) {
		deps := []TransitiveDep{
			{Target: "a", Depth: 1},
			{Target: "b", Depth: 2},
			{Target: "c", Depth: 2},
			{Target: "d", Depth: 3},
			{Target: "e", Depth: 4},
			{Target: "f", Depth: 5},
		}

		summary := computeDepthSummary(deps)

		if summary.Depth1 != 1 {
			t.Errorf("expected 1 depth-1 dep, got %d", summary.Depth1)
		}
		if summary.Depth2 != 2 {
			t.Errorf("expected 2 depth-2 deps, got %d", summary.Depth2)
		}
		if summary.Depth3Plus != 3 {
			t.Errorf("expected 3 depth-3+ deps, got %d", summary.Depth3Plus)
		}
	})
}

func TestBFSReachable(t *testing.T) {
	t.Run("finds all reachable nodes", func(t *testing.T) {
		graph := map[string][]string{
			"a": {"b", "c"},
			"b": {"d"},
			"c": {"d"},
			"d": {"e"},
			"e": {},
		}

		reachable := bfsReachable(graph, "a")

		expected := []string{"b", "c", "d", "e"}
		for _, node := range expected {
			if !reachable[node] {
				t.Errorf("expected %s to be reachable from a", node)
			}
		}
		if reachable["a"] {
			t.Error("node should not be reachable from itself")
		}
	})

	t.Run("handles cycles", func(t *testing.T) {
		graph := map[string][]string{
			"a": {"b"},
			"b": {"c"},
			"c": {"a"},
		}

		reachable := bfsReachable(graph, "a")

		if !reachable["b"] || !reachable["c"] {
			t.Error("expected b and c to be reachable")
		}
	})
}

func TestBFSWithPath(t *testing.T) {
	t.Run("finds shortest path", func(t *testing.T) {
		graph := map[string][]string{
			"a": {"b", "c"},
			"b": {"d"},
			"c": {"d"},
			"d": {},
		}

		path, depth := bfsWithPath(graph, "a", "d")

		if depth != 2 {
			t.Errorf("expected depth 2, got %d", depth)
		}
		if len(path) != 3 {
			t.Errorf("expected path length 3, got %d", len(path))
		}
		if path[0] != "a" || path[len(path)-1] != "d" {
			t.Error("path should start with a and end with d")
		}
	})

	t.Run("returns -1 for unreachable target", func(t *testing.T) {
		graph := map[string][]string{
			"a": {"b"},
			"b": {},
			"c": {},
		}

		_, depth := bfsWithPath(graph, "a", "c")

		if depth != -1 {
			t.Errorf("expected -1 for unreachable, got %d", depth)
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
