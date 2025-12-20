package main

import "sort"

type DependencyDiff struct {
	AddedDeps   map[string][]string `json:"added_deps,omitempty"`
	RemovedDeps map[string][]string `json:"removed_deps,omitempty"`
}

func buildDependencyGraph(comps []Component) map[string][]string {
	graph := make(map[string][]string)
	for _, c := range comps {
		graph[c.ID] = c.Dependencies
	}
	return graph
}

func diffDependencyGraphs(before, after map[string][]string) DependencyDiff {
	diff := DependencyDiff{
		AddedDeps:   make(map[string][]string),
		RemovedDeps: make(map[string][]string),
	}

	// Check for added/changed deps
	for id, afterDeps := range after {
		beforeDeps := before[id]
		beforeSet := toSet(beforeDeps)

		var added []string
		for _, dep := range afterDeps {
			if !beforeSet[dep] {
				added = append(added, dep)
			}
		}
		if len(added) > 0 {
			sort.Strings(added)
			diff.AddedDeps[id] = added
		}
	}

	// Check for removed deps
	for id, beforeDeps := range before {
		afterDeps := after[id]
		afterSet := toSet(afterDeps)

		var removed []string
		for _, dep := range beforeDeps {
			if !afterSet[dep] {
				removed = append(removed, dep)
			}
		}
		if len(removed) > 0 {
			sort.Strings(removed)
			diff.RemovedDeps[id] = removed
		}
	}

	return diff
}

func toSet(slice []string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range slice {
		set[s] = true
	}
	return set
}

func (d *DependencyDiff) IsEmpty() bool {
	return len(d.AddedDeps) == 0 && len(d.RemovedDeps) == 0
}
