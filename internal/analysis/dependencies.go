package analysis

import (
	"sort"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// DependencyDiff contains information about dependency changes
type DependencyDiff struct {
	AddedDeps      map[string][]string `json:"added_deps,omitempty"`
	RemovedDeps    map[string][]string `json:"removed_deps,omitempty"`
	TransitiveNew  []TransitiveDep     `json:"transitive_new,omitempty"`
	TransitiveLost []TransitiveDep     `json:"transitive_lost,omitempty"`
	DepthSummary   *DepthSummary       `json:"depth_summary,omitempty"`
}

// TransitiveDep represents a new transitive dependency
type TransitiveDep struct {
	Target string   `json:"target"` // The new transitive dep
	Via    []string `json:"via"`    // Path to reach it
	Depth  int      `json:"depth"`  // Depth from root
}

// DepthSummary shows deps introduced at various depths
type DepthSummary struct {
	Depth1     int `json:"depth_1"`      // Direct deps
	Depth2     int `json:"depth_2"`      // 2 hops away
	Depth3Plus int `json:"depth_3_plus"` // 3+ hops (risky)
}

// IsEmpty returns true if there are no dependency changes
func (d *DependencyDiff) IsEmpty() bool {
	return len(d.AddedDeps) == 0 && len(d.RemovedDeps) == 0 &&
		len(d.TransitiveNew) == 0 && len(d.TransitiveLost) == 0
}

// BuildDependencyGraph creates a dependency graph from components
func BuildDependencyGraph(comps []sbom.Component) map[string][]string {
	graph := make(map[string][]string)
	for _, c := range comps {
		graph[c.ID] = c.Dependencies
	}
	return graph
}

// DiffDependencyGraphs compares two dependency graphs
func DiffDependencyGraphs(before, after map[string][]string) DependencyDiff {
	diff := DependencyDiff{
		AddedDeps:   make(map[string][]string),
		RemovedDeps: make(map[string][]string),
	}

	// Check for added/changed deps
	for id, afterDeps := range after {
		beforeDeps := before[id]
		beforeSet := ToSet(beforeDeps)

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
		afterSet := ToSet(afterDeps)

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

	// Compute transitive reachability changes
	beforeReach := computeAllReachable(before)
	afterReach := computeAllReachable(after)

	diff.TransitiveNew, diff.TransitiveLost = diffReachability(before, after, beforeReach, afterReach)

	// Compute depth summary for new transitive deps
	if len(diff.TransitiveNew) > 0 {
		diff.DepthSummary = computeDepthSummary(diff.TransitiveNew)
	}

	return diff
}

// computeAllReachable computes the set of all reachable nodes from each node
func computeAllReachable(graph map[string][]string) map[string]map[string]bool {
	reachable := make(map[string]map[string]bool)

	for node := range graph {
		reachable[node] = bfsReachable(graph, node)
	}

	return reachable
}

// bfsReachable finds all nodes reachable from start using BFS
func bfsReachable(graph map[string][]string, start string) map[string]bool {
	visited := make(map[string]bool)
	queue := []string{start}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		for _, dep := range graph[current] {
			if !visited[dep] {
				queue = append(queue, dep)
			}
		}
	}

	// Remove self from reachable set
	delete(visited, start)
	return visited
}

// bfsWithPath finds shortest path from start to target
func bfsWithPath(graph map[string][]string, start, target string) ([]string, int) {
	if start == target {
		return nil, 0
	}

	type node struct {
		id   string
		path []string
	}

	visited := make(map[string]bool)
	queue := []node{{id: start, path: []string{start}}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.id] {
			continue
		}
		visited[current.id] = true

		for _, dep := range graph[current.id] {
			newPath := append([]string{}, current.path...)
			newPath = append(newPath, dep)

			if dep == target {
				return newPath, len(newPath) - 1
			}

			if !visited[dep] {
				queue = append(queue, node{id: dep, path: newPath})
			}
		}
	}

	return nil, -1
}

// diffReachability finds new and lost transitive dependencies
func diffReachability(before, after map[string][]string, beforeReach, afterReach map[string]map[string]bool) ([]TransitiveDep, []TransitiveDep) {
	var newDeps, lostDeps []TransitiveDep
	seen := make(map[string]bool)

	// Find root nodes (nodes that are not dependencies of any other node)
	roots := FindRoots(after)
	if len(roots) == 0 {
		// Fallback: use all nodes as potential roots
		for node := range after {
			roots = append(roots, node)
		}
	}

	// Find new transitive deps - only check from root nodes for correct depth
	for _, root := range roots {
		afterSet := afterReach[root]
		beforeSet := beforeReach[root]
		if beforeSet == nil {
			beforeSet = make(map[string]bool)
		}

		for dep := range afterSet {
			if !beforeSet[dep] && !seen[dep] {
				// This is a new transitive dependency
				path, depth := bfsWithPath(after, root, dep)
				if depth > 1 { // Only report truly transitive (not direct)
					newDeps = append(newDeps, TransitiveDep{
						Target: dep,
						Via:    path,
						Depth:  depth,
					})
					seen[dep] = true
				}
			}
		}
	}

	// Find roots for before graph
	beforeRoots := FindRoots(before)
	if len(beforeRoots) == 0 {
		for node := range before {
			beforeRoots = append(beforeRoots, node)
		}
	}

	seen = make(map[string]bool)

	// Find lost transitive deps
	for _, root := range beforeRoots {
		beforeSet := beforeReach[root]
		afterSet := afterReach[root]
		if afterSet == nil {
			afterSet = make(map[string]bool)
		}

		for dep := range beforeSet {
			if !afterSet[dep] && !seen[dep] {
				path, depth := bfsWithPath(before, root, dep)
				if depth > 1 {
					lostDeps = append(lostDeps, TransitiveDep{
						Target: dep,
						Via:    path,
						Depth:  depth,
					})
					seen[dep] = true
				}
			}
		}
	}

	// Sort for deterministic output
	sort.Slice(newDeps, func(i, j int) bool { return newDeps[i].Target < newDeps[j].Target })
	sort.Slice(lostDeps, func(i, j int) bool { return lostDeps[i].Target < lostDeps[j].Target })

	return newDeps, lostDeps
}

// FindRoots finds nodes that are not dependencies of any other node
func FindRoots(graph map[string][]string) []string {
	// Build set of all nodes that are dependencies
	isDep := make(map[string]bool)
	for _, deps := range graph {
		for _, dep := range deps {
			isDep[dep] = true
		}
	}

	// Roots are nodes that exist in graph but are not dependencies
	var roots []string
	for node := range graph {
		if !isDep[node] {
			roots = append(roots, node)
		}
	}
	sort.Strings(roots)
	return roots
}

// computeDepthSummary summarizes new deps by depth
func computeDepthSummary(deps []TransitiveDep) *DepthSummary {
	summary := &DepthSummary{}

	for _, dep := range deps {
		switch dep.Depth {
		case 1:
			summary.Depth1++
		case 2:
			summary.Depth2++
		default:
			summary.Depth3Plus++
		}
	}

	return summary
}
