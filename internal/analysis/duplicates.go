package analysis

import (
	"sort"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// DuplicateReport holds duplicate component data.
type DuplicateReport struct {
	Before      []DuplicateGroup      `json:"before,omitempty"`
	After       []DuplicateGroup      `json:"after,omitempty"`
	VersionDiff *DuplicateVersionDiff `json:"version_diff,omitempty"`
	Collisions  []Collision           `json:"collisions,omitempty"`
}

// DuplicateGroup is a set of components sharing an ID.
type DuplicateGroup struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Versions   []string         `json:"versions"`
	Components []sbom.Component `json:"components"`
}

// DuplicateVersionDiff tracks version set changes.
type DuplicateVersionDiff struct {
	VersionsAdded      map[string][]string `json:"versions_added,omitempty"`
	VersionsRemoved    map[string][]string `json:"versions_removed,omitempty"`
	NewDuplicates      []DuplicateGroup    `json:"new_duplicates,omitempty"`
	ResolvedDuplicates []DuplicateGroup    `json:"resolved_duplicates,omitempty"`
}

// Collision is an ambiguous identity match.
type Collision struct {
	ID         string           `json:"id"`
	Reason     string           `json:"reason"`
	Components []sbom.Component `json:"components"`
}

func (d *DuplicateVersionDiff) IsEmpty() bool {
	return len(d.VersionsAdded) == 0 &&
		len(d.VersionsRemoved) == 0 &&
		len(d.NewDuplicates) == 0 &&
		len(d.ResolvedDuplicates) == 0
}

// DetectDuplicates finds same-ID components with different versions.
func DetectDuplicates(comps []sbom.Component) []DuplicateGroup {
	groups := make(map[string][]sbom.Component)
	for _, c := range comps {
		groups[c.ID] = append(groups[c.ID], c)
	}

	var dups []DuplicateGroup
	for id, components := range groups {
		if len(components) > 1 {
			versions := make([]string, 0, len(components))
			seen := make(map[string]bool)
			for _, c := range components {
				if !seen[c.Version] {
					versions = append(versions, c.Version)
					seen[c.Version] = true
				}
			}
			sort.Strings(versions)
			dups = append(dups, DuplicateGroup{
				ID:         id,
				Name:       components[0].Name,
				Versions:   versions,
				Components: components,
			})
		}
	}
	sort.Slice(dups, func(i, j int) bool { return dups[i].ID < dups[j].ID })
	return dups
}

// DiffDuplicateVersions compares duplicate groups.
func DiffDuplicateVersions(before, after []DuplicateGroup) DuplicateVersionDiff {
	diff := DuplicateVersionDiff{
		VersionsAdded:   make(map[string][]string),
		VersionsRemoved: make(map[string][]string),
	}

	beforeMap := make(map[string]DuplicateGroup)
	afterMap := make(map[string]DuplicateGroup)

	for _, g := range before {
		beforeMap[g.ID] = g
	}
	for _, g := range after {
		afterMap[g.ID] = g
	}

	for id, afterGroup := range afterMap {
		beforeGroup, exists := beforeMap[id]
		if !exists {
			diff.NewDuplicates = append(diff.NewDuplicates, afterGroup)
		} else {
			beforeVersions := ToSet(beforeGroup.Versions)
			afterVersions := ToSet(afterGroup.Versions)

			for v := range afterVersions {
				if !beforeVersions[v] {
					diff.VersionsAdded[id] = append(diff.VersionsAdded[id], v)
				}
			}

			for v := range beforeVersions {
				if !afterVersions[v] {
					diff.VersionsRemoved[id] = append(diff.VersionsRemoved[id], v)
				}
			}
		}
	}

	for id, beforeGroup := range beforeMap {
		if _, exists := afterMap[id]; !exists {
			diff.ResolvedDuplicates = append(diff.ResolvedDuplicates, beforeGroup)
		}
	}

	sort.Slice(diff.NewDuplicates, func(i, j int) bool {
		return diff.NewDuplicates[i].ID < diff.NewDuplicates[j].ID
	})
	sort.Slice(diff.ResolvedDuplicates, func(i, j int) bool {
		return diff.ResolvedDuplicates[i].ID < diff.ResolvedDuplicates[j].ID
	})
	for id := range diff.VersionsAdded {
		sort.Strings(diff.VersionsAdded[id])
	}
	for id := range diff.VersionsRemoved {
		sort.Strings(diff.VersionsRemoved[id])
	}

	return diff
}

// DetectCollisions finds same-ID components with conflicting characteristics.
func DetectCollisions(comps []sbom.Component) []Collision {
	groups := make(map[string][]sbom.Component)
	for _, c := range comps {
		groups[c.ID] = append(groups[c.ID], c)
	}

	var collisions []Collision
	for id, components := range groups {
		if len(components) < 2 {
			continue
		}

		names := make(map[string]bool)
		for _, c := range components {
			names[c.Name] = true
		}
		if len(names) > 1 {
			collisions = append(collisions, Collision{
				ID:         id,
				Reason:     "name_mismatch",
				Components: components,
			})
			continue
		}

		versionHashes := make(map[string]map[string]string) // version -> algo -> hash
		for _, c := range components {
			if len(c.Hashes) == 0 {
				continue
			}
			if _, exists := versionHashes[c.Version]; !exists {
				versionHashes[c.Version] = make(map[string]string)
			}
			for algo, hash := range c.Hashes {
				if existing, ok := versionHashes[c.Version][algo]; ok && existing != hash {
					collisions = append(collisions, Collision{
						ID:         id,
						Reason:     "hash_mismatch",
						Components: components,
					})
					break
				}
				versionHashes[c.Version][algo] = hash
			}
		}
	}

	sort.Slice(collisions, func(i, j int) bool {
		return collisions[i].ID < collisions[j].ID
	})
	return collisions
}
